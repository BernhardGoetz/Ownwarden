/**
 * Ein kleiner, eigener XML-Baum für die KDBX-Datenbank: sicher einlesen, aufbauen und im
 * Stil von KeePassXC ausgeben.
 *
 * Warum ein eigener Baum statt des DOM von @xmldom/xmldom?
 *   - Lesen und Schreiben arbeiten mit derselben einfachen Struktur (Name, Attribute,
 *     Kinder). Das macht xml-read.ts, xml-write.ts und xml-protected.ts leicht lesbar.
 *   - Die Ausgabe soll genau so aussehen wie bei KeePassXC (Tabulator-Einrückung, leere
 *     Elemente als <Name/>, Zeilenumbruch "\n"). Das lässt sich mit einem eigenen
 *     Serialisierer exakt steuern; XMLSerializer von xmldom rückt gar nicht ein.
 *   - Formatierungs-Leerraum zwischen Elementen wird beim Einlesen verworfen. Unbekannte
 *     Elemente (model.unknown) sehen dadurch immer gleich aus, egal ob KeePassXC oder
 *     Ownwarden die Datei geschrieben hat.
 *
 * @xmldom/xmldom wird nur zum Einlesen benutzt (läuft auch im Service Worker der
 * Browser-Erweiterung, braucht keine DOM-Globals).
 */
import { DOMParser, type Node as DomNode } from "@xmldom/xmldom";
import { corrupt } from "./bytes";

/** Ein XML-Element. Text-Inhalt steht als string in `children`. */
export interface XmlElement {
  name: string;
  /** Attribute in Originalreihenfolge. */
  attributes: Map<string, string>;
  children: XmlNode[];
}

/** Kind eines Elements: weiteres Element oder Text. */
export type XmlNode = XmlElement | string;

/**
 * Höchste erlaubte Verschachtelungstiefe beim Einlesen. Eine echte Datenbank braucht pro
 * Gruppenebene eine Ebene (Einträge ein paar mehr); 1000 reicht für jede vernünftige
 * Gruppenstruktur. Eine manipulierte Datei mit Millionen verschachtelter Elemente würde
 * sonst den Aufrufstapel sprengen (RangeError statt einer sauberen Fehlermeldung).
 */
export const MAX_XML_DEPTH = 1000;

// ---------------------------------------------------------------------------
// Aufbauen
// ---------------------------------------------------------------------------

/**
 * Erzeugt ein Element. `content` ist entweder Text (leerer Text = leeres Element) oder
 * eine Liste von Kindern.
 */
export function xmlElement(
  name: string,
  content: string | XmlNode[] = [],
  attributes: Record<string, string> = {},
): XmlElement {
  const children = typeof content === "string" ? (content === "" ? [] : [content]) : content;
  return { name, attributes: new Map(Object.entries(attributes)), children };
}

/** Tiefe Kopie eines Elements (der Baum wird beim Verschlüsseln verändert). */
export function cloneXmlElement(element: XmlElement): XmlElement {
  return {
    name: element.name,
    attributes: new Map(element.attributes),
    children: element.children.map((child) => (typeof child === "string" ? child : cloneXmlElement(child))),
  };
}

/** Alle Kind-Elemente (ohne Text). */
export function childElements(element: XmlElement): XmlElement[] {
  return element.children.filter((child): child is XmlElement => typeof child !== "string");
}

/**
 * Der Text eines Elements, das nur Text enthalten darf (z. B. <Name>, <Value>).
 * Enthält es Kind-Elemente, ist die Datei kaputt.
 */
export function plainText(element: XmlElement, context: string): string {
  let text = "";
  for (const child of element.children) {
    if (typeof child !== "string") corrupt(`${context}: <${element.name}> darf nur Text enthalten.`);
    text += child;
  }
  return text;
}

// ---------------------------------------------------------------------------
// Einlesen
// ---------------------------------------------------------------------------

/**
 * Liest XML-Text sicher ein und liefert das Wurzelelement.
 *
 * Sicherheit: Dokumente mit DOCTYPE oder ENTITY-Deklaration werden abgelehnt (Schutz vor
 * XXE und „Billion Laughs“). KDBX-Dateien enthalten nie eine DTD.
 *
 * @param context Name des Inhalts für Fehlermeldungen (z. B. "XML-Datenbank")
 */
export function parseXml(text: string, context: string): XmlElement {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    corrupt(`${context}: DOCTYPE- und ENTITY-Deklarationen sind nicht erlaubt.`);
  }
  const parser = new DOMParser({
    locator: false,
    normalizeLineEndings: normalizeXml10LineEndings,
    // Warnungen sind harmlos; Fehler brechen das Einlesen ab (sonst würde xmldom
    // stillschweigend weiterraten, was mit kaputtem XML gemeint sein könnte).
    onError: (level, message) => {
      if (level !== "warning") throw new Error(message);
    },
  });
  let documentElement: DomNode | null;
  try {
    documentElement = parser.parseFromString(text, "text/xml").documentElement;
  } catch (error) {
    // Die Meldung des Parsers enthält nur Positionen und Elementnamen, keine Werte
    // geschützter Felder (die stehen in der Datei ohnehin nur verschlüsselt).
    const reason = error instanceof Error ? error.message.split("\n")[0] : String(error);
    corrupt(`${context}: kein gültiges XML (${reason}).`);
  }
  if (documentElement === null) corrupt(`${context}: kein Wurzelelement.`);
  return convertDomElement(documentElement, 0, context);
}

/**
 * Zeilenenden wie in XML 1.0: "\r\n" und einzelnes "\r" werden zu "\n".
 *
 * Wichtig: Der Standard von xmldom folgt XML 1.1 und würde zusätzlich U+0085, U+2028 und
 * U+2029 in "\n" verwandeln – das würde Notizen und Passwörter mit diesen Zeichen
 * verfälschen. Ein "\r", das als Zeichenreferenz (&#13;) in der Datei steht, bleibt
 * erhalten, weil Zeichenreferenzen erst nach diesem Schritt aufgelöst werden.
 */
function normalizeXml10LineEndings(source: string): string {
  return source.replace(/\r\n?/g, "\n");
}

const DOM_ELEMENT_NODE = 1;
const DOM_TEXT_NODE = 3;
const DOM_CDATA_SECTION_NODE = 4;

/** Wandelt ein xmldom-Element (rekursiv) in den eigenen Baum um. */
function convertDomElement(node: DomNode, depth: number, context: string): XmlElement {
  if (depth > MAX_XML_DEPTH) corrupt(`${context}: XML ist zu tief verschachtelt (mehr als ${MAX_XML_DEPTH} Ebenen).`);
  const domElement = node as unknown as {
    nodeName: string;
    attributes: { length: number; item(index: number): { name: string; value: string } | null };
  };

  const attributes = new Map<string, string>();
  for (let i = 0; i < domElement.attributes.length; i++) {
    const attribute = domElement.attributes.item(i);
    if (attribute) attributes.set(attribute.name, attribute.value);
  }

  const children: XmlNode[] = [];
  // firstChild/nextSibling statt childNodes.item(i): bei xmldom deutlich schneller.
  for (let child = node.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === DOM_ELEMENT_NODE) {
      children.push(convertDomElement(child, depth + 1, context));
    } else if (child.nodeType === DOM_TEXT_NODE || child.nodeType === DOM_CDATA_SECTION_NODE) {
      // Benachbarte Textstücke (z. B. Text + CDATA) zu einem String zusammenfassen.
      const data = (child as unknown as { data: string }).data;
      const last = children[children.length - 1];
      if (typeof last === "string") children[children.length - 1] = last + data;
      else children.push(data);
    }
    // Kommentare und Verarbeitungsanweisungen werden verworfen (KeePassXC tut dasselbe).
  }

  return { name: domElement.nodeName, attributes, children: dropFormattingWhitespace(children) };
}

/**
 * Leerraum zwischen Kind-Elementen (Einrückung) gehört nicht zum Inhalt und wird
 * verworfen. Ein Element, das NUR Text enthält, behält ihn dagegen vollständig – ein
 * Passwort aus drei Leerzeichen bleibt drei Leerzeichen.
 */
function dropFormattingWhitespace(children: XmlNode[]): XmlNode[] {
  const hasElements = children.some((child) => typeof child !== "string");
  if (!hasElements) return children;
  const onlyWhitespaceText = children.every((child) => typeof child !== "string" || /^[ \t\n\r]*$/.test(child));
  return onlyWhitespaceText ? children.filter((child) => typeof child !== "string") : children;
}

// ---------------------------------------------------------------------------
// Ausgeben
// ---------------------------------------------------------------------------

/** Die XML-Deklaration, die KeePassXC schreibt. */
export const XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';

/**
 * Gibt ein ganzes Dokument im Stil von KeePassXC aus: XML-Deklaration, ein Tabulator pro
 * Ebene, Elemente mit Text in einer Zeile, leere Elemente als <Name/>, "\n" am Ende.
 */
export function serializeDocument(root: XmlElement): string {
  // Eine Zeile pro Eintrag im Array: Große Datenbanken haben Millionen Elemente, viele
  // Kleinst-Strings würden das Zusammenfügen und den Speicherbereiniger ausbremsen.
  const lines: string[] = [XML_DECLARATION + "\n"];
  writeIndented(root, 0, lines);
  return lines.join("");
}

/**
 * Gibt ein Element kompakt (ohne Einrückung) aus – so werden unbekannte Elemente im MODELL
 * gespeichert (model.unknown), nicht in der Datei.
 *
 * Anders als beim Schreiben der Datei werden in XML ungültige Zeichen hier NICHT entfernt,
 * sondern als Zeichenreferenz (&#1;) aufbewahrt. Grund: Geschützte Werte in unbekannten
 * Elementen stehen im Modell im Klartext; ein Passwort mit Steuerzeichen ginge sonst
 * verloren, obwohl es in der Datei als Base64 problemlos Platz hat. Das Einlesen mit
 * xmldom (parseXml) versteht diese Referenzen; in die Datei gelangen sie nie (dort werden
 * ungeschützte Werte bereinigt, geschützte stehen als Base64).
 */
export function serializeElement(element: XmlElement): string {
  return compact(element, MODEL_ESCAPING);
}

/** Einrückungen "", "\t", "\t\t", … nur einmal erzeugen. */
const INDENTS: string[] = [];
function indentFor(depth: number): string {
  return (INDENTS[depth] ??= "\t".repeat(depth));
}

function writeIndented(element: XmlElement, depth: number, out: string[]): void {
  const indent = indentFor(depth);
  let hasText = false;
  let hasElements = false;
  for (const child of element.children) {
    if (typeof child !== "string") hasElements = true;
    else if (child !== "") hasText = true;
  }
  if (hasElements && !hasText) {
    out.push(`${indent}${startTag(element, false, FILE_ESCAPING)}\n`);
    for (const child of element.children) {
      if (typeof child !== "string") writeIndented(child, depth + 1, out);
    }
    out.push(`${indent}</${element.name}>\n`);
  } else {
    // Leer, Text oder gemischter Inhalt: in einer Zeile, ohne zusätzlichen Leerraum, damit
    // der Text unverändert bleibt.
    out.push(`${indent}${compact(element, FILE_ESCAPING)}\n`);
  }
}

/** Wie Text und Attributwerte maskiert werden: für die Datei oder für das Modell. */
interface Escaping {
  text(text: string): string;
  attribute(text: string): string;
}

/** Für die Datei: ungültige Zeichen entfernen (wie KeePassXC). */
const FILE_ESCAPING: Escaping = { text: escapeText, attribute: escapeAttribute };

/** Für model.unknown: ungültige Zeichen als Zeichenreferenz aufbewahren (siehe serializeElement). */
const MODEL_ESCAPING: Escaping = {
  text: (text) => text.replace(MODEL_TEXT_PATTERN, (c) => TEXT_ESCAPES[c] ?? characterReference(c)),
  attribute: (text) => text.replace(MODEL_ATTRIBUTE_PATTERN, (c) => ATTRIBUTE_ESCAPES[c] ?? characterReference(c)),
};

function compact(element: XmlElement, escaping: Escaping): string {
  let content = "";
  for (const child of element.children) {
    content += typeof child === "string" ? escaping.text(child) : compact(child, escaping);
  }
  if (content === "") return startTag(element, true, escaping);
  return `${startTag(element, false, escaping)}${content}</${element.name}>`;
}

function startTag(element: XmlElement, selfClosing: boolean, escaping: Escaping): string {
  let tag = `<${element.name}`;
  for (const [name, value] of element.attributes) tag += ` ${name}="${escaping.attribute(value)}"`;
  return tag + (selfClosing ? "/>" : ">");
}

/**
 * Zeichen, die in XML 1.0 gar nicht vorkommen dürfen (auch nicht als &#…;): Steuerzeichen
 * außer Tab/LF/CR, U+FFFE, U+FFFF und einzelne (ungepaarte) UTF-16-Surrogate. KeePassXC
 * entfernt sie beim Schreiben ebenfalls und lehnt beim Lesen sogar &#1; ab (getestet mit
 * 2.7.6); in der DATEI dürfen sie also nie stehen. Geschützte Werte sind davon nicht
 * betroffen: Sie stehen als Base64 in der Datei (und im Modell als Zeichenreferenz, siehe
 * serializeElement – xmldom ist dort nachsichtiger als KeePassXC).
 */
const INVALID_XML_CHARS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

export function stripInvalidXmlChars(text: string): string {
  return text.replace(INVALID_XML_CHARS, "");
}

/**
 * Text maskieren wie KeePassXC (& < > " als Entity). Zusätzlich wird "\r" als &#13;
 * geschrieben, weil ein XML-Parser ein rohes "\r" beim Lesen in "\n" verwandeln würde –
 * Windows-Zeilenenden in Notizen blieben sonst nicht erhalten (KeePassXC verliert sie).
 */
export function escapeText(text: string): string {
  return stripInvalidXmlChars(text).replace(/[&<>"\r]/g, (c) => TEXT_ESCAPES[c]!);
}

/** Attributwert maskieren (in doppelten Anführungszeichen; Leerraum als Zeichenreferenz). */
export function escapeAttribute(text: string): string {
  return stripInvalidXmlChars(text).replace(/[&<>"\t\n\r]/g, (c) => ATTRIBUTE_ESCAPES[c]!);
}

const TEXT_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "\r": "&#13;",
};
const ATTRIBUTE_ESCAPES: Record<string, string> = { ...TEXT_ESCAPES, "\t": "&#9;", "\n": "&#10;" };

/** Wie escapeText/escapeAttribute, aber ungültige Zeichen werden mit erfasst statt entfernt. */
const MODEL_TEXT_PATTERN = new RegExp(`[&<>"\\r]|${INVALID_XML_CHARS.source}`, "g");
const MODEL_ATTRIBUTE_PATTERN = new RegExp(`[&<>"\\t\\n\\r]|${INVALID_XML_CHARS.source}`, "g");

/** Ein Zeichen (bzw. eine UTF-16-Einheit) als numerische Zeichenreferenz, z. B. "&#1;". */
function characterReference(c: string): string {
  return `&#${c.charCodeAt(0)};`;
}
