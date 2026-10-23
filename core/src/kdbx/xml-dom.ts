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
import { KdbxError } from "../contracts";
import { displayText } from "../display-text";
import { corrupt } from "./bytes";
import { MAX_XML_BYTES } from "./constants";

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

/**
 * Höchstzahl der Bestandteile (Elemente, Attribute, Kommentare, Verarbeitungsanweisungen,
 * CDATA) beim Einlesen (Sicherheitsaudit dos-4). xmldom braucht je Bestandteil rund 1 KB
 * Speicher. Dichtes XML wie "<a/><a/>…" schafft 4 Byte je Bestandteil (gemessen: schon 8 MiB
 * davon sprengen den Standard-Heap von Node mit 2 GB).
 *
 * Bei echten Dateien soll die Byte-Grenze MAX_XML_BYTES zuerst greifen (Nachprüfung; vorher
 * MAX_XML_BYTES / 16): KeePassXC 2.7.6 schreibt 30 (Einträge fast ohne Inhalt) bis 42 Byte
 * (übliche Einträge mit Verlauf) je Bestandteil, Ownwarden ab 29 (leere Standardfelder). Bei
 * 32 MiB sind das höchstens rund 1,16 Millionen; erlaubt sind 1,5 Millionen (im Schnitt 22 Byte).
 */
export const MAX_XML_NODES = 1_500_000;

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
    if (typeof child !== "string") corrupt(`${context}: <${displayText(element.name)}> darf nur Text enthalten.`);
    text += child;
  }
  return text;
}

// ---------------------------------------------------------------------------
// Vorprüfung vor xmldom
// ---------------------------------------------------------------------------

/** Grenzen für findXmlLimitViolation. */
export interface XmlLimits {
  /** Höchstlänge des Textes in Zeichen (UTF-16-Einheiten; nie mehr als seine UTF-8-Bytes). */
  maxLength: number;
  /** Höchstzahl ineinander geschachtelter Elemente; das Wurzelelement ist Ebene 1. */
  maxDepth: number;
  /**
   * Höchstzahl der Namensraum-Deklarationen (xmlns="…", xmlns:p="…"), die gleichzeitig gelten:
   * die des Elements selbst und die aller seiner Vorfahren. 0 = gar keine.
   */
  maxNamespaceDeclarations: number;
  /**
   * Höchstzahl der Bestandteile, für die xmldom je ein Objekt anlegt: Elemente, Attribute,
   * Kommentare, Verarbeitungsanweisungen, CDATA. Textstücke stehen nur dazwischen, es gibt
   * also höchstens einen mehr; sie zählen nicht extra.
   */
  maxNodes: number;
}

/** Grenzen für KDBX: Die Datenbank-XML benutzt nie Namensräume (Sicherheitsaudit xml-4, xml-5). */
export const KDBX_XML_LIMITS: Readonly<XmlLimits> = {
  maxLength: MAX_XML_BYTES,
  maxDepth: MAX_XML_DEPTH,
  maxNamespaceDeclarations: 0,
  maxNodes: MAX_XML_NODES,
};

/** Abschnitte, in denen "<" und ">" nichts bedeuten: Verarbeitungsanweisung, Kommentar, CDATA. */
const SKIPPED_SECTIONS: readonly (readonly [opening: string, closing: string])[] = [
  ["<?", "?>"],
  ["<!--", "-->"],
  ["<![CDATA[", "]]>"],
];

/**
 * Prüft XML-Text in EINEM Durchgang (lineare Zeit), BEVOR xmldom ihn einliest
 * (Sicherheitsaudit xml-1, dos-4): Größe, Verschachtelungstiefe, Namensraum-Deklarationen und
 * Zahl der Bestandteile.
 *
 * Warum vorher? xmldom legt für jedes Element, das einen Namensraum deklariert, eine weitere
 * Stufe einer Prototyp-Kette an und sucht jeden Namensraum durch diese Kette. N verschachtelte
 * Elemente mit xmlns kosten dadurch N²: 40 000 Ebenen (0,75 MB) blockieren über 30 Sekunden.
 * Und jeder Bestandteil kostet xmldom rund 1 KB Speicher. Eine Prüfung NACH xmldom kommt für
 * beides zu spät.
 *
 * Zerlegt wird nur so weit, wie das Zählen es braucht: Start- und End-Tags, Kommentare, CDATA,
 * Verarbeitungsanweisungen und Attributwerte in Anführungszeichen (dort zählen "<" und ">"
 * nicht). Was xmldom womöglich ANDERS zerlegen würde (Attribut ohne Anführungszeichen oder ohne
 * Wert, Steuerzeichen als Trenner im Tag, "<!" außer Kommentar und CDATA …), gilt als ungültig.
 * So kann xmldom nie mehr Ebenen oder Deklarationen sehen als hier gezählt. Ob das XML sonst
 * wohlgeformt ist, entscheidet danach xmldom.
 *
 * @returns das Problem (deutsch, ohne Inhalt aus dem Text) oder undefined
 */
export function findXmlLimitViolation(text: string, limits: XmlLimits): string | undefined {
  return findViolation(text, limits)?.message;
}

/**
 * Wie findXmlLimitViolation, sagt aber zusätzlich, ob das Problem nur die Größe ist (zu lang, zu
 * viele Bestandteile): Dann ist das XML vielleicht gültig, nur zu groß für Ownwarden (KdbxError
 * „TooLarge“ statt „Corrupt“, siehe parseXml).
 */
function findViolation(text: string, limits: XmlLimits): { message: string; tooLarge: boolean } | undefined {
  const tooLarge = (message: string) => ({ message, tooLarge: true });
  const invalid = (message: string) => ({ message, tooLarge: false });
  if (text.length > limits.maxLength) return tooLarge(`XML ist zu groß (mehr als ${formatLength(limits.maxLength)})`);
  /** Je offenes Element: Zahl seiner eigenen Namensraum-Deklarationen. */
  const open: number[] = [];
  let declarations = 0;
  let nodes = 0;
  let pos = 0;
  for (;;) {
    const tagStart = text.indexOf("<", pos);
    if (tagStart < 0) return undefined;
    const next = text[tagStart + 1];
    if (next === "/") {
      // End-Tag: wie bei xmldom bis zum nächsten ">".
      const end = text.indexOf(">", tagStart + 2);
      if (end < 0 || open.length === 0) return invalid(invalidMarkup(tagStart));
      declarations -= open.pop()!;
      pos = end + 1;
    } else if (next === "?" || next === "!") {
      const section = SKIPPED_SECTIONS.find(([opening]) => text.startsWith(opening, tagStart));
      if (section === undefined) return invalid(invalidMarkup(tagStart)); // z. B. <!ELEMENT oder <![IGNORE[
      const end = text.indexOf(section[1], tagStart + section[0].length);
      if (end < 0) return invalid(invalidMarkup(tagStart));
      if (++nodes > limits.maxNodes) return tooLarge(tooManyNodes(limits.maxNodes));
      pos = end + section[1].length;
    } else {
      const tag = scanStartTag(text, tagStart + 1);
      if (tag === undefined) return invalid(invalidMarkup(tagStart));
      nodes += 1 + tag.attributes;
      if (nodes > limits.maxNodes) return tooLarge(tooManyNodes(limits.maxNodes));
      if (open.length + 1 > limits.maxDepth) return invalid(`XML ist zu tief verschachtelt (mehr als ${limits.maxDepth} Ebenen)`);
      if (declarations + tag.declarations > limits.maxNamespaceDeclarations) {
        return invalid(
          limits.maxNamespaceDeclarations === 0
            ? "Namensraum-Deklarationen (xmlns) sind nicht erlaubt"
            : `zu viele Namensraum-Deklarationen (mehr als ${limits.maxNamespaceDeclarations} gleichzeitig gültige)`,
        );
      }
      if (!tag.selfClosing) {
        open.push(tag.declarations);
        declarations += tag.declarations;
      }
      pos = tag.end;
    }
  }
}

/**
 * Liest ein Start-Tag ab `start` (gleich hinter "<"): Name, dann Attribute der Form
 * Name="Wert" oder Name='Wert' (Leerraum um "=" erlaubt), dann ">" oder "/>".
 * Alles andere ergibt undefined.
 */
function scanStartTag(
  text: string,
  start: number,
): { end: number; attributes: number; declarations: number; selfClosing: boolean } | undefined {
  let p = skipName(text, start);
  if (p === start) return undefined;
  let attributes = 0;
  let declarations = 0;
  for (;;) {
    p = skipSpace(text, p);
    if (text[p] === ">") return { end: p + 1, attributes, declarations, selfClosing: false };
    if (text[p] === "/") return text[p + 1] === ">" ? { end: p + 2, attributes, declarations, selfClosing: true } : undefined;
    const nameStart = p;
    p = skipName(text, p);
    if (p === nameStart) return undefined;
    attributes++;
    // Genau die Attribute, die xmldom als Deklaration behandelt: "xmlns" und "xmlns:…".
    const name = text.slice(nameStart, p);
    if (name === "xmlns" || name.startsWith("xmlns:")) declarations++;
    p = skipSpace(text, p);
    if (text[p] !== "=") return undefined;
    p = skipSpace(text, p + 1);
    const quote = text[p];
    if (quote !== '"' && quote !== "'") return undefined;
    const close = text.indexOf(quote, p + 1);
    if (close < 0) return undefined;
    p = close + 1;
  }
}

/** Leerraum in Tags: nur die vier Zeichen, die XML 1.0 dafür vorsieht. */
function skipSpace(text: string, p: number): number {
  while (p < text.length) {
    const code = text.charCodeAt(p);
    if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) break;
    p++;
  }
  return p;
}

/**
 * Überspringt einen Element- oder Attributnamen. Er endet an Leerraum, < > / = " ' und an
 * Zeichen, die xmldom (anders als XML 1.0) als Leerraum behandelt: alle Steuerzeichen bis
 * U+0020, U+0080 und – nach seiner Umwandlung von Zeilenenden – U+0085, U+2028, U+2029. An
 * Letzteren lehnt der Aufrufer ab, weil kein Leerraum, "=" oder Tag-Ende folgt.
 */
function skipName(text: string, p: number): number {
  while (p < text.length) {
    const code = text.charCodeAt(p);
    const stop =
      code <= 0x20 ||
      code === 0x3c || // <
      code === 0x3e || // >
      code === 0x2f || // /
      code === 0x3d || // =
      code === 0x22 || // "
      code === 0x27 || // '
      code === 0x80 ||
      code === 0x85 ||
      code === 0x2028 ||
      code === 0x2029;
    if (stop) break;
    p++;
  }
  return p;
}

function invalidMarkup(position: number): string {
  return `kein gültiges XML (fehlerhaftes Markup an Position ${position})`;
}

function tooManyNodes(maxNodes: number): string {
  return `XML hat zu viele Bestandteile (mehr als ${maxNodes} Elemente, Attribute, Kommentare usw.)`;
}

/** 16777216 -> "16 MiB", 1000 -> "1000 Zeichen". */
function formatLength(length: number): string {
  const MIB = 1024 * 1024;
  return length % MIB === 0 ? `${length / MIB} MiB` : `${length} Zeichen`;
}

// ---------------------------------------------------------------------------
// Einlesen
// ---------------------------------------------------------------------------

/** Optionen für parseXml. */
export interface ParseXmlOptions {
  /**
   * true = in XML 1.0 verbotene Zeichen (als Zeichenreferenz wie &#1;) durchlassen. Nur für
   * unbekannte Elemente AUS DEM MODELL: Dort stehen geschützte Werte im Klartext, auch mit
   * Steuerzeichen (siehe serializeElement). In einer Datei sind sie immer ein Fehler.
   */
  allowInvalidChars?: boolean;
}

/** Anfang der Warnung von xmldom, wenn der Text U+FFFD enthält (ein erlaubtes Zeichen). */
const REPLACEMENT_CHARACTER_WARNING = "Unicode replacement character detected";

/**
 * Liest XML-Text sicher ein und liefert das Wurzelelement.
 *
 * Sicherheit:
 *   - Dokumente mit DOCTYPE oder ENTITY-Deklaration werden abgelehnt (Schutz vor XXE und
 *     „Billion Laughs“). KDBX-Dateien enthalten nie eine DTD.
 *   - Größe, Tiefe, Namensräume und Zahl der Bestandteile prüft findXmlLimitViolation,
 *     bevor xmldom läuft (Sicherheitsaudit xml-1, dos-4). Ist nur die Größe das Problem (zu lang,
 *     zu viele Bestandteile), heißt der Fehler „TooLarge“ (zu groß für Ownwarden), sonst „Corrupt“.
 *   - KDBX benutzt keine Namensräume: Deklarationen und Namen mit Präfix (p:Entry, xml:space)
 *     sind ein Fehler. KeePassXC vergleicht nur den lokalen Namen und läse <p:Entry> als
 *     Eintrag, Ownwarden sähe ein unbekanntes Element (Sicherheitsaudit xml-4, xml-5).
 *   - In XML 1.0 verbotene Zeichen (auch als &#1;) sind ein Fehler, wie bei KeePassXC
 *     (Sicherheitsaudit xml-2), außer mit `allowInvalidChars`.
 *
 * @param context Name des Inhalts für Fehlermeldungen (z. B. "XML-Datenbank")
 */
export function parseXml(text: string, context: string, options: ParseXmlOptions = {}): XmlElement {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    corrupt(`${context}: DOCTYPE- und ENTITY-Deklarationen sind nicht erlaubt.`);
  }
  const problem = findViolation(text, KDBX_XML_LIMITS);
  if (problem?.tooLarge) throw new KdbxError("TooLarge", `${context}: zu groß für Ownwarden – ${problem.message}.`);
  if (problem !== undefined) corrupt(`${context}: ${problem.message}.`);
  let reason: string | undefined;
  const parser = new DOMParser({
    locator: false,
    normalizeLineEndings: normalizeXml10LineEndings,
    // Jede Meldung bricht ab, auch eine Warnung: Mit Warnungen „repariert“ xmldom nachlässige
    // Syntax (Attributwert ohne Anführungszeichen, fehlender Leerraum …), die KeePassXC ablehnt
    // (Sicherheitsaudit xml-5). Einzige Ausnahme: der Hinweis auf U+FFFD im Text.
    onError: (level, message) => {
      if (level === "warning" && message.startsWith(REPLACEMENT_CHARACTER_WARNING)) return;
      reason ??= message;
      throw new Error(message);
    },
  });
  let documentElement: DomNode | null;
  try {
    documentElement = parser.parseFromString(text, "text/xml").documentElement;
  } catch (error) {
    // Die Meldung von xmldom zitiert Stücke des Textes (in einer Datei nie geschützte Werte, die
    // stehen dort nur verschlüsselt): entschärft und gekürzt weitergeben (Sicherheitsaudit leak-1).
    const message = reason ?? (error instanceof Error ? error.message : String(error));
    corrupt(`${context}: kein gültiges XML (${displayText(message.split("\n")[0]!)}).`);
  }
  if (documentElement === null) corrupt(`${context}: kein Wurzelelement.`);
  return convertDomElement(documentElement, 0, context, options.allowInvalidChars === true);
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
function convertDomElement(node: DomNode, depth: number, context: string, allowInvalidChars: boolean): XmlElement {
  // Die Vorprüfung lehnt zu Tiefes schon vor xmldom ab; das hier schützt nur den Aufrufstapel.
  if (depth > MAX_XML_DEPTH) corrupt(`${context}: XML ist zu tief verschachtelt (mehr als ${MAX_XML_DEPTH} Ebenen).`);
  const domElement = node as unknown as {
    nodeName: string;
    attributes: { length: number; item(index: number): { name: string; value: string } | null };
  };
  const name = domElement.nodeName;
  // Namensraum-Deklarationen lehnt schon die Vorprüfung ab; übrig bleibt das vordefinierte
  // Präfix xml: (z. B. <xml:x>, xml:space="preserve").
  // Namen in Meldungen nur über displayText: Sie stammen aus der Datei und können Megabytes lang
  // sein (Sicherheitsaudit leak-1; Steuer- und Bidi-Zeichen lehnt xmldom in Namen schon ab).
  if (name.includes(":")) corrupt(`${context}: Namensraum-Präfixe sind nicht erlaubt (<${displayText(name)}>).`);

  const attributes = new Map<string, string>();
  for (let i = 0; i < domElement.attributes.length; i++) {
    const attribute = domElement.attributes.item(i);
    if (!attribute) continue;
    if (attribute.name.includes(":")) {
      corrupt(`${context}: Namensraum-Präfixe sind nicht erlaubt (${displayText(attribute.name)} in <${displayText(name)}>).`);
    }
    const invalid = allowInvalidChars ? undefined : findInvalidXmlChar(attribute.value);
    if (invalid !== undefined) {
      corrupt(`${context}: Attribut ${displayText(attribute.name)} in <${displayText(name)}> enthält ein in XML 1.0 ungültiges Zeichen (${invalid}).`);
    }
    attributes.set(attribute.name, attribute.value);
  }

  const children: XmlNode[] = [];
  // firstChild/nextSibling statt childNodes.item(i): bei xmldom deutlich schneller.
  for (let child = node.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === DOM_ELEMENT_NODE) {
      children.push(convertDomElement(child, depth + 1, context, allowInvalidChars));
    } else if (child.nodeType === DOM_TEXT_NODE || child.nodeType === DOM_CDATA_SECTION_NODE) {
      // Benachbarte Textstücke (z. B. Text + CDATA) zu einem String zusammenfassen.
      const data = (child as unknown as { data: string }).data;
      // xmldom prüft die Zeichen nicht; geprüft wird der Text NACH dem Auflösen von &#…;.
      const invalid = allowInvalidChars ? undefined : findInvalidXmlChar(data);
      if (invalid !== undefined) corrupt(`${context}: <${displayText(name)}> enthält ein in XML 1.0 ungültiges Zeichen (${invalid}).`);
      const last = children[children.length - 1];
      if (typeof last === "string") children[children.length - 1] = last + data;
      else children.push(data);
    }
    // Kommentare und Verarbeitungsanweisungen werden verworfen (KeePassXC tut dasselbe).
  }

  return { name, attributes, children: dropFormattingWhitespace(children) };
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
 * Anders als beim Schreiben der Datei sind in XML ungültige Zeichen hier KEIN Fehler, sondern
 * werden als Zeichenreferenz (&#1;) aufbewahrt. Grund: Geschützte Werte in unbekannten
 * Elementen stehen im Modell im Klartext; ein Passwort mit Steuerzeichen ginge sonst
 * verloren, obwohl es in der Datei als Base64 problemlos Platz hat. parseXml liest diese
 * Referenzen mit `allowInvalidChars`; in die Datei gelangen sie nie (geschützte Werte stehen
 * dort als Base64, ungeschützte mit solchen Zeichen lehnt escapeText ab).
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

/** Für die Datei: ungültige Zeichen sind ein Fehler (siehe requireValidXmlChars). */
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
 * entfernt sie beim Schreiben und lehnt beim Lesen sogar &#1; ab (getestet mit 2.7.6); in der
 * DATEI dürfen sie also nie stehen. Ownwarden lehnt sie beim Lesen ab (KdbxError "Corrupt")
 * und beim Schreiben ebenfalls (RangeError) – entfernen hieße, Daten still zu verändern
 * (Sicherheitsaudit xml-2). Geschützte Werte sind davon nicht betroffen: Sie stehen als Base64
 * in der Datei (und im Modell als Zeichenreferenz, siehe serializeElement).
 */
const INVALID_XML_CHARS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
/** Wie INVALID_XML_CHARS, aber ohne "g" (exec/test ohne lastIndex-Zustand). */
const INVALID_XML_CHAR = new RegExp(INVALID_XML_CHARS.source);

/** Entfernt die verbotenen Zeichen (nur zum Prüfen, z. B. in index.ts; der Writer entfernt nichts). */
export function stripInvalidXmlChars(text: string): string {
  return text.replace(INVALID_XML_CHARS, "");
}

/** Das erste in XML 1.0 verbotene Zeichen als "U+000B" oder undefined. */
function findInvalidXmlChar(text: string): string | undefined {
  const match = INVALID_XML_CHAR.exec(text);
  return match === null ? undefined : `U+${match[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Wirft einen RangeError, wenn `text` ein in XML 1.0 verbotenes Zeichen enthält. Die Datei
 * kann es nicht speichern; es still zu entfernen hieße, das Modell zu verändern, ohne dass es
 * jemand merkt (Sicherheitsaudit xml-2). vault-ops lehnt solche Eingaben schon vorher ab.
 *
 * @param what was geprüft wird, für die Fehlermeldung (z. B. "Eintrag …: Feldname")
 */
export function requireValidXmlChars(text: string, what: string): void {
  const invalid = findInvalidXmlChar(text);
  if (invalid !== undefined) throw new RangeError(`${what} enthält ein Zeichen, das XML nicht speichern kann (${invalid}).`);
}

/**
 * Text maskieren wie KeePassXC (& < > " als Entity). Zusätzlich wird "\r" als &#13;
 * geschrieben, weil ein XML-Parser ein rohes "\r" beim Lesen in "\n" verwandeln würde –
 * Windows-Zeilenenden in Notizen blieben sonst nicht erhalten (KeePassXC verliert sie).
 * Verbotene Zeichen: RangeError (requireValidXmlChars).
 */
export function escapeText(text: string): string {
  requireValidXmlChars(text, "Modell: Text");
  return text.replace(/[&<>"\r]/g, (c) => TEXT_ESCAPES[c]!);
}

/** Attributwert maskieren (in doppelten Anführungszeichen; Leerraum als Zeichenreferenz). */
export function escapeAttribute(text: string): string {
  requireValidXmlChars(text, "Modell: Attributwert");
  return text.replace(/[&<>"\t\n\r]/g, (c) => ATTRIBUTE_ESCAPES[c]!);
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
