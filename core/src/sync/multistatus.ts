/**
 * Liest die Antwort auf PROPFIND (WebDAV "207 Multi-Status", RFC 4918 Abschnitt 13).
 *
 * Beispiel (Nextcloud, gekürzt):
 *   <d:multistatus xmlns:d="DAV:">
 *     <d:response>
 *       <d:href>/remote.php/webdav/ownwarden-backups/tresor.20261015-120000-000.kdbx</d:href>
 *       <d:propstat>
 *         <d:prop><d:getetag>"6f1c…"</d:getetag><d:resourcetype/></d:prop>
 *         <d:status>HTTP/1.1 200 OK</d:status>
 *       </d:propstat>
 *     </d:response>
 *   </d:multistatus>
 *
 * Das Präfix ("d:", "D:" oder keins) wählt jeder Server selbst; maßgeblich ist nur der
 * Namensraum "DAV:". Deshalb wird namensraumbewusst gelesen (getElementsByTagNameNS).
 *
 * Läuft auch im Service Worker (@xmldom/xmldom braucht kein DOM des Browsers).
 */
import { DOMParser, type Element as DomElement } from "@xmldom/xmldom";
import { displayText } from "../display-text";
import { findXmlLimitViolation, type XmlLimits } from "../kdbx/xml-dom";

const DAV_NS = "DAV:";

/**
 * Grenzen, geprüft BEVOR xmldom läuft (Sicherheitsaudit xml-1): Verschachtelte Elemente mit
 * Namensraum-Deklarationen kosten xmldom quadratisch viel Zeit, jeder Bestandteil rund 1 KB
 * Speicher – und das ohne Schlüssel, der Server bestimmt die Antwort. Eine echte Antwort mit
 * 20 Sicherungskopien hat rund 10 KiB, etwa 300 Elemente und weniger als 10 Ebenen
 * (multistatus/response/propstat/prop/lockdiscovery/activelock/…); 50 000 Bestandteile reichen
 * für Tausende Dateien. Gezählt werden nur Deklarationen, die gleichzeitig gelten: Apache
 * mod_dav deklariert in JEDER <response> drei Namensräume, gleichzeitig gelten so nur fünf.
 */
const PROPFIND_XML_LIMITS: XmlLimits = {
  maxLength: 4 * 1024 * 1024,
  maxDepth: 32,
  maxNamespaceDeclarations: 64,
  maxNodes: 50_000,
};

/** Eine Ressource aus der Antwort. */
export interface DavResource {
  /** href genau wie vom Server (meist ein absoluter Pfad, noch prozentkodiert). */
  href: string;
  /**
   * Eigenschaften im Namensraum DAV: aus Abschnitten mit Status 2xx: lokaler Name -> Text
   * (getrimmt). Eigenschaften mit Status 404 („gibt es nicht“) fehlen hier.
   */
  props: Map<string, string>;
  /** true, wenn <resourcetype> ein <collection/> enthält (Ordner). */
  isCollection: boolean;
}

/**
 * Wandelt den XML-Text einer 207-Antwort in eine Liste von Ressourcen.
 * Wirft einen Error mit deutscher Meldung, wenn der Text kein gültiges Multi-Status-XML ist.
 *
 * Sicherheit: DOCTYPE- und ENTITY-Deklarationen werden abgelehnt (Schutz vor XXE und
 * „Billion Laughs“); ein echter WebDAV-Server schickt nie eine DTD. Größe, Tiefe,
 * Namensräume und Bestandteile begrenzt PROPFIND_XML_LIMITS. Meldungen zitieren Server-Text
 * nur entschärft.
 */
export function parseMultistatus(xmlText: string): DavResource[] {
  if (/<!DOCTYPE|<!ENTITY/i.test(xmlText)) {
    throw new Error("PROPFIND-Antwort: DOCTYPE- und ENTITY-Deklarationen sind nicht erlaubt.");
  }
  const problem = findXmlLimitViolation(xmlText, PROPFIND_XML_LIMITS);
  if (problem !== undefined) throw new Error(`PROPFIND-Antwort: ${problem}.`);
  let reason: string | undefined;
  const parser = new DOMParser({
    locator: false,
    onError: (level, message) => {
      if (level === "warning") return;
      reason ??= message;
      throw new Error(message);
    },
  });
  let root: DomElement | null;
  try {
    root = parser.parseFromString(xmlText, "application/xml").documentElement;
  } catch (error) {
    // Die Meldung von xmldom zitiert Stücke der Antwort, die der Server frei bestimmt
    // (Steuerzeichen, Zeilenumbrüche …): nur entschärft und gekürzt (Sicherheitsaudit leak-1).
    const message = reason ?? (error instanceof Error ? error.message : String(error));
    throw new Error(`PROPFIND-Antwort ist kein gültiges XML (${displayText(message.split("\n")[0]!)}).`);
  }
  if (root === null || root.namespaceURI !== DAV_NS || root.localName !== "multistatus") {
    throw new Error("PROPFIND-Antwort: <multistatus> im Namensraum DAV: fehlt.");
  }
  return davChildren(root, "response").map(readResponse);
}

/** Eine <response>. Ohne <href> ist die Antwort kaputt. */
function readResponse(response: DomElement): DavResource {
  const hrefElement = davChildren(response, "href")[0];
  const href = hrefElement?.textContent?.trim() ?? "";
  if (href === "") throw new Error("PROPFIND-Antwort: <response> ohne <href>.");

  const props = new Map<string, string>();
  let isCollection = false;
  for (const propstat of davChildren(response, "propstat")) {
    if (!isSuccessStatus(davChildren(propstat, "status")[0]?.textContent ?? "")) continue;
    for (const prop of davChildren(propstat, "prop")) {
      for (const property of elementChildren(prop)) {
        if (property.namespaceURI !== DAV_NS || property.localName === null) continue;
        props.set(property.localName, (property.textContent ?? "").trim());
        if (property.localName === "resourcetype" && davChildren(property, "collection").length > 0) isCollection = true;
      }
    }
  }
  return { href, props, isCollection };
}

/** "HTTP/1.1 200 OK" -> true für 2xx. */
function isSuccessStatus(statusLine: string): boolean {
  const match = /^\s*HTTP\/\S+\s+(\d{3})/.exec(statusLine);
  return match !== null && match[1]!.startsWith("2");
}

/** Direkte Kind-Elemente. */
function elementChildren(element: DomElement): DomElement[] {
  const result: DomElement[] = [];
  for (let child = element.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === 1) result.push(child as DomElement);
  }
  return result;
}

/** Direkte Kind-Elemente mit diesem lokalen Namen im Namensraum DAV:. */
function davChildren(element: DomElement, localName: string): DomElement[] {
  return elementChildren(element).filter((child) => child.namespaceURI === DAV_NS && child.localName === localName);
}
