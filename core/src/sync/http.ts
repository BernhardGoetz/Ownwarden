/**
 * Kleine HTTP-Hilfen für die WebDAV-Anbindung (webdav.ts) und den Server-Test
 * (cli/webdav-probe.ts).
 *
 * Läuft auch im Service Worker der Browser-Erweiterung: nur fetch, URL, Headers,
 * TextEncoder und btoa – keine Node-APIs.
 */
import { displayText } from "../display-text";
import type { Millis } from "../model";

/** Rechnernamen, für die unverschlüsseltes http:// erlaubt ist (nur für Tests auf dem eigenen Rechner). */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** true, wenn der Rechnername auf den eigenen Rechner zeigt (localhost, 127.0.0.1, [::1]). */
export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

/**
 * Prüft eine vom Nutzer eingetragene Speicher-Adresse und liefert sie als URL.
 *
 * Erlaubt ist nur https://. Ausnahme: http:// auf den eigenen Rechner (Testserver). Über
 * http:// gingen Passwort (Basic-Auth) und Tresor-Datei im Klartext durchs Netz.
 * Zugangsdaten in der Adresse (https://name:pw@host/…) werden abgelehnt, weil die Adresse in
 * Meldungen auftaucht. Abfrage (?…) und Anker (#…) haben in einer WebDAV-Adresse nichts zu
 * suchen und würden das Ableiten von Ordner- und Backup-Adressen verfälschen. Zum Pfad siehe
 * hasPlainPath.
 *
 * @param label Bezeichnung für Fehlermeldungen, z. B. "Adresse der Tresor-Datei"
 */
export function parseStorageUrl(raw: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError(`${label}: keine gültige Adresse.`);
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHost(url.hostname))) {
    throw new TypeError(`${label}: nur https:// ist erlaubt (http:// nur für localhost, 127.0.0.1 und [::1]).`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new TypeError(`${label}: Zugangsdaten gehören nicht in die Adresse.`);
  }
  if (url.search !== "" || url.hash !== "") {
    throw new TypeError(`${label}: Die Adresse darf kein "?" und kein "#" enthalten.`);
  }
  if (!hasPlainPath(raw, url)) {
    throw new TypeError(
      `${label}: Der Pfad darf keine leeren Abschnitte ("//"), keine Abschnitte "." oder "..", keinen "\\" und kein kodiertes "/" oder "\\" (%2F, %5C) enthalten.`,
    );
  }
  return url;
}

/**
 * true, wenn der Pfad der Adresse schlicht ist (Sicherheitsaudit network-3): keine leeren
 * Abschnitte ("//"), kein "\", kein kodiertes "/" oder "\" (%2F, %5C) und keine Abschnitte "."
 * oder ".." (auch kodiert, z. B. "%2e%2e"). Beginnt ein Pfad mit "//", liest ein URL-Parser ihn
 * als Adresse eines ANDEREN Rechners; die übrigen Formen führen über Umwege (Dekodieren, "\" als
 * "/", Auflösen von "..") zum selben Ergebnis oder an eine andere Stelle als eingetragen.
 * Nextcloud und MagentaCLOUD brauchen nichts davon.
 *
 * "\" und Punkt-Abschnitte löst der URL-Parser schon beim Lesen auf; dafür wird deshalb die
 * Eingabe selbst geprüft (ohne Tabulatoren und Zeilenumbrüche, die der Parser ebenfalls entfernt).
 */
function hasPlainPath(raw: string, url: URL): boolean {
  if (raw.includes("\\") || url.pathname.includes("//") || /%2f|%5c/i.test(url.pathname)) return false;
  const input = raw.replace(/[\t\n\r]/g, "");
  const pathStart = input.indexOf("/", input.indexOf("//") + 2);
  if (pathStart < 0) return true;
  const path = input.slice(pathStart).split(/[?#]/)[0]!;
  return !path.split("/").some((segment) => /^(?:\.|%2e){1,2}$/i.test(segment));
}

/** Die Adresse ohne Zugangsdaten, für Meldungen (Zugangsdaten sind ohnehin nie in der URL). */
export function describeUrl(url: URL): string {
  return `${url.origin}${url.pathname}`;
}

/**
 * Wert für den Authorization-Header (Basic-Auth, RFC 7617) mit UTF-8 für Umlaute usw.
 * btoa() allein kann nur Latin-1; deshalb erst UTF-8-Bytes bilden, dann Base64.
 * Ein ":" im Benutzernamen ist bei Basic-Auth nicht darstellbar und wird abgelehnt.
 */
export function basicAuthorization(username: string, password: string): string {
  if (username.includes(":")) throw new TypeError('Der Benutzername darf bei Basic-Auth kein ":" enthalten.');
  const bytes = new TextEncoder().encode(`${username}:${password}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

/** Date-Header (z. B. "Thu, 15 Oct 2026 17:25:06 GMT") -> Millisekunden; undefined, wenn fehlend/ungültig. */
export function parseHttpDate(value: string | null): Millis | undefined {
  if (value === null || value.trim() === "") return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
}

/** Header-Wert oder null, wenn er fehlt oder leer ist. */
export function headerValue(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  return value === null || value === "" ? null : value;
}

/** true für einen schwachen ETag (W/"…"). If-Match vergleicht laut RFC 9110 STARK – ein schwacher ETag passt dort nie. */
export function isWeakEtag(etag: string): boolean {
  return etag.startsWith("W/");
}

/** true, wenn die Antwort eine Weiterleitung ist (bei redirect: "manual" im Browser: type "opaqueredirect", Status 0). */
export function isRedirect(response: Response): boolean {
  return response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400);
}

/**
 * Verwirft den Antwort-Körper, damit die Verbindung frei wird. Fehler dabei sind egal
 * (die Antwort ist dann ohnehin unbrauchbar).
 */
export async function discardBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // absichtlich ignoriert
  }
}

/**
 * Bytes als fetch-Körper. fetch verlangt einen Uint8Array über einem echten ArrayBuffer;
 * liegt er über einem SharedArrayBuffer, wird kopiert.
 */
export function bytesBody(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return data.buffer instanceof ArrayBuffer ? (data as Uint8Array<ArrayBuffer>) : new Uint8Array(data);
}

/**
 * Kurzer, harmloser Grund aus einem fetch-Fehler (z. B. "ECONNREFUSED" oder "TimeoutError").
 * `secrets` werden zur Sicherheit aus dem Text entfernt – fetch nennt keine Header, aber
 * eine eingeschleuste fetch-Funktion (Tests, Erweiterung) könnte es tun. Der Fehlertext kann
 * Teile der Server-Antwort enthalten; er erscheint deshalb nur über displayText (Sicherheitsaudit
 * leak-1), und zwar erst nach dem Entfernen der Geheimnisse (sonst könnte das Kürzen eines
 * zerschneiden).
 */
export function fetchFailureReason(error: unknown, secrets: readonly string[]): string {
  const parts: string[] = [];
  if (error instanceof Error) {
    parts.push(error.name === "TimeoutError" ? "Zeitüberschreitung" : error.name === "AbortError" ? "abgebrochen" : error.message);
    const cause = (error as { cause?: unknown }).cause;
    if (cause instanceof Error) parts.push((cause as { code?: string }).code ?? cause.message);
  } else {
    parts.push(String(error));
  }
  let text = parts.filter((part) => part !== "").join(": ");
  for (const secret of secrets) if (secret !== "") text = text.split(secret).join("***");
  return displayText(text, 400);
}
