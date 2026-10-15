/**
 * Byte-Kodierung für den Feld-Merge: kanonische Werte, Vergleiche, Fingerabdrücke.
 *
 * Warum so genau? TypeScript (Erweiterung) und Kotlin (Android) müssen bei gleichem Inhalt
 * BYTEGLEICHE kanonische Werte bilden, sonst
 *   - passen die Fingerabdrücke in Ownwarden.FieldTimes nicht zusammen (jede Seite hielte
 *     die Werte der anderen für „extern geändert“), und
 *   - entscheidet der Gleichstand-Vergleich auf beiden Plattformen verschieden.
 * Das Format ist deshalb bewusst einfach und in spec/README.md beschrieben:
 *
 *   encodeParts([p1, p2, …]) = für jedes Teil: Länge als uint32 Big Endian, dann die Bytes.
 *   Texte werden als UTF-8 kodiert, Zahlen als Dezimaltext, Listen in Listen rekursiv.
 */
import { sha256 } from "@noble/hashes/sha2.js";

/** Ein Teil eines kanonischen Werts: Text (UTF-8), rohe Bytes oder eine verschachtelte Liste. */
export type Part = string | Uint8Array | readonly Part[];

const utf8 = new TextEncoder();

/**
 * Text -> UTF-8. Einzelne Surrogate (kommen in XML nicht vor) werden zu U+FFFD.
 * Kurze reine ASCII-Texte (der Normalfall bei Feldnamen) werden direkt kopiert – das ist
 * deutlich schneller als der Aufruf von TextEncoder und ergibt dieselben Bytes.
 */
export function utf8Bytes(text: string): Uint8Array {
  const length = text.length;
  if (length <= 64) {
    const out = new Uint8Array(length);
    let i = 0;
    for (; i < length; i++) {
      const code = text.charCodeAt(i);
      if (code > 0x7f) break;
      out[i] = code;
    }
    if (i === length) return out;
  }
  return utf8.encode(text);
}

/** Kodiert eine Liste von Teilen längenpräfixiert (siehe Kopfkommentar). */
export function encodeParts(parts: readonly Part[]): Uint8Array {
  const encoded = parts.map(partBytes);
  let total = 0;
  for (const bytes of encoded) total += 4 + bytes.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const bytes of encoded) {
    view.setUint32(offset, bytes.length, false);
    out.set(bytes, offset + 4);
    offset += 4 + bytes.length;
  }
  return out;
}

function partBytes(part: Part): Uint8Array {
  if (typeof part === "string") return utf8Bytes(part);
  if (part instanceof Uint8Array) return part;
  return encodeParts(part);
}

/**
 * Vergleicht zwei Byte-Folgen lexikografisch (vorzeichenlose Bytes; ein Präfix ist kleiner).
 * Ergebnis < 0, 0 oder > 0. Grundlage aller festen Gleichstand-Regeln.
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

/** Vergleicht zwei Texte über ihre UTF-8-Bytes (= Unicode-Codepunkt-Reihenfolge). */
export function compareText(a: string, b: string): number {
  return a === b ? 0 : compareBytes(utf8Bytes(a), utf8Bytes(b));
}

/** true, wenn beide Byte-Folgen gleich sind. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a === b || compareBytes(a, b) === 0;
}

/** Bytes -> Base64url ohne "=" (RFC 4648, Abschnitt 5). */
export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Fingerabdruck eines kanonischen Werts: Base64url der ersten 12 Byte von SHA-256
 * (16 Zeichen). 96 Bit reichen, um zufällige Gleichheit praktisch auszuschließen, und
 * halten Ownwarden.FieldTimes klein. (Kein Sicherheitsmerkmal: Wer die Datei ändern kann,
 * kann auch die Fingerabdrücke ändern.)
 */
export function fingerprint(canonical: Uint8Array): string {
  return base64Url(sha256(canonical).subarray(0, 12));
}

/** Dezimaltext einer ganzen Zahl (für kanonische Werte). */
export function decimal(value: number): string {
  return String(Math.trunc(value));
}

/** Millisekunden -> ganze Sekunden (abgerundet). KDBX speichert Zeiten nur sekundengenau. */
export function toSeconds(millis: number): number {
  return Math.floor(millis / 1000);
}

/** Früheste Zeit, die KDBX speichern kann: 0001-01-01T00:00:00Z (in ms seit 1970). */
export const MIN_KDBX_TIME = -62_135_596_800_000;

/** Späteste Zeit, die KDBX speichern kann: 9999-12-31T23:59:59Z (in ms seit 1970). */
export const MAX_KDBX_TIME = 253_402_300_799_000;

/**
 * true für eine ganze Zahl im Zeitbereich von KDBX. Zeiten außerhalb (z. B. aus kaputten
 * Ownwarden.FieldTimes) dürfen nie ins Ergebnis gelangen: Sie würden jeden Vergleich gewinnen,
 * und die Datenbank ließe sich danach nicht mehr speichern (Jahr > 9999).
 */
export function isKdbxTime(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= MIN_KDBX_TIME && (value as number) <= MAX_KDBX_TIME;
}
