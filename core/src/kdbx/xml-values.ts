/**
 * Umwandlung einzelner Werte zwischen KDBX-XML-Text und Modell: Zeiten, Wahrheitswerte,
 * Zahlen, UUIDs, Tags, Base64, UTF-8.
 *
 * Alle Lese-Funktionen werfen bei ungültigem Inhalt KdbxError("Corrupt"). Die
 * Fehlermeldungen nennen nur, WAS kaputt ist (`what`), nie den Wert selbst – der könnte
 * ein Geheimnis sein.
 *
 * Abgeglichen mit KeePassXC 2.7.6 (src/format/KdbxXmlReader.cpp, KdbxXmlWriter.cpp) und
 * KeePass 2.x (KdbxFile.Read.Streamed.cs, StrUtil.cs).
 */
import type { Millis, Uuid } from "../model";
import { corrupt } from "./bytes";

// ---------------------------------------------------------------------------
// Base64 und UTF-8
// ---------------------------------------------------------------------------

/**
 * Base64 -> Bytes. Leerraum wird ignoriert, fehlendes "=" am Ende toleriert (wie KeePassXC).
 * Ungültige Zeichen oder eine unmögliche Länge ergeben einen Fehler.
 */
export function decodeBase64(text: string, what: string): Uint8Array {
  let binary: string;
  try {
    // atob gibt es im Browser, im Service Worker und in Node (ab 16) – anders als Buffer.
    binary = atob(text);
  } catch {
    corrupt(`${what}: ungültiges Base64.`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Bytes -> Base64 (mit "="-Auffüllung, ohne Zeilenumbrüche). */
export function encodeBase64(bytes: Uint8Array): string {
  // In Stücken, weil String.fromCharCode(...riesigesArray) den Aufrufstapel sprengt.
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
/** Wie strictUtf8, aber ein U+FEFF am Anfang bleibt erhalten (ignoreBOM = „nicht anfassen“). */
const strictUtf8KeepBom = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * UTF-8 -> Text für die GANZE XML-Datei; ungültiges UTF-8 ist ein Fehler (statt stiller
 * Ersatzzeichen). Ein Byte-Order-Mark am Anfang der Datei wird entfernt.
 */
export function decodeUtf8Strict(bytes: Uint8Array, what: string): string {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    corrupt(`${what}: kein gültiges UTF-8.`);
  }
}

/**
 * UTF-8 -> Text für einen EINZELNEN Wert (entschlüsselter geschützter Wert). Wie
 * decodeUtf8Strict, aber ein U+FEFF am Anfang gehört zum Wert und bleibt erhalten:
 * TextDecoder würde es sonst bei jedem Aufruf entfernen – ein Passwort, das mit diesem
 * (unsichtbaren) Zeichen beginnt, wäre danach ein anderes.
 *
 * Bei geschützten Werten ist die strenge Prüfung zugleich eine Plausibilitätsprüfung: Läuft
 * der innere Zufallsstrom aus dem Takt, entsteht fast immer ungültiges UTF-8.
 */
export function decodeUtf8Value(bytes: Uint8Array, what: string): string {
  try {
    return strictUtf8KeepBom.decode(bytes);
  } catch {
    corrupt(`${what}: kein gültiges UTF-8.`);
  }
}

// ---------------------------------------------------------------------------
// Zeiten
// ---------------------------------------------------------------------------

/**
 * KDBX 4 speichert Zeiten als Base64 eines int64 (Little Endian): Sekunden seit
 * 0001-01-01T00:00:00Z. Dieser Zeitpunkt liegt 62 135 596 800 Sekunden vor dem
 * Unix-Nullpunkt (1970-01-01).
 */
export const SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH = 62_135_596_800n;

/**
 * Späteste darstellbare Zeit: 9999-12-31T23:59:59Z (DateTime.MaxValue in KeePass).
 * Spätere oder negative Werte kann KeePass nicht lesen.
 */
export const MAX_KDBX_SECONDS = 315_537_897_599n;

/** Erkennt eine ISO-8601-Zeit wie "2026-10-14T16:37:20Z" (KDBX-3-Stil). */
const ISO_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?$/;

/**
 * Text -> Millisekunden seit 1970. Liest KDBX-4-Base64 und – für ältere oder von Hand
 * erzeugte Dateien – ISO-8601-Text. Bruchteile von Sekunden werden abgeschnitten, damit
 * gelesene Zeiten immer Vielfache von 1000 sind.
 */
export function decodeTime(text: string, what: string): Millis {
  const trimmed = text.trim();
  const iso = ISO_TIME.exec(trimmed);
  if (iso) return decodeIsoTime(iso, what);

  const bytes = decodeBase64(trimmed, what);
  if (bytes.length !== 8) corrupt(`${what}: Zeitangabe hat ${bytes.length} statt 8 Byte.`);
  const seconds = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigInt64(0, true);
  if (seconds < 0n || seconds > MAX_KDBX_SECONDS) corrupt(`${what}: Zeitangabe außerhalb von Jahr 1 bis 9999.`);
  return Number(seconds - SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH) * 1000;
}

function decodeIsoTime(match: RegExpExecArray, what: string): Millis {
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const date = new Date(0);
  // setUTCFullYear statt Date.UTC: Date.UTC macht aus Jahr 0..99 die Jahre 1900..1999.
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  // Überlauf erkennen (z. B. 30. Februar oder 25 Uhr): Date würde ihn still weiterrechnen.
  const valid =
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59;
  if (!valid || year < 1) corrupt(`${what}: ungültige ISO-Zeitangabe.`);

  let millis = date.getTime();
  const zone = match[7];
  if (zone !== undefined && zone !== "Z") {
    // "+02:00" heißt: Ortszeit = UTC + 2 h, also UTC = Ortszeit - 2 h.
    const sign = zone.startsWith("-") ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    const offsetMinutes = Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4));
    millis -= sign * offsetMinutes * 60_000;
  }
  // Die Zeitzone kann eine Zeit über die Grenzen schieben (z. B. 0001-01-01T00:00+01:00).
  // Gleiche Regel wie bei Base64-Zeiten: Was sich nicht wieder speichern ließe, ist ungültig.
  const seconds = BigInt(millis / 1000) + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH;
  if (seconds < 0n || seconds > MAX_KDBX_SECONDS) corrupt(`${what}: Zeitangabe außerhalb von Jahr 1 bis 9999.`);
  return millis;
}

/**
 * Millisekunden seit 1970 -> KDBX-4-Text (Base64 von int64 LE Sekunden seit Jahr 1).
 * Millisekunden werden abgerundet (KDBX kennt nur ganze Sekunden).
 */
export function encodeTime(millis: Millis): string {
  if (!Number.isFinite(millis)) throw new RangeError(`Ungültige Zeit im Modell: ${millis}`);
  const seconds = BigInt(Math.floor(millis / 1000)) + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH;
  if (seconds < 0n || seconds > MAX_KDBX_SECONDS) {
    throw new RangeError(`Zeit im Modell liegt außerhalb von Jahr 1 bis 9999: ${millis}`);
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigInt64(0, seconds, true);
  return encodeBase64(bytes);
}

// ---------------------------------------------------------------------------
// Wahrheitswerte und Zahlen
// ---------------------------------------------------------------------------

/** "True"/"False" in beliebiger Groß-/Kleinschreibung (wie KeePassXC). */
export function decodeBool(text: string, what: string): boolean {
  const normalized = text.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  corrupt(`${what}: "True" oder "False" erwartet.`);
}

/** Wahrheitswert so, wie KeePass und KeePassXC ihn schreiben. */
export function encodeBool(value: boolean): string {
  return value ? "True" : "False";
}

/**
 * Wert eines Attributs wie Protected="True" (KeePassXC: "true" ohne Rücksicht auf
 * Groß-/Kleinschreibung oder "1"; KeePass schreibt immer "True").
 */
export function isTrueAttribute(value: string | undefined): boolean {
  return value !== undefined && (value.toLowerCase() === "true" || value === "1");
}

/** Ganze Zahl (Dezimaltext, optional mit Vorzeichen). */
export function decodeInteger(text: string, what: string): number {
  const trimmed = text.trim();
  if (!/^[+-]?\d{1,16}$/.test(trimmed)) corrupt(`${what}: ganze Zahl erwartet.`);
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value)) corrupt(`${what}: Zahl ist zu groß.`);
  return value;
}

/** Ganze Zahl -> Text. Wirft, wenn das Modell keine ganze Zahl enthält. */
export function encodeInteger(value: number, what: string): string {
  if (!Number.isSafeInteger(value)) throw new RangeError(`${what}: keine ganze Zahl im Modell: ${value}`);
  return String(value);
}

// ---------------------------------------------------------------------------
// UUIDs
// ---------------------------------------------------------------------------

/**
 * Base64-UUID aus der Datei prüfen (genau 16 Byte) und in einheitlicher Schreibweise
 * zurückgeben. So sind UUIDs im Modell direkt vergleichbar, auch wenn eine Datei z. B.
 * Leerraum oder fehlende "="-Zeichen enthält.
 */
export function decodeUuid(text: string, what: string): Uuid {
  const bytes = decodeBase64(text.trim(), what);
  if (bytes.length !== 16) corrupt(`${what}: UUID hat ${bytes.length} statt 16 Byte.`);
  return encodeBase64(bytes);
}

/** Prüft eine UUID aus dem Modell, bevor sie geschrieben wird. */
export function encodeUuid(uuid: Uuid, what: string): string {
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64(uuid, what);
  } catch {
    throw new RangeError(`${what}: UUID im Modell ist kein Base64.`);
  }
  if (bytes.length !== 16) throw new RangeError(`${what}: UUID im Modell hat ${bytes.length} statt 16 Byte.`);
  return encodeBase64(bytes);
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

/**
 * Tags-Text -> Liste. KeePass und KeePassXC trennen beim Lesen an "," und ";".
 * Leerraum am Rand wird entfernt, leere Tags und Doppelte fallen weg; die Reihenfolge
 * bleibt wie in der Datei (KeePassXC sortiert beim Speichern alphabetisch).
 */
export function parseTags(text: string): string[] {
  const tags: string[] = [];
  for (const part of text.split(/[,;]/)) {
    const tag = part.trim();
    if (tag !== "" && !tags.includes(tag)) tags.push(tag);
  }
  return tags;
}

/**
 * Liste -> Tags-Text, getrennt mit ";" wie KeePass. (KeePassXC 2.7 schreibt "," – beide
 * Programme lesen beide Trennzeichen.) Ein Tag darf selbst kein "," oder ";" enthalten,
 * sonst zerfällt es beim nächsten Lesen in zwei Tags.
 */
export function formatTags(tags: readonly string[]): string {
  return tags.join(";");
}
