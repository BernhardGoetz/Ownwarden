/**
 * Namen der Sicherungskopien und die Auswahl, welche beim Aufräumen gelöscht werden.
 *
 * Schema: "<Basisname>.<UTC-Zeit yyyyMMdd-HHmmss-SSS>.<Fassung>.kdbx", z. B. für "tresor.kdbx":
 *   tresor.20261015-171500-042.3f9a0c12d4e5.kdbx
 * <Fassung> sind 12 Hex-Zeichen aus dem ETag der gesicherten Fassung (backupVersionTag).
 * Ältere Sicherungen ohne diesen Teil ("tresor.20261015-171500-042.kdbx") werden weiter
 * erkannt und aufgeräumt.
 *
 * Warum so?
 *   - Die Endung .kdbx bleibt: KeePassXC & Co. öffnen eine Sicherung direkt.
 *   - Die Zeit steht mit fester Breite im Namen; die alphabetische Reihenfolge ist damit
 *     auch die zeitliche. Das Aufräumen braucht keine Datumsangaben des Servers.
 *     Achtung: Es ist die Uhr des jeweiligen GERÄTS. Geht eine andere Uhr etwas vor, wirkt
 *     deren Sicherung „neuer“. Deshalb löscht WebDavAdapter.pruneBackups die Sicherung der eben
 *     überschriebenen Fassung nie, egal wo sie in dieser Reihenfolge steht.
 *   - Die Fassung im Namen macht das Sichern wiederholbar (Review xc-1): Gibt es schon eine
 *     Sicherung derselben Fassung, legt backup() keine weitere an. Sonst legte jeder gescheiterte
 *     Schreibversuch eine weitere Kopie derselben Fassung an, und beim Aufräumen fielen dafür
 *     ältere, VERSCHIEDENE Fassungen heraus.
 *   - Der Basisname im Namen trennt die Sicherungen mehrerer Tresor-Dateien, die sich einen
 *     Sicherungsordner teilen: Aufgeräumt werden nur die Sicherungen DIESER Datei.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import type { Millis } from "../model";

/**
 * Kennung einer Fassung für den Namen der Sicherung: die ersten 6 Byte von SHA-256 über den
 * ETag (UTF-8, genau wie vom Server geliefert) als 12 Hex-Zeichen. Der ETag selbst kann
 * Zeichen enthalten, die in Dateinamen stören ("/", Anführungszeichen); 48 Bit schließen eine
 * zufällige Gleichheit zweier Fassungen praktisch aus.
 */
export function backupVersionTag(etag: string): string {
  return Array.from(sha256(new TextEncoder().encode(etag)).subarray(0, 6), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Basisname: Dateiname ohne die Endung ".kdbx" (andere Endungen bleiben Teil des Namens). */
export function backupBaseName(fileName: string): string {
  return fileName.replace(/\.kdbx$/i, "");
}

/** UTC-Zeit als "yyyyMMdd-HHmmss-SSS". */
export function backupTimestamp(time: Millis): string {
  const date = new Date(time);
  if (Number.isNaN(date.getTime())) throw new RangeError("Ungültige Zeit für den Namen der Sicherungskopie.");
  const pad = (value: number, width = 2) => String(value).padStart(width, "0");
  return (
    `${pad(date.getUTCFullYear(), 4)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}-` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}-${pad(date.getUTCMilliseconds(), 3)}`
  );
}

/** Name der Sicherungskopie von `fileName` in der Fassung `etag`, angelegt zum Zeitpunkt `time`. */
export function backupFileName(fileName: string, time: Millis, etag: string): string {
  return `${backupBaseName(fileName)}.${backupTimestamp(time)}.${backupVersionTag(etag)}.kdbx`;
}

/** Bestandteile des Namens einer Sicherungskopie. */
export interface BackupNameParts {
  /** "yyyyMMdd-HHmmss-SSS" */
  timestamp: string;
  /** Kennung der Fassung (backupVersionTag); null bei älteren Sicherungen ohne sie. */
  versionTag: string | null;
}

/**
 * Bestandteile, wenn `candidate` eine Sicherungskopie von `fileName` ist, sonst null.
 * Der Vergleich des Basisnamens ist exakt (Groß-/Kleinschreibung zählt).
 */
export function parseBackupName(fileName: string, candidate: string): BackupNameParts | null {
  const prefix = `${backupBaseName(fileName)}.`;
  if (!candidate.startsWith(prefix)) return null;
  const match = /^(\d{8}-\d{6}-\d{3})(?:\.([0-9a-f]{12}))?\.kdbx$/.exec(candidate.slice(prefix.length));
  return match === null ? null : { timestamp: match[1]!, versionTag: match[2] ?? null };
}

/** Zeitstempel-Teil, wenn `candidate` eine Sicherungskopie von `fileName` ist, sonst null. */
export function backupTimestampOf(fileName: string, candidate: string): string | null {
  return parseBackupName(fileName, candidate)?.timestamp ?? null;
}

/**
 * Welche Sicherungen gelöscht werden sollen, damit von `fileName` nur die neuesten `keep`
 * übrig bleiben. Fremde Dateien im Ordner werden nie ausgewählt.
 */
export function backupsToDelete(fileName: string, candidates: readonly string[], keep: number): string[] {
  const backups = candidates
    .map((name) => ({ name, timestamp: backupTimestampOf(fileName, name) }))
    .filter((item): item is { name: string; timestamp: string } => item.timestamp !== null)
    // Neueste zuerst; bei gleicher Zeit entscheidet der Name (feste Reihenfolge).
    .sort((a, b) => (a.timestamp !== b.timestamp ? (a.timestamp < b.timestamp ? 1 : -1) : a.name < b.name ? 1 : -1));
  return backups.slice(Math.max(keep, 0)).map((item) => item.name);
}
