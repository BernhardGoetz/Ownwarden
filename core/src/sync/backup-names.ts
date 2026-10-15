/**
 * Namen der Sicherungskopien und die Auswahl, welche beim Aufräumen gelöscht werden.
 *
 * Schema: "<Basisname>.<UTC-Zeit yyyyMMdd-HHmmss-SSS>.kdbx", z. B. für "tresor.kdbx":
 *   tresor.20261015-171500-042.kdbx
 *
 * Warum so?
 *   - Die Endung .kdbx bleibt: KeePassXC & Co. öffnen eine Sicherung direkt.
 *   - Die Zeit steht mit fester Breite im Namen; die alphabetische Reihenfolge ist damit
 *     auch die zeitliche. Das Aufräumen braucht keine Datumsangaben des Servers.
 *     Achtung: Es ist die Uhr des jeweiligen GERÄTS. Geht eine andere Uhr etwas vor, wirkt
 *     deren Sicherung „neuer“. Deshalb löscht WebDavAdapter.pruneBackups die eben angelegte
 *     Sicherung nie, egal wo sie in dieser Reihenfolge steht.
 *   - Der Basisname im Namen trennt die Sicherungen mehrerer Tresor-Dateien, die sich einen
 *     Sicherungsordner teilen: Aufgeräumt werden nur die Sicherungen DIESER Datei.
 */
import type { Millis } from "../model";

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

/** Name der Sicherungskopie von `fileName` zum Zeitpunkt `time`. */
export function backupFileName(fileName: string, time: Millis): string {
  return `${backupBaseName(fileName)}.${backupTimestamp(time)}.kdbx`;
}

/**
 * Zeitstempel-Teil, wenn `candidate` eine Sicherungskopie von `fileName` ist, sonst null.
 * Der Vergleich des Basisnamens ist exakt (Groß-/Kleinschreibung zählt).
 */
export function backupTimestampOf(fileName: string, candidate: string): string | null {
  const prefix = `${backupBaseName(fileName)}.`;
  if (!candidate.startsWith(prefix)) return null;
  const match = /^(\d{8}-\d{6}-\d{3})\.kdbx$/.exec(candidate.slice(prefix.length));
  return match === null ? null : match[1]!;
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
