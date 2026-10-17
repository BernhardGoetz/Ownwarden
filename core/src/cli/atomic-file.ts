/**
 * Atomares Schreiben einer Datei (nur Node, nur für die Kommandozeile).
 *
 * Warum? Die lokale .kdbx-Datei ist der Zwischenspeicher eines Clients. Stürzt das Programm
 * (oder der Rechner) mitten im Schreiben ab, darf sie nie halb geschrieben zurückbleiben –
 * sonst wäre die lokale Kopie unlesbar. Deshalb:
 *   1. alles in eine NEUE temporäre Datei im selben Ordner schreiben,
 *   2. auf die Platte zwingen (fsync),
 *   3. per rename an die Stelle der alten Datei setzen. rename innerhalb eines Ordners ist
 *      atomar: Danach gibt es entweder die alte oder die neue Datei, nie eine Mischung.
 *   4. den Ordner synchronisieren, damit auch das Umbenennen einen Absturz übersteht
 *      (unter Windows nicht möglich und nicht nötig; Fehler dort werden ignoriert).
 * Scheitert etwas, wird die temporäre Datei entfernt; die alte Datei bleibt unverändert.
 *
 * Windows (Review cli-2): Dort scheitert das Umbenennen kurzzeitig mit EPERM, EACCES oder EBUSY,
 * solange ein anderes Programm die Datei offen hält – typisch Virenscanner, Suchindex oder
 * OneDrive/Dropbox direkt nach dem Schreiben. Deshalb wird es dort einige Male mit kurzen
 * Pausen wiederholt (zusammen gut 3 s), wie es auch graceful-fs und write-file-atomic tun.
 */
import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

/** Pausen zwischen den Versuchen, umzubenennen (ms); nur bei vorübergehenden Fehlern, siehe oben. */
export const RENAME_RETRY_DELAYS_MS: readonly number[] = [50, 100, 200, 400, 800, 1600];

/** Fehler-Codes, mit denen Windows ein Umbenennen vorübergehend ablehnt. */
const TRANSIENT_RENAME_ERRORS = new Set(["EPERM", "EACCES", "EBUSY"]);

export interface AtomicWriteOptions {
  /** Umbenennen bei EPERM/EACCES/EBUSY wiederholen; Standard: nur unter Windows. */
  retryRename?: boolean;
  /** Nur für Tests: eigenes Umbenennen bzw. eigene Pausen. */
  rename?: (from: string, to: string) => void;
  retryDelaysMs?: readonly number[];
}

/**
 * Schreibt `data` atomar nach `path`. Die Datei bekommt die Rechte 0600 (nur der Besitzer darf
 * lesen) – das wirkt nur unter Linux/macOS; unter Windows erbt sie die Zugriffsrechte des Ordners.
 */
export function writeFileAtomic(path: string, data: Uint8Array, options: AtomicWriteOptions = {}): void {
  const target = resolve(path);
  const dir = dirname(target);
  // Punkt am Anfang: versteckt; Zufall: zwei gleichzeitige Schreiber kommen sich nicht in die Quere.
  const temp = join(dir, `.${basename(target)}.${randomBytes(6).toString("hex")}.tmp`);
  try {
    writeAndSync(temp, data);
    renameWithRetry(temp, target, options);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
  syncDirectory(dir);
}

function renameWithRetry(from: string, to: string, options: AtomicWriteOptions): void {
  const rename = options.rename ?? renameSync;
  const delays = (options.retryRename ?? process.platform === "win32") ? (options.retryDelaysMs ?? RENAME_RETRY_DELAYS_MS) : [];
  for (let attempt = 0; ; attempt++) {
    try {
      rename(from, to);
      return;
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      if (attempt >= delays.length || typeof code !== "string" || !TRANSIENT_RENAME_ERRORS.has(code)) throw error;
      sleepSync(delays[attempt]!);
    }
  }
}

/** Wartet synchron (die Kommandozeile hat währenddessen nichts anderes zu tun). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function writeAndSync(path: string, data: Uint8Array): void {
  // "wx": nur neu anlegen – eine vorhandene Datei gleichen Namens wird nie überschrieben.
  const fd = openSync(path, "wx", 0o600);
  try {
    let offset = 0;
    while (offset < data.length) offset += writeSync(fd, data, offset, data.length - offset);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function syncDirectory(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Windows kann Ordner nicht öffnen/synchronisieren; die Datei selbst ist schon sicher geschrieben.
  }
}
