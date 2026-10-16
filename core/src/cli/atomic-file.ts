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
 */
import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

/** Schreibt `data` atomar nach `path` (Rechte 0600: nur der Besitzer darf lesen). */
export function writeFileAtomic(path: string, data: Uint8Array): void {
  const target = resolve(path);
  const dir = dirname(target);
  // Punkt am Anfang: versteckt; Zufall: zwei gleichzeitige Schreiber kommen sich nicht in die Quere.
  const temp = join(dir, `.${basename(target)}.${randomBytes(6).toString("hex")}.tmp`);
  try {
    writeAndSync(temp, data);
    renameSync(temp, target);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
  syncDirectory(dir);
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
