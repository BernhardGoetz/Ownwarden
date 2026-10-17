/**
 * Lokale Sicherungskopien der Kommandozeile (nur Node; Review sync-1, Entscheidung des
 * Eigentümers vom 2026-10-17).
 *
 * Warum? `sync` ersetzt die lokale .kdbx-Datei durch das Ergebnis des Zusammenführens. Eine
 * Änderung, die dieses Gerät noch nie hochgeladen hat, steht NUR in der lokalen Datei. Verliert
 * sie beim Zusammenführen – z. B. gegen eine neuere Löschung auf einem anderen Gerät, so ist die
 * Regel –, wäre sie danach nirgends mehr: Die Sicherungskopien auf dem Server enthalten nur
 * frühere Fassungen der SERVER-Datei. Deshalb kopiert `sync` die bisherige lokale Datei vorher
 * in den Ordner `ownwarden-local-backups/` neben ihr.
 *
 *   - Name: "<Name ohne .kdbx>.<UTC-Zeit yyyyMMdd-HHmmss-SSS>.kdbx" (Zeit wie bei den Sicherungen
 *     auf dem Server), bei gleicher Millisekunde mit "-2", "-3" … hinter der Zeit. Die Endung
 *     bleibt .kdbx: KeePassXC öffnet eine Sicherung direkt (gleiches Master-Passwort).
 *   - Inhalt: die bisherige Datei Byte für Byte (also weiterhin verschlüsselt).
 *   - Behalten werden die neuesten LOCAL_BACKUPS_TO_KEEP Kopien DIESER Datei (andere Dateien im
 *     Ordner bleiben unberührt); die eben angelegte wird nie gelöscht. Aufräumen ist „best
 *     effort“: Lässt sich eine alte Kopie nicht löschen, gibt es nur einen Hinweis.
 *   - Geschrieben wird atomar mit Rechten 0600, der Ordner mit 0700 (atomic-file.ts; beides wirkt
 *     nur unter Linux/macOS, unter Windows gelten die geerbten Rechte des Ordners).
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { backupBaseName, backupTimestamp } from "../sync/backup-names";
import { writeFileAtomic } from "./atomic-file";

/** Ordner für die lokalen Sicherungskopien, neben der lokalen Datei. */
export const LOCAL_BACKUP_FOLDER = "ownwarden-local-backups";

/** So viele lokale Sicherungskopien pro Datei bleiben liegen. */
export const LOCAL_BACKUPS_TO_KEEP = 10;

export interface LocalBackupResult {
  /** Pfad der angelegten Sicherungskopie. */
  path: string;
  /** Hinweise vom Aufräumen (leer: keine). */
  warnings: string[];
}

/**
 * Kopiert `file` in den Sicherungsordner daneben und räumt alte Kopien dieser Datei auf.
 * Wirft, wenn sich die Kopie nicht anlegen lässt – dann darf der Aufrufer die Datei nicht ersetzen.
 */
export function backupLocalFile(file: string, now: number, keep: number = LOCAL_BACKUPS_TO_KEEP): LocalBackupResult {
  if (!Number.isInteger(keep) || keep < 1) throw new RangeError("backupLocalFile: keep muss eine ganze Zahl ≥ 1 sein.");
  const source = resolve(file);
  const folder = join(dirname(source), LOCAL_BACKUP_FOLDER);
  mkdirSync(folder, { recursive: true, mode: 0o700 });
  const base = backupBaseName(basename(source));
  const stamp = backupTimestamp(now);
  let name = `${base}.${stamp}.kdbx`;
  for (let counter = 2; existsSync(join(folder, name)); counter++) name = `${base}.${stamp}-${counter}.kdbx`;
  const path = join(folder, name);
  writeFileAtomic(path, new Uint8Array(readFileSync(source)));
  return { path, warnings: pruneLocalBackups(folder, base, name, keep) };
}

/** Löscht die ältesten Kopien von `base`, bis `keep` übrig sind (`created` bleibt immer). */
function pruneLocalBackups(folder: string, base: string, created: string, keep: number): string[] {
  let names: string[];
  try {
    names = readdirSync(folder);
  } catch (error) {
    return [`Alte lokale Sicherungskopien wurden nicht aufgeräumt (${errorText(error)}).`];
  }
  const pattern = new RegExp(`^${escapeRegExp(base)}\\.(\\d{8}-\\d{6}-\\d{3})(?:-(\\d+))?\\.kdbx$`);
  const others = names
    .filter((name) => name !== created)
    .map((name) => ({ name, match: pattern.exec(name) }))
    .filter((item): item is { name: string; match: RegExpExecArray } => item.match !== null)
    // Älteste zuerst: nach Zeit, bei gleicher Zeit nach dem Zähler (ohne Zähler = 1).
    .sort((a, b) => a.match[1]!.localeCompare(b.match[1]!) || Number(a.match[2] ?? 1) - Number(b.match[2] ?? 1));
  const warnings: string[] = [];
  for (const { name } of others.slice(0, Math.max(0, others.length - (keep - 1)))) {
    try {
      rmSync(join(folder, name), { force: true });
    } catch (error) {
      warnings.push(`Alte lokale Sicherungskopie „${name}“ ließ sich nicht löschen (${errorText(error)}).`);
    }
  }
  return warnings;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
