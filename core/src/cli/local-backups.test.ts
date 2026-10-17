/**
 * Lokale Sicherungskopien der Kommandozeile (local-backups.ts, Review sync-1) und das
 * Wiederholen des Umbenennens beim atomaren Schreiben unter Windows (atomic-file.ts, Review cli-2).
 */
import { mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, removeTmpDir } from "../../test/helpers/keepassxc";
import { writeFileAtomic } from "./atomic-file";
import { backupLocalFile, LOCAL_BACKUP_FOLDER, LOCAL_BACKUPS_TO_KEEP } from "./local-backups";

/** 2026-10-17T12:00:00.000Z */
const T = Date.UTC(2026, 9, 17, 12, 0, 0, 0);

describe("backupLocalFile", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("local-backups");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("kopiert die Datei Byte für Byte in ownwarden-local-backups/ daneben; Name mit UTC-Zeit; Rechte nur für den Besitzer", () => {
    const sub = join(dir, "kopie");
    mkdirSync(sub);
    const file = join(sub, "tresor.kdbx");
    writeFileSync(file, Uint8Array.from([1, 2, 3, 4]));
    const result = backupLocalFile(file, T + 42);
    expect(result).toEqual({ path: join(sub, LOCAL_BACKUP_FOLDER, "tresor.20261017-120000-042.kdbx"), warnings: [] });
    expect([...readFileSync(result.path)]).toEqual([1, 2, 3, 4]);
    expect(readdirSync(join(sub, LOCAL_BACKUP_FOLDER))).toEqual(["tresor.20261017-120000-042.kdbx"]); // keine Temporärdatei
    if (process.platform !== "win32") {
      expect(statSync(result.path).mode & 0o777).toBe(0o600);
      expect(statSync(join(sub, LOCAL_BACKUP_FOLDER)).mode & 0o777).toBe(0o700);
    }
  });

  it("gleiche Millisekunde: eigener Name mit Zähler, nichts wird überschrieben", () => {
    const sub = join(dir, "gleiche-zeit");
    mkdirSync(sub);
    const file = join(sub, "a.kdbx");
    writeFileSync(file, "eins");
    const first = backupLocalFile(file, T);
    writeFileSync(file, "zwei");
    const second = backupLocalFile(file, T);
    expect(second.path).toBe(join(sub, LOCAL_BACKUP_FOLDER, "a.20261017-120000-000-2.kdbx"));
    expect(readFileSync(first.path, "utf8")).toBe("eins");
    expect(readFileSync(second.path, "utf8")).toBe("zwei");
  });

  it(`behält die neuesten ${LOCAL_BACKUPS_TO_KEEP} Kopien DIESER Datei; fremde Dateien und die eben angelegte bleiben`, () => {
    const sub = join(dir, "aufraeumen");
    mkdirSync(sub);
    const file = join(sub, "a.kdbx");
    const folder = join(sub, LOCAL_BACKUP_FOLDER);
    mkdirSync(folder);
    // Fremde Dateien im selben Ordner: Sicherungen einer anderen Datei, eigene Notizen.
    writeFileSync(join(folder, "a.b.20200101-000000-000.kdbx"), "andere Datei");
    writeFileSync(join(folder, "notiz.txt"), "eigene Datei");
    for (let i = 0; i < 12; i++) {
      writeFileSync(file, `Fassung ${i}`);
      backupLocalFile(file, T + i * 1000);
    }
    const own = readdirSync(folder).filter((name) => /^a\.\d{8}-\d{6}-\d{3}(-\d+)?\.kdbx$/.test(name)).sort();
    expect(own).toHaveLength(LOCAL_BACKUPS_TO_KEEP);
    expect(own[0]).toBe("a.20261017-120002-000.kdbx"); // die beiden ältesten sind weg
    expect(readFileSync(join(folder, own.at(-1)!), "utf8")).toBe("Fassung 11");
    expect(readdirSync(folder)).toEqual(expect.arrayContaining(["a.b.20200101-000000-000.kdbx", "notiz.txt"]));

    // Geht die Uhr jetzt nach (Name „älter“ als alle anderen), bleibt die neue Kopie trotzdem.
    writeFileSync(file, "nach Uhr-Rücksprung");
    const back = backupLocalFile(file, T - 3_600_000);
    expect(readFileSync(back.path, "utf8")).toBe("nach Uhr-Rücksprung");
    expect(readdirSync(folder).filter((name) => /^a\.\d{8}/.test(name))).toHaveLength(LOCAL_BACKUPS_TO_KEEP);
  });

  it("fehlt die Datei, wirft es (der Aufrufer ersetzt dann nichts)", () => {
    expect(() => backupLocalFile(join(dir, "gibt-es-nicht.kdbx"), T)).toThrow();
    expect(() => backupLocalFile(join(dir, "x.kdbx"), T, 0)).toThrow(RangeError);
  });
});

describe("writeFileAtomic: Umbenennen unter Windows wiederholen (Review cli-2)", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("atomic-retry");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  const failing = (codes: string[], real: (from: string, to: string) => void) => {
    let calls = 0;
    const rename = (from: string, to: string) => {
      const code = codes[calls++];
      if (code !== undefined) throw Object.assign(new Error(`${code}: operation not permitted, rename`), { code });
      real(from, to);
    };
    return { rename, calls: () => calls };
  };

  it("EPERM/EBUSY/EACCES kurzzeitig: nach einigen Versuchen geschrieben", () => {
    const path = join(dir, "voruebergehend.kdbx");
    const fake = failing(["EPERM", "EBUSY", "EACCES"], renameSync);
    writeFileAtomic(path, Uint8Array.from([7, 8]), { retryRename: true, rename: fake.rename, retryDelaysMs: [1, 1, 1, 1] });
    expect([...readFileSync(path)]).toEqual([7, 8]);
    expect(fake.calls()).toBe(4);
  });

  it("dauerhaft gesperrt: Fehler nach den Wiederholungen, temporäre Datei entfernt, Ziel unverändert", () => {
    const path = join(dir, "gesperrt.kdbx");
    writeFileSync(path, "alt");
    const fake = failing(["EPERM", "EPERM", "EPERM", "EPERM"], renameSync);
    expect(() => writeFileAtomic(path, Uint8Array.from([1]), { retryRename: true, rename: fake.rename, retryDelaysMs: [1, 1, 1] })).toThrow(/EPERM/);
    expect(fake.calls()).toBe(4); // erster Versuch + 3 Wiederholungen
    expect(readFileSync(path, "utf8")).toBe("alt");
    expect(readdirSync(dir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });

  it("andere Fehler (z. B. ENOENT) und andere Systeme als Windows: keine Wiederholung", () => {
    const path = join(dir, "anderer-fehler.kdbx");
    const other = failing(["ENOENT"], renameSync);
    expect(() => writeFileAtomic(path, Uint8Array.from([1]), { retryRename: true, rename: other.rename, retryDelaysMs: [1, 1] })).toThrow(/ENOENT/);
    expect(other.calls()).toBe(1);
    const posix = failing(["EPERM"], renameSync);
    expect(() => writeFileAtomic(path, Uint8Array.from([1]), { retryRename: false, rename: posix.rename })).toThrow(/EPERM/);
    expect(posix.calls()).toBe(1);
  });
});
