import { describe, expect, it } from "vitest";
import { backupFileName, backupsToDelete, backupTimestampOf, backupVersionTag, parseBackupName } from "./backup-names";

describe("Namen der Sicherungskopien", () => {
  const tag = backupVersionTag('"etag-1"');

  it("Basisname + UTC-Zeit yyyyMMdd-HHmmss-SSS + Kennung der Fassung + .kdbx", () => {
    const time = Date.UTC(2026, 9, 5, 7, 3, 9, 4);
    expect(backupFileName("tresor.kdbx", time, '"etag-1"')).toBe(`tresor.20261005-070309-004.${tag}.kdbx`);
    expect(backupFileName("Tresor.KDBX", time, '"etag-1"')).toBe(`Tresor.20261005-070309-004.${tag}.kdbx`);
    expect(backupFileName("daten.db", time, '"etag-1"')).toBe(`daten.db.20261005-070309-004.${tag}.kdbx`);
    expect(() => backupFileName("t.kdbx", Number.NaN, '"etag-1"')).toThrow(RangeError);
  });

  it("Kennung der Fassung: 12 Hex-Zeichen, fest pro ETag, verschieden für verschiedene ETags (Review xc-1)", () => {
    expect(tag).toMatch(/^[0-9a-f]{12}$/);
    expect(backupVersionTag('"etag-1"')).toBe(tag);
    // SHA-256 über den ETag genau wie vom Server (auch schwach, mit Sonderzeichen)
    expect(backupVersionTag("")).toBe("e3b0c44298fc");
    expect(new Set(['"etag-1"', '"etag-2"', 'W/"etag-1"', "etag-1"].map(backupVersionTag)).size).toBe(4);
  });

  it("erkennt nur Sicherungen derselben Datei", () => {
    expect(backupTimestampOf("tresor.kdbx", "tresor.20261005-070309-004.kdbx")).toBe("20261005-070309-004");
    expect(backupTimestampOf("tresor.kdbx", "tresor2.20261005-070309-004.kdbx")).toBeNull();
    expect(backupTimestampOf("tresor.kdbx", "Tresor.20261005-070309-004.kdbx")).toBeNull();
    expect(backupTimestampOf("tresor.kdbx", "tresor.20261005-070309-004.kdbx.part")).toBeNull();
    expect(backupTimestampOf("tresor.kdbx", "tresor.kdbx")).toBeNull();
    // Basisname, der selbst wie eine Sicherung aussieht
    expect(backupTimestampOf("a.20261005-070309-004.kdbx", "a.20261005-070309-004.20261006-000000-000.kdbx")).toBe("20261006-000000-000");
    expect(backupTimestampOf("a.kdbx", "a.20261005-070309-004.20261006-000000-000.kdbx")).toBeNull();
  });

  it("liest Zeit und Kennung; ältere Namen ohne Kennung bleiben Sicherungen", () => {
    expect(parseBackupName("tresor.kdbx", `tresor.20261005-070309-004.${tag}.kdbx`)).toEqual({ timestamp: "20261005-070309-004", versionTag: tag });
    expect(parseBackupName("tresor.kdbx", "tresor.20261005-070309-004.kdbx")).toEqual({ timestamp: "20261005-070309-004", versionTag: null });
    expect(parseBackupName("tresor.kdbx", "tresor.20261005-070309-004.ABCDEF012345.kdbx")).toBeNull();
    expect(parseBackupName("tresor.kdbx", "tresor.20261005-070309-004.abc.kdbx")).toBeNull();
    expect(parseBackupName("anderer.kdbx", `tresor.20261005-070309-004.${tag}.kdbx`)).toBeNull();
  });

  it("wählt die ältesten über `keep` hinaus zum Löschen aus", () => {
    const names = [
      "t.20261003-000000-000.kdbx",
      "t.20261001-000000-000.kdbx",
      "fremd.20200101-000000-000.kdbx",
      `t.20261002-000000-000.${tag}.kdbx`,
      "t.20261004-000000-000.kdbx",
    ];
    expect(backupsToDelete("t.kdbx", names, 2).sort()).toEqual(["t.20261001-000000-000.kdbx", `t.20261002-000000-000.${tag}.kdbx`]);
    expect(backupsToDelete("t.kdbx", names, 10)).toEqual([]);
    expect(backupsToDelete("t.kdbx", names, 0)).toHaveLength(4);
  });
});
