import { describe, expect, it } from "vitest";
import { backupFileName, backupsToDelete, backupTimestampOf } from "./backup-names";

describe("Namen der Sicherungskopien", () => {
  it("Basisname + UTC-Zeit yyyyMMdd-HHmmss-SSS + .kdbx", () => {
    const time = Date.UTC(2026, 9, 5, 7, 3, 9, 4);
    expect(backupFileName("tresor.kdbx", time)).toBe("tresor.20261005-070309-004.kdbx");
    expect(backupFileName("Tresor.KDBX", time)).toBe("Tresor.20261005-070309-004.kdbx");
    expect(backupFileName("daten.db", time)).toBe("daten.db.20261005-070309-004.kdbx");
    expect(() => backupFileName("t.kdbx", Number.NaN)).toThrow(RangeError);
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

  it("wählt die ältesten über `keep` hinaus zum Löschen aus", () => {
    const names = [
      "t.20261003-000000-000.kdbx",
      "t.20261001-000000-000.kdbx",
      "fremd.20200101-000000-000.kdbx",
      "t.20261002-000000-000.kdbx",
      "t.20261004-000000-000.kdbx",
    ];
    expect(backupsToDelete("t.kdbx", names, 2).sort()).toEqual(["t.20261001-000000-000.kdbx", "t.20261002-000000-000.kdbx"]);
    expect(backupsToDelete("t.kdbx", names, 10)).toEqual([]);
    expect(backupsToDelete("t.kdbx", names, 0)).toHaveLength(4);
  });
});
