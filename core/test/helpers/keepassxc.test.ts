/**
 * Tests der Test-Hilfen selbst: removeTmpDir löscht rekursiv und darf deshalb NUR
 * Unterordner von core/test/.tmp anfassen – nie den .tmp-Ordner selbst (dort liegen auch
 * Ordner anderer, parallel laufender Tests) und nie Geschwister wie „.tmp-irgendwas“.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { TMP_ROOT, createTmpDir, isInsideTmpRoot, removeTmpDir } from "./keepassxc";

describe("removeTmpDir / isInsideTmpRoot", () => {
  it("Regression: lehnt Geschwisterordner mit gleichem Namensanfang ab", () => {
    // Existiert nicht – der Test kann also auch bei einem Fehler nichts löschen.
    expect(() => removeTmpDir(`${TMP_ROOT}-fremd`)).toThrow();
  });

  it("akzeptiert nur echte Unterordner von .tmp", () => {
    expect(isInsideTmpRoot(TMP_ROOT)).toBe(false);
    expect(isInsideTmpRoot(`${TMP_ROOT}/`)).toBe(false);
    expect(isInsideTmpRoot(`${TMP_ROOT}-fremd`)).toBe(false);
    expect(isInsideTmpRoot(join(TMP_ROOT, "..", "helpers"))).toBe(false);
    expect(isInsideTmpRoot(join(TMP_ROOT, "a", "..", ".."))).toBe(false);
    expect(isInsideTmpRoot(join(TMP_ROOT, "mein-test-1234"))).toBe(true);
  });

  it("legt an und räumt wieder weg", () => {
    const dir = createTmpDir("helper-selbsttest");
    expect(existsSync(dir)).toBe(true);
    removeTmpDir(dir);
    expect(existsSync(dir)).toBe(false);
  });
});
