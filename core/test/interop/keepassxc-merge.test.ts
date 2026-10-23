/**
 * Integration (e): Wie verhält sich `keepassxc-cli merge` (KeePassXC 2.7.6, Standardmodus)?
 * Dokumentiert die Begründung für die Regel „KeePassXC nicht zum Synchronisieren benutzen“
 * (PROJECT-CONTEXT.md): KeePassXC führt pro EINTRAG statt pro Feld zusammen und übernimmt
 * Löschungen im Standardmodus nicht.
 *
 * Beobachtet (Stand dieses Tests, 2026-10-16) – stimmt mit dem Faktencheck überein:
 *   1. Eine endgültige Löschung in der zweiten Datei wird NICHT übernommen. KeePassXC meldet
 *      „Database was not modified by merge operation“, der Eintrag bleibt, und nicht einmal der
 *      Lösch-Vermerk (DeletedObjects) wird übernommen.
 *   2. Ändern beide Dateien verschiedene Felder desselben Eintrags, gewinnt die NEUERE Fassung
 *      als Ganzes; die Änderung der älteren steht nur noch im Verlauf.
 * Zum Vergleich führt jeweils mergeVaults dieselben Dateien zusammen: Löschung bzw. beide
 * Feldänderungen kommen an.
 *
 * Neu (gab es vorher nicht). Wird übersprungen ohne keepassxc-cli.
 */
import { copyFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, hasKeepassxc, listKpxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../helpers/keepassxc";
import { entryAt, kpxcExportedVault, readKdbxFile, TEST_KDF, waitForNextSecond, writeKdbxFile } from "../helpers/kdbx-files";
import { createNewVault } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import { createEntry } from "../../src/merge/vault-ops";
import type { Uuid } from "../../src/model";

const PASSWORD = "Interop-e-äöü";
const kpxc = (args: string[], extraInput = "") => runKpxcOk(args, `${PASSWORD}\n${extraInput}`);

describe.skipIf(!hasKeepassxc())("Integration (e): Zusammenführen mit keepassxc-cli merge (Standardmodus)", () => {
  let dir: string;
  let basePath: string;
  let weg: Uuid;
  let konto: Uuid;

  beforeAll(async () => {
    dir = createTmpDir("interop-e");
    const vault = createNewVault({ name: "Merge", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    // Ohne Papierkorb ist `keepassxc-cli rm` sofort eine endgültige Löschung (mit DeletedObjects).
    vault.meta.recycleBinEnabled = false;
    const clock = createVaultClock(vault);
    createEntry(vault, vault.root.uuid, { Title: "Bleibt" }, clock);
    weg = createEntry(vault, vault.root.uuid, { Title: "Weg", Password: "weg-pw" }, clock).uuid;
    konto = createEntry(vault, vault.root.uuid, { Title: "Konto", UserName: "u0", Password: "p0" }, clock).uuid;
    basePath = join(dir, "basis.kdbx");
    await writeKdbxFile(vault, basePath, PASSWORD);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  function copies(name: string): { a: string; b: string } {
    const a = join(dir, `${name}-a.kdbx`);
    const b = join(dir, `${name}-b.kdbx`);
    copyFileSync(basePath, a);
    copyFileSync(basePath, b);
    return { a, b };
  }

  it("eine endgültige Löschung wird von KeePassXC NICHT übernommen – von Ownwarden schon", async () => {
    const { a, b } = copies("loeschen");
    await waitForNextSecond();
    await kpxc(["rm", "-q", b, "Weg"]);
    const deletedInB = await kpxcExportedVault(b, PASSWORD);
    expect(deletedInB.vault.deletedObjects.map((item) => item.uuid)).toEqual([weg]);

    // Ownwarden zuerst (liest die unveränderten Dateien), dann KeePassXC.
    const ours = mergeVaults(await readKdbxFile(a, PASSWORD), await readKdbxFile(b, PASSWORD), { now: Date.now() });
    expect(findEntry(ours.vault, weg)).toBeUndefined();
    expect(ours.vault.deletedObjects.map((item) => item.uuid)).toContain(weg);
    expect(ours.report.entriesDeleted).toBe(1);

    // Ohne -q: KeePassXC soll sein Ergebnis melden (nur die Passwort-Abfrage, nie das Passwort).
    const merged = await runKpxcOk(["merge", "-s", a, b], `${PASSWORD}\n`);
    expect(merged.stdout + merged.stderr).toContain("Database was not modified by merge operation");
    expect((await listKpxc(a, PASSWORD)).sort()).toEqual(["Bleibt", "Konto", "Weg"]);
    expect((await kpxcExportedVault(a, PASSWORD)).vault.deletedObjects).toEqual([]);
  });

  it("verschiedene Felder desselben Eintrags: KeePassXC behält die neuere Fassung als Ganzes, Ownwarden beide Änderungen", async () => {
    const { a, b } = copies("felder");
    await waitForNextSecond();
    await kpxc(["edit", "-q", "-u", "u-von-b", b, "Konto"]); // älter
    await waitForNextSecond();
    await kpxc(["edit", "-q", "-p", a, "Konto"], "p-von-a\n"); // neuer

    const ours = mergeVaults(await readKdbxFile(a, PASSWORD), await readKdbxFile(b, PASSWORD), { now: Date.now() });
    const mergedEntry = findEntry(ours.vault, konto)!;
    expect(mergedEntry.strings.get("UserName")?.value).toBe("u-von-b");
    expect(mergedEntry.strings.get("Password")?.value).toBe("p-von-a");

    await runKpxcOk(["merge", "-q", "-s", a, b], `${PASSWORD}\n`);
    const shown = await showKpxcEntry(a, PASSWORD, "Konto", { showProtected: true, attributes: ["UserName", "Password"] });
    expect(shown).toBe("u0\np-von-a\n"); // Benutzername von b ist im aktuellen Eintrag verloren …
    const history = entryAt((await kpxcExportedVault(a, PASSWORD)).vault, "Konto").entry.history;
    expect(history.some((old) => old.strings.get("UserName")?.value === "u-von-b")).toBe(true); // … steht nur im Verlauf
  });
});
