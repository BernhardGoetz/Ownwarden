/**
 * Integration (d): Feld-Zeitstempel überstehen KeePassXC, und Ownwarden erkennt GENAU die
 * Felder, die KeePassXC geändert hat.
 *
 *   1. Ownwarden schreibt eine Datenbank (writeKdbx) mit drei Einträgen.
 *   2. KeePassXC 2.7.6 ändert das Passwort von "Mail" und den Titel von "Bank" (keepassxc-cli edit).
 *   3. readKdbx: Ownwarden.FieldTimes ist noch da; KeePassXCs "_LAST_MODIFIED" gibt es zwar,
 *      es spielt aber keine Rolle; effectiveFieldTimes meldet als extern geändert GENAU
 *      s:Password bei "Mail", s:Title bei "Bank" und nichts beim unberührten "Dummy".
 *   4. Zusammenführen mit einem Ownwarden-Gerät, das ein ANDERES Feld desselben Eintrags
 *      geändert hat (vor bzw. nach KeePassXC): beide Änderungen bleiben. KeePassXC liest das Ergebnis.
 *
 * Bereits vorhanden: src/kdbx/xml.interop.test.ts (FieldTimes überstehen KeePassXC),
 * src/merge/merge.interop.test.ts (keine Scheinänderungen; Benutzername in KeePassXC +
 * Passwort in Ownwarden). Neu hier: die genaue Feld-Erkennung (welches Feld, welche Zeit),
 * Titeländerung, beide Reihenfolgen, alles über readKdbx/writeKdbx.
 * Wird übersprungen ohne keepassxc-cli.
 */
import { copyFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, hasKeepassxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../helpers/keepassxc";
import { readKdbxFile, TEST_KDF, waitForNextSecond, writeKdbxFile } from "../helpers/kdbx-files";
import { FIELD_TIMES_KEY } from "../../src/contracts";
import { createNewVault } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { effectiveFieldTimes, readFieldTimes } from "../../src/merge/field-times";
import { mergeVaults } from "../../src/merge/merge";
import { findEntryLocation } from "../../src/merge/tree";
import { createEntry, setField } from "../../src/merge/vault-ops";
import type { Uuid, Vault } from "../../src/model";

const PASSWORD = "Interop-d-äöü";
const kpxc = (args: string[], extraInput = "") => runKpxcOk(args, `${PASSWORD}\n${extraInput}`);

describe.skipIf(!hasKeepassxc())("Integration (d): Feld-Zeitstempel und Erkennung externer Änderungen", () => {
  let dir: string;
  let ownPath: string;
  let kpxcPath: string;
  const uuids = {} as Record<"mail" | "bank" | "dummy", Uuid>;

  beforeAll(async () => {
    dir = createTmpDir("interop-d");
    const vault = createNewVault({ name: "Extern", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    const clock = createVaultClock(vault);
    uuids.mail = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "alt", URL: "https://mail.example" }, clock).uuid;
    uuids.bank = createEntry(vault, vault.root.uuid, { Title: "Bank", UserName: "bob", Password: "bank-pw" }, clock).uuid;
    uuids.dummy = createEntry(vault, vault.root.uuid, { Title: "Dummy", UserName: "d" }, clock).uuid;
    ownPath = join(dir, "ownwarden.kdbx");
    await writeKdbxFile(vault, ownPath, PASSWORD);

    // KeePassXC ändert die Datei (in der nächsten Sekunde, KDBX-Zeiten sind sekundengenau).
    kpxcPath = join(dir, "keepassxc.kdbx");
    copyFileSync(ownPath, kpxcPath);
    await waitForNextSecond();
    await kpxc(["edit", "-q", "-p", kpxcPath, "Mail"], "neu-von-keepassxc\n");
    await kpxc(["edit", "-q", "-t", "Bank neu", kpxcPath, "Bank"]);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  function placed(vault: Vault, uuid: Uuid) {
    const location = findEntryLocation(vault, uuid);
    if (location === undefined) throw new Error(`Eintrag ${uuid} fehlt`);
    return location;
  }

  it("FieldTimes überleben; _LAST_MODIFIED ist da, zählt aber nicht; genau die geänderten Felder gelten als extern geändert", async () => {
    const before = await readKdbxFile(ownPath, PASSWORD);
    const after = await readKdbxFile(kpxcPath, PASSWORD);

    for (const uuid of Object.values(uuids)) {
      const { entry } = placed(after, uuid);
      // Unverändert übernommen – KeePassXC fasst den Wert nicht an.
      expect(entry.customData.get(FIELD_TIMES_KEY)?.value).toBe(placed(before, uuid).entry.customData.get(FIELD_TIMES_KEY)!.value);
      expect(entry.customData.has("_LAST_MODIFIED")).toBe(true);
    }

    const expected: Record<keyof typeof uuids, string[]> = { mail: ["s:Password"], bank: ["s:Title"], dummy: [] };
    for (const [name, fields] of Object.entries(expected) as [keyof typeof uuids, string[]][]) {
      const { entry, group } = placed(after, uuids[name]);
      const effective = effectiveFieldTimes(entry, group.uuid);
      expect(effective.sealed, name).toBe(true);
      expect(effective.externalFields, name).toEqual(fields);
      expect(effective.externallyEdited, name).toBe(fields.length > 0);

      // Geänderte Felder bekommen die (sekundengenaue) Änderungszeit von KeePassXC, alle
      // übrigen behalten exakt ihren Ownwarden-Zeitstempel.
      const stored = readFieldTimes(entry)!;
      for (const [key, time] of effective.times) {
        if (fields.includes(key)) {
          expect(time.t, `${name} ${key}`).toBe(Math.floor(entry.times.lastModification / 1000) * 1000);
          expect(time.t, `${name} ${key}`).toBeGreaterThan(stored.fields.get(key)!.t);
        } else {
          expect(time.t, `${name} ${key}`).toBe(stored.fields.get(key)!.t);
        }
      }
    }
  });

  it.each([
    ["Ownwarden ändert VOR KeePassXC (Gerät war offline)", false],
    ["Ownwarden ändert NACH KeePassXC", true],
  ])("%s ein anderes Feld desselben Eintrags: beide Änderungen bleiben", async (_name, afterKeePassXC) => {
    const local = await readKdbxFile(ownPath, PASSWORD);
    if (afterKeePassXC) await waitForNextSecond();
    const clock = createVaultClock(local, afterKeePassXC ? () => Date.now() : () => placed(local, uuids.mail).entry.times.lastModification + 1);
    setField(local, uuids.mail, "UserName", "alice-ownwarden", {}, clock);
    setField(local, uuids.bank, "URL", "https://bank.example", {}, clock);

    const remote = await readKdbxFile(kpxcPath, PASSWORD);
    const { vault, report } = mergeVaults(local, remote, { now: Date.now() });
    expect(report.externalEdits.sort()).toEqual([uuids.mail, uuids.bank].sort());

    const mail = placed(vault, uuids.mail).entry;
    expect(mail.strings.get("UserName")?.value).toBe("alice-ownwarden");
    expect(mail.strings.get("Password")?.value).toBe("neu-von-keepassxc");
    const bank = placed(vault, uuids.bank).entry;
    expect(bank.strings.get("Title")?.value).toBe("Bank neu");
    expect(bank.strings.get("URL")?.value).toBe("https://bank.example");
    // Kein alter Wert geht verloren: Die überschriebene Fassung steht im Verlauf.
    expect(mail.history.some((old) => old.strings.get("Password")?.value === "alt")).toBe(true);

    const mergedPath = join(dir, `merged-${afterKeePassXC ? "nach" : "vor"}.kdbx`);
    await writeKdbxFile(vault, mergedPath, PASSWORD);
    const shown = await showKpxcEntry(mergedPath, PASSWORD, "Mail", { showProtected: true, attributes: ["UserName", "Password"] });
    expect(shown).toBe("alice-ownwarden\nneu-von-keepassxc\n");
    expect(await showKpxcEntry(mergedPath, PASSWORD, "Bank neu", { attributes: ["URL"] })).toBe("https://bank.example\n");
  });
});
