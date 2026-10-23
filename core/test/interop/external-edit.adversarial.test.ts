/**
 * Gegenprobe zu Integration (d): Erkennt Ownwarden auch Änderungen durch KeePassXC an
 * Anhängen, an der Elterngruppe und an einem Eintrag mit Passkey – und nur diese?
 *
 * Test (d) deckt Textfelder ab (Passwort, Titel). Hier, jeweils mit keepassxc-cli 2.7.6 an
 * einer von Ownwarden geschriebenen Datei:
 *   - attachment-import  -> genau "a:<neu>" gilt als extern geändert
 *   - attachment-rm      -> genau "a:<alt>" gilt als extern entfernt
 *   - mv                 -> genau "parent" und "misc": KeePassXC setzt dabei (KDBX 4.1)
 *                           PreviousParentGroup auf die alte Gruppe – eine echte Änderung,
 *                           die zu "misc" gehört (beobachtet mit 2.7.6; die Datei wird 4.1)
 *   - edit -u am Passkey-Eintrag -> genau "s:UserName"; der Passkey (alle KPEX_PASSKEY_*-
 *     Attribute, Schutz-Flags) bleibt unberührt und gilt NICHT als geändert
 * Danach Zusammenführen mit einem Ownwarden-Gerät, das NACH KeePassXC andere Felder
 * derselben Einträge geändert hat: Beide Seiten bleiben erhalten, KeePassXC sieht das Ergebnis.
 * Wird übersprungen ohne keepassxc-cli.
 */
import { copyFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, exportKpxcAttachment, hasKeepassxc, importKpxcAttachment, listKpxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../helpers/keepassxc";
import { kpxcExportedVault, readKdbxFile, TEST_KDF, waitForNextSecond, writeKdbxFile } from "../helpers/kdbx-files";
import { createNewVault } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { effectiveFieldTimes } from "../../src/merge/field-times";
import { mergeVaults } from "../../src/merge/merge";
import { findEntryLocation } from "../../src/merge/tree";
import { createEntry, createGroup, setAttachment, setField, setPasskey } from "../../src/merge/vault-ops";
import type { Uuid, Vault } from "../../src/model";

const PASSWORD = "Interop-d2-äöü";
const kpxc = (args: string[], extraInput = "") => runKpxcOk(args, `${PASSWORD}\n${extraInput}`);
const ALT = new TextEncoder().encode("alter Anhang\n");
const NEU = Uint8Array.from({ length: 700 }, (_, i) => (i * 37) % 256);
/** Test-Passkey: KEIN echter Schlüssel. */
const PASSKEY = {
  KPEX_PASSKEY_USERNAME: "alice@example.org",
  KPEX_PASSKEY_CREDENTIAL_ID: { value: "dGVzdC1jcmVkZW50aWFsLWlk", protected: true },
  KPEX_PASSKEY_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nVGVzdHNjaGx1ZXNzZWw=\n-----END PRIVATE KEY-----",
  KPEX_PASSKEY_RELYING_PARTY: "webauthn.example",
  KPEX_PASSKEY_USER_HANDLE: { value: "dXNlci1oYW5kbGU", protected: true },
};

describe.skipIf(!hasKeepassxc())("Gegenprobe (d): Anhänge, Verschieben und Passkey-Eintrag in KeePassXC geändert", () => {
  let dir: string;
  let ownPath: string;
  let kpxcPath: string;
  const uuids = {} as Record<"mail" | "rechnung" | "umzug" | "passkey" | "archiv", Uuid>;

  beforeAll(async () => {
    dir = createTmpDir("interop-d2");
    const vault = createNewVault({ name: "Extern2", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    const clock = createVaultClock(vault);
    uuids.archiv = createGroup(vault, vault.root.uuid, "Archiv", clock).uuid;
    uuids.mail = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "mail-pw" }, clock).uuid;
    uuids.rechnung = createEntry(vault, vault.root.uuid, { Title: "Rechnung", Notes: "n0" }, clock).uuid;
    setAttachment(vault, uuids.rechnung, "alt.txt", ALT, {}, clock);
    uuids.umzug = createEntry(vault, vault.root.uuid, { Title: "Umzug", UserName: "u" }, clock).uuid;
    uuids.passkey = createEntry(vault, vault.root.uuid, { Title: "Passkey", UserName: "alice", URL: "https://webauthn.example" }, clock).uuid;
    setPasskey(vault, uuids.passkey, PASSKEY, clock);
    ownPath = join(dir, "ownwarden.kdbx");
    await writeKdbxFile(vault, ownPath, PASSWORD);

    kpxcPath = join(dir, "keepassxc.kdbx");
    copyFileSync(ownPath, kpxcPath);
    await waitForNextSecond();
    writeFileSync(join(dir, "neu.bin"), NEU);
    await importKpxcAttachment(kpxcPath, PASSWORD, "Mail", "neu.bin", join(dir, "neu.bin"));
    await kpxc(["attachment-rm", "-q", kpxcPath, "Rechnung", "alt.txt"]);
    await kpxc(["mv", "-q", kpxcPath, "Umzug", "Archiv"]);
    await kpxc(["edit", "-q", "-u", "alice-kpxc", kpxcPath, "Passkey"]);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  function placed(vault: Vault, uuid: Uuid) {
    const location = findEntryLocation(vault, uuid);
    if (location === undefined) throw new Error(`Eintrag ${uuid} fehlt`);
    return location;
  }

  it("genau die von KeePassXC geänderten Felder gelten als extern geändert", async () => {
    const after = await readKdbxFile(kpxcPath, PASSWORD);
    const expected: Record<"mail" | "rechnung" | "umzug" | "passkey", string[]> = {
      mail: ["a:neu.bin"],
      rechnung: ["a:alt.txt"],
      umzug: ["misc", "parent"],
      passkey: ["s:UserName"],
    };
    for (const [name, fields] of Object.entries(expected) as [keyof typeof expected, string[]][]) {
      const { entry, group } = placed(after, uuids[name]);
      const effective = effectiveFieldTimes(entry, group.uuid);
      expect(effective.sealed, name).toBe(true);
      expect(effective.externalFields, name).toEqual(fields);
    }
    const moved = placed(after, uuids.umzug).entry;
    expect(moved.previousParentGroup).toBe(after.root.uuid);
    expect(after.settings.versionMinor).toBe(1);
    // Der Passkey ist nach KeePassXC unverändert (Werte und Schutz-Flags).
    const passkeyEntry = placed(after, uuids.passkey).entry;
    const before = placed(await readKdbxFile(ownPath, PASSWORD), uuids.passkey).entry;
    for (const name of Object.keys(PASSKEY)) expect(passkeyEntry.strings.get(name), name).toEqual(before.strings.get(name));
  });

  it("Zusammenführen mit Ownwarden-Änderungen NACH KeePassXC: beides bleibt, KeePassXC sieht das Ergebnis", async () => {
    const local = await readKdbxFile(ownPath, PASSWORD);
    await waitForNextSecond();
    const clock = createVaultClock(local, () => Date.now());
    setField(local, uuids.mail, "Password", "mail-pw-neu", {}, clock);
    setField(local, uuids.rechnung, "Notes", "n1", {}, clock);
    setField(local, uuids.umzug, "UserName", "u-neu", {}, clock);
    setField(local, uuids.passkey, "URL", "https://webauthn.example/login", {}, clock);

    const remote = await readKdbxFile(kpxcPath, PASSWORD);
    // Beide Richtungen müssen dasselbe Ergebnis liefern.
    for (const [a, b] of [
      [local, remote],
      [remote, local],
    ] as const) {
      const { vault } = mergeVaults(a, b, { now: Date.now() });
      const mail = placed(vault, uuids.mail).entry;
      expect(mail.strings.get("Password")?.value).toBe("mail-pw-neu");
      expect(mail.attachments.map((item) => item.name)).toEqual(["neu.bin"]);
      expect(placed(vault, uuids.rechnung).entry.attachments).toEqual([]);
      expect(placed(vault, uuids.rechnung).entry.strings.get("Notes")?.value).toBe("n1");
      const umzug = placed(vault, uuids.umzug);
      expect(umzug.group.uuid).toBe(uuids.archiv);
      expect(umzug.entry.strings.get("UserName")?.value).toBe("u-neu");
      expect(umzug.entry.previousParentGroup).toBe(vault.root.uuid);
      const passkey = placed(vault, uuids.passkey).entry;
      expect(passkey.strings.get("UserName")?.value).toBe("alice-kpxc");
      expect(passkey.strings.get("URL")?.value).toBe("https://webauthn.example/login");
    }

    const mergedPath = join(dir, "merged.kdbx");
    await writeKdbxFile(mergeVaults(local, remote, { now: Date.now() }).vault, mergedPath, PASSWORD);
    expect((await listKpxc(mergedPath, PASSWORD, { recursive: true })).filter((line) => !line.endsWith("/")).sort()).toEqual([
      "Archiv/Umzug",
      "Mail",
      "Passkey",
      "Rechnung",
    ]);
    expect(Buffer.from(await exportKpxcAttachment(mergedPath, PASSWORD, "Mail", "neu.bin")).equals(Buffer.from(NEU))).toBe(true);
    const names = Object.keys(PASSKEY);
    const shown = await showKpxcEntry(mergedPath, PASSWORD, "Passkey", { showProtected: true, attributes: ["UserName", "URL", ...names] });
    const values = Object.values(PASSKEY).map((value) => (typeof value === "string" ? value : value.value));
    expect(shown).toBe(`alice-kpxc\nhttps://webauthn.example/login\n${values.join("\n")}\n`);
    // Schutz-Flags der Passkey-Attribute kommen bei KeePassXC an.
    const seen = placed((await kpxcExportedVault(mergedPath, PASSWORD)).vault, uuids.passkey).entry;
    expect(seen.strings.get("KPEX_PASSKEY_PRIVATE_KEY_PEM")?.protected).toBe(true);
    expect(seen.strings.get("KPEX_PASSKEY_CREDENTIAL_ID")?.protected).toBe(true);
    expect(seen.strings.get("KPEX_PASSKEY_USERNAME")?.protected).toBe(false);
    expect(seen.tags).toEqual(["Passkey"]);
  });
});
