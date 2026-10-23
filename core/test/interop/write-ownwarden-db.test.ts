/**
 * Integration (b): Ownwarden baut eine Datenbank nur über die öffentlichen Funktionen
 * (createNewVault + vault-ops) und schreibt sie mit writeKdbx. KeePassXC 2.7.6 muss sie ohne
 * Warnungen öffnen und dieselben Daten zeigen:
 *   ls -R          Gruppen, verschobener Eintrag, Papierkorb, gelöschter Eintrag fehlt
 *   show -s        geschützte und ungeschützte Felder, Passkey-Attribute
 *   attachment-export  Anhänge byte-genau (auch Binärdaten)
 *   export xml     Ownwarden.FieldTimes in CustomData jedes Eintrags, Tags, Lösch-Vermerk
 *
 * Bereits vorhandene, verwandte Tests: src/kdbx/xml.interop.test.ts („Änderungen von
 * Ownwarden sind in KeePassXC sichtbar“, ohne vault-ops), src/kdbx/xml.verify.interop.test.ts
 * (Randfälle), src/merge/merge.interop.test.ts (vault-ops-Datenbank, aber nur für den Merge).
 * Wird übersprungen ohne keepassxc-cli.
 */
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, exportKpxcAttachment, hasKeepassxc, listKpxc, removeTmpDir, showKpxcEntry } from "../helpers/keepassxc";
import { entryAt, KPXC_XML_WARNING, kpxcExportedVault, TEST_KDF, writeKdbxFile } from "../helpers/kdbx-files";
import { FIELD_TIMES_KEY } from "../../src/contracts";
import { createNewVault } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { readFieldTimes } from "../../src/merge/field-times";
import {
  createEntry,
  createGroup,
  deleteEntry,
  findEntry,
  moveEntry,
  recycleEntry,
  setAttachment,
  setPasskey,
  setTags,
} from "../../src/merge/vault-ops";
import type { Uuid, Vault } from "../../src/model";

const PASSWORD = "Interop-b-äöü";
const SCAN = new Uint8Array(randomBytes(3000));
const NOTE = new TextEncoder().encode("Notiz äöü\r\nmit CRLF\n");
/** Test-Passkey: KEIN echter Schlüssel, nur Testdaten im Format von KeePassXC. */
const PASSKEY = {
  KPEX_PASSKEY_USERNAME: "alice@example.org",
  KPEX_PASSKEY_CREDENTIAL_ID: "dGVzdC1jcmVkZW50aWFsLWlk",
  KPEX_PASSKEY_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nTUlJQkdUZXN0RGF0ZW4=\n-----END PRIVATE KEY-----",
  KPEX_PASSKEY_RELYING_PARTY: "webauthn.example",
  KPEX_PASSKEY_USER_HANDLE: "dXNlci1oYW5kbGU",
};

interface Built {
  vault: Vault;
  uuids: { giro: Uuid; passkey: Uuid; moved: Uuid; deleted: Uuid; recycled: Uuid };
}

function buildVault(): Built {
  const vault = createNewVault({ name: "Ownwarden-Interop", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
  const clock = createVaultClock(vault);
  const bank = createGroup(vault, vault.root.uuid, "Bank", clock);
  const archive = createGroup(vault, vault.root.uuid, "Archiv", clock);

  const giro = createEntry(
    vault,
    bank.uuid,
    { Title: "Giro", UserName: "bob", Password: "giro-geheim", PIN: { value: "4711", protected: true }, Kontonummer: "DE00 1234" },
    clock,
  );
  setAttachment(vault, giro.uuid, "scan.bin", SCAN, {}, clock);
  setAttachment(vault, giro.uuid, "notiz.txt", NOTE, { protected: false }, clock);
  setTags(vault, giro.uuid, ["Bank", "Wichtig"], clock);

  const passkey = createEntry(vault, vault.root.uuid, { Title: "Passkey-Seite", UserName: "alice@example.org", URL: "https://webauthn.example" }, clock);
  setPasskey(vault, passkey.uuid, PASSKEY, clock);

  const moved = createEntry(vault, vault.root.uuid, { Title: "Umzug", Password: "umzug-pw" }, clock);
  moveEntry(vault, moved.uuid, archive.uuid, clock);

  const deleted = createEntry(vault, vault.root.uuid, { Title: "Weg", Password: "weg-pw" }, clock);
  deleteEntry(vault, deleted.uuid, clock);

  const recycled = createEntry(vault, vault.root.uuid, { Title: "Im Papierkorb" }, clock);
  recycleEntry(vault, recycled.uuid, clock);

  return { vault, uuids: { giro: giro.uuid, passkey: passkey.uuid, moved: moved.uuid, deleted: deleted.uuid, recycled: recycled.uuid } };
}

describe.skipIf(!hasKeepassxc())("Integration (b): Ownwarden baut, KeePassXC liest", () => {
  let dir: string;
  let path: string;
  let built: Built;

  beforeAll(async () => {
    dir = createTmpDir("interop-b");
    path = join(dir, "ownwarden.kdbx");
    built = buildVault();
    await writeKdbxFile(built.vault, path, PASSWORD);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("ls: Gruppen, verschobener Eintrag, Papierkorb; der gelöschte Eintrag fehlt", async () => {
    const entries = (await listKpxc(path, PASSWORD, { recursive: true })).filter((line) => !line.endsWith("/"));
    expect(entries.sort()).toEqual(["Archiv/Umzug", "Bank/Giro", "Papierkorb/Im Papierkorb", "Passkey-Seite"]);
  });

  it("show -s: geschützte und ungeschützte Felder", async () => {
    const shown = await showKpxcEntry(path, PASSWORD, "Bank/Giro", {
      showProtected: true,
      attributes: ["UserName", "Password", "PIN", "Kontonummer"],
    });
    expect(shown).toBe("bob\ngiro-geheim\n4711\nDE00 1234\n");
    // Ohne -s und ohne -a verdeckt KeePassXC das Passwort. (Beobachtet mit 2.7.6: Mit -a gibt
    // KeePassXC auch geschützte Felder OHNE -s im Klartext aus – das Schutz-Flag prüfen wir
    // deshalb im Export, siehe unten.)
    const overview = await showKpxcEntry(path, PASSWORD, "Bank/Giro");
    expect(overview).toContain("Password: PROTECTED");
    expect(overview).not.toContain("giro-geheim");
    const { vault: seen } = await kpxcExportedVault(path, PASSWORD);
    const giro = entryAt(seen, "Bank/Giro").entry;
    expect(giro.strings.get("PIN")).toEqual({ value: "4711", protected: true });
    expect(giro.strings.get("Password")).toEqual({ value: "giro-geheim", protected: true });
    expect(giro.strings.get("Kontonummer")).toEqual({ value: "DE00 1234", protected: false });
  });

  it("show -s: der Passkey mit allen KPEX_PASSKEY_*-Attributen", async () => {
    const names = Object.keys(PASSKEY);
    const shown = await showKpxcEntry(path, PASSWORD, "Passkey-Seite", { showProtected: true, attributes: names });
    expect(shown).toBe(`${Object.values(PASSKEY).join("\n")}\n`);
  });

  it("attachment-export: Anhänge byte-genau", async () => {
    expect(Buffer.from(await exportKpxcAttachment(path, PASSWORD, "Bank/Giro", "scan.bin")).equals(Buffer.from(SCAN))).toBe(true);
    expect(Buffer.from(await exportKpxcAttachment(path, PASSWORD, "Bank/Giro", "notiz.txt")).equals(Buffer.from(NOTE))).toBe(true);
  });

  it("export xml: ohne Warnungen; Ownwarden.FieldTimes, Tags und Lösch-Vermerk kommen bei KeePassXC an", async () => {
    const { vault: seen, xml, stderr } = await kpxcExportedVault(path, PASSWORD);
    expect(stderr).not.toMatch(KPXC_XML_WARNING);
    expect(xml).toContain(`<Key>${FIELD_TIMES_KEY}</Key>`);

    for (const uuid of [built.uuids.giro, built.uuids.passkey, built.uuids.moved, built.uuids.recycled]) {
      const ours = findEntry(built.vault, uuid)!;
      const theirs = findEntry(seen, uuid)!;
      expect(theirs.customData.get(FIELD_TIMES_KEY)?.value, uuid).toBe(ours.customData.get(FIELD_TIMES_KEY)!.value);
    }
    // Feld-Zeitstempel für Anhänge, Tags, Passkey (als Einheit) und die Elterngruppe:
    const giroTimes = readFieldTimes(findEntry(seen, built.uuids.giro)!)!;
    expect([...giroTimes.fields.keys()]).toEqual(expect.arrayContaining(["a:scan.bin", "a:notiz.txt", "tags", "s:PIN", "parent"]));
    expect(readFieldTimes(findEntry(seen, built.uuids.passkey)!)!.fields.has("passkey")).toBe(true);

    expect([...entryAt(seen, "Bank/Giro").entry.tags].sort()).toEqual(["Bank", "Wichtig"]);
    expect(entryAt(seen, "Passkey-Seite").entry.tags).toEqual(["Passkey"]);
    expect(seen.deletedObjects.map((item) => item.uuid)).toEqual([built.uuids.deleted]);
    expect(seen.meta.recycleBinUuid).toBe(built.vault.meta.recycleBinUuid);
    expect(seen.meta.databaseName).toBe("Ownwarden-Interop");
  });
});
