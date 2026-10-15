/**
 * Feld-Merge im Zusammenspiel mit KeePassXC 2.7.6 (Referenzprogramm). Wird übersprungen,
 * wenn `keepassxc-cli` fehlt.
 *
 *   1. KeePassXC lädt und speichert eine Ownwarden-Datei nur (ändert einen anderen Eintrag):
 *      Das darf an den übrigen Einträgen KEINE Änderung vortäuschen (Fingerabdrücke müssen
 *      gegen die Umformungen von KeePassXC robust sein).
 *   2. KeePassXC ändert den Benutzernamen, Ownwarden (anderes Gerät) das Passwort: beides bleibt.
 *   3. KeePassXC verschiebt den Eintrag in den Papierkorb, Ownwarden ändert ihn: Eintrag im
 *      Papierkorb mit Ownwardens Änderung.
 *   4. Ein in KeePassXC angelegter Eintrag OHNE FieldTimes: Ownwarden ändert das Passwort,
 *      danach ändert KeePassXC den Benutzernamen – beides bleibt (Verfeinerung über den Verlauf).
 * Das Ergebnis wird jeweils gespeichert und von KeePassXC gelesen.
 */
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { addKpxcEntry, createTmpDir, hasKeepassxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../../test/helpers/keepassxc";
import { newGroup, newVault, uuidFromName } from "../../test/helpers/vault-builder";
import type { Credentials, Vault } from "../model";
import { decryptContainer, encryptContainer } from "../kdbx/container";
import { createInnerStream, newInnerStreamKey } from "../kdbx/inner-stream";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "../kdbx/xml";
import { createVaultClock } from "./clock";
import { effectiveFieldTimes } from "./field-times";
import { mergeVaults } from "./merge";
import { findEntryLocation } from "./tree";
import { createEntry, createGroup, editEntry, setAttachment, setField, setPasskey, setTags } from "./vault-ops";

const PASSWORD = "Merge-Interop-äöü";
const CREDENTIALS: Credentials = { password: PASSWORD };
const KPXC_XML_WARNING = /KdbxXmlReader|skip element|Invalid|Unmapped|unused key|Duplicate|Missing/i;

async function load(path: string): Promise<Vault> {
  const payload = await decryptContainer(new Uint8Array(readFileSync(path)), CREDENTIALS);
  return parseVaultXml(payload.xml, payload.binaries, createInnerStream(payload.innerStreamId, payload.innerStreamKey), payload.settings);
}

/** Speichert wie der spätere Codec (siehe Bericht der Etappe „xml“). */
async function save(vault: Vault, path: string): Promise<void> {
  const innerStreamKey = newInnerStreamKey();
  const settings = { ...vault.settings, versionMinor: Math.max(vault.settings.versionMinor, kdbxMinorVersionRequired(vault)) as 0 | 1 };
  const { xml, binaries } = serializeVaultXml({ ...vault, settings }, createInnerStream("chacha20", innerStreamKey));
  writeFileSync(path, await encryptContainer({ settings, innerStreamId: "chacha20", innerStreamKey, binaries, xml }, CREDENTIALS));
}

const kpxc = (args: string[]) => runKpxcOk(args, `${PASSWORD}\n`);
const waitForNextSecond = () => new Promise((resolve) => setTimeout(resolve, 1100));

/** Eintrag mit Titel (ohne Verlauf), samt Elterngruppe. */
function byTitle(vault: Vault, title: string) {
  const all: { uuid: string }[] = [];
  const walk = (group: Vault["root"]): void => {
    for (const entry of group.entries) if (entry.strings.get("Title")?.value === title) all.push(entry);
    group.groups.forEach(walk);
  };
  walk(vault.root);
  if (all.length !== 1) throw new Error(`Eintrag "${title}" ${all.length}-mal gefunden`);
  return findEntryLocation(vault, all[0]!.uuid)!;
}

/** Eine Ownwarden-Datenbank mit möglichst vielen Merkmalen, die KeePassXC umformt. */
function ownwardenVault(): Vault {
  const vault = newVault({
    root: newGroup({ uuid: uuidFromName("root"), name: "Root" }),
    settings: { kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 } },
  });
  vault.meta.customIcons.push({ uuid: uuidFromName("icon"), data: Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]) });
  const clock = createVaultClock(vault);
  const bank = createGroup(vault, vault.root.uuid, "Bank", clock);
  const mail = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "pw-alt", Notes: "Zeile 1\r\nZeile 2" }, clock);
  setTags(vault, mail.uuid, ["Zeta", "alpha", "Mitte"], clock);
  setAttachment(vault, mail.uuid, "b.txt", new TextEncoder().encode("B"), { protected: false }, clock);
  setAttachment(vault, mail.uuid, "a.txt", new TextEncoder().encode("A"), { protected: false }, clock);
  editEntry(vault, mail.uuid, (draft) => {
    draft.iconId = 12;
    draft.customIconUuid = uuidFromName("icon");
    draft.times.expires = true;
    draft.times.expiry = Date.now() + 123_456; // nicht sekundengenau
    draft.customData.set("Typ", { value: "login\r\nzwei" });
  }, clock);
  const site = createEntry(vault, bank.uuid, { Title: "Site", Geheim: { value: "﻿mit BOM", protected: true } }, clock);
  setPasskey(vault, site.uuid, { KPEX_PASSKEY_USERNAME: "alice", KPEX_PASSKEY_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----", KPEX_PASSKEY_RELYING_PARTY: "site.example" }, clock);
  createEntry(vault, vault.root.uuid, { Title: "Dummy" }, clock);
  return vault;
}

describe.skipIf(!hasKeepassxc())("KeePassXC-Interop: Feld-Merge", () => {
  let dir: string;
  let original: Vault;
  let originalPath: string;

  beforeAll(async () => {
    dir = createTmpDir("merge-interop");
    original = ownwardenVault();
    originalPath = join(dir, "ownwarden.kdbx");
    await save(original, originalPath);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("Laden+Speichern in KeePassXC täuscht keine Änderungen vor", async () => {
    const path = join(dir, "resaved.kdbx");
    copyFileSync(originalPath, path);
    const edit = await kpxc(["edit", "-q", "-u", "geändert", path, "Dummy"]);
    expect(edit.stderr).not.toMatch(KPXC_XML_WARNING);
    const resaved = await load(path);

    for (const title of ["Mail", "Site"]) {
      const { entry, group } = byTitle(resaved, title);
      const effective = effectiveFieldTimes(entry, group.uuid);
      expect(effective.sealed, title).toBe(true);
      expect(effective.externalFields, title).toEqual([]);
      expect(effective.externallyEdited, title).toBe(false);
    }
    const dummy = byTitle(resaved, "Dummy").entry;
    const { report } = mergeVaults(await load(originalPath), resaved, { now: Date.now() });
    expect(report.externalEdits).toEqual([dummy.uuid]);
    expect(report.fieldConflicts.filter((c) => c.entryUuid !== dummy.uuid)).toEqual([]);
  });

  it("KeePassXC ändert den Benutzernamen, Ownwarden das Passwort: beides bleibt", async () => {
    const local = await load(originalPath);
    const mailUuid = byTitle(local, "Mail").entry.uuid;
    setField(local, mailUuid, "Password", "pw-ownwarden", {}, createVaultClock(local));

    const remotePath = join(dir, "kpxc-edit.kdbx");
    copyFileSync(originalPath, remotePath);
    await waitForNextSecond();
    await kpxc(["edit", "-q", "-u", "bob", remotePath, "Mail"]);

    const { vault, report } = mergeVaults(local, await load(remotePath), { now: Date.now() });
    const mail = byTitle(vault, "Mail").entry;
    expect(mail.strings.get("UserName")?.value).toBe("bob");
    expect(mail.strings.get("Password")?.value).toBe("pw-ownwarden");
    expect(report.externalEdits).toEqual([mailUuid]);

    const mergedPath = join(dir, "merged-edit.kdbx");
    await save(vault, mergedPath);
    const shown = await showKpxcEntry(mergedPath, PASSWORD, "Mail", { showProtected: true, attributes: ["UserName", "Password"] });
    expect(shown).toBe("bob\npw-ownwarden\n");
  });

  it("KeePassXC verschiebt in den Papierkorb, Ownwarden ändert: Eintrag im Papierkorb mit Änderung", async () => {
    const local = await load(originalPath);
    const mailUuid = byTitle(local, "Mail").entry.uuid;
    const remotePath = join(dir, "kpxc-rm.kdbx");
    copyFileSync(originalPath, remotePath);
    await kpxc(["rm", "-q", remotePath, "Mail"]);
    await waitForNextSecond();
    setField(local, mailUuid, "Password", "pw-nach-rm", {}, createVaultClock(local));

    const { vault, report } = mergeVaults(local, await load(remotePath), { now: Date.now() });
    const { entry, group } = byTitle(vault, "Mail");
    expect(group.uuid).toBe(vault.meta.recycleBinUuid);
    expect(entry.strings.get("Password")?.value).toBe("pw-nach-rm");
    expect(report.entriesDeleted).toBe(0);

    const mergedPath = join(dir, "merged-rm.kdbx");
    await save(vault, mergedPath);
    const shown = await showKpxcEntry(mergedPath, PASSWORD, `${group.name}/Mail`, { showProtected: true, attributes: ["Password"] });
    expect(shown).toBe("pw-nach-rm\n");
  });

  it("Eintrag ohne FieldTimes (in KeePassXC angelegt): Passwort von Ownwarden, später Benutzername von KeePassXC", async () => {
    const basePath = join(dir, "kpxc-entry.kdbx");
    copyFileSync(originalPath, basePath);
    await addKpxcEntry(basePath, PASSWORD, "Forum", { username: "u0", password: "p0" });

    const local = await load(basePath);
    const forum = byTitle(local, "Forum");
    expect(effectiveFieldTimes(forum.entry, forum.group.uuid).sealed).toBe(false);
    await waitForNextSecond();
    setField(local, forum.entry.uuid, "Password", "p1", {}, createVaultClock(local));

    const remotePath = join(dir, "kpxc-entry-remote.kdbx");
    copyFileSync(basePath, remotePath);
    await waitForNextSecond();
    await kpxc(["edit", "-q", "-u", "u1", remotePath, "Forum"]); // neuer als Ownwardens Änderung

    const { vault } = mergeVaults(local, await load(remotePath), { now: Date.now() });
    const merged = byTitle(vault, "Forum").entry;
    expect(merged.strings.get("UserName")?.value).toBe("u1");
    expect(merged.strings.get("Password")?.value).toBe("p1");

    const mergedPath = join(dir, "merged-forum.kdbx");
    await save(vault, mergedPath);
    const shown = await showKpxcEntry(mergedPath, PASSWORD, "Forum", { showProtected: true, attributes: ["UserName", "Password"] });
    expect(shown).toBe("u1\np1\n");
  });
});
