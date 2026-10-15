/**
 * Zusammenspiel der XML-Schicht mit KeePassXC (Referenzprogramm). Wird übersprungen, wenn
 * `keepassxc-cli` nicht installiert ist.
 *
 *   KeePassXC -> Ownwarden: KeePassXC baut eine Datenbank (Gruppen, Einträge, Anhänge,
 *                           Verlauf), Ownwarden liest sie ins Modell.
 *   Ownwarden -> KeePassXC: Ownwarden schreibt (neuer innerer Strom, neuer Pool), KeePassXC
 *                           muss die Datei OHNE Warnungen lesen und dasselbe sehen.
 *   KeePassXC ändert eine Ownwarden-Datei: Ownwarden.FieldTimes muss das überstehen
 *                           (Annahme aus PROJECT-CONTEXT.md).
 */
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  addKpxcEntry,
  createKpxcDb,
  createTmpDir,
  exportKpxcAttachment,
  hasKeepassxc,
  importKpxcAttachment,
  mkdirKpxc,
  removeTmpDir,
  runKpxcOk,
  showKpxcEntry,
} from "../../test/helpers/keepassxc";
import { identityStream } from "../../test/fixtures/xml/fixtures";
import { FIELD_TIMES_KEY, type DecryptedPayload } from "../contracts";
import type { CustomData, Entry, Group, Vault } from "../model";
import { utf8Decode, utf8Encode } from "./bytes";
import { decryptContainer, encryptContainer } from "./container";
import { createInnerStream, newInnerStreamKey } from "./inner-stream";
import { parseVaultXml, serializeVaultXml } from "./xml";

const DB_PASSWORD = "XML-Interop-Passwort-äöü";
const CREDENTIALS = { password: DB_PASSWORD };
const NOTE = "Notiz-Anhang äöü\n";
const RANDOM_ATTACHMENT = new Uint8Array(randomBytes(1000));

/** Meldungen, mit denen KeePassXC Probleme beim Lesen der XML anzeigt. */
const KPXC_XML_WARNING = /KdbxXmlReader|skip element|Invalid|Unmapped|unused key|Duplicate|Missing/i;

async function load(path: string): Promise<{ payload: DecryptedPayload; vault: Vault }> {
  const payload = await decryptContainer(new Uint8Array(readFileSync(path)), CREDENTIALS);
  const stream = createInnerStream(payload.innerStreamId, payload.innerStreamKey);
  return { payload, vault: parseVaultXml(payload.xml, payload.binaries, stream, payload.settings) };
}

/** Speichert wie später der Codec: neuer Strom-Schlüssel, XML neu, Container neu. */
async function save(vault: Vault, path: string): Promise<void> {
  const innerStreamKey = newInnerStreamKey();
  const { xml, binaries } = serializeVaultXml(vault, createInnerStream("chacha20", innerStreamKey));
  const file = await encryptContainer(
    { settings: vault.settings, innerStreamId: "chacha20", innerStreamKey, binaries, xml },
    CREDENTIALS,
  );
  writeFileSync(path, file);
}

/**
 * Lässt KeePassXC die Datei als XML exportieren und liest den Export wieder ins Modell.
 * Der Export enthält geschützte Werte im Klartext (ProtectInMemory) und Anhänge nur als
 * Verweis – deshalb wird der Pool der Datei selbst übergeben.
 */
async function kpxcView(path: string): Promise<{ vault: Vault; stderr: string }> {
  const { payload } = await load(path);
  const result = await runKpxcOk(["export", "-q", "-f", "xml", path], `${DB_PASSWORD}\n`);
  const vault = parseVaultXml(utf8Encode(result.stdout), payload.binaries, identityStream(), payload.settings);
  return { vault, stderr: result.stderr };
}

/**
 * Das Modell ohne `settings`: Jedes Speichern erzeugt einen neuen KDF-Salt, die Einstellungen
 * zweier Dateien unterscheiden sich also immer. Hier geht es nur um den XML-Inhalt.
 */
function content(vault: Vault): Omit<Vault, "settings"> {
  const { settings: _settings, ...rest } = vault;
  return rest;
}

/**
 * Wie `content`, aber ohne den CustomData-Eintrag `_LAST_MODIFIED`: KeePassXC setzt ihn
 * beim LADEN jeder Datenbank auf die aktuelle Uhrzeit (CustomData::set). Zwei Exporte,
 * die eine Sekunde auseinanderliegen, unterscheiden sich darin – unabhängig von Ownwarden.
 */
function kpxcComparable(vault: Vault): Omit<Vault, "settings"> {
  const strip = (customData: CustomData): CustomData =>
    new Map([...customData].filter(([key]) => key !== "_LAST_MODIFIED"));
  const entry = (e: Entry): Entry => ({ ...e, customData: strip(e.customData), history: e.history.map(entry) });
  const group = (g: Group): Group => ({
    ...g,
    customData: strip(g.customData),
    entries: g.entries.map(entry),
    groups: g.groups.map(group),
  });
  const rest = content(vault);
  return { ...rest, meta: { ...rest.meta, customData: strip(rest.meta.customData) }, root: group(rest.root) };
}

function findEntry(group: Group, title: string): Entry {
  for (const entry of group.entries) if (entry.strings.get("Title")?.value === title) return entry;
  for (const child of group.groups) {
    try {
      return findEntry(child, title);
    } catch {
      // in der nächsten Gruppe weitersuchen
    }
  }
  throw new Error(`Eintrag "${title}" nicht gefunden`);
}

describe.skipIf(!hasKeepassxc())("KeePassXC-Interop: XML", () => {
  let dir: string;
  let kpxcPath: string;

  beforeAll(async () => {
    dir = createTmpDir("kdbx-xml");
    kpxcPath = join(dir, "keepassxc.kdbx");
    await createKpxcDb(kpxcPath, DB_PASSWORD, { version: "4.1" });
    await mkdirKpxc(kpxcPath, DB_PASSWORD, "Bank");
    await addKpxcEntry(kpxcPath, DB_PASSWORD, "Bank/Giro", {
      username: "bob",
      url: "https://bank.example.org",
      password: "giro-geheim",
      notes: "Zeile 1\nZeile 2 & <b>",
    });
    await addKpxcEntry(kpxcPath, DB_PASSWORD, "Mail", { username: "alice", password: "Mail-Passwort äöü" });
    const notePath = join(dir, "notiz.txt");
    writeFileSync(notePath, NOTE);
    const randomPath = join(dir, "zufall.bin");
    writeFileSync(randomPath, RANDOM_ATTACHMENT);
    await importKpxcAttachment(kpxcPath, DB_PASSWORD, "Bank/Giro", "notiz.txt", notePath);
    await importKpxcAttachment(kpxcPath, DB_PASSWORD, "Mail", "kopie.txt", notePath);
    await importKpxcAttachment(kpxcPath, DB_PASSWORD, "Mail", "zufall.bin", randomPath);
    // Ändern erzeugt in KeePassXC einen Verlaufseintrag.
    await runKpxcOk(["edit", "-q", "-u", "alice2", kpxcPath, "Mail"], `${DB_PASSWORD}\n`);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("liest eine von KeePassXC geschriebene Datenbank", async () => {
    const { vault, payload } = await load(kpxcPath);
    expect(payload.settings.versionMinor).toBe(1);
    expect(vault.root.name).toBe("Root");
    expect(vault.root.tags).toEqual(["kdbx41"]);
    expect(vault.root.customData.get("Ownwarden.Test")?.value).toBe("kdbx4");

    const giro = findEntry(vault.root, "Giro");
    expect(giro.strings.get("UserName")).toEqual({ value: "bob", protected: false });
    expect(giro.strings.get("Password")).toEqual({ value: "giro-geheim", protected: true });
    expect(giro.strings.get("Notes")?.value).toBe("Zeile 1\nZeile 2 & <b>");
    expect(utf8Decode(giro.attachments[0]!.data)).toBe(NOTE);

    const mail = findEntry(vault.root, "Mail");
    expect(mail.strings.get("UserName")?.value).toBe("alice2");
    expect(mail.strings.get("Password")?.value).toBe("Mail-Passwort äöü");
    expect(mail.attachments.map((a) => a.name)).toEqual(["kopie.txt", "zufall.bin"]);
    expect(Buffer.from(mail.attachments[1]!.data).equals(Buffer.from(RANDOM_ATTACHMENT))).toBe(true);
    // Gleicher Inhalt in zwei Einträgen steht im Pool nur einmal.
    expect(mail.attachments[0]!.data).toBe(giro.attachments[0]!.data);
    expect(mail.history.length).toBeGreaterThanOrEqual(1);
    expect(mail.history.at(-1)!.strings.get("UserName")?.value).toBe("alice");
    expect(mail.unknown.some((xml) => xml.startsWith("<AutoType>"))).toBe(true);
  });

  it("schreibt die innere XML byte-genau so, wie KeePassXC sie geschrieben hat", async () => {
    const { vault, payload } = await load(kpxcPath);
    const out = serializeVaultXml(vault, createInnerStream(payload.innerStreamId, payload.innerStreamKey));
    expect(utf8Decode(out.xml)).toBe(utf8Decode(payload.xml));
    expect(out.binaries.map((b) => Buffer.from(b.data).toString("hex"))).toEqual(
      payload.binaries.map((b) => Buffer.from(b.data).toString("hex")),
    );
  });

  it("KeePassXC liest die von Ownwarden geschriebene Datei ohne Warnungen und sieht dasselbe", async () => {
    const { vault } = await load(kpxcPath);
    const ownPath = join(dir, "ownwarden.kdbx");
    await save(vault, ownPath);

    const original = await kpxcView(kpxcPath);
    const rewritten = await kpxcView(ownPath);
    expect(rewritten.stderr).not.toMatch(KPXC_XML_WARNING);
    expect(kpxcComparable(rewritten.vault)).toEqual(kpxcComparable(original.vault));
    // Und Ownwarden selbst liest die eigene Datei verlustfrei.
    expect(content((await load(ownPath)).vault)).toEqual(content(vault));
  });

  it("Gegenprobe: Ein fremdes Element erzeugt wirklich eine KeePassXC-Warnung auf stderr", async () => {
    const { vault } = await load(kpxcPath);
    vault.meta.unknown.push("<FremdesElement>x</FremdesElement>");
    const ownPath = join(dir, "fremd.kdbx");
    await save(vault, ownPath);
    const { stderr } = await kpxcView(ownPath);
    expect(stderr).toMatch(KPXC_XML_WARNING);
    expect(stderr).toContain("FremdesElement");
  });

  it("Änderungen von Ownwarden sind in KeePassXC sichtbar (Feld, Anhänge, Gruppe)", async () => {
    const { vault } = await load(kpxcPath);
    const mail = findEntry(vault.root, "Mail");
    mail.strings.set("PIN", { value: "4711 & <äöü>", protected: true });
    mail.strings.set("Title", { value: "Mail neu", protected: false });
    const newData = new Uint8Array(randomBytes(300));
    mail.attachments.push({ name: "neu.bin", data: newData, protected: true });
    const giro = findEntry(vault.root, "Giro");
    // Gleiche Bytes in einem zweiten Eintrag (eigenes Array): muss im Pool zusammenfallen.
    giro.attachments.push({ name: "auch-neu.bin", data: newData.slice(), protected: true });
    vault.root.groups.push({
      ...vault.root.groups[0]!,
      uuid: Buffer.from(randomBytes(16)).toString("base64"),
      name: "Neue Gruppe",
      entries: [],
      groups: [],
    });

    const ownPath = join(dir, "geaendert.kdbx");
    await save(vault, ownPath);

    const pin = await showKpxcEntry(ownPath, DB_PASSWORD, "Mail neu", { showProtected: true, attributes: ["PIN"] });
    expect(pin.trim()).toBe("4711 & <äöü>");
    const exported = await exportKpxcAttachment(ownPath, DB_PASSWORD, "Bank/Giro", "auch-neu.bin");
    expect(Buffer.from(exported).equals(Buffer.from(newData))).toBe(true);
    const random = await exportKpxcAttachment(ownPath, DB_PASSWORD, "Mail neu", "zufall.bin");
    expect(Buffer.from(random).equals(Buffer.from(RANDOM_ATTACHMENT))).toBe(true);

    const { vault: seen, stderr } = await kpxcView(ownPath);
    expect(stderr).not.toMatch(KPXC_XML_WARNING);
    expect(seen.root.groups.map((g) => g.name)).toEqual(["Bank", "Neue Gruppe"]);
    const { payload } = await load(ownPath);
    expect(payload.binaries).toHaveLength(3); // notiz.txt, zufall.bin, neu.bin
  });

  it("Ownwarden.FieldTimes und unbekannte Elemente überstehen das Speichern in KeePassXC", async () => {
    const { vault } = await load(kpxcPath);
    const mail = findEntry(vault.root, "Mail");
    mail.customData.set(FIELD_TIMES_KEY, { value: '{"s:Password":1792058400000}' });
    const ownPath = join(dir, "fieldtimes.kdbx");
    await save(vault, ownPath);

    // KeePassXC ändert den Eintrag und speichert die Datei selbst neu.
    await runKpxcOk(["edit", "-q", "-u", "carol", ownPath, "Mail"], `${DB_PASSWORD}\n`);

    const after = findEntry((await load(ownPath)).vault.root, "Mail");
    expect(after.strings.get("UserName")?.value).toBe("carol");
    expect(after.customData.get(FIELD_TIMES_KEY)?.value).toBe('{"s:Password":1792058400000}');
    expect(after.unknown.some((xml) => xml.startsWith("<AutoType>"))).toBe(true);
    // Wichtig für den Feld-Merge: KeePassXC 2.7.6 kopiert CustomData NICHT in den
    // Verlaufseintrag, den es beim Ändern anlegt (Entry::beginUpdate). Die alte Fassung im
    // Verlauf hat also keine FieldTimes, und KeePassXC ergänzt _LAST_MODIFIED am Eintrag.
    const newestHistory = after.history.at(-1)!;
    expect(newestHistory.strings.get("UserName")?.value).toBe("alice2");
    expect(newestHistory.customData.get(FIELD_TIMES_KEY)).toBeUndefined();
    expect(after.customData.has("_LAST_MODIFIED")).toBe(true);
  });

  it("schreibt KDBX 4.0, die KeePassXC ohne Warnungen liest", async () => {
    const path40 = join(dir, "kpxc40.kdbx");
    await createKpxcDb(path40, DB_PASSWORD, { version: "4.0" });
    await addKpxcEntry(path40, DB_PASSWORD, "Eintrag", { username: "dave", password: "vier-null" });
    const { vault, payload } = await load(path40);
    expect(payload.settings.versionMinor).toBe(0);

    const ownPath = join(dir, "own40.kdbx");
    await save(vault, ownPath);
    const original = await kpxcView(path40);
    const rewritten = await kpxcView(ownPath);
    expect(rewritten.stderr).not.toMatch(KPXC_XML_WARNING);
    expect(kpxcComparable(rewritten.vault)).toEqual(kpxcComparable(original.vault));
    expect((await load(ownPath)).payload.settings.versionMinor).toBe(0);
  });
});
