/**
 * Tests für parseVaultXml / serializeVaultXml (XML <-> Modell).
 *
 * Fixtures: core/test/fixtures/xml/
 *   keepassxc-4.1.xml   genau im Format von KeePassXC 2.7.6 (Reihenfolge, Einrückung,
 *                       Maskierung); geschützte Werte im Klartext, werden für den Test mit
 *                       einem Referenz-Strom verschlüsselt.
 *   foreign-quirks.xml  Besonderheiten anderer Programme (ISO-Zeiten, ProtectInMemory,
 *                       geschützte Werte in unbekannten Elementen, Kommentare, CDATA …).
 */
import { describe, expect, it } from "vitest";
import {
  IMAGE_ATTACHMENT,
  NOTE_ATTACHMENT,
  OLD_ATTACHMENT,
  ReferenceStream,
  decryptProtectedText,
  encryptProtectedText,
  identityStream,
  keepassxcFixtureBinaries,
  readXmlFixture,
  sampleVault,
  testUuid,
} from "../../test/fixtures/xml/fixtures";
import type { InnerStreamCipher, PoolBinary } from "../contracts";
import { NULL_UUID, type KdbxSettings, type Vault } from "../model";
import { utf8Decode, utf8Encode } from "./bytes";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "./xml";

const corrupt = expect.objectContaining({ name: "KdbxError", code: "Corrupt" });

const SETTINGS_41: KdbxSettings = {
  versionMinor: 1,
  cipher: "aes256",
  compression: true,
  kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 2, memoryBytes: 1 << 26, iterations: 3, version: 0x13 },
};

interface ParseOptions {
  binaries?: PoolBinary[];
  stream?: InnerStreamCipher;
  settings?: KdbxSettings;
}

function parse(xml: string, options: ParseOptions = {}): Vault {
  return parseVaultXml(utf8Encode(xml), options.binaries ?? [], options.stream ?? identityStream(), options.settings ?? SETTINGS_41);
}

/** Modell -> XML -> Modell mit zwei Referenz-Strömen gleichen Schlüssels. */
function roundTrip(vault: Vault): { vault: Vault; xml: string; binaries: PoolBinary[] } {
  const out = serializeVaultXml(vault, new ReferenceStream(3));
  const reparsed = parseVaultXml(out.xml, out.binaries, new ReferenceStream(3), vault.settings);
  return { vault: reparsed, xml: utf8Decode(out.xml), binaries: out.binaries };
}

/** Minimales gültiges Dokument; `entry` und `meta` werden eingesetzt. */
function minimalXml(parts: { meta?: string; group?: string; root?: string } = {}): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
  <Meta>${parts.meta ?? ""}</Meta>
  <Root>
    <Group><UUID>${testUuid(1)}</UUID><Name>Root</Name>${parts.group ?? ""}</Group>
    ${parts.root ?? ""}
  </Root>
</KeePassFile>`;
}

function entryXml(inner: string): string {
  return `<Entry><UUID>${testUuid(10)}</UUID>${inner}</Entry>`;
}

// ---------------------------------------------------------------------------
// KeePassXC-Fixture
// ---------------------------------------------------------------------------

describe("KeePassXC-Fixture (KDBX 4.1)", () => {
  const fixture = readXmlFixture("keepassxc-4.1.xml");
  const encrypted = encryptProtectedText(fixture, new ReferenceStream(7));
  const vault = () => parse(encrypted, { binaries: keepassxcFixtureBinaries(), stream: new ReferenceStream(7) });

  it("liest Meta, Icons, CustomData und Lösch-Vermerke", () => {
    const { meta, deletedObjects, rootUnknown } = vault();
    expect(meta.generator).toBe("KeePassXC");
    expect(meta.databaseName).toBe("Test-Tresor");
    expect(meta.databaseNameChanged).toBe(Date.parse("2026-01-02T03:04:05Z"));
    expect(meta.recycleBinEnabled).toBe(true);
    expect(meta.recycleBinUuid).toBe("x0wP0lqD8Zvw3HlDlThO/g==");
    expect(meta.recycleBinChanged).toBe(Date.parse("2026-05-20T08:30:00Z"));
    expect(meta.historyMaxItems).toBe(10);
    expect(meta.historyMaxSize).toBe(6291456);
    expect(meta.customIcons).toEqual([
      {
        uuid: "ybJHV9Cxoy/S8/T/AEV83w==",
        name: "Mail-Icon",
        lastModified: Date.parse("2026-03-01T12:00:00Z"),
        data: Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3]),
      },
    ]);
    expect([...meta.customData]).toEqual([
      ["KPXC_DECRYPTION_TIME_PREFERENCE", { value: "1000", lastModified: Date.parse("2026-01-02T03:04:05Z") }],
      ["_LAST_MODIFIED", { value: "Thu Oct 15 11:11:11 2026 GMT" }],
    ]);
    // Alles, was Ownwarden nicht selbst auswertet, bleibt in Originalreihenfolge erhalten.
    expect(meta.unknown.map((xml) => /^<(\w+)/.exec(xml)![1])).toEqual([
      "DatabaseDescription",
      "DatabaseDescriptionChanged",
      "DefaultUserName",
      "DefaultUserNameChanged",
      "MaintenanceHistoryDays",
      "Color",
      "MasterKeyChanged",
      "MasterKeyChangeRec",
      "MasterKeyChangeForce",
      "MemoryProtection",
      "EntryTemplatesGroup",
      "EntryTemplatesGroupChanged",
      "LastSelectedGroup",
      "LastTopVisibleGroup",
      "SettingsChanged",
    ]);
    expect(deletedObjects).toEqual([
      { uuid: "+ECmodD0udkXmVg3TmqJUQ==", deletionTime: Date.parse("2026-05-20T08:30:00Z") },
      { uuid: "2OEz8X4jv1kwRlR/E6pAcg==", deletionTime: Date.parse("2026-10-15T10:00:00Z") },
    ]);
    expect(rootUnknown).toEqual([]);
  });

  it("liest Gruppen mit Tags, Icons, PreviousParentGroup und unbekannten Elementen", () => {
    const { root } = vault();
    expect(root.uuid).toBe("BOAjqnBuvJQoczAc1LOewQ==");
    expect(root.name).toBe("Root");
    expect(root.notes).toBe("Wurzel & Co.");
    expect(root.tags).toEqual(["Wichtig", "Familie"]);
    expect(root.iconId).toBe(48);
    expect(root.times.lastModification).toBe(Date.parse("2026-10-15T11:11:11Z"));
    expect([...root.customData]).toEqual([["Ownwarden.Test", { value: "kdbx4" }]]);
    expect(root.unknown).toEqual([
      "<IsExpanded>True</IsExpanded>",
      "<DefaultAutoTypeSequence/>",
      "<EnableAutoType>null</EnableAutoType>",
      "<EnableSearching>null</EnableSearching>",
      "<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>",
    ]);
    expect(root.groups.map((g) => g.name)).toEqual(["Bank", "Papierkorb"]);
    const bank = root.groups[0]!;
    expect(bank.customIconUuid).toBe("ybJHV9Cxoy/S8/T/AEV83w==");
    expect(bank.previousParentGroup).toBe("x0wP0lqD8Zvw3HlDlThO/g==");
    expect(bank.tags).toEqual([]);
    expect(root.groups[1]!.entries[0]!.previousParentGroup).toBe("BOAjqnBuvJQoczAc1LOewQ==");
  });

  it("liest einen Eintrag mit allen Feldern, geschützten Werten und Verlauf", () => {
    const mail = vault().root.entries[0]!;
    expect(mail.uuid).toBe("C7IrT/JEypakB1/cITyCjA==");
    expect(mail.iconId).toBe(1);
    expect(mail.customIconUuid).toBe("ybJHV9Cxoy/S8/T/AEV83w==");
    expect(mail.foregroundColor).toBe("#FF0000");
    expect(mail.backgroundColor).toBe("#00FF00");
    expect(mail.overrideUrl).toBe("cmd://firefox %1");
    expect(mail.tags).toEqual(["Mail", "Privat"]);
    expect(mail.qualityCheck).toBe(false);
    expect(mail.previousParentGroup).toBeUndefined();
    expect(mail.times).toEqual({
      lastModification: Date.parse("2026-10-15T11:11:11Z"),
      creation: Date.parse("2026-01-02T03:04:05Z"),
      lastAccess: Date.parse("2026-10-15T11:11:11Z"),
      expiry: Date.parse("2027-12-31T23:59:59Z"),
      expires: true,
      usageCount: 7,
      locationChanged: Date.parse("2026-01-02T03:04:05Z"),
    });
    expect([...mail.strings]).toEqual([
      [
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        {
          value: "-----BEGIN PRIVATE KEY-----\nTUlHSEFnRUFNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQkcwd2F3SUJBUVFn\n-----END PRIVATE KEY-----",
          protected: true,
        },
      ],
      ["Leer", { value: "", protected: true }],
      ["Notes", { value: "Zeile 1\nZeile 2 & <b>fett</b> \"zitiert\" 'einfach'", protected: false }],
      ["Password", { value: "Geheim & <sicher> äöü €", protected: true }],
      ["PIN", { value: "1234", protected: true }],
      ["Title", { value: "Mail-Konto", protected: false }],
      ["URL", { value: "https://mail.example.org", protected: false }],
      ["UserName", { value: "alice@example.org", protected: false }],
    ]);
    expect(mail.attachments).toEqual([
      { name: "notiz.txt", data: NOTE_ATTACHMENT, protected: true },
      { name: "bild.png", data: IMAGE_ATTACHMENT, protected: true },
    ]);
    expect(mail.customData.get("Ownwarden.FieldTimes")).toEqual({ value: '{"s:Password":1792062671000}' });
    expect(mail.unknown).toEqual([
      "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation>" +
        "<DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>" +
        "<Association><Window>Mail - Firefox</Window><KeystrokeSequence/></Association></AutoType>",
    ]);

    expect(mail.history).toHaveLength(2);
    expect(mail.history.map((h) => h.strings.get("Password"))).toEqual([
      { value: "alt-1", protected: true },
      { value: "alt-2", protected: true },
    ]);
    expect(mail.history.map((h) => h.history)).toEqual([[], []]);
    expect(mail.history[0]!.attachments).toEqual([{ name: "notiz.txt", data: NOTE_ATTACHMENT, protected: true }]);
    expect(mail.history[1]!.attachments).toEqual([{ name: "alt.txt", data: OLD_ATTACHMENT, protected: true }]);
  });

  it("löst geteilte Anhänge auf dasselbe Pool-Objekt auf", () => {
    const { root } = vault();
    const giro = root.groups[0]!.entries[0]!;
    expect(giro.attachments[0]!.name).toBe("kopie.png");
    expect(giro.attachments[0]!.data).toBe(root.entries[0]!.attachments[1]!.data);
  });

  it("verbraucht genau so viele Strom-Bytes wie die geschützten Werte lang sind", () => {
    const stream = new ReferenceStream(7);
    parse(encrypted, { binaries: keepassxcFixtureBinaries(), stream });
    const expected = new ReferenceStream(7);
    decryptProtectedText(encrypted, expected);
    expect(stream.consumed).toBe(expected.consumed);
    expect(stream.consumed).toBeGreaterThan(100);
  });

  it("schreibt die Datei byte-genau so zurück, wie KeePassXC sie geschrieben hat", () => {
    const out = serializeVaultXml(vault(), new ReferenceStream(7));
    expect(utf8Decode(out.xml)).toBe(encrypted);
    expect(out.binaries).toEqual(keepassxcFixtureBinaries());
  });

  it("scheitert mit falschem Strom-Schlüssel (geschützte Werte sind dann kein UTF-8)", () => {
    expect(() => parse(encrypted, { binaries: keepassxcFixtureBinaries(), stream: new ReferenceStream(8) })).toThrow(
      corrupt,
    );
  });
});

// ---------------------------------------------------------------------------
// Fremde Besonderheiten
// ---------------------------------------------------------------------------

describe("Fremde Besonderheiten (foreign-quirks.xml)", () => {
  const fixture = readXmlFixture("foreign-quirks.xml");
  const encrypted = encryptProtectedText(fixture, new ReferenceStream(5));
  const vault = () => parse(encrypted, { stream: new ReferenceStream(5) });

  it("liest ISO-Zeiten, Kleinschreibung, CDATA, Tags mit Komma und ProtectInMemory", () => {
    const { meta, root } = vault();
    expect(meta.generator).toBe("KeePass");
    expect(meta.databaseNameChanged).toBe(Date.parse("2026-01-02T03:04:05Z"));
    expect(meta.recycleBinEnabled).toBe(false);
    expect(meta.historyMaxItems).toBe(10);
    // Doppelter CustomData-Schlüssel: der letzte gewinnt (wie KeePassXC).
    expect([...meta.customData]).toEqual([["doppelt", { value: "zweiter" }]]);
    expect(root.name).toBe("Wurzel <CDATA>");
    expect(root.times).toEqual({
      lastModification: Date.parse("2026-03-01T12:00:00Z"),
      creation: Date.parse("2026-01-02T03:04:05Z"),
      lastAccess: 0,
      expiry: 0,
      expires: true,
      usageCount: 0,
      locationChanged: 0,
    });
    const entry = root.entries[0]!;
    expect(entry.tags).toEqual(["Bank", "Privat"]);
    expect([...entry.strings]).toEqual([
      ["Title", { value: "Fremder Eintrag", protected: false }],
      ["Password", { value: "klein-geschrieben", protected: true }],
      ["Exportiert", { value: "klartext-export", protected: true }],
      ["Leerzeichen", { value: "   ", protected: false }],
    ]);
    expect(entry.history[0]!.strings.get("Password")).toEqual({ value: "verlauf", protected: true });
  });

  it("entschlüsselt auch geschützte Werte in unbekannten Elementen und bewahrt sie im Klartext auf", () => {
    const { meta, root, rootUnknown } = vault();
    expect(meta.unknown).toEqual([
      '<PluginData><Secret Protected="True">plugin-geheimnis</Secret><Plain>offen</Plain></PluginData>',
    ]);
    expect(root.entries[0]!.unknown).toEqual([
      '<PluginEntryData><Nested><Value Protected="True">im-unbekannten-element</Value></Nested></PluginEntryData>',
    ]);
    expect(rootUnknown).toEqual(['<ForeignRootChild><X Protected="True">am-ende</X></ForeignRootChild>']);
  });

  it("verwirft KDBX-3-Reste in <Meta> und fremde Kinder von <KeePassFile>", () => {
    const { meta } = vault();
    expect(meta.unknown.join("")).not.toMatch(/HeaderHash|Binaries/);
    const out = utf8Decode(serializeVaultXml(vault(), identityStream()).xml);
    expect(out).not.toMatch(/HeaderHash|<Binaries|ForeignTopLevel/);
  });

  it("verschlüsselt beim Schreiben alle geschützten Werte in Dokumentreihenfolge", () => {
    const out = utf8Decode(serializeVaultXml(vault(), new ReferenceStream(9)).xml);
    expect(decryptProtectedText(out, new ReferenceStream(9))).toEqual([
      "plugin-geheimnis",
      "klein-geschrieben",
      "klartext-export",
      "im-unbekannten-element",
      "verlauf",
      "am-ende",
    ]);
    // ProtectInMemory wird zu einem echten Schutz; "true" wird zu "True" (KeePass versteht nur das).
    expect(out).not.toMatch(/ProtectInMemory|Protected="true"/);
    for (const secret of ["plugin-geheimnis", "klein-geschrieben", "klartext-export", "im-unbekannten", "verlauf", "am-ende"]) {
      expect(out).not.toContain(secret);
    }
  });
});

// ---------------------------------------------------------------------------
// Modell-Rundlauf
// ---------------------------------------------------------------------------

describe("Modell -> XML -> Modell", () => {
  it("ist verlustfrei für KDBX 4.1", () => {
    const original = sampleVault(true);
    const { vault } = roundTrip(original);
    expect(vault).toEqual(original);
    // toEqual vergleicht Maps ohne Reihenfolge – die Reihenfolge muss aber erhalten bleiben.
    expect([...vault.root.entries[0]!.strings.keys()]).toEqual([...original.root.entries[0]!.strings.keys()]);
    expect([...vault.meta.customData.keys()]).toEqual([...original.meta.customData.keys()]);
    expect([...vault.root.entries[0]!.customData.keys()]).toEqual(["Ownwarden.FieldTimes", "Typ"]);
  });

  it("ist verlustfrei für KDBX 4.0 (ohne 4.1-Merkmale)", () => {
    const original = sampleVault(false);
    expect(kdbxMinorVersionRequired(original)).toBe(0);
    expect(roundTrip(original).vault).toEqual(original);
  });

  it("lässt 4.1-Elemente in KDBX 4.0 weg; kdbxMinorVersionRequired erkennt das vorher", () => {
    const vault41 = sampleVault(true);
    expect(kdbxMinorVersionRequired(vault41)).toBe(1);
    const as40: Vault = { ...vault41, settings: { ...vault41.settings, versionMinor: 0 } };
    const { vault, xml } = roundTrip(as40);
    expect(xml).not.toMatch(/QualityCheck|PreviousParentGroup|<Tags>Finanzen|<Name>Icon|LastModificationTime>[^<]*<\/LastModificationTime>\s*<\/(Item|Icon)>/);
    expect(vault.root.entries[0]!.qualityCheck).toBeUndefined();
    expect(vault.root.entries[0]!.previousParentGroup).toBeUndefined();
    expect(vault.root.groups[0]!.tags).toEqual([]);
    expect(vault.meta.customIcons[0]).toEqual({ uuid: testUuid(90), data: vault41.meta.customIcons[0]!.data });
    expect(vault.meta.customData.get("KPXC_DECRYPTION_TIME_PREFERENCE")).toEqual({ value: "1000" });
    // Entry-Tags gibt es dagegen schon in 4.0.
    expect(vault.root.entries[0]!.tags).toEqual(["Mail", "Privat"]);
  });

  it("schreibt LastModificationTime in CustomData nur bei 4.1 und liest es dann zurück", () => {
    const { xml, vault } = roundTrip(sampleVault(true));
    expect(xml).toMatch(/<Key>KPXC_DECRYPTION_TIME_PREFERENCE<\/Key>\s*<Value>1000<\/Value>\s*<LastModificationTime>/);
    expect(vault.meta.customData.get("KPXC_DECRYPTION_TIME_PREFERENCE")!.lastModified).toBe(Date.parse("2026-03-03T03:03:03Z"));
  });

  it("verschlüsselt geschützte Werte in Dokumentreihenfolge – auch in Verlauf und unbekannten Elementen", () => {
    const out = utf8Decode(serializeVaultXml(sampleVault(true), new ReferenceStream(4)).xml);
    expect(decryptProtectedText(out, new ReferenceStream(4))).toEqual([
      "meta-geheimnis", // <FremdesMeta> am Ende von <Meta>
      "Pa$$w0rd & <äöü>   €",
      // "Leer geschützt" steht als <Value Protected="True"/> da und verbraucht keinen Strom.
      "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----",
      "im unbekannten Element", // <PluginData> im Eintrag, vor dem Verlauf
      "Mail-passwort", // Verlauf 1
      "Mail alt-passwort", // Verlauf 2
      "0815", // Eintrag in Untergruppe
      "wurzel-geheimnis", // unbekanntes Kind von <Root>
    ]);
    for (const secret of ["Pa$$w0rd", "meta-geheimnis", "wurzel-geheimnis", "0815", "BEGIN PRIVATE KEY"]) {
      expect(out).not.toContain(secret);
    }
  });

  it("ordnet bekannte und unbekannte Elemente wie KeePassXC an", () => {
    const out = utf8Decode(serializeVaultXml(sampleVault(true), identityStream()).xml);
    const order = (parent: string) => {
      const block = new RegExp(`\\n(\\t*)<${parent}>\\n([\\s\\S]*?)\\n\\1</${parent}>`).exec(out)![2]!;
      const depth = /^\t*/.exec(block)![0].length;
      return [...block.matchAll(new RegExp(`^\\t{${depth}}<(\\w+)`, "gm"))].map((m) => m[1]);
    };
    expect(order("Meta")).toEqual([
      "Generator",
      "DatabaseName",
      "DatabaseNameChanged",
      "DatabaseDescription",
      "MemoryProtection",
      "CustomIcons",
      "RecycleBinEnabled",
      "RecycleBinUUID",
      "RecycleBinChanged",
      "HistoryMaxItems",
      "HistoryMaxSize",
      "CustomData",
      "FremdesMeta",
    ]);
    expect(order("Entry")).toEqual([
      "UUID",
      "IconID",
      "CustomIconUUID",
      "ForegroundColor",
      "BackgroundColor",
      "OverrideURL",
      "Tags",
      "Times",
      "QualityCheck",
      "PreviousParentGroup",
      ...Array<string>(7).fill("String"),
      "Binary",
      "Binary",
      "Binary",
      "AutoType",
      "CustomData",
      "PluginData",
      "History",
    ]);
    expect(order("Root")).toEqual(["Group", "DeletedObjects", "FremdeWurzel"]);
  });

  it("weigert sich, ein bekanntes Element als „unbekannt“ zu schreiben oder kaputtes XML einzusetzen", () => {
    const withTimes = sampleVault(false);
    withTimes.root.entries[0]!.unknown.push("<Times/>");
    expect(() => serializeVaultXml(withTimes, identityStream())).toThrow(/<Times> gehört nicht/);
    const broken = sampleVault(false);
    broken.meta.unknown.push("<kaputt>");
    expect(() => serializeVaultXml(broken, identityStream())).toThrow(corrupt);
  });

  it("verändert das Modell nicht und schreibt bei gleichem Strom identisch", () => {
    const vault = sampleVault(true);
    const first = serializeVaultXml(vault, new ReferenceStream(2));
    expect(vault).toEqual(sampleVault(true));
    const second = serializeVaultXml(vault, new ReferenceStream(2));
    expect(utf8Decode(second.xml)).toBe(utf8Decode(first.xml));
  });

  it("übernimmt fehlende Standardwerte und eine leere Datenbank", () => {
    const vault = parse(minimalXml());
    expect(vault.meta).toEqual({
      generator: "",
      databaseName: "",
      databaseNameChanged: 0,
      recycleBinEnabled: true,
      recycleBinUuid: NULL_UUID,
      recycleBinChanged: 0,
      historyMaxItems: 10,
      historyMaxSize: 6 * 1024 * 1024,
      customIcons: [],
      customData: new Map(),
      unknown: [],
    });
    expect(vault.root).toEqual({
      uuid: testUuid(1),
      name: "Root",
      notes: "",
      iconId: 0,
      times: { creation: 0, lastModification: 0, lastAccess: 0, expiry: 0, expires: false, usageCount: 0, locationChanged: 0 },
      tags: [],
      customData: new Map(),
      groups: [],
      entries: [],
      unknown: [],
    });
    expect(vault.deletedObjects).toEqual([]);
    expect(vault.settings).toBe(SETTINGS_41);
    expect(roundTrip(vault).vault).toEqual(vault);
  });

  it("liest einen Eintrag ohne optionale Elemente", () => {
    const entry = parse(minimalXml({ group: entryXml("") })).root.entries[0]!;
    expect(entry).toEqual({
      uuid: testUuid(10),
      iconId: 0,
      foregroundColor: "",
      backgroundColor: "",
      overrideUrl: "",
      tags: [],
      times: { creation: 0, lastModification: 0, lastAccess: 0, expiry: 0, expires: false, usageCount: 0, locationChanged: 0 },
      strings: new Map(),
      attachments: [],
      customData: new Map(),
      history: [],
      unknown: [],
    });
  });
});

// ---------------------------------------------------------------------------
// Anhänge
// ---------------------------------------------------------------------------

describe("Anhänge und Binär-Pool", () => {
  it("speichert gleiche Anhänge nur einmal, in der Reihenfolge der ersten Verwendung", () => {
    const { binaries, xml, vault } = roundTrip(sampleVault(true));
    const text = (b: PoolBinary) => [new TextDecoder().decode(b.data), b.protected];
    expect(binaries.map(text)).toEqual([
      ["geteilter Inhalt", true], // Mail, Verlauf 1 und Giro
      [new TextDecoder().decode(Uint8Array.from([0, 255, 1, 254])), false],
      ["geteilter Inhalt", false], // gleiche Bytes, anderes Schutz-Flag -> eigener Eintrag
      ["Verlauf", true], // nur im Verlauf
    ]);
    expect([...xml.matchAll(/<Value Ref="(\d+)"\/>/g)].map((m) => m[1])).toEqual(["0", "1", "2", "0", "3", "0"]);
    // Nach dem Lesen teilen sich die Einträge wieder dasselbe Array.
    expect(vault.root.groups[0]!.entries[0]!.attachments[0]!.data).toBe(vault.root.entries[0]!.attachments[0]!.data);
  });

  it("schreibt Anhänge in Verlaufseinträgen und liest sie zurück", () => {
    const { vault } = roundTrip(sampleVault(true));
    expect(vault.root.entries[0]!.history[1]!.attachments).toEqual([
      { name: "nur-im-verlauf.txt", data: new TextEncoder().encode("Verlauf"), protected: true },
    ]);
  });

  it("meldet einen Verweis auf einen fehlenden Pool-Eintrag als Corrupt", () => {
    const xml = minimalXml({ group: entryXml('<Binary><Key>a.txt</Key><Value Ref="1"/></Binary>') });
    const pool = [{ data: Uint8Array.of(1), protected: true }];
    expect(() => parse(xml, { binaries: pool })).toThrow(corrupt);
    expect(() => parse(xml, { binaries: pool })).toThrow(/Pool-Eintrag 1/);
    const bad = minimalXml({ group: entryXml('<Binary><Key>a.txt</Key><Value Ref="x"/></Binary>') });
    expect(() => parse(bad, { binaries: pool })).toThrow(corrupt);
  });

  it("liest Inline-Anhänge alter Dateien (offen und geschützt)", () => {
    const plain = Buffer.from("inline").toString("base64");
    const secret = Buffer.from("geheim").toString("base64");
    const xml = minimalXml({
      group: entryXml(
        `<Binary><Key>a</Key><Value>${plain}</Value></Binary><Binary><Key>b</Key><Value Protected="True">${secret}</Value></Binary>`,
      ),
    });
    expect(parse(xml).root.entries[0]!.attachments).toEqual([
      { name: "a", data: new TextEncoder().encode("inline"), protected: false },
      { name: "b", data: new TextEncoder().encode("geheim"), protected: true },
    ]);
  });

  it("fasst doppelte Anhang-Namen mit gleichem Inhalt zusammen und lehnt verschiedene ab", () => {
    const pool = [
      { data: Uint8Array.of(1), protected: true },
      { data: Uint8Array.of(2), protected: true },
    ];
    const same = minimalXml({
      group: entryXml('<Binary><Key>a</Key><Value Ref="0"/></Binary><Binary><Key>a</Key><Value Ref="0"/></Binary>'),
    });
    expect(parse(same, { binaries: pool }).root.entries[0]!.attachments).toHaveLength(1);
    const different = minimalXml({
      group: entryXml('<Binary><Key>a</Key><Value Ref="0"/></Binary><Binary><Key>a</Key><Value Ref="1"/></Binary>'),
    });
    expect(() => parse(different, { binaries: pool })).toThrow(/doppelt/);
  });

  it("weigert sich, doppelte Anhang-Namen zu schreiben", () => {
    const vault = sampleVault(false);
    const mail = vault.root.entries[0]!;
    mail.attachments.push({ ...mail.attachments[0]!, data: Uint8Array.of(9) });
    expect(() => serializeVaultXml(vault, identityStream())).toThrow(/doppelt/);
  });
});

// ---------------------------------------------------------------------------
// Fehlerhafte Dateien
// ---------------------------------------------------------------------------

describe("Fehlerhafte Dateien ergeben KdbxError Corrupt", () => {
  const cases: [string, string, RegExp][] = [
    ["DOCTYPE", '<!DOCTYPE x [<!ENTITY a "b">]>' + minimalXml().replace(/^<\?xml[^>]*>/, ""), /DOCTYPE/],
    ["kein XML", "das ist kein XML", /kein gültiges XML/],
    ["falsches Wurzelelement", "<KeePass><Root/></KeePass>", /KeePassFile/],
    ["Root fehlt", "<KeePassFile><Meta/></KeePassFile>", /<Root> fehlt/],
    ["Wurzelgruppe fehlt", "<KeePassFile><Root><DeletedObjects/></Root></KeePassFile>", /Wurzelgruppe fehlt/],
    ["zwei Wurzelgruppen", minimalXml({ root: `<Group><UUID>${testUuid(2)}</UUID></Group>` }), /<Group> kommt mehrfach/],
    ["zwei Meta", "<KeePassFile><Meta/><Meta/><Root/></KeePassFile>", /<Meta> kommt mehrfach/],
    ["Eintrag ohne UUID", minimalXml({ group: "<Entry><IconID>0</IconID></Entry>" }), /UUID fehlt/],
    ["Eintrag mit Null-UUID", minimalXml({ group: `<Entry><UUID>${NULL_UUID}</UUID></Entry>` }), /UUID fehlt/],
    ["UUID kein Base64", minimalXml({ group: "<Entry><UUID>%%%</UUID></Entry>" }), /ungültiges Base64/],
    ["UUID falsche Länge", minimalXml({ group: "<Entry><UUID>AAAA</UUID></Entry>" }), /3 statt 16 Byte/],
    ["doppelte UUID", minimalXml({ group: entryXml(`<UUID>${testUuid(11)}</UUID>`) }), /<UUID> kommt mehrfach/],
    ["IconID keine Zahl", minimalXml({ group: entryXml("<IconID>abc</IconID>") }), /IconID: ganze Zahl/],
    ["IconID negativ", minimalXml({ group: "<IconID>-1</IconID>" }), /negativ/],
    ["Expires kein Wahrheitswert", minimalXml({ group: "<Times><Expires>vielleicht</Expires></Times>" }), /Expires/],
    ["Zeit kaputt", minimalXml({ group: "<Times><CreationTime>AAAA</CreationTime></Times>" }), /CreationTime/],
    ["HistoryMaxItems < -1", minimalXml({ meta: "<HistoryMaxItems>-2</HistoryMaxItems>" }), /HistoryMaxItems/],
    [
      "doppeltes Feld",
      minimalXml({
        group: entryXml("<String><Key>Title</Key><Value>a</Value></String><String><Key>Title</Key><Value>b</Value></String>"),
      }),
      /Feld "Title" kommt doppelt/,
    ],
    ["Feld ohne Key", minimalXml({ group: entryXml("<String><Value>a</Value></String>") }), /<Key> fehlt/],
    ["Feld ohne Value", minimalXml({ group: entryXml("<String><Key>a</Key></String>") }), /<Value> fehlt/],
    ["Anhang ohne Key", minimalXml({ group: entryXml('<Binary><Value Ref="0"/></Binary>') }), /<Key> fehlt/],
    [
      "Verlauf im Verlauf",
      minimalXml({ group: entryXml(`<History><Entry><UUID>${testUuid(10)}</UUID><History/></Entry></History>`) }),
      /keinen Verlauf/,
    ],
    [
      "geschützter Wert kein Base64",
      minimalXml({ group: entryXml('<String><Key>P</Key><Value Protected="True">%%%</Value></String>') }),
      /Geschützter Wert/,
    ],
    [
      "geschützter Wert mit Kind-Elementen",
      minimalXml({ group: entryXml('<String><Key>P</Key><Value Protected="True"><x/></Value></String>') }),
      /nur Text/,
    ],
    [
      "geschützter Wert kein UTF-8",
      minimalXml({ group: entryXml('<String><Key>P</Key><Value Protected="True">//8=</Value></String>') }),
      /kein gültiges UTF-8/,
    ],
    [
      "Lösch-Vermerk ohne Zeit",
      minimalXml({ root: `<DeletedObjects><DeletedObject><UUID>${testUuid(5)}</UUID></DeletedObject></DeletedObjects>` }),
      /DeletionTime> fehlt/,
    ],
    [
      "CustomData ohne Value",
      minimalXml({ group: "<CustomData><Item><Key>k</Key></Item></CustomData>" }),
      /<Value> fehlt/,
    ],
    [
      "Icon ohne Daten",
      minimalXml({ meta: `<CustomIcons><Icon><UUID>${testUuid(9)}</UUID></Icon></CustomIcons>` }),
      /<Data> fehlt/,
    ],
    ["zu tief verschachtelt", minimalXml({ group: "<Group>".repeat(1500) + "</Group>".repeat(1500) }), /zu tief/],
  ];

  it.each(cases)("%s", (_name, xml, message) => {
    expect(() => parse(xml)).toThrow(corrupt);
    expect(() => parse(xml)).toThrow(message);
  });

  it("lehnt ungültiges UTF-8 in der XML ab", () => {
    const bytes = utf8Encode(minimalXml({ group: "<Notes>X</Notes>" }));
    bytes[bytes.indexOf(0x58)] = 0xff; // das "X" durch ein ungültiges Byte ersetzen
    expect(() => parseVaultXml(bytes, [], identityStream(), SETTINGS_41)).toThrow(/kein gültiges UTF-8/);
  });

  it("nennt in Fehlermeldungen keine geheimen Werte", () => {
    const xml = minimalXml({ group: entryXml('<String><Key>P</Key><Value Protected="True">c2VocmdlaGVpbQ==</Value></String><IconID>sehr-geheim</IconID>') });
    expect(() => parse(xml)).toThrow(/IconID/);
    expect(() => parse(xml)).not.toThrow(/sehr-geheim|sehrgeheim/);
  });
});
