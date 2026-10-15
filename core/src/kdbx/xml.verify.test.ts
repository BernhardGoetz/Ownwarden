/**
 * Gegenprüfung der XML-Schicht (adversarial verification): gezielte Tests für Verdachtsfälle,
 * die beim Review von xml*.ts aufgefallen sind. Jeder Test beschreibt im Namen die
 * Eigenschaft, die gelten MUSS. Tests, die einen echten Fehler gefunden haben, bleiben als
 * Regressionstests stehen (Kommentar "Regression").
 */
import { describe, expect, it } from "vitest";
import { ReferenceStream, decryptProtectedText, encryptProtectedText, identityStream, sampleVault, testUuid } from "../../test/fixtures/xml/fixtures";
import { KdbxError, type InnerStreamCipher, type PoolBinary } from "../contracts";
import { NULL_UUID, type Entry, type KdbxSettings, type Vault } from "../model";
import { utf8Decode, utf8Encode } from "./bytes";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "./xml";

const corrupt = expect.objectContaining({ name: "KdbxError", code: "Corrupt" });

const SETTINGS_41: KdbxSettings = {
  versionMinor: 1,
  cipher: "aes256",
  compression: true,
  kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 2, memoryBytes: 1 << 26, iterations: 3, version: 0x13 },
};

function parse(xml: string, binaries: PoolBinary[] = [], stream: InnerStreamCipher = identityStream()): Vault {
  return parseVaultXml(utf8Encode(xml), binaries, stream, SETTINGS_41);
}

function roundTrip(vault: Vault): { vault: Vault; xml: string; binaries: PoolBinary[] } {
  const out = serializeVaultXml(vault, new ReferenceStream(3));
  const reparsed = parseVaultXml(out.xml, out.binaries, new ReferenceStream(3), vault.settings);
  return { vault: reparsed, xml: utf8Decode(out.xml), binaries: out.binaries };
}

/** Base64 von UTF-8 (für geschützte Werte mit identityStream: Chiffretext = Klartext). */
const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

/** Kleinste gültige Datei; Teile werden eingesetzt. */
function doc(parts: { meta?: string; group?: string; root?: string } = {}): string {
  return `<?xml version="1.0" encoding="UTF-8"?><KeePassFile><Meta>${parts.meta ?? ""}</Meta><Root>` +
    `<Group><UUID>${testUuid(1)}</UUID><Name>Root</Name>${parts.group ?? ""}</Group>${parts.root ?? ""}</Root></KeePassFile>`;
}

function minimalEntry(uuidNumber: number, overrides: Partial<Entry> = {}): Entry {
  return {
    uuid: testUuid(uuidNumber),
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
    ...overrides,
  };
}

/**
 * Schreibt das Modell und liest das Ergebnis wieder ein. Erlaubt ist, dass das SCHREIBEN ein
 * fehlerhaftes Modell ablehnt; verboten ist, eine Datei zu erzeugen, die Ownwarden danach
 * selbst nicht mehr lesen kann (der Tresor wäre nach dem Hochladen unbrauchbar).
 */
function writeThenRead(vault: Vault): "rejected-on-write" | Vault {
  let out: { xml: Uint8Array; binaries: PoolBinary[] };
  try {
    out = serializeVaultXml(vault, identityStream());
  } catch (error) {
    // Ein Modellfehler beim Schreiben darf KEIN KdbxError sein (der hieße "Datei kaputt").
    expect(error).not.toBeInstanceOf(KdbxError);
    return "rejected-on-write";
  }
  return parseVaultXml(out.xml, out.binaries, identityStream(), vault.settings);
}

// ---------------------------------------------------------------------------
// Unbekannte Elemente
// ---------------------------------------------------------------------------

describe("Unbekannte Elemente: Reihenfolge und Inhalt", () => {
  it("Regression: behält die Reihenfolge unbekannter Elemente auch in KeePass-2.x-Anordnung (SettingsChanged vorn)", () => {
    const vault = sampleVault(true);
    vault.meta.unknown = [
      "<SettingsChanged>h29i4g4AAAA=</SettingsChanged>",
      "<DatabaseDescription>Beschreibung</DatabaseDescription>",
      "<MemoryProtection><ProtectTitle>False</ProtectTitle></MemoryProtection>",
      "<FremdesMeta>x</FremdesMeta>",
      "<LastSelectedGroup>AAAAAAAAAAAAAAAAAAAAAA==</LastSelectedGroup>",
    ];
    vault.root.unknown = ["<EnableAutoType>null</EnableAutoType>", "<IsExpanded>True</IsExpanded>"];
    const once = roundTrip(vault);
    expect(once.vault.meta.unknown).toEqual(vault.meta.unknown);
    expect(once.vault.root.unknown).toEqual(vault.root.unknown);
    // Und stabil: ein zweiter Durchlauf ändert nichts mehr.
    expect(utf8Decode(serializeVaultXml(once.vault, new ReferenceStream(3)).xml)).toBe(once.xml);
  });

  it("Regression: bewahrt Steuerzeichen in GESCHÜTZTEN Werten innerhalb unbekannter Elemente", () => {
    const secret = "a\u0001b\u001bc￿d\u0000e";
    const xml = doc({ meta: `<PluginData><Secret Protected="True">${b64(secret)}</Secret></PluginData>` });
    const vault = parse(xml);
    const out = utf8Decode(serializeVaultXml(vault, identityStream()).xml);
    const written = /<Secret Protected="True">([^<]*)<\/Secret>/.exec(out)![1]!;
    expect(Buffer.from(written, "base64").toString("utf8")).toBe(secret);
    // Auch über einen echten Strom und ein zweites Einlesen hinweg.
    const again = roundTrip(vault).vault;
    expect(again.meta.unknown).toEqual(vault.meta.unknown);
  });

  it("schreibt KEINE ungültigen XML-Zeichen in die Datei (auch nicht aus unbekannten Elementen)", () => {
    const xml = doc({ meta: `<PluginData><Plain>x&#1;y</Plain><Secret Protected="True">${b64("\u0001")}</Secret></PluginData>` });
    const out = utf8Decode(serializeVaultXml(parse(xml), identityStream()).xml);
    expect(out).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]|&#(0*[0-8]|0*1[1-2]|0*1[4-9]|0*2\d|0*3[01]|65534|65535);|&#x0*([0-8bcef]|1[0-9a-f]|fff[ef]);/i);
  });

  it("Regression: ein geschützter Wert, der mit U+FEFF beginnt, behält dieses Zeichen", () => {
    // TextDecoder entfernt ein BOM am Anfang JEDES decode-Aufrufs – geschützte Werte werden
    // einzeln dekodiert, ein Passwort darf aber mit jedem beliebigen Zeichen beginnen.
    const vault = sampleVault(true);
    const mail = vault.root.entries[0]!;
    mail.strings.set("Password", { value: "﻿BOM-Passwort", protected: true });
    mail.unknown.push('<PluginBom><S Protected="True">﻿im-unbekannten</S></PluginBom>');
    const back = roundTrip(vault).vault.root.entries[0]!;
    expect(back.strings.get("Password")).toEqual({ value: "﻿BOM-Passwort", protected: true });
    expect(back.unknown).toContain('<PluginBom><S Protected="True">﻿im-unbekannten</S></PluginBom>');
  });

  it("geschützte Werte bekannter Felder überstehen Steuerzeichen und U+FFFF", () => {
    const vault = sampleVault(true);
    vault.root.entries[0]!.strings.set("Steuer", { value: "\u0000\u0001\u001f￾￿\r\n", protected: true });
    expect(roundTrip(vault).vault.root.entries[0]!.strings.get("Steuer")).toEqual({
      value: "\u0000\u0001\u001f￾￿\r\n",
      protected: true,
    });
  });
});

// ---------------------------------------------------------------------------
// Zeiten
// ---------------------------------------------------------------------------

describe("Zeiten an den Rändern", () => {
  const YEAR_1 = Date.parse("0001-01-01T00:00:00Z");
  const YEAR_9999 = Date.parse("9999-12-31T23:59:59Z");

  it("Jahr 1, Jahr 9999, vor 1970 und Millisekunden überstehen den Rundlauf", () => {
    const vault = sampleVault(true);
    const entry = vault.root.entries[0]!;
    entry.times = {
      creation: YEAR_1,
      lastModification: Date.parse("1969-07-20T20:17:40Z"),
      lastAccess: -1, // eine Millisekunde vor 1970 -> abgerundet auf -1000
      expiry: YEAR_9999,
      expires: true,
      usageCount: 2 ** 40,
      locationChanged: 1_700_000_000_999,
    };
    expect(roundTrip(vault).vault.root.entries[0]!.times).toEqual({
      creation: YEAR_1,
      lastModification: Date.parse("1969-07-20T20:17:40Z"),
      lastAccess: -1000,
      expiry: YEAR_9999,
      expires: true,
      usageCount: 2 ** 40,
      locationChanged: 1_700_000_000_000,
    });
  });

  it("liest ISO-Zeiten (KDBX 3) an den Rändern", () => {
    const times =
      "<Times><CreationTime>0001-01-01T00:00:00Z</CreationTime>" +
      "<LastModificationTime>1969-12-31T23:59:59.999Z</LastModificationTime>" +
      "<ExpiryTime>9999-12-31T23:59:59Z</ExpiryTime>" +
      "<LastAccessTime>2026-10-15T12:00:00+0200</LastAccessTime></Times>";
    const vault = parse(doc({ group: times }));
    expect(vault.root.times.creation).toBe(YEAR_1);
    expect(vault.root.times.lastModification).toBe(-1000);
    expect(vault.root.times.expiry).toBe(YEAR_9999);
    expect(vault.root.times.lastAccess).toBe(Date.parse("2026-10-15T10:00:00Z"));
    expect(roundTrip(vault).vault.root.times).toEqual(vault.root.times);
  });

  it.each([
    ["Zeitzone schiebt vor Jahr 1", "0001-01-01T00:00:00+01:00"],
    ["Zeitzone schiebt hinter Jahr 9999", "9999-12-31T23:59:59-00:01"],
  ])("Regression: eine eingelesene ISO-Zeit muss sich auch wieder speichern lassen (%s)", (_name, iso) => {
    let vault: Vault;
    try {
      vault = parse(doc({ group: `<Times><CreationTime>${iso}</CreationTime></Times>` }));
    } catch (error) {
      expect(error).toEqual(corrupt);
      return;
    }
    expect(() => serializeVaultXml(vault, identityStream())).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Dokumentreihenfolge geschützter Werte
// ---------------------------------------------------------------------------

describe("Geschützte Werte in Dokumentreihenfolge", () => {
  /** Ungewöhnliche, aber gültige Anordnung: Untergruppe VOR Eintrag, Verlauf VOR den Strings. */
  const plain = `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
  <Meta><X><S Protected="True">m1</S></X><DatabaseName>DB</DatabaseName></Meta>
  <Root>
    <Group>
      <UUID>${testUuid(1)}</UUID>
      <Group>
        <UUID>${testUuid(2)}</UUID>
        <Entry><UUID>${testUuid(20)}</UUID><String><Key>Password</Key><Value Protected="True">g1</Value></String></Entry>
      </Group>
      <Foreign><V Protected="True">f1</V></Foreign>
      <Entry>
        <UUID>${testUuid(10)}</UUID>
        <History>
          <Entry><UUID>${testUuid(10)}</UUID><String><Key>Password</Key><Value Protected="True">h1</Value></String></Entry>
          <Entry><UUID>${testUuid(10)}</UUID><String><Key>Password</Key><Value Protected="True"></Value></String>
            <AutoType><X Protected="True">h2-at</X></AutoType></Entry>
        </History>
        <String><Key>Password</Key><Value Protected="True">e1</Value></String>
        <Binary><Key>inline</Key><Value Protected="True">e2-bin</Value></Binary>
        <String><Key>PIN</Key><Value Protected="True">e3</Value></String>
      </Entry>
    </Group>
    <R><V Protected="True">r1</V></R>
  </Root>
</KeePassFile>`;

  it("liest jeden Wert mit dem richtigen Stück des Schlüsselstroms", () => {
    const vault = parse(encryptProtectedText(plain, new ReferenceStream(11)), [], new ReferenceStream(11));
    expect(vault.meta.unknown).toEqual(['<X><S Protected="True">m1</S></X>']);
    expect(vault.root.groups[0]!.entries[0]!.strings.get("Password")?.value).toBe("g1");
    expect(vault.root.unknown).toEqual(['<Foreign><V Protected="True">f1</V></Foreign>']);
    const entry = vault.root.entries[0]!;
    expect(entry.history.map((h) => h.strings.get("Password")?.value)).toEqual(["h1", ""]);
    expect(entry.history[1]!.unknown).toEqual(['<AutoType><X Protected="True">h2-at</X></AutoType>']);
    expect(entry.strings.get("Password")?.value).toBe("e1");
    expect(utf8Decode(entry.attachments[0]!.data)).toBe("e2-bin");
    expect(entry.strings.get("PIN")?.value).toBe("e3");
    expect(vault.rootUnknown).toEqual(['<R><V Protected="True">r1</V></R>']);
  });

  it("verschlüsselt beim Schreiben in der Reihenfolge der AUSGABE", () => {
    const vault = parse(encryptProtectedText(plain, new ReferenceStream(11)), [], new ReferenceStream(11));
    const out = utf8Decode(serializeVaultXml(vault, new ReferenceStream(12)).xml);
    // Ausgabe-Reihenfolge: Meta, Fremdes der Gruppe, Eintrag (Strings, Unbekanntes, Verlauf),
    // dann die Untergruppe, am Ende Fremdes von Root. Der Inline-Anhang wandert in den Pool.
    // Der leere geschützte Wert steht als <Value Protected="True"/> da (verbraucht nichts und
    // wird vom regulären Ausdruck in decryptProtectedText nicht gezählt).
    expect(out).toContain('<Value Protected="True"/>');
    expect(decryptProtectedText(out, new ReferenceStream(12))).toEqual(["m1", "f1", "e1", "e3", "h1", "h2-at", "g1", "r1"]);
    const again = parseVaultXml(utf8Encode(out), serializeVaultXml(vault, new ReferenceStream(12)).binaries, new ReferenceStream(12), SETTINGS_41);
    expect(again.root.entries[0]!.strings.get("PIN")?.value).toBe("e3");
    expect(utf8Decode(again.root.entries[0]!.attachments[0]!.data)).toBe("e2-bin");
  });
});

// ---------------------------------------------------------------------------
// XXE / DOCTYPE / Entities
// ---------------------------------------------------------------------------

describe("XXE und Entities", () => {
  const body = doc({ group: "<Notes>&xxe;</Notes>" }).replace(/^<\?xml[^>]*>/, "");
  it.each([
    ["DOCTYPE klein geschrieben", `<!doctype KeePassFile SYSTEM "file:///etc/passwd">${doc().replace(/^<\?xml[^>]*>/, "")}`],
    ["externe Entity", `<?xml version="1.0"?><!DOCTYPE KeePassFile [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>${body}`],
    [
      "Billion Laughs",
      `<?xml version="1.0"?><!DOCTYPE KeePassFile [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>${doc({ group: "<Notes>&b;</Notes>" }).replace(/^<\?xml[^>]*>/, "")}`,
    ],
    ["unbekannte Entity ohne DOCTYPE", doc({ group: "<Notes>&xxe;</Notes>" })],
    ["HTML-Entity", doc({ group: "<Notes>a&nbsp;b</Notes>" })],
    ["Parameter-Entity", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % p SYSTEM "http://example.org/x.dtd"> %p;]>${body}`],
  ])("lehnt ab: %s", (_name, xml) => {
    expect(() => parse(xml)).toThrow(corrupt);
  });

  it("akzeptiert die fünf vordefinierten Entities und Zeichenreferenzen", () => {
    const vault = parse(doc({ group: "<Notes>&amp;&lt;&gt;&quot;&apos;&#65;&#x42;&#13;</Notes>" }));
    expect(vault.root.notes).toBe("&<>\"'AB\r");
  });

  it("liest eine Datei mit UTF-8-BOM", () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...utf8Encode(doc())]);
    expect(parseVaultXml(bytes, [], identityStream(), SETTINGS_41).root.name).toBe("Root");
  });
});

// ---------------------------------------------------------------------------
// Binär-Pool
// ---------------------------------------------------------------------------

describe("Binär-Pool: Neuaufbau und Verweise", () => {
  it("baut den Pool neu (unbenutzte fallen weg, neue Indizes) und Verweise im Verlauf stimmen danach", () => {
    const A = utf8Encode("A-Inhalt");
    const B = utf8Encode("B-Inhalt");
    const C = utf8Encode("C-Inhalt");
    const pool: PoolBinary[] = [
      { data: A, protected: true },
      { data: utf8Encode("ungenutzt"), protected: true },
      { data: B, protected: false },
      { data: C, protected: true },
    ];
    const entry =
      `<Entry><UUID>${testUuid(10)}</UUID><Binary><Key>c</Key><Value Ref=" 3 "/></Binary>` +
      `<History><Entry><UUID>${testUuid(10)}</UUID><Binary><Key>a</Key><Value Ref="0"/></Binary>` +
      `<Binary><Key>c-alt</Key><Value Ref="3"/></Binary></Entry></History></Entry>` +
      `<Entry><UUID>${testUuid(11)}</UUID><Binary><Key>b</Key><Value Ref="2"/></Binary></Entry>`;
    const vault = parse(doc({ group: entry }), pool);
    const { vault: back, binaries, xml } = roundTrip(vault);
    // Reihenfolge der ersten Verwendung in der AUSGABE: c (Eintrag 1), a (Verlauf), b (Eintrag 2).
    expect(binaries.map((b) => [utf8Decode(b.data), b.protected])).toEqual([
      ["C-Inhalt", true],
      ["A-Inhalt", true],
      ["B-Inhalt", false],
    ]);
    expect([...xml.matchAll(/<Value Ref="(\d+)"\/>/g)].map((m) => m[1])).toEqual(["0", "1", "0", "2"]);
    const [first, second] = back.root.entries;
    expect(first!.attachments).toEqual([{ name: "c", data: C, protected: true }]);
    expect(first!.history[0]!.attachments).toEqual([
      { name: "a", data: A, protected: true },
      { name: "c-alt", data: C, protected: true },
    ]);
    expect(second!.attachments).toEqual([{ name: "b", data: B, protected: false }]);
  });

  it("schreibt einen leeren Anhang und liest ihn zurück", () => {
    const vault = sampleVault(false);
    vault.root.entries[0]!.attachments.push({ name: "leer.txt", data: new Uint8Array(0), protected: true });
    const { vault: back } = roundTrip(vault);
    expect(back.root.entries[0]!.attachments.at(-1)).toEqual({ name: "leer.txt", data: new Uint8Array(0), protected: true });
  });

  it("serializeVaultXml verändert die Anhang-Daten des Modells nicht (kein Wipe geteilter Arrays)", () => {
    const vault = sampleVault(true);
    const data = vault.root.entries[0]!.attachments[0]!.data;
    const copy = data.slice();
    serializeVaultXml(vault, new ReferenceStream(1));
    expect(data).toEqual(copy);
  });
});

// ---------------------------------------------------------------------------
// Leere und fehlende optionale Elemente
// ---------------------------------------------------------------------------

describe("Leere und fehlende optionale Elemente", () => {
  it("liest leere Elemente als Standardwerte und schreibt sie verlustfrei zurück", () => {
    const entry =
      `<Entry><UUID>${testUuid(10)}</UUID><IconID/><CustomIconUUID/><ForegroundColor/><BackgroundColor/>` +
      `<OverrideURL/><Tags/><Times/><QualityCheck/><PreviousParentGroup/>` +
      `<String><Key>Password</Key><Value Protected="True"/></String><String><Key/><Value/></String>` +
      `<Binary><Key>leer</Key><Value/></Binary><CustomData/><History/></Entry>`;
    const group =
      `<Notes/><IconID/><CustomIconUUID/><Times><CreationTime/><Expires/><UsageCount/></Times><Tags/>` +
      `<PreviousParentGroup/><CustomData><Item><Key>k</Key><Value/><LastModificationTime/></Item></CustomData>${entry}`;
    const meta =
      "<Generator/><DatabaseName/><DatabaseNameChanged/><RecycleBinEnabled/><RecycleBinUUID/><RecycleBinChanged/>" +
      "<HistoryMaxItems/><HistoryMaxSize/><CustomIcons/><CustomData/>";
    const vault = parse(doc({ meta, group, root: "<DeletedObjects/>" }));
    const e = vault.root.entries[0]!;
    expect(e.iconId).toBe(0);
    expect(e.customIconUuid).toBeUndefined();
    expect(e.qualityCheck).toBeUndefined();
    expect(e.previousParentGroup).toBeUndefined();
    expect([...e.strings]).toEqual([
      ["Password", { value: "", protected: true }],
      ["", { value: "", protected: false }],
    ]);
    expect(e.attachments).toEqual([{ name: "leer", data: new Uint8Array(0), protected: false }]);
    expect(vault.root.customData.get("k")).toEqual({ value: "" });
    expect(vault.meta.recycleBinUuid).toBe(NULL_UUID);
    expect(vault.meta.historyMaxItems).toBe(10);
    expect(roundTrip(vault).vault).toEqual(vault);
  });
});

// ---------------------------------------------------------------------------
// Symmetrie: Was Ownwarden schreibt, muss Ownwarden lesen können
// ---------------------------------------------------------------------------

describe("Schreiben erzeugt nie eine Datei, die das Lesen ablehnt", () => {
  const cases: [string, (vault: Vault) => void][] = [
    [
      "zwei Feldnamen, die sich nur durch ungültige XML-Zeichen unterscheiden",
      (v) => v.root.entries[0]!.strings.set("Title\u0001", { value: "zweiter Titel", protected: false }),
    ],
    [
      "zwei Anhang-Namen, die sich nur durch ungültige XML-Zeichen unterscheiden",
      (v) => v.root.entries[0]!.attachments.push({ name: "offen.bin\u0002", data: Uint8Array.of(7), protected: false }),
    ],
    ["negative Icon-Nummer am Eintrag", (v) => (v.root.entries[0]!.iconId = -1)],
    ["negative Icon-Nummer an der Gruppe", (v) => (v.root.iconId = -3)],
    ["HistoryMaxItems kleiner -1", (v) => (v.meta.historyMaxItems = -2)],
    ["HistoryMaxSize kleiner -1", (v) => (v.meta.historyMaxSize = -5)],
    ["Null-UUID am Eintrag", (v) => (v.root.entries[0]!.uuid = NULL_UUID)],
    ["Null-UUID an einer Gruppe", (v) => (v.root.groups[0]!.uuid = NULL_UUID)],
    ["Null-UUID im Verlauf", (v) => (v.root.entries[0]!.history[0]!.uuid = NULL_UUID)],
    ["Null-UUID bei einem Icon", (v) => (v.meta.customIcons[0]!.uuid = NULL_UUID)],
    ["Null-UUID bei einem Lösch-Vermerk", (v) => (v.deletedObjects[0]!.uuid = NULL_UUID)],
    ["Eintrag mit Verlauf im Verlauf (wird nicht geschrieben)", (v) => v.root.entries[0]!.history[0]!.history.push(minimalEntry(10))],
  ];

  it.each(cases)("%s", (_name, mutate) => {
    const vault = sampleVault(true);
    mutate(vault);
    expect(() => writeThenRead(vault)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// KDBX 4.0 / 4.1
// ---------------------------------------------------------------------------

describe("KDBX 4.0 und 4.1", () => {
  it("kdbxMinorVersionRequired erkennt 4.1-Merkmale auch tief in Untergruppen und im Verlauf", () => {
    const vault = sampleVault(false);
    expect(kdbxMinorVersionRequired(vault)).toBe(0);
    const deep = sampleVault(false);
    deep.root.groups[0]!.groups.push({ ...deep.root.groups[1]!, uuid: testUuid(44), previousParentGroup: testUuid(1) });
    expect(kdbxMinorVersionRequired(deep)).toBe(1);
    const history = sampleVault(false);
    history.root.entries[0]!.history[0]!.qualityCheck = false;
    expect(kdbxMinorVersionRequired(history)).toBe(1);
    const icon = sampleVault(false);
    icon.meta.customIcons[0]!.lastModified = 0;
    expect(kdbxMinorVersionRequired(icon)).toBe(1);
  });

  it("eine 4.0-Datei mit 4.1-Elementen wird gelesen, und kdbxMinorVersionRequired verlangt danach 4.1", () => {
    const xml = doc({ group: `<Tags>a</Tags><Entry><UUID>${testUuid(10)}</UUID><QualityCheck>False</QualityCheck></Entry>` });
    const vault = parseVaultXml(utf8Encode(xml), [], identityStream(), { ...SETTINGS_41, versionMinor: 0 });
    expect(vault.root.tags).toEqual(["a"]);
    expect(vault.root.entries[0]!.qualityCheck).toBe(false);
    expect(kdbxMinorVersionRequired(vault)).toBe(1);
  });
});
