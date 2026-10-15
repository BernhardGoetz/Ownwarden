/**
 * Gegenprüfung mit KeePassXC: Eine Datenbank, die Ownwarden VON GRUND AUF erzeugt (nicht
 * von KeePassXC übernommen), mit möglichst vielen Randfällen. KeePassXC muss sie
 *   1. ohne Warnungen lesen und dieselben Werte zeigen (export, show),
 *   2. selbst neu speichern können, ohne dass Daten verloren gehen (danach liest Ownwarden
 *      die von KeePassXC geschriebene Fassung und vergleicht mit dem Original).
 * Für KDBX 4.1 und 4.0. Wird übersprungen, wenn `keepassxc-cli` fehlt.
 *
 * Bekannte Eigenheiten von KeePassXC 2.7.6, die der Vergleich ausgleicht (siehe kpxcNormal):
 *   - "\r" in Texten: KeePassXC liest &#13; richtig, schreibt "\r" aber roh – jeder
 *     XML-Leser macht daraus "\n". (Ownwarden schreibt &#13; und behält es.)
 *   - Tags werden sortiert; CustomData bekommt _LAST_MODIFIED (auch in Meta);
 *     LastModificationTime in CustomData von Einträgen/Gruppen fällt weg.
 *   - Alle Anhänge bekommen im Pool das Schutz-Flag; Anhänge stehen nach Namen sortiert.
 *   - Unbekannte Elemente von Gruppen/Einträgen schreibt KeePassXC nach eigenem Wissen neu.
 *   - Jeder Eintrag hat bei KeePassXC immer die fünf Standardfelder (leer, wenn nicht gesetzt).
 *   - Mit eigenem Icon (CustomIconUUID) setzt KeePassXC die IconID auf 0 (Entry::setIcon).
 *   - Ein U+FEFF am ANFANG eines geschützten Werts verliert KeePassXC beim Laden (Qt entfernt
 *     es beim Dekodieren). Ownwarden und KeePass 2.x behalten es; in der Datei steht es.
 */
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sampleVault, testUuid, identityStream } from "../../test/fixtures/xml/fixtures";
import { createTmpDir, hasKeepassxc, removeTmpDir, runKpxc, runKpxcOk } from "../../test/helpers/keepassxc";
import type { PoolBinary } from "../contracts";
import { STANDARD_FIELDS, type Attachment, type CustomData, type Entry, type Group, type ProtectedString, type Vault } from "../model";
import { utf8Encode } from "./bytes";
import { decryptContainer, encryptContainer } from "./container";
import { createInnerStream, newInnerStreamKey } from "./inner-stream";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "./xml";

const PASSWORD = "Verify-Interop-äöü";
const CREDENTIALS = { password: PASSWORD };
const KPXC_XML_WARNING = /KdbxXmlReader|skip element|Invalid|Unmapped|unused key|Duplicate|Missing/i;

const LONG_SECRET = "x".repeat(700) + "€";
const NOTES = "CRLF\r\nLF\nCR\rEnde 🔑 ]]> &#13; \"zitiert\" 'einfach' <tag>";

/** Ownwarden-Modell mit Randfällen (ohne Plugin-Elemente, die KeePassXC nicht kennt). */
function edgeVault(kdbx41: boolean): Vault {
  const vault = sampleVault(kdbx41);
  // Schnelle KDF, damit KeePassXC nicht lange rechnet.
  vault.settings.kdf = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 };
  // Meta in der Reihenfolge von KeePass 2.x (SettingsChanged direkt am Anfang).
  vault.meta.unknown = [
    "<SettingsChanged>h29i4g4AAAA=</SettingsChanged>",
    "<DatabaseDescription>Beschreibung äöü</DatabaseDescription>",
    "<MaintenanceHistoryDays>123</MaintenanceHistoryDays>",
    "<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName>" +
      "<ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes></MemoryProtection>",
  ];
  vault.rootUnknown = [];

  const mail = vault.root.entries[0]!;
  mail.unknown = mail.unknown.filter((xml) => !xml.startsWith("<PluginData"));
  mail.tags = ["Zeta", "Mein Tag", "alpha"];
  mail.times = {
    ...mail.times,
    creation: Date.parse("0001-01-01T00:00:00Z"),
    lastAccess: Date.parse("1900-01-01T00:00:00Z"),
    expiry: Date.parse("9999-12-31T23:59:59Z"),
  };
  mail.strings.set("Notes", { value: NOTES, protected: false });
  mail.strings.set("Rand", { value: "  rand \n", protected: true });
  mail.strings.set("Lang", { value: LONG_SECRET, protected: true });
  mail.strings.set("Feld 🔑 äöü", { value: "Wert 🔑", protected: false });
  mail.strings.set("Zeilenanfang", { value: "\nX", protected: false });
  mail.strings.set("BOM", { value: "\ufeffbeginnt-mit-U+FEFF", protected: true });
  mail.attachments.push(
    { name: "leer.txt", data: new Uint8Array(0), protected: true },
    { name: "Bild äöü 🔑.bin", data: new Uint8Array(randomBytes(5000)), protected: true },
  );
  // Verlauf mit mehreren geschützten Werten (Stromreihenfolge über den Verlauf hinweg).
  for (const [i, item] of mail.history.entries()) item.strings.set("PIN", { value: `alt-pin-${i}-äöü`, protected: true });

  // Ein Eintrag, den KeePassXC beim Neuspeichern ändern darf (alle anderen bleiben unberührt).
  vault.root.entries.push({
    ...vault.root.groups[0]!.entries[0]!,
    uuid: testUuid(99),
    strings: new Map([["Title", { value: "Dummy", protected: false }]]),
    attachments: [],
    history: [],
  });
  expect(kdbxMinorVersionRequired(vault)).toBe(kdbx41 ? 1 : 0);
  return vault;
}

async function save(vault: Vault, path: string): Promise<void> {
  const innerStreamKey = newInnerStreamKey();
  const { xml, binaries } = serializeVaultXml(vault, createInnerStream("chacha20", innerStreamKey));
  const file = await encryptContainer({ settings: vault.settings, innerStreamId: "chacha20", innerStreamKey, binaries, xml }, CREDENTIALS);
  writeFileSync(path, file);
}

async function load(path: string): Promise<{ vault: Vault; binaries: PoolBinary[] }> {
  const payload = await decryptContainer(new Uint8Array(readFileSync(path)), CREDENTIALS);
  const stream = createInnerStream(payload.innerStreamId, payload.innerStreamKey);
  return { vault: parseVaultXml(payload.xml, payload.binaries, stream, payload.settings), binaries: payload.binaries };
}

// ---------------------------------------------------------------------------
// Vergleich unter Berücksichtigung der KeePassXC-Eigenheiten
// ---------------------------------------------------------------------------

interface Options {
  /** Anhänge mit vergleichen (nur sinnvoll, wenn KeePassXC die Datei selbst geschrieben hat). */
  attachments: boolean;
}

const lf = (text: string) => text.replace(/\r\n?/g, "\n");
/** Vergleichsform eines Werts: Zeilenenden wie KeePassXC; U+FEFF am Anfang verliert KeePassXC. */
const kpxcText = (text: string) => lf(text).replace(/^\ufeff/, "");

function stripCustomData(customData: CustomData, keepLastModified: boolean): CustomData {
  return new Map(
    [...customData]
      .filter(([key]) => key !== "_LAST_MODIFIED")
      .map(([key, item]) => [key, keepLastModified ? item : { value: item.value }]),
  );
}

/** Leere Standardfelder ergänzt KeePassXC immer; für den Vergleich weglassen. */
function normalStrings(strings: Map<string, ProtectedString>): Record<string, ProtectedString> {
  const isStandard = (key: string) => (STANDARD_FIELDS as readonly string[]).includes(key);
  return Object.fromEntries(
    [...strings]
      .filter(([key, s]) => !(isStandard(key) && s.value === ""))
      .map(([key, s]) => [key, { value: kpxcText(s.value), protected: s.protected }]),
  );
}

/** Mit eigenem Icon ist die IconID bei KeePassXC immer 0. */
const normalIconId = (item: { iconId: number; customIconUuid?: string }) => (item.customIconUuid ? 0 : item.iconId);

function normalEntry(entry: Entry, options: Options): unknown {
  return {
    uuid: entry.uuid,
    iconId: normalIconId(entry),
    customIconUuid: entry.customIconUuid,
    foregroundColor: entry.foregroundColor,
    backgroundColor: entry.backgroundColor,
    overrideUrl: entry.overrideUrl,
    tags: [...entry.tags].sort(),
    times: entry.times,
    strings: normalStrings(entry.strings),
    attachments: options.attachments
      ? [...entry.attachments]
          .sort((a, b) => (a.name < b.name ? -1 : 1))
          .map((a: Attachment) => ({ name: a.name, hex: Buffer.from(a.data).toString("hex"), protected: true }))
      : entry.attachments.length,
    customData: stripCustomData(entry.customData, false),
    history: entry.history.map((item) => normalEntry(item, options)),
    qualityCheck: entry.qualityCheck,
    previousParentGroup: entry.previousParentGroup,
  };
}

function normalGroup(group: Group, options: Options): unknown {
  return {
    uuid: group.uuid,
    name: group.name,
    notes: lf(group.notes),
    iconId: normalIconId(group),
    customIconUuid: group.customIconUuid,
    times: group.times,
    tags: [...group.tags].sort(),
    customData: stripCustomData(group.customData, false),
    previousParentGroup: group.previousParentGroup,
    entries: group.entries.filter((e) => e.uuid !== testUuid(99)).map((e) => normalEntry(e, options)),
    groups: group.groups.map((g) => normalGroup(g, options)),
  };
}

/** Das Modell so, wie KeePassXC es sehen und wieder schreiben muss. */
function kpxcNormal(vault: Vault, options: Options): unknown {
  const { meta } = vault;
  return {
    meta: {
      databaseName: meta.databaseName,
      databaseNameChanged: meta.databaseNameChanged,
      recycleBinEnabled: meta.recycleBinEnabled,
      recycleBinUuid: meta.recycleBinUuid,
      recycleBinChanged: meta.recycleBinChanged,
      historyMaxItems: meta.historyMaxItems,
      historyMaxSize: meta.historyMaxSize,
      customIcons: meta.customIcons,
      customData: stripCustomData(meta.customData, true),
      // Diese Meta-Elemente kennt KeePassXC; es muss sie übernehmen.
      known: meta.unknown.filter((xml) => /^<(DatabaseDescription|MaintenanceHistoryDays|MemoryProtection)>/.test(xml)).sort(),
    },
    root: normalGroup(vault.root, options),
    deletedObjects: vault.deletedObjects,
  };
}

// ---------------------------------------------------------------------------

describe.skipIf(!hasKeepassxc())("KeePassXC-Interop: von Ownwarden erzeugte Datenbank mit Randfällen", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("xml-verify");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  describe.each([
    ["KDBX 4.1", true],
    ["KDBX 4.0", false],
  ])("%s", (_name, kdbx41) => {
    const original = edgeVault(kdbx41);
    let path: string;

    beforeAll(async () => {
      path = join(dir, `ownwarden-${kdbx41 ? "41" : "40"}.kdbx`);
      await save(original, path);
    });

    it("KeePassXC liest die Datei ohne Warnungen und sieht dieselben Werte (export)", async () => {
      const result = await runKpxcOk(["export", "-q", "-f", "xml", path], `${PASSWORD}\n`);
      expect(result.stderr).not.toMatch(KPXC_XML_WARNING);
      // Im Export stehen geschützte Werte im Klartext (ProtectInMemory); Anhänge nur als Verweis
      // in KeePassXCs eigenen Pool – die werden hier daher nur gezählt.
      const { binaries } = await load(path);
      const seen = parseVaultXml(utf8Encode(result.stdout), binaries, identityStream(), original.settings);
      expect(kpxcNormal(seen, { attachments: false })).toEqual(kpxcNormal(original, { attachments: false }));
    });

    it("KeePassXC zeigt CR, Emoji, Leerraum am Rand und lange geschützte Werte byte-genau (show)", async () => {
      const show = async (attribute: string) =>
        (await runKpxcOk(["show", "-q", "-s", "-a", attribute, path, "Mail"], `${PASSWORD}\n`)).stdout;
      // `show -a` hängt genau ein "\n" an.
      expect(await show("Notes")).toBe(`${NOTES}\n`);
      expect(await show("Rand")).toBe("  rand \n\n");
      expect(await show("Lang")).toBe(`${LONG_SECRET}\n`);
      expect(await show("Feld 🔑 äöü")).toBe("Wert 🔑\n");
      // Bekannte Eigenheit von KeePassXC 2.7.6: Das U+FEFF am Anfang geht beim Laden verloren
      // (Ownwarden schreibt es; xml.verify.test.ts prüft, dass Ownwarden es zurückliest).
      expect(await show("BOM")).toBe("beginnt-mit-U+FEFF\n");
    });

    it("KeePassXC speichert die Datei neu, ohne Daten zu verlieren (Anhänge, Verlauf, Zeiten an den Rändern)", async () => {
      const resavedPath = join(dir, `resaved-${kdbx41 ? "41" : "40"}.kdbx`);
      writeFileSync(resavedPath, readFileSync(path));
      const edit = await runKpxc(["edit", "-q", "-u", "geändert", resavedPath, "Dummy"], `${PASSWORD}\n`);
      expect(edit.code).toBe(0);
      expect(edit.stderr).not.toMatch(KPXC_XML_WARNING);

      const { vault: resaved } = await load(resavedPath);
      expect(resaved.settings.versionMinor).toBe(kdbx41 ? 1 : 0);
      expect(resaved.root.entries.find((e) => e.uuid === testUuid(99))!.strings.get("UserName")?.value).toBe("geändert");
      expect(kpxcNormal(resaved, { attachments: true })).toEqual(kpxcNormal(original, { attachments: true }));
    });
  });
});
