/**
 * Integration (c): Treue beim Durchreichen. Eine von KeePassXC gebaute Datenbank wird mit
 * readKdbx gelesen und mit writeKdbx unverändert neu geschrieben. Der XML-Export von KeePassXC
 * (`keepassxc-cli export -f xml`) muss für beide Dateien GLEICH sein – als Text.
 *
 * Normalisiert wird nur, was sich unabhängig von Ownwarden unterscheiden MUSS – auch zwei
 * Exporte DERSELBEN Datei unterscheiden sich darin:
 *   - Der Wert von CustomData "_LAST_MODIFIED": KeePassXC setzt ihn beim LADEN jeder
 *     Datenbank auf die aktuelle Uhrzeit (Meta, Gruppen, Einträge).
 *   - Die Reihenfolge der <Item>s in <CustomData>: KeePassXC hält CustomData in einer
 *     Hash-Tabelle (Qt würfelt den Hash-Startwert pro Programmstart). Beobachtet mit 2.7.6:
 *     Sechs Exporte derselben Datei lieferten fünf verschiedene Reihenfolgen. (Ownwarden
 *     wertet die Reihenfolge von CustomData deshalb nirgends aus, siehe sync/vault-equal.ts.)
 * Sonst nichts: Zeiten, UUIDs, Reihenfolgen, Verlauf, Anhang-Verweise, unbekannte Elemente
 * (AutoType, MemoryProtection, Farben …) müssen exakt übereinstimmen.
 *
 * Bereits vorhanden: src/kdbx/xml.interop.test.ts vergleicht die eingelesenen Modelle beider
 * Exporte und die innere XML byte-genau (über die Einzelbausteine). Neu hier: über
 * readKdbx/writeKdbx, als Textvergleich, mit mehr KeePassXC-Merkmalen (eigenes Icon,
 * Beschreibung, Verlaufsgrenzen, Papierkorb, endgültige Löschung).
 * Wird übersprungen ohne keepassxc-cli.
 */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { addKpxcEntry, createTmpDir, hasKeepassxc, importKpxcAttachment, importKpxcXml, removeTmpDir, runKpxcOk } from "../helpers/keepassxc";
import { KPXC_XML_WARNING, readKdbxFile, writeKdbxFile } from "../helpers/kdbx-files";

const PASSWORD = "Interop-c-äöü";
const b64 = () => randomBytes(16).toString("base64");
/** Ein winziges PNG-artiges Icon (Inhalt egal, KeePassXC speichert die Bytes). */
const ICON = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]).toString("base64");

function importXml(iconUuid: string): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>Ownwarden-Test</Generator>
    <DatabaseName>Treue</DatabaseName>
    <DatabaseDescription>Beschreibung äöü &amp; &lt;Sonderzeichen&gt;</DatabaseDescription>
    <DefaultUserName>standard-user</DefaultUserName>
    <MaintenanceHistoryDays>90</MaintenanceHistoryDays>
    <Color>#FF0000</Color>
    <MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>True</ProtectUserName><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes></MemoryProtection>
    <CustomIcons><Icon><UUID>${iconUuid}</UUID><Data>${ICON}</Data></Icon></CustomIcons>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <HistoryMaxItems>5</HistoryMaxItems>
    <HistoryMaxSize>1048576</HistoryMaxSize>
    <CustomData><Item><Key>Meta.Eigenes</Key><Value>wert</Value></Item></CustomData>
  </Meta>
  <Root>
    <Group>
      <UUID>${b64()}</UUID>
      <Name>Root</Name>
      <Notes>Notiz der Wurzel</Notes>
      <CustomData><Item><Key>Ownwarden.Test</Key><Value>kdbx4</Value></Item></CustomData>
      <Group>
        <UUID>${b64()}</UUID>
        <Name>Privat</Name>
        <IconID>12</IconID>
        <Entry>
          <UUID>${b64()}</UUID>
          <IconID>0</IconID>
          <CustomIconUUID>${iconUuid}</CustomIconUUID>
          <ForegroundColor>#112233</ForegroundColor>
          <BackgroundColor>#445566</BackgroundColor>
          <OverrideURL>cmd://firefox %1</OverrideURL>
          <Tags>alpha;Beta</Tags>
          <Times><Expires>True</Expires><ExpiryTime>2031-01-02T03:04:05Z</ExpiryTime></Times>
          <String><Key>Title</Key><Value>Reich</Value></String>
          <String><Key>UserName</Key><Value ProtectInMemory="True">geschützter-name</Value></String>
          <String><Key>Password</Key><Value ProtectInMemory="True">reich-pw</Value></String>
          <String><Key>Notes</Key><Value>Zeile 1
Zeile 2 &amp; &lt;b&gt;</Value></String>
          <String><Key>Geheimfrage</Key><Value ProtectInMemory="True">Antwort</Value></String>
          <AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence><Association><Window>Bank*</Window><KeystrokeSequence>{PASSWORD}{ENTER}</KeystrokeSequence></Association></AutoType>
          <CustomData><Item><Key>Eigenes.Merkmal</Key><Value>x</Value></Item></CustomData>
        </Entry>
      </Group>
    </Group>
    <DeletedObjects/>
  </Root>
</KeePassFile>
`;
}

/** Siehe Kopfkommentar: Wert von _LAST_MODIFIED gleichmachen, <Item>s in <CustomData> sortieren. */
function normalizeExport(xml: string): string {
  const withoutTimes = xml.replace(/(<Key>_LAST_MODIFIED<\/Key>\s*<Value>)[^<]*(<\/Value>)/g, "$1…$2");
  return withoutTimes.replace(/(<CustomData>)([\s\S]*?)(\s*<\/CustomData>)/g, (_all, open: string, body: string, close: string) => {
    const items = body.match(/\s*<Item>[\s\S]*?<\/Item>/g) ?? [];
    expect(items.join("")).toBe(body); // nur <Item>s, nichts verloren
    return open + [...items].sort().join("") + close;
  });
}

describe.skipIf(!hasKeepassxc())("Integration (c): KeePassXC -> readKdbx -> writeKdbx -> KeePassXC", () => {
  let dir: string;
  let originalPath: string;

  beforeAll(async () => {
    dir = createTmpDir("interop-c");
    originalPath = join(dir, "keepassxc.kdbx");
    await importKpxcXml(importXml(b64()), originalPath, PASSWORD);
    await addKpxcEntry(originalPath, PASSWORD, "Privat/Mail", { username: "alice", password: "mail-pw", url: "https://mail.example", notes: "n" });
    await runKpxcOk(["edit", "-q", "-u", "alice2", originalPath, "Privat/Mail"], `${PASSWORD}\n`); // Verlauf
    await addKpxcEntry(originalPath, PASSWORD, "Wegwerf", { username: "x" });
    await runKpxcOk(["rm", "-q", originalPath, "Wegwerf"], `${PASSWORD}\n`); // in den Papierkorb …
    await runKpxcOk(["rm", "-q", originalPath, "Recycle Bin/Wegwerf"], `${PASSWORD}\n`); // … und endgültig (DeletedObjects)
    await addKpxcEntry(originalPath, PASSWORD, "Papierkorb-Eintrag", {});
    await runKpxcOk(["rm", "-q", originalPath, "Papierkorb-Eintrag"], `${PASSWORD}\n`);
    writeFileSync(join(dir, "anhang.bin"), randomBytes(2048));
    await importKpxcAttachment(originalPath, PASSWORD, "Privat/Reich", "anhang.bin", join(dir, "anhang.bin"));
    await importKpxcAttachment(originalPath, PASSWORD, "Privat/Mail", "gleich.bin", join(dir, "anhang.bin")); // gleicher Inhalt: ein Pool-Eintrag
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("der XML-Export ist bis auf _LAST_MODIFIED identisch; KeePassXC warnt nicht", async () => {
    const rewrittenPath = join(dir, "ownwarden.kdbx");
    const vault = await readKdbxFile(originalPath, PASSWORD);
    await writeKdbxFile(vault, rewrittenPath, PASSWORD);

    const original = await runKpxcOk(["export", "-q", "-f", "xml", originalPath], `${PASSWORD}\n`);
    const rewritten = await runKpxcOk(["export", "-q", "-f", "xml", rewrittenPath], `${PASSWORD}\n`);
    expect(rewritten.stderr).not.toMatch(KPXC_XML_WARNING);
    // Plausibilität: Der Export enthält wirklich, worum es geht.
    for (const needle of ["<DatabaseDescription>", "<CustomIcons>", "<DeletedObject>", "<History>", "<Association>", "Recycle Bin", "Geheimfrage"]) {
      expect(original.stdout).toContain(needle);
    }
    expect(normalizeExport(rewritten.stdout)).toBe(normalizeExport(original.stdout));
  });

  it("auch die Einstellungen der Datei bleiben (db-info)", async () => {
    const rewrittenPath = join(dir, "ownwarden-info.kdbx");
    await writeKdbxFile(await readKdbxFile(originalPath, PASSWORD), rewrittenPath, PASSWORD);
    // Weggelassen: "UUID" würfelt KeePassXC bei JEDEM Öffnen neu (zweimal db-info auf dieselbe
    // Datei zeigt zwei UUIDs), "Location" ist der Pfad, "Last saved" die Änderungszeit der Datei.
    const info = async (path: string) =>
      (await runKpxcOk(["db-info", "-q", path], `${PASSWORD}\n`)).stdout
        .split("\n")
        .filter((line) => !/^(UUID|Location|Last saved):/.test(line));
    const original = await info(originalPath);
    expect(original).toEqual(expect.arrayContaining(["Cipher: AES 256-bit", "Recycle bin is enabled."]));
    expect(await info(rewrittenPath)).toEqual(original);
  });
});
