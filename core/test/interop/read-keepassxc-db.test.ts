/**
 * Integration (a): Eine Datenbank, die KeePassXC 2.7.6 gebaut und gespeichert hat, liest
 * Ownwarden über die öffentliche Funktion readKdbx vollständig und richtig.
 *
 * KeePassXC baut: Gruppen, mehrere Einträge, eigene Felder (geschützt und ungeschützt),
 * Anhänge (attachment-import, auch Binärdaten), einen Eintrag mit Verlauf (zweimal geändert)
 * und einen gelöschten Eintrag (rm = in den Papierkorb).
 *
 * Bereits vorhandene, verwandte Tests (nicht doppelt geprüft):
 *   src/kdbx/xml.interop.test.ts       Gruppen, Einträge, Anhänge, ein Verlaufseintrag (über die Einzelbausteine)
 *   src/kdbx/container.interop.test.ts Container, KDF-Varianten, große Anhänge
 * Neu hier: eigene Felder mit/ohne Schutz, zwei Verlaufseinträge, Papierkorb, alles über readKdbx.
 *
 * Eigene Felder kann keepassxc-cli nicht anlegen; sie kommen über `keepassxc-cli import`
 * (KeePassXC liest die XML und schreibt die Datei selbst). Wird übersprungen ohne keepassxc-cli.
 */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  addKpxcEntry,
  createTmpDir,
  hasKeepassxc,
  importKpxcAttachment,
  importKpxcXml,
  mkdirKpxc,
  removeTmpDir,
  runKpxcOk,
} from "../helpers/keepassxc";
import { entriesWithPaths, entryAt, readKdbxFile } from "../helpers/kdbx-files";
import { effectiveFieldTimes } from "../../src/merge/field-times";
import type { Vault } from "../../src/model";

const PASSWORD = "Interop-a-äöü";
const SCAN = new Uint8Array(randomBytes(5000)); // Binärdaten inkl. 0x00 und ungültigem UTF-8
const NOTE = "Notiz äöü\nzweite Zeile\n";
const b64 = () => randomBytes(16).toString("base64");

/** XML für `keepassxc-cli import`: Wurzel mit CustomData (erzwingt KDBX 4), Gruppe "Bank", Eintrag mit eigenen Feldern. */
function importXml(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>Ownwarden-Test</Generator>
    <DatabaseName>KeePassXC-Tresor</DatabaseName>
    <RecycleBinEnabled>True</RecycleBinEnabled>
  </Meta>
  <Root>
    <Group>
      <UUID>${b64()}</UUID>
      <Name>Root</Name>
      <CustomData><Item><Key>Ownwarden.Test</Key><Value>kdbx4</Value></Item></CustomData>
      <Group>
        <UUID>${b64()}</UUID>
        <Name>Bank</Name>
        <Entry>
          <UUID>${b64()}</UUID>
          <String><Key>Title</Key><Value>Giro</Value></String>
          <String><Key>UserName</Key><Value>bob</Value></String>
          <String><Key>Password</Key><Value ProtectInMemory="True">giro-geheim</Value></String>
          <String><Key>PIN</Key><Value ProtectInMemory="True">4711</Value></String>
          <String><Key>Kontonummer</Key><Value>DE00 1234 5678</Value></String>
        </Entry>
      </Group>
    </Group>
    <DeletedObjects/>
  </Root>
</KeePassFile>
`;
}

describe.skipIf(!hasKeepassxc())("Integration (a): KeePassXC baut, Ownwarden liest (readKdbx)", () => {
  let dir: string;
  let vault: Vault;

  beforeAll(async () => {
    dir = createTmpDir("interop-a");
    const path = join(dir, "keepassxc.kdbx");
    await importKpxcXml(importXml(), path, PASSWORD);
    await mkdirKpxc(path, PASSWORD, "Mail");
    await addKpxcEntry(path, PASSWORD, "Mail/Web-Mail", { username: "alice", password: "mail-pw äöü", url: "https://mail.example" });
    await addKpxcEntry(path, PASSWORD, "Forum", { username: "u0", password: "p0" });
    await runKpxcOk(["edit", "-q", "-u", "u1", path, "Forum"], `${PASSWORD}\n`);
    await runKpxcOk(["edit", "-q", "--url", "https://forum.example", path, "Forum"], `${PASSWORD}\n`);
    await addKpxcEntry(path, PASSWORD, "Alt", { username: "weg" });
    await runKpxcOk(["rm", "-q", path, "Alt"], `${PASSWORD}\n`); // Papierkorb ist an: nur verschieben
    writeFileSync(join(dir, "scan.bin"), SCAN);
    writeFileSync(join(dir, "notiz.txt"), NOTE);
    await importKpxcAttachment(path, PASSWORD, "Bank/Giro", "scan.bin", join(dir, "scan.bin"));
    await importKpxcAttachment(path, PASSWORD, "Bank/Giro", "notiz.txt", join(dir, "notiz.txt"));
    vault = await readKdbxFile(path, PASSWORD);
  });

  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("Gruppen und Einträge an der richtigen Stelle (gelöschter Eintrag im Papierkorb)", () => {
    expect(vault.meta.databaseName).toBe("KeePassXC-Tresor");
    expect(vault.root.groups.map((group) => group.name).sort()).toEqual(["Bank", "Mail", "Recycle Bin"]);
    expect(entriesWithPaths(vault).map((item) => item.path).sort()).toEqual(["Bank/Giro", "Forum", "Mail/Web-Mail", "Recycle Bin/Alt"]);

    // Papierkorb: KeePassXC hat ihn beim ersten rm angelegt und in Meta eingetragen.
    const bin = vault.root.groups.find((group) => group.name === "Recycle Bin")!;
    expect(vault.meta.recycleBinEnabled).toBe(true);
    expect(vault.meta.recycleBinUuid).toBe(bin.uuid);
    // Verschieben in den Papierkorb ist keine Löschung (PROJECT-CONTEXT, „Papierkorb“).
    expect(vault.deletedObjects).toEqual([]);
  });

  it("eigene Felder mit und ohne Schutz, Standardfelder, Anhänge byte-genau", () => {
    const { entry } = entryAt(vault, "Bank/Giro");
    expect(entry.strings.get("UserName")).toEqual({ value: "bob", protected: false });
    expect(entry.strings.get("Password")).toEqual({ value: "giro-geheim", protected: true });
    expect(entry.strings.get("PIN")).toEqual({ value: "4711", protected: true });
    expect(entry.strings.get("Kontonummer")).toEqual({ value: "DE00 1234 5678", protected: false });
    // KeePassXC sortiert Anhänge nach Namen und markiert sie als geschützt.
    expect(entry.attachments.map((a) => [a.name, a.protected])).toEqual([
      ["notiz.txt", true],
      ["scan.bin", true],
    ]);
    expect(new TextDecoder().decode(entry.attachments[0]!.data)).toBe(NOTE);
    expect(Buffer.from(entry.attachments[1]!.data).equals(Buffer.from(SCAN))).toBe(true);

    const mail = entryAt(vault, "Mail/Web-Mail").entry;
    expect(mail.strings.get("Password")).toEqual({ value: "mail-pw äöü", protected: true });
    expect(mail.strings.get("URL")?.value).toBe("https://mail.example");
  });

  it("Eintrag mit Verlauf: zwei frühere Fassungen, älteste zuerst", () => {
    const { entry, group } = entryAt(vault, "Forum");
    expect(entry.strings.get("UserName")?.value).toBe("u1");
    expect(entry.strings.get("URL")?.value).toBe("https://forum.example");
    expect(entry.history).toHaveLength(2);
    expect(entry.history.map((old) => [old.strings.get("UserName")?.value, old.strings.get("URL")?.value])).toEqual([
      ["u0", ""],
      ["u1", ""],
    ]);
    expect(entry.history[0]!.strings.get("Password")).toEqual({ value: "p0", protected: true });
    // Ohne Ownwarden.FieldTimes: Feld-Zeiten kommen aus Eintragszeit und Verlauf.
    expect(effectiveFieldTimes(entry, group.uuid).sealed).toBe(false);
  });
});
