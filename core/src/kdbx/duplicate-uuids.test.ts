/**
 * Tests für doppelte UUIDs in EINER Datei (Review kdbx-1): Beim Lesen bekommt jedes spätere
 * Vorkommen eine abgeleitete UUID (duplicate-uuids.ts), damit beim Zusammenführen nichts
 * verloren geht. Den Abgleich über WebDAV prüft test/review/kdbx-1.test.ts.
 */
import { describe, expect, it } from "vitest";
import { identityStream, testUuid } from "../../test/fixtures/xml/fixtures";
import type { Entry, Group, KdbxSettings, Vault } from "../model";
import { utf8Decode, utf8Encode } from "./bytes";
import { deriveDuplicateUuid } from "./duplicate-uuids";
import { parseVaultXml, serializeVaultXml } from "./xml";

const SETTINGS: KdbxSettings = {
  versionMinor: 1,
  cipher: "aes256",
  compression: true,
  kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 2, memoryBytes: 1 << 26, iterations: 3, version: 0x13 },
};

const ROOT = testUuid(1);
const G = testUuid(2);
const X = testUuid(10);
/** Testvektoren (unabhängig mit Python hashlib nachgerechnet) – auch für die Kotlin-Fassung. */
const X_DUPLICATE_1 = "IRVzD02hLpXDl92SvdLBPw=="; // hex 2115730f4da12e95c397dd92bdd2c13f
const X_DUPLICATE_2 = "6I8NDDR350InJO1VUtSsrg=="; // hex e88f0d0c3477e7422724ed5552d4acae

function parse(xml: string): Vault {
  return parseVaultXml(utf8Encode(xml), [], identityStream(), SETTINGS);
}

/** Dokument mit Wurzelgruppe ROOT; `content` steht in der Wurzelgruppe, `root` daneben. */
function doc(content: string, root = ""): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile><Meta/><Root><Group><UUID>${ROOT}</UUID><Name>Root</Name>${content}</Group>${root}</Root></KeePassFile>`;
}

function entry(uuid: string, title: string, inner = ""): string {
  return `<Entry><UUID>${uuid}</UUID><String><Key>Title</Key><Value>${title}</Value></String>${inner}</Entry>`;
}

function group(uuid: string, name: string, inner = ""): string {
  return `<Group><UUID>${uuid}</UUID><Name>${name}</Name>${inner}</Group>`;
}

function history(...items: string[]): string {
  return `<History>${items.join("")}</History>`;
}

function deletedObject(uuid: string): string {
  return `<DeletedObjects><DeletedObject><UUID>${uuid}</UUID><DeletionTime>2026-01-01T00:00:00Z</DeletionTime></DeletedObject></DeletedObjects>`;
}

/** [Titel, UUID] aller aktuellen Einträge (Wurzel zuerst, dann Untergruppen). */
function entryUuids(vault: Vault): [string, string][] {
  const result: [string, string][] = [];
  const visit = (g: Group): void => {
    for (const e of g.entries) result.push([title(e), e.uuid]);
    g.groups.forEach(visit);
  };
  visit(vault.root);
  return result;
}

function title(e: Entry): string {
  return e.strings.get("Title")?.value ?? "";
}

describe("doppelte UUIDs beim Lesen (Review kdbx-1)", () => {
  it("Testvektor: erste 16 Byte von SHA-256(\"Ownwarden-Duplicate\" || UUID || k als uint32 LE)", () => {
    expect(deriveDuplicateUuid(X, 1)).toBe(X_DUPLICATE_1);
    expect(deriveDuplicateUuid(X, 2)).toBe(X_DUPLICATE_2);
  });

  it("doppelte Eintrags-UUID: das spätere Vorkommen bekommt die abgeleitete UUID, sein Verlauf folgt", () => {
    const vault = parse(doc(entry(X, "Bank") + group(G, "Sub", entry(X, "Mail", history(entry(X, "Mail alt"))))));
    expect(entryUuids(vault)).toEqual([
      ["Bank", X],
      ["Mail", X_DUPLICATE_1],
    ]);
    const mail = vault.root.groups[0]!.entries[0]!;
    expect(mail.history.map((item) => [title(item), item.uuid])).toEqual([["Mail alt", X_DUPLICATE_1]]);
  });

  it("es zählt die Dokumentreihenfolge: ein Eintrag NACH der Untergruppe ist das spätere Vorkommen", () => {
    const vault = parse(doc(group(G, "Sub", entry(X, "Mail")) + entry(X, "Bank")));
    expect(entryUuids(vault)).toEqual([
      ["Bank", X_DUPLICATE_1],
      ["Mail", X],
    ]);
  });

  it("Verlaufseinträge mit der UUID ihres Eintrags sind keine Duplikate", () => {
    const vault = parse(doc(entry(X, "Bank", history(entry(X, "v1"), entry(X, "v2")))));
    const bank = vault.root.entries[0]!;
    expect(bank.uuid).toBe(X);
    expect(bank.history.map((item) => item.uuid)).toEqual([X, X]);
  });

  it("drei Vorkommen: Zähler 1 und 2", () => {
    const vault = parse(doc(entry(X, "a") + entry(X, "b") + entry(X, "c")));
    expect(entryUuids(vault)).toEqual([
      ["a", X],
      ["b", X_DUPLICATE_1],
      ["c", X_DUPLICATE_2],
    ]);
  });

  it("schon vergebene Kandidaten (Eintrag oder Lösch-Vermerk) werden übersprungen", () => {
    // Datei schon einmal repariert, dann kam dieselbe UUID ein drittes Mal dazu.
    expect(entryUuids(parse(doc(entry(X, "a") + entry(X_DUPLICATE_1, "b") + entry(X, "c"))))).toEqual([
      ["a", X],
      ["b", X_DUPLICATE_1],
      ["c", X_DUPLICATE_2],
    ]);
    // Ein Lösch-Vermerk für den ersten Kandidaten darf den Eintrag nicht „löschen“.
    expect(entryUuids(parse(doc(entry(X, "a") + entry(X, "b"), deletedObject(X_DUPLICATE_1))))).toEqual([
      ["a", X],
      ["b", X_DUPLICATE_2],
    ]);
  });

  it("doppelte Gruppen-UUID: die spätere Gruppe bekommt eine neue UUID und behält ihren Inhalt", () => {
    const vault = parse(doc(group(G, "A", entry(testUuid(11), "a")) + group(G, "B", entry(testUuid(12), "b"))));
    expect(vault.root.groups.map((g) => [g.name, g.uuid, g.entries.map(title)])).toEqual([
      ["A", G, ["a"]],
      ["B", deriveDuplicateUuid(G, 1), ["b"]],
    ]);
  });

  it("eine Untergruppe mit der UUID der Wurzel wird umbenannt", () => {
    const vault = parse(doc(group(ROOT, "Sub", entry(X, "a"))));
    expect(vault.root.uuid).toBe(ROOT);
    expect(vault.root.groups[0]!.uuid).toBe(deriveDuplicateUuid(ROOT, 1));
    expect(vault.root.groups[0]!.entries.map(title)).toEqual(["a"]);
  });

  it("Gruppen und Einträge teilen sich einen Namensraum (wie bei KeePass)", () => {
    const vault = parse(doc(group(G, "Sub", entry(G, "a"))));
    expect(vault.root.groups[0]!.uuid).toBe(G);
    expect(vault.root.groups[0]!.entries[0]!.uuid).toBe(deriveDuplicateUuid(G, 1));
  });

  it("jedes Lesen derselben Datei ergibt dieselben UUIDs; nach dem Speichern ist die Datei repariert", () => {
    const xml = doc(entry(X, "Bank") + group(G, "Sub", entry(X, "Mail")));
    const first = parse(xml);
    expect(parse(xml)).toEqual(first);

    const saved = serializeVaultXml(first, identityStream());
    expect(utf8Decode(saved.xml)).toContain(`<UUID>${X_DUPLICATE_1}</UUID>`);
    expect(parseVaultXml(saved.xml, saved.binaries, identityStream(), SETTINGS)).toEqual(first);
  });

  it("eine Datei ohne doppelte UUIDs bleibt unverändert", () => {
    const vault = parse(doc(entry(X, "a") + group(G, "Sub", entry(testUuid(11), "b")), deletedObject(testUuid(12))));
    expect(entryUuids(vault)).toEqual([
      ["a", X],
      ["b", testUuid(11)],
    ]);
    expect(vault.root.groups[0]!.uuid).toBe(G);
  });
});
