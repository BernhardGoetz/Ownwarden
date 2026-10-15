/**
 * vaultsEquivalent: was als „inhaltlich gleich“ gilt (kein Schreiben nötig) und was nicht.
 */
import { describe, expect, it } from "vitest";
import { attachment, newEntry, newGroup, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import type { Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { vaultsEquivalent } from "./vault-equal";

/** Datenbank mit Gruppe, zwei Einträgen (einer mit Verlauf und Anhängen), Icon, CustomData und Lösch-Vermerken. */
function sample(): Vault {
  const history = newEntry({ uuid: uuidFromName("e1"), at: T0, title: "Alt" });
  const e1 = newEntry({
    uuid: uuidFromName("e1"),
    at: T0 + 5000,
    title: "Mail",
    fields: { Password: "geheim", Eigenes: "x" },
    attachments: [attachment("a.txt", "A"), attachment("b.txt", "B")],
    customData: new Map([
      ["Ownwarden.FieldTimes", { value: '{"v":1}' }],
      ["Farbe", { value: "rot" }],
    ]),
    history: [history],
    tags: ["b", "a"],
  });
  const e2 = newEntry({ uuid: uuidFromName("e2"), at: T0 + 6000, title: "Bank" });
  const sub = newGroup({ uuid: uuidFromName("g1"), name: "Sub", entries: [newEntry({ uuid: uuidFromName("e3"), title: "Tief" })] });
  return newVault({
    root: newGroup({ uuid: uuidFromName("root"), name: "Root", entries: [e1, e2], groups: [sub] }),
    meta: {
      customIcons: [
        { uuid: uuidFromName("i1"), data: new Uint8Array([1, 2]), lastModified: T0 },
        { uuid: uuidFromName("i2"), data: new Uint8Array([3]) },
      ],
      customData: new Map([["Meta", { value: "1", lastModified: T0 }]]),
    },
    deletedObjects: [
      { uuid: uuidFromName("weg1"), deletionTime: T0 },
      { uuid: uuidFromName("weg2"), deletionTime: T0 + 1000 },
    ],
  });
}

function entry(vault: Vault, index: number) {
  return vault.root.entries[index]!;
}

describe("vaultsEquivalent: gilt als gleich", () => {
  it("identische und kopierte Datenbanken", () => {
    const vault = sample();
    expect(vaultsEquivalent(vault, vault)).toBe(true);
    expect(vaultsEquivalent(vault, cloneVault(vault))).toBe(true);
  });

  it("Zeiten mit Millisekunden gegen dieselben Zeiten aus der Datei (ganze Sekunden)", () => {
    const inMemory = sample();
    const fromFile = cloneVault(inMemory);
    entry(inMemory, 0).times.lastModification += 999;
    entry(inMemory, 0).history[0]!.times.creation += 1;
    inMemory.root.groups[0]!.times.locationChanged += 500;
    inMemory.meta.databaseNameChanged += 1;
    inMemory.meta.customIcons[0]!.lastModified! += 10;
    inMemory.meta.customData.get("Meta")!.lastModified! += 10;
    inMemory.deletedObjects[0]!.deletionTime += 999;
    expect(vaultsEquivalent(inMemory, fromFile)).toBe(true);
  });

  it("andere Reihenfolge von Einträgen, Gruppen, Lösch-Vermerken, Icons, Anhängen und Map-Schlüsseln", () => {
    const a = sample();
    const b = cloneVault(a);
    b.root.entries.reverse();
    b.root.groups.reverse();
    b.deletedObjects.reverse();
    b.meta.customIcons.reverse();
    entry(b, 1).attachments.reverse(); // nach reverse() ist Eintrag 1 der „Mail“-Eintrag
    entry(b, 1).customData = new Map([...entry(b, 1).customData].reverse());
    entry(b, 1).strings = new Map([...entry(b, 1).strings].reverse());
    expect(vaultsEquivalent(a, b)).toBe(true);
  });

  it("neuer KDF-Salt, anderer Generator, _LAST_MODIFIED von KeePassXC", () => {
    const a = sample();
    const b = cloneVault(a);
    if (b.settings.kdf.type !== "aes") b.settings.kdf.salt = crypto.getRandomValues(new Uint8Array(32));
    b.meta.generator = "KeePassXC";
    entry(b, 0).customData.set("_LAST_MODIFIED", { value: "Thu Oct 15 2026" });
    b.root.customData.set("_LAST_MODIFIED", { value: "x" });
    b.meta.customData.set("_LAST_MODIFIED", { value: "y" });
    expect(vaultsEquivalent(a, b)).toBe(true);
  });

  it("AES-KDF: neuer Seed zählt nicht, andere Rundenzahl schon", () => {
    const a = sample();
    a.settings.kdf = { type: "aes", seed: new Uint8Array(32), rounds: 1000 };
    const b = cloneVault(a);
    b.settings.kdf = { type: "aes", seed: new Uint8Array(32).fill(7), rounds: 1000 };
    expect(vaultsEquivalent(a, b)).toBe(true);
    b.settings.kdf.rounds = 2000;
    expect(vaultsEquivalent(a, b)).toBe(false);
  });
});

describe("vaultsEquivalent: erkennt echte Unterschiede", () => {
  const changes: [string, (vault: Vault) => void][] = [
    ["Feldwert", (v) => entry(v, 0).strings.set("Password", { value: "anders", protected: true })],
    ["Schutz-Flag", (v) => entry(v, 0).strings.set("Password", { value: "geheim", protected: false })],
    ["neues Feld", (v) => entry(v, 0).strings.set("Neu", { value: "", protected: false })],
    ["Anhang-Bytes", (v) => (entry(v, 0).attachments[0] = attachment("a.txt", "anders"))],
    ["Anhang entfernt", (v) => entry(v, 0).attachments.pop()],
    ["Verlauf", (v) => entry(v, 0).history.pop()],
    ["Tags-Reihenfolge (Feldwert)", (v) => entry(v, 0).tags.reverse()],
    ["FieldTimes", (v) => entry(v, 0).customData.set("Ownwarden.FieldTimes", { value: '{"v":2}' })],
    ["Änderungszeit um eine Sekunde", (v) => (entry(v, 0).times.lastModification += 1000)],
    ["Eintrag in andere Gruppe", (v) => v.root.groups[0]!.entries.push(v.root.entries.pop()!)],
    ["Eintrag gelöscht", (v) => v.root.entries.pop()],
    ["Gruppenname", (v) => (v.root.groups[0]!.name = "Anders")],
    ["Lösch-Vermerk", (v) => v.deletedObjects.pop()],
    ["Icon-Bytes", (v) => (v.meta.customIcons[0]!.data = new Uint8Array([9]))],
    ["Datenbankname", (v) => (v.meta.databaseName = "Neu")],
    ["Verlaufsgrenze", (v) => (v.meta.historyMaxItems = 3)],
    ["unbekanntes Meta-Element", (v) => v.meta.unknown.push("<DatabaseDescription>x</DatabaseDescription>")],
    ["unbekanntes Root-Element", (v) => v.rootUnknown.push("<X/>")],
    ["Verschlüsselung", (v) => (v.settings.cipher = "chacha20")],
    ["KDF-Parameter", (v) => v.settings.kdf.type !== "aes" && (v.settings.kdf.iterations += 1)],
    ["KDBX-Version", (v) => (v.settings.versionMinor = 1)],
  ];

  it.each(changes)("%s", (_name, change) => {
    const a = sample();
    const b = cloneVault(a);
    change(b);
    expect(vaultsEquivalent(a, b)).toBe(false);
    expect(vaultsEquivalent(b, a)).toBe(false);
  });
});
