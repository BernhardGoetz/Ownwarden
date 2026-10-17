/**
 * Tests für vault-ops.ts (Bearbeiten mit korrekten Feld-Zeitstempeln) und clock.ts.
 */
import { describe, expect, it } from "vitest";
import { allEntries, newEntry, newGroup, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import { identityStream } from "../../test/fixtures/xml/fixtures";
import { FIELD_TIMES_KEY } from "../contracts";
import { parseVaultXml, serializeVaultXml } from "../kdbx/xml";
import { stripInvalidXmlChars } from "../kdbx/xml-dom";
import type { Entry, Vault } from "../model";
import { createVaultClock, latestVaultTime, VaultClock } from "./clock";
import { effectiveFieldTimes, type FieldTime } from "./field-times";
import { findEntryLocation } from "./tree";
import {
  createEntry,
  createGroup,
  deleteEntry,
  deleteGroup,
  editEntry,
  findEntry,
  findGroup,
  moveEntry,
  moveGroup,
  recycleEntry,
  removeAttachment,
  removeField,
  removePasskey,
  renameGroup,
  setAttachment,
  setField,
  setPasskey,
  setTags,
} from "./vault-ops";

/** Uhr mit fester Zeitquelle `time` (ms); `advance` stellt sie weiter. */
function fakeClock(vault: Vault, start = T0 + 10_000) {
  let time = start;
  const clock = new VaultClock(vault, () => time);
  return { clock, advance: (ms: number) => (time += ms) };
}

function setup() {
  const vault = newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root" }) });
  const { clock, advance } = fakeClock(vault);
  const bank = createGroup(vault, vault.root.uuid, "Bank", clock, { uuid: uuidFromName("bank") });
  const entry = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "alt" }, clock, { uuid: uuidFromName("e1") });
  return { vault, clock, advance, bank, entry };
}

const times = (vault: Vault, uuid: string): Record<string, FieldTime> => {
  const location = findEntryLocation(vault, uuid)!;
  return Object.fromEntries(effectiveFieldTimes(location.entry, location.group.uuid).times);
};

describe("Uhr", () => {
  it("liefert streng steigende Zeiten, auch wenn die Geräteuhr steht oder zurückspringt", () => {
    let source = 5000;
    const clock = new VaultClock(undefined, () => source);
    expect(clock.now()).toBe(5000);
    expect(clock.now()).toBe(5001);
    source = 1000;
    expect(clock.now()).toBe(5002);
    clock.observe(9000);
    expect(clock.now()).toBe(9001);
  });

  it("liegt immer über dem größten Zeitstempel der Datenbank (auch FieldTimes und Löschungen)", () => {
    const vault = newVault();
    const entry = newEntry({ at: T0 });
    entry.customData.set(FIELD_TIMES_KEY, { value: `{"v":1,"w":${T0},"f":{"s:Title":{"t":${T0 + 777},"h":"x"}}}` });
    entry.times.expiry = T0 + 10 ** 12; // Ablaufdatum zählt NICHT
    vault.root.entries.push(entry);
    expect(latestVaultTime(vault)).toBe(T0 + 777);
    vault.deletedObjects.push({ uuid: uuidFromName("x"), deletionTime: T0 + 900 });
    expect(createVaultClock(vault, () => 0).now()).toBe(T0 + 901);
  });
});

describe("Einträge bearbeiten", () => {
  it("createEntry legt Standardfelder an, schützt Password und versiegelt alle Felder mit „jetzt“", () => {
    const { vault, entry } = setup();
    expect([...entry.strings.keys()]).toEqual(["Title", "UserName", "Password", "URL", "Notes"]);
    expect(entry.strings.get("Password")).toEqual({ value: "alt", protected: true });
    const t = entry.times.lastModification;
    expect(times(vault, entry.uuid)).toEqual({
      "s:Title": { t, present: true },
      "s:UserName": { t, present: true },
      "s:Password": { t, present: true },
      parent: { t, present: true },
    });
    expect(() => createEntry(vault, vault.root.uuid, {}, createVaultClock(vault), { uuid: entry.uuid })).toThrow(/schon/);
  });

  it("setField: nur das geänderte Feld bekommt die neue Zeit; alte Fassung (ohne FieldTimes) in den Verlauf", () => {
    const { vault, entry, clock, advance } = setup();
    const created = entry.times.lastModification;
    advance(5000);
    const updated = setField(vault, entry.uuid, "Password", "neu", {}, clock);
    const now = updated.times.lastModification;
    expect(now).toBeGreaterThan(created);
    expect(updated.strings.get("Password")).toEqual({ value: "neu", protected: true });
    expect(times(vault, entry.uuid)["s:Password"]).toEqual({ t: now, present: true });
    expect(times(vault, entry.uuid)["s:UserName"]).toEqual({ t: created, present: true });
    expect(updated.history).toHaveLength(1);
    expect(updated.history[0]!.strings.get("Password")!.value).toBe("alt");
    expect(updated.history[0]!.customData.has(FIELD_TIMES_KEY)).toBe(false);
    expect(findEntry(vault, entry.uuid)).toBe(updated);

    // Unverändert -> keine neue Fassung, keine neue Zeit.
    const same = setField(vault, entry.uuid, "Password", "neu", {}, clock);
    expect(same).toBe(updated);
    expect(same.history).toHaveLength(1);
  });

  it("removeField setzt einen Lösch-Marker; Standardfelder bleiben leer bestehen", () => {
    const { vault, entry, clock } = setup();
    setField(vault, entry.uuid, "PIN", "1234", { protected: true }, clock);
    const pinRemovedAt = removeField(vault, entry.uuid, "PIN", clock).times.lastModification;
    const afterUser = removeField(vault, entry.uuid, "UserName", clock);
    expect(afterUser).toBe(entry); // dasselbe Objekt, in place geändert
    expect(afterUser.strings.has("PIN")).toBe(false);
    expect(afterUser.strings.get("UserName")).toEqual({ value: "", protected: false });
    const t = times(vault, entry.uuid);
    expect(t["s:PIN"]).toEqual({ t: pinRemovedAt, present: false });
    expect(t["s:UserName"]).toEqual({ t: afterUser.times.lastModification, present: false });
  });

  it("Passkey-Attribute nur über setPasskey (als Einheit, mit Tag Passkey)", () => {
    const { vault, entry, clock } = setup();
    expect(() => setField(vault, entry.uuid, "KPEX_PASSKEY_USERNAME", "x", {}, clock)).toThrow(/setPasskey/);
    expect(() => setPasskey(vault, entry.uuid, { Title: "x" }, clock)).toThrow(/kein Passkey-Attribut/);
    setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "a", KPEX_PASSKEY_USER_HANDLE: "h", KPEX_PASSKEY_PRIVATE_KEY_PEM: "pem" }, clock);
    const replaced = setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "b", KPEX_PASSKEY_PRIVATE_KEY_PEM: "pem2" }, clock);
    expect([...replaced.strings.keys()].filter((k) => k.startsWith("KPEX"))).toEqual(["KPEX_PASSKEY_USERNAME", "KPEX_PASSKEY_PRIVATE_KEY_PEM"]);
    expect(replaced.strings.get("KPEX_PASSKEY_PRIVATE_KEY_PEM")!.protected).toBe(true);
    expect(replaced.tags).toEqual(["Passkey"]);
    expect(times(vault, entry.uuid).passkey).toEqual({ t: replaced.times.lastModification, present: true });
    const removed = removePasskey(vault, entry.uuid, clock);
    expect([...removed.strings.keys()].some((k) => k.startsWith("KPEX"))).toBe(false);
    expect(removed.tags).toEqual([]);
    expect(times(vault, entry.uuid).passkey).toEqual({ t: removed.times.lastModification, present: false });
  });

  it("Anhänge: Bytes werden kopiert, gleicher Inhalt ist keine Änderung", () => {
    const { vault, entry, clock } = setup();
    const data = Uint8Array.of(1, 2, 3);
    const first = setAttachment(vault, entry.uuid, "a.bin", data, {}, clock);
    data[0] = 99; // Aufrufer ändert sein Array später – der Eintrag nicht
    expect([...first.attachments[0]!.data]).toEqual([1, 2, 3]);
    expect(first.attachments[0]!.protected).toBe(true);
    expect(setAttachment(vault, entry.uuid, "a.bin", Uint8Array.of(1, 2, 3), {}, clock)).toBe(first);
    const removed = removeAttachment(vault, entry.uuid, "a.bin", clock);
    expect(removed.attachments).toEqual([]);
    expect(times(vault, entry.uuid)["a:a.bin"]!.present).toBe(false);
  });

  it("setTags bereinigt Tags und lehnt Trennzeichen ab", () => {
    const { vault, entry, clock } = setup();
    expect(setTags(vault, entry.uuid, [" Bank ", "Privat", "Bank", ""], clock).tags).toEqual(["Bank", "Privat"]);
    expect(() => setTags(vault, entry.uuid, ["a,b"], clock)).toThrow(/","/);
    expect(() => setTags(vault, entry.uuid, ["a;b"], clock)).toThrow();
  });

  it("editEntry erkennt jede Feldänderung selbst (z. B. Icon, Ablauf, CustomData)", () => {
    const { vault, entry, clock } = setup();
    const edited = editEntry(
      vault,
      entry.uuid,
      (draft) => {
        draft.iconId = 7;
        draft.times.expires = true;
        draft.times.expiry = T0 + 99_000;
        draft.customData.set("Typ", { value: "karte" });
        draft.times.lastModification = 0; // wird von editEntry überschrieben
      },
      clock,
    );
    const t = edited.times.lastModification;
    expect(t).toBeGreaterThan(T0);
    expect(edited.times.expiry).toBe(T0 + 99_000);
    const fieldTimes = times(vault, entry.uuid);
    expect(fieldTimes.icon).toEqual({ t, present: true });
    expect(fieldTimes.expiry).toEqual({ t, present: true });
    expect(fieldTimes["cd:Typ"]).toEqual({ t, present: true });
    expect(fieldTimes["s:Title"]!.t).toBeLessThan(t);
  });

  it("übernimmt beim Bearbeiten eine Änderung, die KeePassXC inzwischen gemacht hat", () => {
    const { vault, entry, clock, advance } = setup();
    // „KeePassXC“: ändert den Benutzernamen, ohne FieldTimes anzufassen.
    entry.strings.set("UserName", { value: "kpxc", protected: false });
    entry.times.lastModification = T0 + 20_000;
    advance(30_000);
    const updated = setField(vault, entry.uuid, "Password", "neu", {}, clock);
    const t = times(vault, entry.uuid);
    expect(t["s:UserName"]).toEqual({ t: T0 + 20_000, present: true });
    expect(t["s:Password"]).toEqual({ t: updated.times.lastModification, present: true });
    expect(effectiveFieldTimes(updated, vault.root.uuid).externallyEdited).toBe(false); // neu versiegelt
  });

  it("hält die Verlaufsgrenzen der Datei ein", () => {
    const { vault, entry, clock } = setup();
    vault.meta.historyMaxItems = 2;
    for (const value of ["1", "2", "3", "4"]) setField(vault, entry.uuid, "Password", value, {}, clock);
    const current = findEntry(vault, entry.uuid)!;
    expect(current.history.map((h) => h.strings.get("Password")!.value)).toEqual(["2", "3"]);
  });

  it("moveEntry: Feld parent und locationChanged = jetzt, kein Verlaufseintrag", () => {
    const { vault, entry, clock, bank } = setup();
    const moved = moveEntry(vault, entry.uuid, bank.uuid, clock);
    expect(bank.entries).toEqual([moved]);
    expect(vault.root.entries).toEqual([]);
    expect(moved.history).toEqual([]);
    expect(moved.times.locationChanged).toBe(moved.times.lastModification);
    expect(times(vault, entry.uuid).parent).toEqual({ t: moved.times.locationChanged, present: true });
    expect(moveEntry(vault, entry.uuid, bank.uuid, clock)).toBe(moved);
  });

  it("deleteEntry: Eintrag weg, Lösch-Vermerk neuer als jede Änderung", () => {
    const { vault, entry, clock } = setup();
    entry.times.lastModification = T0 + 500_000; // Zeit „aus der Zukunft“ eines anderen Geräts
    deleteEntry(vault, entry.uuid, clock);
    expect(findEntry(vault, entry.uuid)).toBeUndefined();
    expect(vault.deletedObjects).toEqual([{ uuid: entry.uuid, deletionTime: T0 + 500_001 }]);
  });

  it("recycleEntry: erst in den Papierkorb (wird angelegt), dort dann endgültig löschen", () => {
    const { vault, entry, clock } = setup();
    expect(recycleEntry(vault, entry.uuid, clock)).toBe(true);
    const bin = findGroup(vault, vault.meta.recycleBinUuid)!;
    expect(bin.name).toBe("Papierkorb");
    expect(bin.entries.map((e) => e.uuid)).toEqual([entry.uuid]);
    expect(recycleEntry(vault, entry.uuid, clock)).toBe(false);
    expect(findEntry(vault, entry.uuid)).toBeUndefined();
    expect(vault.deletedObjects.map((d) => d.uuid)).toEqual([entry.uuid]);
  });
});

describe("Gruppen bearbeiten", () => {
  it("renameGroup/moveGroup setzen lastModification bzw. locationChanged", () => {
    const { vault, clock, bank } = setup();
    const sub = createGroup(vault, vault.root.uuid, "Sub", clock);
    const renamed = renameGroup(vault, bank.uuid, "Banken", clock);
    expect(renamed.name).toBe("Banken");
    expect(renamed.times.lastModification).toBeGreaterThan(renamed.times.creation);
    moveGroup(vault, sub.uuid, bank.uuid, clock);
    expect(bank.groups).toEqual([sub]);
    expect(sub.times.locationChanged).toBeGreaterThan(sub.times.creation);
    expect(() => moveGroup(vault, bank.uuid, sub.uuid, clock)).toThrow(/in sich selbst/);
    expect(() => moveGroup(vault, vault.root.uuid, bank.uuid, clock)).toThrow(/Wurzel/);
  });

  it("deleteGroup: Lösch-Vermerke für die Gruppe und alles darin", () => {
    const { vault, clock, bank, entry } = setup();
    const sub = createGroup(vault, bank.uuid, "Sub", clock);
    moveEntry(vault, entry.uuid, sub.uuid, clock);
    const other: Entry = createEntry(vault, bank.uuid, { Title: "x" }, clock);
    deleteGroup(vault, bank.uuid, clock);
    expect(findGroup(vault, bank.uuid)).toBeUndefined();
    expect(allEntries(vault)).toEqual([]);
    expect(vault.deletedObjects.map((d) => d.uuid).sort()).toEqual([bank.uuid, sub.uuid, entry.uuid, other.uuid].sort());
    expect(() => deleteGroup(vault, vault.root.uuid, clock)).toThrow(/Wurzel/);
  });
});

describe("UUIDs", () => {
  it("Gruppen und Einträge teilen sich einen Namensraum: keine UUID doppelt (mergeVaults lehnt doppelte ab)", () => {
    const { vault, clock, bank, entry } = setup();
    expect(() => createEntry(vault, vault.root.uuid, { Title: "x" }, clock, { uuid: bank.uuid })).toThrow(/Gruppe mit der UUID/);
    expect(() => createEntry(vault, vault.root.uuid, { Title: "x" }, clock, { uuid: vault.root.uuid })).toThrow(/Gruppe mit der UUID/);
    expect(() => createGroup(vault, vault.root.uuid, "G", clock, { uuid: entry.uuid })).toThrow(/Eintrag mit der UUID/);
    expect(() => createEntry(vault, vault.root.uuid, { Title: "x" }, clock, { uuid: entry.uuid })).toThrow(/Eintrag mit der UUID/);
  });
});

describe("Zeichen, die KDBX nicht speichern kann (Review kdbx-2)", () => {
  /** Speichern und Laden über XML. */
  const saveAndLoad = (vault: Vault): Vault => {
    const { xml, binaries } = serializeVaultXml(vault, identityStream());
    return parseVaultXml(xml, binaries, identityStream(), vault.settings);
  };

  it("lehnt in ungeschütztem Text genau die Zeichen ab, die der Writer entfernen würde", () => {
    const { vault, clock, bank } = setup();
    const wrong: string[] = [];
    const check = (text: string, label: string): void => {
      let rejected = false;
      try {
        renameGroup(vault, bank.uuid, text, clock);
      } catch (error) {
        expect(error).toBeInstanceOf(RangeError);
        rejected = true;
      }
      if (rejected !== (stripInvalidXmlChars(text) !== text)) wrong.push(label);
    };
    for (let code = 0; code < 0x10000; code++) check(`a${String.fromCharCode(code)}b`, `U+${code.toString(16)}`);
    check("a😀b", "Surrogat-Paar");
    check("a\uDE00\uD83Db", "Surrogat-Paar verkehrt herum");
    check("\uD83D", "hohes Surrogat am Ende");
    check("\uDE00a", "tiefes Surrogat am Anfang");
    expect(wrong).toEqual([]);
  });

  it("geschützte Werte: nur einzelne Surrogate werden abgelehnt (genau die, die UTF-8 nicht kennt); Steuerzeichen bleiben erhalten", () => {
    const { vault, entry, clock } = setup();
    for (const value of ["a\u0001b", "a\u000Bb", "a￾b", "a😀b", "a\uD800b", "a\uDC00b", "\uD800"]) {
      const lost = new TextDecoder().decode(new TextEncoder().encode(value)) !== value;
      const attempt = () => setField(vault, entry.uuid, "Password", value, { protected: true }, clock);
      if (lost) expect(attempt, JSON.stringify(value)).toThrow(RangeError);
      else expect(attempt, JSON.stringify(value)).not.toThrow();
    }
    setField(vault, entry.uuid, "Password", "Zeile1\u000BZeile2", { protected: true }, clock);
    expect(findEntry(saveAndLoad(vault), entry.uuid)!.strings.get("Password")).toEqual({ value: "Zeile1\u000BZeile2", protected: true });
  });

  it("jeder Weg ins Modell lehnt ab, ohne etwas zu verändern; die Meldung nennt den Wert nicht", () => {
    const { vault, entry, clock, bank } = setup();
    const before = structuredClone(vault);
    const attempts: [string, () => unknown][] = [
      ["createEntry: Wert", () => createEntry(vault, vault.root.uuid, { Title: "geheim\u000B" }, clock)],
      ["createEntry: geschützter Wert", () => createEntry(vault, vault.root.uuid, { Title: "x", Password: "geheim\uD800" }, clock)],
      ["createEntry: Feldname", () => createEntry(vault, vault.root.uuid, { "PIN\u0001": "1" }, clock)],
      ["createEntry: Tag", () => createEntry(vault, vault.root.uuid, { Title: "x" }, clock, { tags: ["a\u0002b"] })],
      ["setField: Wert", () => setField(vault, entry.uuid, "Notes", "geheim\u0007", {}, clock)],
      ["setField: Feldname", () => setField(vault, entry.uuid, "Frage￿", "1", {}, clock)],
      ["setAttachment: Name", () => setAttachment(vault, entry.uuid, "a\u0000.txt", Uint8Array.of(1), {}, clock)],
      ["setTags", () => setTags(vault, entry.uuid, ["a￾b"], clock)],
      ["setPasskey: ungeschützter Wert", () => setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "geheim\u001F" }, clock)],
      ["editEntry: CustomData-Schlüssel", () => editEntry(vault, entry.uuid, (draft) => void draft.customData.set("k\u0003", { value: "v" }), clock)],
      ["editEntry: CustomData-Wert", () => editEntry(vault, entry.uuid, (draft) => void draft.customData.set("k", { value: "geheim\u0003" }), clock)],
      ["editEntry: OverrideURL", () => editEntry(vault, entry.uuid, (draft) => void (draft.overrideUrl = "cmd://geheim\u000C"), clock)],
      ["editEntry: Farbe", () => editEntry(vault, entry.uuid, (draft) => void (draft.foregroundColor = "#FF0000\u0008"), clock)],
      ["editEntry: Text-Feld", () => editEntry(vault, entry.uuid, (draft) => void draft.strings.set("UserName", { value: "geheim\uDBFF", protected: false }), clock)],
      ["createGroup", () => createGroup(vault, vault.root.uuid, "Bank\u000B", clock)],
      ["renameGroup", () => renameGroup(vault, bank.uuid, "Bank\u000B", clock)],
    ];
    for (const [label, attempt] of attempts) {
      expect(attempt, label).toThrow(RangeError);
      expect(attempt, label).toThrow(/KDBX nicht speichern/);
      try {
        attempt();
      } catch (error) {
        expect((error as Error).message, label).not.toContain("geheim");
      }
    }
    expect(vault).toEqual(before);
  });
});
