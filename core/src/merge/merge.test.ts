/**
 * Einzeltests für mergeVaults, die über die sprachneutralen Testfälle (spec-cases.test.ts)
 * hinausgehen: Meta, Icons, doppelte UUIDs, verschiedene Wurzeln, Wiederherstellungsgruppe,
 * Verlaufsgröße, _LAST_MODIFIED, Bericht.
 */
import { describe, expect, it } from "vitest";
import { allGroups, newEntry, newGroup, newVault, secret, T0, uuidFromName } from "../../test/helpers/vault-builder";
import { FIELD_TIMES_KEY } from "../contracts";
import type { Entry, Group, Vault } from "../model";
import { cloneVault } from "./clone";
import { effectiveFieldTimes, sealFieldTimes } from "./field-times";
import { approximateSize, mergeHistory, truncateHistory } from "./history";
import { mergeVaults, RECOVERY_GROUP_NAME, RECOVERY_GROUP_UUID } from "./merge";

const NOW = T0 + 1_000_000;
const u = uuidFromName;

/** Eintrag, von Ownwarden versiegelt (alle Felder zur Zeit `at`, sofern nicht anders angegeben). */
function sealedEntry(name: string, at: number, fields: Record<string, string>, fieldTimes: Record<string, number> = {}, parent = u("root")): Entry {
  const entry = newEntry({ uuid: u(name), at, fields });
  sealFieldTimes(entry, new Map(Object.entries(fieldTimes).map(([k, t]) => [k, { t, present: true }])), parent);
  return entry;
}

function vaultWith(entries: Entry[], groups: Group[] = [], extra: Partial<Vault> = {}): Vault {
  return { ...newVault({ root: newGroup({ uuid: u("root"), name: "Root", at: T0, entries, groups }) }), ...extra };
}

describe("mergeVaults – Einzelfälle", () => {
  it("doppelte UUID innerhalb EINER Datenbank: Programmfehler, mergeVaults bricht ab statt still zusammenzulegen", () => {
    // Früher wurden die Vorkommen zusammengeführt – bei vollem Verlauf ging dabei eines samt
    // Passwort verloren (Review kdbx-1). Der KDBX-Leser vergibt doppelten UUIDs jetzt neue.
    const g = newGroup({ uuid: u("g"), name: "G", at: T0 });
    const first = sealedEntry("dup", T0 + 1000, { Title: "A", UserName: "alt" }, { "s:UserName": T0 + 1000, "s:Title": T0 });
    const second = sealedEntry("dup", T0 + 2000, { Title: "A", Password: "neu" }, { "s:Password": T0 + 2000, "s:Title": T0 }, u("g"));
    g.entries.push(second);
    const broken = vaultWith([first], [g]);
    const fine = vaultWith([sealedEntry("dup", T0, { Title: "A" })]);
    expect(() => mergeVaults(broken, fine, { now: NOW })).toThrow(/kommt in local mehrfach vor/);
    expect(() => mergeVaults(fine, broken, { now: NOW })).toThrow(/kommt in remote mehrfach vor/);
  });

  it("verschiedene Wurzel-UUIDs gelten als dieselbe Wurzel (kleinere UUID gewinnt, beide Richtungen)", () => {
    const a = vaultWith([sealedEntry("e1", T0, { Title: "A" })]);
    const b = vaultWith([sealedEntry("e2", T0, { Title: "B" }, {}, u("andere-wurzel"))]);
    b.root.uuid = u("andere-wurzel");
    for (const [x, y] of [[a, b], [b, a]] as const) {
      const { vault } = mergeVaults(x, y, { now: NOW });
      expect(vault.root.uuid).toBe([u("root"), u("andere-wurzel")].sort()[0]);
      expect(vault.root.entries.map((e) => e.strings.get("Title")?.value).sort()).toEqual(["A", "B"]);
      expect(allGroups(vault)).toHaveLength(1);
    }
  });

  it("Meta: Icons vereinigt; gelöschte fallen weg, außer sie werden benutzt; CustomData nach Zeit; Version max", () => {
    const icon = (name: string, lastModified?: number) => ({ uuid: u(name), data: new TextEncoder().encode(name), ...(lastModified ? { lastModified } : {}) });
    const user = sealedEntry("e1", T0, { Title: "mit Icon" });
    user.customIconUuid = u("benutzt");
    const a = vaultWith([user]);
    // Icon-Zeiten zählen in ganzen Sekunden (wie alle KDBX-Zeiten).
    a.meta.customIcons = [icon("benutzt"), icon("geloescht"), icon("beide", T0 + 1000)];
    a.meta.customData = new Map([["k", { value: "alt", lastModified: T0 }], ["nur-a", { value: "1" }]]);
    a.settings.versionMinor = 0;
    a.deletedObjects = [{ uuid: u("geloescht"), deletionTime: T0 + 5000 }, { uuid: u("benutzt"), deletionTime: T0 + 5000 }];
    const b = vaultWith([cloneVault(a).root.entries[0]!]);
    b.meta.customIcons = [{ ...icon("beide", T0 + 2000), data: Uint8Array.of(7) }, icon("nur-b")];
    b.meta.customData = new Map([["k", { value: "neu", lastModified: T0 + 1000 }]]);
    b.settings.versionMinor = 1;

    const { vault } = mergeVaults(a, b, { now: NOW });
    expect(vault.meta.customIcons.map((i) => i.uuid)).toEqual([u("benutzt"), u("beide"), u("nur-b")]);
    expect([...vault.meta.customIcons[1]!.data]).toEqual([7]); // neuere LastModificationTime
    expect(vault.deletedObjects).toEqual([{ uuid: u("geloescht"), deletionTime: T0 + 5000 }]);
    expect(vault.meta.customData.get("k")?.value).toBe("neu");
    expect(vault.meta.customData.get("nur-a")?.value).toBe("1");
    expect(vault.settings.versionMinor).toBe(1);
    expect(vault.meta.generator).toBe("Ownwarden");
  });

  it("Wiederherstellungsgruppe: feste UUID, wird wiederverwendet und nach früherer Löschung neu angelegt", () => {
    expect(atob(RECOVERY_GROUP_UUID)).toBe("OwnwardenRecover");
    const bank = newGroup({ uuid: u("bank"), name: "Bank", at: T0 });
    const orphan = (name: string, at: number) => sealedEntry(name, at, { Title: name }, {}, u("bank"));
    const offline = vaultWith([], [{ ...bank, entries: [orphan("e1", T0 + 1000)] }]);
    const deleter = vaultWith([], [], {
      deletedObjects: [
        { uuid: u("bank"), deletionTime: T0 + 5000 },
        { uuid: RECOVERY_GROUP_UUID, deletionTime: NOW + 7000 }, // früher gelöscht, Uhr ging vor
      ],
    });
    const first = mergeVaults(offline, deleter, { now: NOW });
    const recovery = first.vault.root.groups.find((g) => g.uuid === RECOVERY_GROUP_UUID)!;
    expect(recovery.name).toBe(RECOVERY_GROUP_NAME);
    expect(recovery.times.creation).toBe(NOW + 8000); // nach der Löschung (ganze Sekunde danach)
    expect(recovery.entries.map((e) => e.uuid)).toEqual([u("e1")]);
    expect(first.vault.deletedObjects.map((d) => d.uuid)).toEqual([u("bank")]);
    expect(first.report.orphansRecovered).toBe(1);

    // Ein zweites Gerät rettet später einen weiteren Eintrag: dieselbe Gruppe, keine zweite.
    const offline2 = vaultWith([], [{ ...bank, entries: [orphan("e2", T0 + 2000)] }]);
    const second = mergeVaults(first.vault, offline2, { now: NOW + 50_000 });
    const groups = second.vault.root.groups.filter((g) => g.name === RECOVERY_GROUP_NAME);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.entries.map((e) => e.uuid).sort()).toEqual([u("e1"), u("e2")].sort());
  });

  it("gelöschte Gruppe bleibt, wenn eine Untergruppe darin einen neueren Eintrag hat", () => {
    const sub = newGroup({ uuid: u("sub"), name: "Sub", at: T0, entries: [sealedEntry("neu", T0 + 9000, { Title: "neu" }, {}, u("sub"))] });
    const kept = vaultWith([], [newGroup({ uuid: u("g"), name: "G", at: T0, groups: [sub] })]);
    const deleter = vaultWith([], [], { deletedObjects: [{ uuid: u("g"), deletionTime: T0 + 5000 }, { uuid: u("sub"), deletionTime: T0 + 5000 }] });
    const { vault } = mergeVaults(deleter, kept, { now: NOW });
    expect(vault.root.groups.map((g) => g.name)).toEqual(["G"]);
    expect(vault.root.groups[0]!.groups[0]!.entries).toHaveLength(1);
    expect(vault.deletedObjects).toEqual([]);
  });

  it("_LAST_MODIFIED als einziger Unterschied: unverändert übernehmen (ohne _LAST_MODIFIED), kein Konflikt", () => {
    const entry = sealedEntry("e1", T0, { Title: "A" });
    const a = vaultWith([entry]);
    const b = cloneVault(a);
    b.root.entries[0]!.customData.set("_LAST_MODIFIED", { value: "Thu Oct 15 11:11:11 2026 GMT" });
    const { vault, report } = mergeVaults(a, b, { now: NOW });
    expect(vault.root.entries[0]!.customData.has("_LAST_MODIFIED")).toBe(false);
    expect(vault.root.entries[0]!.customData.get(FIELD_TIMES_KEY)).toEqual(entry.customData.get(FIELD_TIMES_KEY));
    expect(report.fieldConflicts).toEqual([]);
    expect(report.entriesUpdated).toBe(0);
  });

  it("Bericht: Konflikte mit Gleichstand-Kennzeichen und extern geänderte Einträge", () => {
    const a = vaultWith([sealedEntry("e1", T0 + 2000, { Title: "A", Password: "x" }, { "s:Password": T0 + 2000, "s:Title": T0 })]);
    const b = vaultWith([sealedEntry("e1", T0 + 2000, { Title: "A", Password: "y" }, { "s:Password": T0 + 2000, "s:Title": T0 })]);
    b.root.entries[0]!.strings.set("Title", { value: "extern", protected: false }); // „KeePassXC“
    b.root.entries[0]!.times.lastModification = T0 + 3000;
    const { report, vault } = mergeVaults(a, b, { now: NOW });
    expect(report.fieldConflicts).toEqual([
      { entryUuid: u("e1"), field: "s:Title", winner: "remote", tieBreak: false },
      { entryUuid: u("e1"), field: "s:Password", winner: "remote", tieBreak: true },
    ]);
    expect(report.externalEdits).toEqual([u("e1")]);
    const merged = vault.root.entries[0]!;
    expect(merged.strings.get("Password")?.value).toBe("y");
    expect(effectiveFieldTimes(merged, u("root")).externallyEdited).toBe(false); // neu versiegelt
  });

  it("geschützte Werte bleiben geschützt; Anhang-Bytes werden geteilt, nicht verändert", () => {
    const data = Uint8Array.of(1, 2, 3);
    const a = vaultWith([sealedEntry("e1", T0, { Title: "A", Pin: "1" })]);
    a.root.entries[0]!.strings.set("Pin", secret("1"));
    a.root.entries[0]!.attachments.push({ name: "x", data, protected: true });
    sealFieldTimes(a.root.entries[0]!, new Map(), u("root"));
    const b = cloneVault(a);
    b.root.entries[0]!.strings.set("Title", { value: "B", protected: false });
    b.root.entries[0]!.times.lastModification = T0 + 5000;
    const { vault } = mergeVaults(a, b, { now: NOW });
    expect(vault.root.entries[0]!.strings.get("Pin")).toEqual(secret("1"));
    expect(vault.root.entries[0]!.attachments[0]!.data).toBe(data);
    expect([...data]).toEqual([1, 2, 3]);
  });
});

describe("Verlauf", () => {
  const item = (title: string, at: number, size = 0): Entry =>
    newEntry({ uuid: u("h"), at, fields: { Title: title, ...(size > 0 ? { Notes: "x".repeat(size) } : {}) } });

  it("Größengrenze: von der neuesten Fassung rückwärts, ältere fallen heraus", () => {
    const history = [item("1", T0, 100), item("2", T0 + 1, 100), item("3", T0 + 2, 100)];
    const size = approximateSize(history[2]!);
    expect(truncateHistory(history, -1, 2 * size).map((h) => h.strings.get("Title")!.value)).toEqual(["2", "3"]);
    expect(truncateHistory(history, -1, 2 * size - 1).map((h) => h.strings.get("Title")!.value)).toEqual(["3"]);
    expect(truncateHistory(history, 0, -1)).toEqual([]);
    expect(truncateHistory(history, -1, -1)).toHaveLength(3);
  });

  it("vereinigt ohne Doppelte, sortiert nach Zeit – unabhängig von der Reihenfolge", () => {
    const items = [item("b", T0 + 2000), item("a", T0 + 1000), item("a", T0 + 1000), item("c", T0 + 1000)];
    const limits = { historyMaxItems: -1, historyMaxSize: -1 };
    const forward = mergeHistory(items, limits).map((h) => [h.times.lastModification, h.strings.get("Title")!.value]);
    const backward = mergeHistory([...items].reverse(), limits).map((h) => [h.times.lastModification, h.strings.get("Title")!.value]);
    expect(forward).toEqual(backward);
    expect(forward).toHaveLength(3);
    expect(forward.map(([t]) => t)).toEqual([T0 + 1000, T0 + 1000, T0 + 2000]);
  });

  it("dieselbe Fassung mit und ohne CustomData (Verlaufseintrag von KeePassXC) zählt nur einmal", () => {
    const withCustomData = item("a", T0 + 1000);
    withCustomData.customData.set("Typ", { value: "login" });
    const fromKeepassxc = item("a", T0 + 1000);
    const limits = { historyMaxItems: -1, historyMaxSize: -1 };
    const forward = mergeHistory([withCustomData, fromKeepassxc], limits);
    const backward = mergeHistory([fromKeepassxc, withCustomData], limits);
    expect(forward).toHaveLength(1);
    expect(forward).toEqual(backward);
  });
});
