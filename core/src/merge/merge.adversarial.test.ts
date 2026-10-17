/**
 * Gegenproben zum Feld-Merge (adversariale Prüfung nach dem Bau der Stufe „merge“).
 *
 * Schwerpunkt: Was passiert, wenn eine Seite im Arbeitsspeicher liegt (Zeiten
 * millisekundengenau) und die andere gerade aus der Datei gelesen wurde (KDBX: nur ganze
 * Sekunden)? Genau das ist der Normalfall beim Abgleich: local = eigene Fassung im Speicher,
 * remote = Datei vom WebDAV-Server. Zwei Geräte müssen dabei zum SELBEN Ergebnis kommen,
 * sonst schreiben sie sich gegenseitig ihre Fassung zurück („Ping-Pong“).
 *
 * Dazu: unsinnige Zeiten in Ownwarden.FieldTimes, monotone Uhr, Löschen gegen Ändern in
 * derselben Sekunde, Verlauf ohne Doppelte.
 */
import { describe, expect, it } from "vitest";
import { identityStream } from "../../test/fixtures/xml/fixtures";
import { newEntry, newGroup, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import { FIELD_TIMES_KEY } from "../contracts";
import { parseVaultXml, serializeVaultXml } from "../kdbx/xml";
import type { Entry, Millis, Vault } from "../model";
import { cloneVault } from "./clone";
import { VaultClock } from "./clock";
import { encodeParts, fingerprint, MAX_KDBX_TIME } from "./encoding";
import { effectiveFieldTimes, readFieldTimes, sealFieldTimes } from "./field-times";
import { normalizeTags } from "./fields";
import { contentFingerprint, historySnapshot } from "./history";
import { mergeVaults } from "./merge";
import { entryUuids, randomScenario, semanticView } from "./testing/random-vaults";
import { findEntry, findGroup, moveGroup, renameGroup, setField } from "./vault-ops";

const u = uuidFromName;
const NOW = T0 + 1_000_000;

/** Speichern und wieder laden (echter XML-Weg): Danach sind alle KDBX-Zeiten ganze Sekunden. */
function saveAndLoad(vault: Vault): Vault {
  const { xml, binaries } = serializeVaultXml(vault, identityStream());
  return parseVaultXml(xml, binaries, identityStream(), vault.settings);
}

/** Uhr, die genau die angegebene Zeit liefert (nur ein Aufruf erwartet). */
function clockAt(vault: Vault, time: Millis): VaultClock {
  return new VaultClock(vault, () => time);
}

/** Ausgangslage: Wurzel, Gruppe „Bank“, ein versiegelter Eintrag e1 – alles schon einmal gespeichert. */
function baseVault(): Vault {
  const vault = newVault({ root: newGroup({ uuid: u("root"), name: "Root", at: T0, groups: [newGroup({ uuid: u("g"), name: "Bank", at: T0 })] }) });
  const entry = newEntry({ uuid: u("e1"), at: T0, fields: { Title: "Mail", Password: "alt" } });
  vault.root.entries.push(entry);
  // Einmal über vault-ops ändern, damit der Eintrag versiegelt ist.
  setField(vault, u("e1"), "UserName", "alice", {}, clockAt(vault, T0 + 1000));
  return saveAndLoad(vault);
}

describe("Zwei Geräte kommen zum selben Ergebnis (Speicher ms gegen Datei s)", () => {
  it("Gruppe in derselben Sekunde auf beiden Geräten umbenannt", () => {
    const base = baseVault();
    const a = cloneVault(base);
    const b = cloneVault(base);
    renameGroup(a, u("g"), "Von A", clockAt(a, T0 + 10_300));
    renameGroup(b, u("g"), "Von B", clockAt(b, T0 + 10_600));

    const onA = mergeVaults(a, saveAndLoad(b), { now: NOW }).vault;
    const onB = mergeVaults(b, saveAndLoad(a), { now: NOW }).vault;
    expect(findGroup(onA, u("g"))!.name).toBe(findGroup(onB, u("g"))!.name);
  });

  it("Datenbankname in derselben Sekunde auf beiden Geräten geändert", () => {
    const base = baseVault();
    const a = cloneVault(base);
    const b = cloneVault(base);
    a.meta.databaseName = "Von A";
    a.meta.databaseNameChanged = T0 + 10_300;
    b.meta.databaseName = "Von B";
    b.meta.databaseNameChanged = T0 + 10_600;

    const onA = mergeVaults(a, saveAndLoad(b), { now: NOW }).vault;
    const onB = mergeVaults(b, saveAndLoad(a), { now: NOW }).vault;
    expect(onA.meta.databaseName).toBe(onB.meta.databaseName);
  });

  it("Löschen gegen Ändern in derselben Sekunde: beide Geräte löschen", () => {
    const base = baseVault();
    const a = cloneVault(base);
    const b = cloneVault(base);
    a.root.entries = [];
    a.deletedObjects.push({ uuid: u("e1"), deletionTime: T0 + 5_100 });
    setField(b, u("e1"), "Password", "neu", {}, clockAt(b, T0 + 5_300));

    const onA = mergeVaults(a, saveAndLoad(b), { now: NOW }).vault;
    const onB = mergeVaults(b, saveAndLoad(a), { now: NOW }).vault;
    expect(findEntry(onA, u("e1"))).toBeUndefined();
    expect(findEntry(onB, u("e1"))).toBeUndefined();
  });

  it("Verlauf: dieselbe Fassung aus dem Speicher (ms) und aus der Datei (s) zählt nur einmal", () => {
    const local = baseVault();
    // Erste Änderung, dann speichern (die Datei auf dem Server hat diese Fassung, sekundengenau) …
    setField(local, u("e1"), "Password", "zwei", {}, clockAt(local, T0 + 10_300));
    const file = saveAndLoad(local);
    // … zweite Änderung im Speicher: Die erste Fassung kommt (mit ms-Zeit) in den Verlauf.
    setField(local, u("e1"), "Password", "drei", {}, clockAt(local, T0 + 20_500));

    const merged = findEntry(mergeVaults(local, file, { now: NOW }).vault, u("e1"))!;
    expect(merged.strings.get("Password")!.value).toBe("drei");
    // „alt“ zweimal: ohne und mit UserName (siehe baseVault); „zwei“ genau einmal.
    const versions = merged.history.map((item) => [item.strings.get("Password")!.value, item.strings.get("UserName")?.value ?? ""]);
    expect(versions).toEqual([["alt", ""], ["alt", "alice"], ["zwei", "alice"]]);
  });

  it("Verlauf: dieselbe Fassung mit CustomData (Ownwarden) und ohne (KeePassXC) – beide Geräte behalten dieselbe", () => {
    const diverging: string[] = [];
    for (const typ of ["karte", "login", "identitaet", "notiz", "a", "b", "c", "d", "e", "f", "g", "h"]) {
      // Gerät A hat Fassung V im Speicher (ms) und speichert sie; Gerät B lädt diese Datei.
      const a = newVault({ root: newGroup({ uuid: u("root"), at: T0 }) });
      const entry = newEntry({ uuid: u("e1"), at: T0 + 10_300, fields: { Title: "t", Password: "p" } });
      entry.customData.set("Typ", { value: typ });
      sealFieldTimes(entry, new Map(), u("root"));
      a.root.entries.push(entry);
      const b = saveAndLoad(a);
      // KeePassXC ändert das Passwort: V kommt OHNE CustomData in den Verlauf.
      const remote = cloneVault(b);
      const external = remote.root.entries[0]!;
      external.history.push({ ...historySnapshot(external), customData: new Map() });
      external.strings.set("Password", { value: "p2", protected: true });
      external.times.lastModification = T0 + 20_000;
      const file = saveAndLoad(remote);

      const onA = saveAndLoad(mergeVaults(a, file, { now: NOW }).vault);
      const onB = saveAndLoad(mergeVaults(b, file, { now: NOW }).vault);
      const history = (v: Vault) => findEntry(v, u("e1"))!.history.map((h) => [h.times.lastModification, contentFingerprint(h)]);
      if (JSON.stringify(history(onA)) !== JSON.stringify(history(onB))) diverging.push(typ);
    }
    expect(diverging).toEqual([]);
  });

  it("KDBX-Zeiten zählen als Feld-Zeitstempel nur in ganzen Sekunden (PROJECT-CONTEXT: „auf Sekunden abgerundet“)", () => {
    // Eintrag ohne FieldTimes (z. B. von KeePassXC), Änderungszeit im Speicher millisekundengenau.
    const unsealed = newEntry({ uuid: u("e2"), at: T0 + 4_700, fields: { Title: "x" } });
    unsealed.times.locationChanged = T0 + 3_200;
    const times = effectiveFieldTimes(unsealed, u("root")).times;
    expect(times.get("s:Title")).toEqual({ t: T0 + 4_000, present: true });
    expect(times.get("parent")).toEqual({ t: T0 + 3_000, present: true });

    // Versiegelter Eintrag, danach extern (ohne Ownwarden) geändert: Basiszeit ebenfalls abgerundet.
    const sealed = findEntry(baseVault(), u("e1"))!;
    sealed.strings.set("URL", { value: "https://extern", protected: false });
    sealed.times.lastModification = T0 + 9_900;
    expect(effectiveFieldTimes(sealed, u("root")).times.get("s:URL")).toEqual({ t: T0 + 9_000, present: true });
  });

  it("Eintrag ohne FieldTimes, im Speicher ms-genau: beide Geräte entscheiden gleich", () => {
    const entryAt = (at: Millis, notes: string) => newEntry({ uuid: u("e3"), at, fields: { Title: "t", Notes: notes } });
    const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [entryAt(T0 + 3_001, "x\r\ny")] }) });
    const b = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [entryAt(T0 + 3_002, "x\ny")] }) });
    const onA = mergeVaults(a, saveAndLoad(b), { now: NOW }).vault;
    const onB = mergeVaults(b, saveAndLoad(a), { now: NOW }).vault;
    expect(findEntry(onA, u("e3"))!.strings.get("Notes")).toEqual(findEntry(onB, u("e3"))!.strings.get("Notes"));
  });

  it("Eigenschaft: merge(a, Datei(b)) und merge(b, Datei(a)) sind nach dem Speichern gleich", () => {
    /** Anzahl doppelter Verlaufsfassungen (gleiche Sekunde, gleicher Inhalt ohne CustomData). */
    const duplicates = (entry: Entry | undefined): number => {
      if (entry === undefined) return 0;
      const keys = entry.history.map((h) => `${Math.floor(h.times.lastModification / 1000)}|${contentFingerprint(h, { withoutCustomData: true })}`);
      return keys.length - new Set(keys).size;
    };
    const failures: number[] = [];
    for (let seed = 1; seed <= 150; seed++) {
      const { a, b, now } = randomScenario(seed);
      const onA = saveAndLoad(mergeVaults(a, saveAndLoad(b), { now }).vault);
      const onB = saveAndLoad(mergeVaults(b, saveAndLoad(a), { now }).vault);
      if (JSON.stringify(semanticView(onA)) !== JSON.stringify(semanticView(onB))) failures.push(seed);
      // Stabil auch über die Datei: Ergebnis laden und erneut mit einer Eingabe abgleichen.
      for (const input of [a, b]) {
        const again = saveAndLoad(mergeVaults(onA, saveAndLoad(input), { now }).vault);
        if (JSON.stringify(semanticView(again)) !== JSON.stringify(semanticView(onA))) failures.push(1000 + seed);
      }
      // Der Merge erzeugt keine NEUEN Doppelten im Verlauf. (Unveränderte Einträge reicht er
      // durch, wie sie sind – auch mit Doppelten, die die Eingabe schon hatte.)
      for (const vault of [onA, onB]) {
        for (const uuid of entryUuids(vault)) {
          const before = Math.max(duplicates(findEntry(a, uuid)), duplicates(findEntry(b, uuid)));
          if (duplicates(findEntry(vault, uuid)) > before) failures.push(-seed);
        }
      }
    }
    expect(failures).toEqual([]);
  });
});

describe("Änderungen in derselben Sekunde", () => {
  it("Gruppe umbenennen/verschieben, nachdem ein anderes Gerät es in derselben Sekunde tat: die spätere Änderung gewinnt", () => {
    const base = baseVault();
    base.root.groups.push(newGroup({ uuid: u("ziel"), name: "Ziel", at: T0 }));
    const a = cloneVault(base);
    renameGroup(a, u("g"), "Zebra", clockAt(a, T0 + 10_300));
    moveGroup(a, u("g"), u("ziel"), clockAt(a, T0 + 10_300));
    const file = saveAndLoad(a);
    // Gerät B lädt diese Datei und ändert in derselben Sekunde weiter (Name „kleiner“ als „Zebra“).
    const b = cloneVault(file);
    renameGroup(b, u("g"), "Anton", clockAt(b, T0 + 10_600));
    moveGroup(b, u("g"), u("root"), clockAt(b, T0 + 10_700));

    for (const merged of [mergeVaults(b, file, { now: NOW }).vault, mergeVaults(file, b, { now: NOW }).vault, mergeVaults(a, saveAndLoad(b), { now: NOW }).vault]) {
      expect(findGroup(merged, u("g"))!.name).toBe("Anton");
      expect(merged.root.groups.map((g) => g.uuid)).toContain(u("g"));
    }
  });

  it("gleiche Entscheidung in derselben Sekunde mit verschiedenen ms: Ergebnis trotzdem symmetrisch (auch die Zeiten)", () => {
    const base = baseVault();
    base.root.groups.push(newGroup({ uuid: u("ziel"), name: "Ziel", at: T0 }));
    const a = cloneVault(base);
    const b = cloneVault(base);
    moveGroup(a, u("g"), u("ziel"), clockAt(a, T0 + 10_300));
    moveGroup(b, u("g"), u("ziel"), clockAt(b, T0 + 10_600));
    a.meta.databaseName = b.meta.databaseName = "Gleich";
    a.meta.databaseNameChanged = T0 + 20_300;
    b.meta.databaseNameChanged = T0 + 20_600;
    a.meta.recycleBinEnabled = b.meta.recycleBinEnabled = false;
    a.meta.recycleBinChanged = T0 + 30_300;
    b.meta.recycleBinChanged = T0 + 30_600;
    const ab = mergeVaults(a, b, { now: NOW }).vault;
    const ba = mergeVaults(b, a, { now: NOW }).vault;
    expect(findGroup(ab, u("g"))!.times).toEqual(findGroup(ba, u("g"))!.times);
    expect([ab.meta.databaseNameChanged, ab.meta.recycleBinChanged]).toEqual([ba.meta.databaseNameChanged, ba.meta.recycleBinChanged]);
  });

  it("Meta-CustomData ohne LastModificationTime (KDBX 4.0): beide Geräte wählen denselben Wert", () => {
    const base = baseVault();
    const a = cloneVault(base);
    const b = cloneVault(base);
    a.meta.customData.set("KPXC_DECRYPTION_TIME_PREFERENCE", { value: "1000" });
    b.meta.customData.set("KPXC_DECRYPTION_TIME_PREFERENCE", { value: "2000" });
    const onA = mergeVaults(a, saveAndLoad(b), { now: NOW }).vault;
    const onB = mergeVaults(b, saveAndLoad(a), { now: NOW }).vault;
    expect(onA.meta.customData.get("KPXC_DECRYPTION_TIME_PREFERENCE")).toEqual(onB.meta.customData.get("KPXC_DECRYPTION_TIME_PREFERENCE"));
  });

  it("KeePassXC ändert ein Feld in derselben Sekunde, in der Ownwarden versiegelt hat: KeePassXC gewinnt", () => {
    const local = baseVault();
    setField(local, u("e1"), "Password", "ownwarden", {}, clockAt(local, T0 + 10_300));
    const file = saveAndLoad(local);
    const external = findEntry(file, u("e1"))!; // „KeePassXC“: gleiche Sekunde, FieldTimes bleiben stehen
    external.strings.set("Password", { value: "keepassxc", protected: true });
    expect(external.times.lastModification).toBe(T0 + 10_000);
    for (const merged of [mergeVaults(local, file, { now: NOW }).vault, mergeVaults(file, local, { now: NOW }).vault]) {
      expect(findEntry(merged, u("e1"))!.strings.get("Password")!.value).toBe("keepassxc");
    }
  });
});

describe("Plattformunabhängige Vereinheitlichung", () => {
  it("Tags: genau die in spec/README.md aufgezählten Leerzeichen fallen am Rand weg – nicht mehr, nicht weniger", () => {
    const trimmed = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, ...Array.from({ length: 11 }, (_, i) => 0x2000 + i), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff];
    const wrong: string[] = [];
    for (let code = 0; code < 0x10000; code++) {
      if (code >= 0xd800 && code <= 0xdfff) continue;
      const c = String.fromCharCode(code);
      const expected = trimmed.includes(code) ? "x" : c + "x" + c;
      if (normalizeTags([c + "x" + c])[0] !== expected) wrong.push(`U+${code.toString(16)}`);
    }
    expect(wrong).toEqual([]);
  });
});

describe("Reine Funktion", () => {
  it("doppelte UUIDs in EINER Datenbank (Eintrag, Gruppe, Wurzel-UUID als Untergruppe, Eintrag = Gruppe): Abbruch in beiden Richtungen, Eingaben unverändert", () => {
    // Früher wurden doppelte Vorkommen still zusammengeführt (dabei konnte eines samt Passwort
    // verloren gehen, Review kdbx-1). Der KDBX-Leser vergibt ihnen jetzt neue UUIDs; kommt
    // trotzdem eine doppelte an, ist das ein Programmfehler und mergeVaults bricht ab.
    const dupEntry = (at: Millis, password: string) => {
      const entry = newEntry({ uuid: u("dup"), at, fields: { Title: "D", Password: password } });
      sealFieldTimes(entry, new Map(), u("root"));
      return entry;
    };
    const broken = [
      newVault({
        root: newGroup({ uuid: u("root"), at: T0, groups: [newGroup({ uuid: u("g"), at: T0, entries: [dupEntry(T0 + 1000, "eins")] })], entries: [dupEntry(T0 + 2000, "zwei")] }),
      }),
      newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [newGroup({ uuid: u("g"), name: "G alt", at: T0 }), newGroup({ uuid: u("g"), name: "G neu", at: T0 + 5000 })] }) }),
      newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [newGroup({ uuid: u("root"), name: "falsche Wurzel", at: T0 })] }) }),
      newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [newGroup({ uuid: u("dup"), at: T0 })], entries: [dupEntry(T0, "x")] }) }),
    ];
    const fine = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [dupEntry(T0 + 500, "null")] }) });
    for (const a of broken) {
      const aBefore = cloneVault(a);
      expect(() => mergeVaults(a, fine, { now: NOW })).toThrow(/mehrfach/);
      expect(() => mergeVaults(fine, a, { now: NOW })).toThrow(/mehrfach/);
      expect(a).toEqual(aBefore);
    }
  });

  it("Untergruppe mit der Wurzel-UUID der ANDEREN Seite: wird Teil der Wurzel, beide Richtungen gleich", () => {
    // Verschiedene Wurzeln: Das Ergebnis hat die kleinere UUID; bei der anderen Seite ist sie eine Untergruppe.
    const [small, big] = [u("root"), u("andere")].sort() as [string, string];
    const a = newVault({ root: newGroup({ uuid: small, at: T0, entries: [newEntry({ uuid: u("e1"), at: T0, fields: { Title: "A" } })] }) });
    const b = newVault({
      root: newGroup({ uuid: big, at: T0, groups: [newGroup({ uuid: small, at: T0, entries: [newEntry({ uuid: u("e2"), at: T0, fields: { Title: "B" } })] })] }),
    });
    const ab = mergeVaults(a, b, { now: NOW }).vault;
    const ba = mergeVaults(b, a, { now: NOW }).vault;
    expect(semanticView(ba)).toEqual(semanticView(ab));
    expect(ab.root.uuid).toBe(small);
    expect(ab.root.groups).toEqual([]);
    expect(ab.root.entries.map((e) => e.uuid).sort()).toEqual([u("e1"), u("e2")].sort());
  });
});

describe("Aufrufer-Fehler", () => {
  it("ungültiges options.now wird abgelehnt statt NaN in Zeiten und FieldTimes zu schreiben", () => {
    const orphan = newEntry({ uuid: u("waise"), at: T0 + 1000, fields: { Title: "Waise" } });
    sealFieldTimes(orphan, new Map(), u("weg"));
    const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [newGroup({ uuid: u("weg"), at: T0, entries: [orphan] })] }) });
    const b = newVault({ root: newGroup({ uuid: u("root"), at: T0 }), deletedObjects: [{ uuid: u("weg"), deletionTime: T0 + 5000 }] });
    for (const now of [Number.NaN, Infinity, 1e300]) {
      expect(() => mergeVaults(a, b, { now })).toThrow(RangeError);
    }
    expect(() => mergeVaults(a, b, { now: NOW })).not.toThrow();
  });
});

describe("Zyklen und Wiederherstellungsgruppe", () => {
  it("Zyklus über die Wiederherstellungsgruppe und Waisen: alles bleibt mit der Wurzel verbunden, beide Richtungen gleich", () => {
    const recovery = newGroup({ uuid: "T3dud2FyZGVuUmVjb3Zlcg==", name: "Wiederhergestellt (Ownwarden)", at: T0 });
    const x = newGroup({ uuid: u("x"), name: "X", at: T0 });
    const doomed = newGroup({ uuid: u("weg"), name: "Weg", at: T0, entries: [newEntry({ uuid: u("waise"), at: T0 + 1000, fields: { Title: "Waise" } })] });
    // A: X liegt in der Wiederherstellungsgruppe; B: die Wiederherstellungsgruppe liegt in X.
    const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [{ ...recovery, groups: [{ ...x, times: { ...x.times, locationChanged: T0 + 3000 } }] }, doomed] }) });
    const b = newVault({
      root: newGroup({ uuid: u("root"), at: T0, groups: [{ ...x, groups: [{ ...recovery, times: { ...recovery.times, locationChanged: T0 + 4000 } }] }] }),
      deletedObjects: [{ uuid: u("weg"), deletionTime: T0 + 5000 }],
    });
    const ab = mergeVaults(a, b, { now: NOW });
    const ba = mergeVaults(b, a, { now: NOW });
    expect(semanticView(ba.vault)).toEqual(semanticView(ab.vault));
    expect(findEntry(ab.vault, u("waise"))).toBeDefined();
    expect(findGroup(ab.vault, u("weg"))).toBeUndefined();
    expect(semanticView(mergeVaults(ab.vault, a, { now: NOW }).vault)).toEqual(semanticView(ab.vault));
    expect(semanticView(mergeVaults(ab.vault, b, { now: NOW }).vault)).toEqual(semanticView(ab.vault));
  });
});

describe("Unsinnige Zeiten in Ownwarden.FieldTimes", () => {
  /** Eintrag, dessen FieldTimes für „Title“ den Zeitpunkt `t` behaupten (Fingerabdruck passt). */
  function entryClaiming(t: number, title: string, at: Millis): Entry {
    const entry = newEntry({ uuid: u("e1"), at, fields: { Title: title } });
    const hash = fingerprint(encodeParts(["s", title, "0"]));
    entry.customData.set(FIELD_TIMES_KEY, { value: `{"v":1,"w":${at},"f":{"s:Title":{"t":${t},"h":"${hash}"}}}` });
    return entry;
  }

  it.each([
    ["Jahr 33658", 1e15],
    ["größte sichere Ganzzahl", Number.MAX_SAFE_INTEGER],
    ["vor Jahr 1", -1e15],
  ])("Zeit außerhalb von KDBX (%s) gilt als ungültig; das Ergebnis bleibt speicherbar", (_name, t) => {
    const garbage = entryClaiming(t, "Müll", T0);
    expect(readFieldTimes(garbage)).toBeUndefined();

    const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [garbage] }) });
    const b = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [newEntry({ uuid: u("e1"), at: T0 + 5000, fields: { Title: "neu" } })] }) });
    for (const [x, y] of [[a, b], [b, a]] as const) {
      const merged = mergeVaults(x, y, { now: NOW }).vault;
      expect(() => saveAndLoad(merged)).not.toThrow();
      expect(findEntry(merged, u("e1"))!.strings.get("Title")!.value).toBe("neu");
    }
  });

  it("die Uhr lässt sich durch unsinnige Zeiten nicht aus dem KDBX-Bereich schieben", () => {
    const vault = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [entryClaiming(1e15, "Müll", T0)] }) });
    const clock = new VaultClock(vault, () => T0 + 50_000);
    expect(clock.now()).toBe(T0 + 50_000);
    clock.observe(Number.MAX_SAFE_INTEGER);
    clock.observe(Infinity);
    const first = clock.now();
    const second = clock.now();
    expect(second).toBeGreaterThan(first);
    expect(first).toBeLessThan(253_402_300_800_000); // 10000-01-01
  });

  it.each([
    ["tief verschachtelt", "[".repeat(200_000) + "]".repeat(200_000)],
    ["f mit null", '{"v":1,"w":1,"f":{"s:A":null}}'],
    ["t als Kommazahl", '{"v":1,"w":1,"f":{"s:A":{"t":1.5,"h":"x"}}}'],
    ["t als Exponent außerhalb", '{"v":1,"w":1,"f":{"s:A":{"t":1e400,"h":"x"}}}'],
    ["d als true", '{"v":1,"w":1,"f":{"s:A":{"t":1,"d":true}}}'],
    ["h als Zahl", '{"v":1,"w":1,"f":{"s:A":{"t":1,"h":5}}}'],
    ["Version als Text", '{"v":"1","w":1,"f":{}}'],
    ["__proto__ als f", '{"v":1,"w":1,"__proto__":{"f":{}}}'],
    ["leerer Text", ""],
  ])("kaputtes JSON (%s): kein Absturz, keine Wirkung auf Merge und Uhr", (_name, value) => {
    const entry = newEntry({ uuid: u("e1"), at: T0 + 2000, fields: { Title: "x" } });
    entry.customData.set(FIELD_TIMES_KEY, { value });
    expect(readFieldTimes(entry)).toBeUndefined();
    expect(effectiveFieldTimes(entry, u("root")).sealed).toBe(false);
    const vault = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [entry] }) });
    expect(new VaultClock(vault, () => 0).now()).toBe(T0 + 2001);
    const other = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [newEntry({ uuid: u("e1"), at: T0 + 3000, fields: { Title: "y" } })] }) });
    expect(findEntry(mergeVaults(vault, other, { now: NOW }).vault, u("e1"))!.strings.get("Title")!.value).toBe("y");
  });

  it("wirksame Zeiten eines Eintrags mit ungültigen FieldTimes: wie nie versiegelt", () => {
    const garbage = entryClaiming(1e15, "Müll", T0 + 7000);
    const effective = effectiveFieldTimes(garbage, u("root"));
    expect(effective.sealed).toBe(false);
    expect(effective.times.get("s:Title")).toEqual({ t: T0 + 7000, present: true });
  });

  describe("Zeiten am Ende des KDBX-Bereichs (Review merge-4)", () => {
    /** Alle Zeiten "t" und "w" in Ownwarden.FieldTimes eines Eintrags (wirft, wenn sie fehlen). */
    function storedTimes(entry: Entry): number[] {
      const stored = readFieldTimes(entry);
      expect(stored, "FieldTimes gültig").toBeDefined();
      return [stored!.sealedAt, ...[...stored!.fields.values()].map((field) => field.t)];
    }

    it("die Uhr bleibt bei MAX_KDBX_TIME stehen statt dahinter zu laufen", () => {
      const clock = new VaultClock(undefined, () => T0);
      clock.observe(MAX_KDBX_TIME);
      expect(clock.now()).toBe(MAX_KDBX_TIME);
      expect(clock.now()).toBe(MAX_KDBX_TIME);
      expect(new VaultClock(undefined, () => MAX_KDBX_TIME + 5000).now()).toBe(MAX_KDBX_TIME);
    });

    it("eine Änderung nach einem Feld-Zeitstempel von Jahr 9999 schreibt lesbare FieldTimes", () => {
      const vault = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [entryClaiming(MAX_KDBX_TIME, "Ende", T0)] }) });
      const entry = setField(vault, u("e1"), "UserName", "alice", {}, new VaultClock(vault, () => T0 + 50_000));
      expect(Math.max(...storedTimes(entry))).toBe(MAX_KDBX_TIME);
      expect(entry.times.lastModification).toBe(MAX_KDBX_TIME);
      expect(() => saveAndLoad(vault)).not.toThrow();
    });

    it("extern geändert nach t = MAX_KDBX_TIME: wirksame Zeit bleibt im Bereich, das Ergebnis lesbar", () => {
      const changed = entryClaiming(MAX_KDBX_TIME, "Ende", T0);
      changed.strings.set("Title", { value: "extern", protected: false }); // Fingerabdruck passt nicht mehr
      expect(effectiveFieldTimes(changed, u("root")).times.get("s:Title")).toEqual({ t: MAX_KDBX_TIME, present: true });
      const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [changed] }) });
      const b = newVault({ root: newGroup({ uuid: u("root"), at: T0, entries: [newEntry({ uuid: u("e1"), at: T0 + 5000, fields: { Title: "neu" } })] }) });
      const merged = findEntry(mergeVaults(a, b, { now: NOW }).vault, u("e1"))!;
      expect(merged.strings.get("Title")!.value).toBe("extern");
      expect(Math.max(...storedTimes(merged))).toBe(MAX_KDBX_TIME);
    });

    it("Verschiebung durch den Merge (Waise) nach Zeiten von Jahr 9999: alles bleibt speicherbar und lesbar", () => {
      const orphan = newEntry({ uuid: u("waise"), at: T0, fields: { Title: "Waise" } });
      sealFieldTimes(orphan, new Map([["parent", { t: MAX_KDBX_TIME, present: true }]]), u("weg"));
      const lostGroup = newGroup({ uuid: u("verloren"), name: "Verloren", at: T0, times: { ...newGroup().times, locationChanged: MAX_KDBX_TIME } });
      const doomed = newGroup({ uuid: u("weg"), name: "Weg", at: T0, entries: [orphan], groups: [lostGroup] });
      const a = newVault({ root: newGroup({ uuid: u("root"), at: T0, groups: [doomed] }) });
      // Gelöscht in derselben (letzten) Sekunde: Die Löschung gewinnt, Eintrag und Untergruppe sind Waisen.
      const b = newVault({ root: newGroup({ uuid: u("root"), at: T0 }), deletedObjects: [{ uuid: u("weg"), deletionTime: MAX_KDBX_TIME }] });
      const { vault, report } = mergeVaults(a, b, { now: NOW });
      expect(report.orphansRecovered).toBe(2);
      expect(Math.max(...storedTimes(findEntry(vault, u("waise"))!))).toBe(MAX_KDBX_TIME);
      expect(findGroup(vault, u("verloren"))!.times.locationChanged).toBe(MAX_KDBX_TIME);
      expect(() => saveAndLoad(vault)).not.toThrow();
    });

    it("sealFieldTimes schreibt keine Zeit außerhalb des KDBX-Bereichs", () => {
      const entry = newEntry({ uuid: u("e1"), at: T0, fields: { Title: "x" } });
      expect(() => sealFieldTimes(entry, new Map([["s:Title", { t: MAX_KDBX_TIME + 1, present: true }]]), u("root"))).toThrow(RangeError);
      expect(entry.customData.has(FIELD_TIMES_KEY)).toBe(false);
    });
  });
});
