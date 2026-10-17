/**
 * NUR FÜR TESTS: zufällige, aber reproduzierbare Szenarien für die Eigenschafts-Tests des
 * Merge (merge.property.test.ts) und eine „inhaltliche Sicht“ auf eine Datenbank.
 *
 * Ein Szenario: Aus einer zufälligen Ausgangs-Datenbank entstehen zwei Kopien (zwei Geräte),
 * auf denen unabhängig zufällige Änderungen passieren – über vault-ops (wie Ownwarden) und
 * direkt am Modell (wie KeePassXC, ohne FieldTimes zu pflegen).
 *
 * Zufall: eigener PRNG mit Startwert (mulberry32), damit jeder Fehlschlag mit seinem Seed
 * wiederholbar ist. NICHT für Sicherheitszwecke.
 */
import { FIELD_TIMES_KEY } from "../../contracts";
import { NULL_UUID, type Entry, type Group, type Millis, type Uuid, type Vault } from "../../model";
import { cloneVault } from "../clone";
import { VaultClock } from "../clock";
import { toSeconds } from "../encoding";
import { effectiveFieldTimes } from "../field-times";
import { entryFields, LAST_MODIFIED_KEY, materializeStandardFields, normalizeTags } from "../fields";
import { groupCanonical } from "../merge-group";
import { contentFingerprint } from "../history";
import { forEachGroup } from "../tree";
import {
  createEntry,
  createGroup,
  deleteEntry,
  deleteGroup,
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
  editEntry,
} from "../vault-ops";

/** Deterministischer Zufallszahlengenerator (mulberry32). */
export class Prng {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0;
  }

  /** Gleichverteilt in [0, 1). */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Ganze Zahl in [min, max]. */
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }

  pick<T>(items: readonly T[]): T {
    if (items.length === 0) throw new Error("pick aus leerer Liste");
    return items[this.int(0, items.length - 1)]!;
  }

  chance(probability: number): boolean {
    return this.next() < probability;
  }

  /** 16 Zufallsbytes als Base64-UUID. */
  uuid(): Uuid {
    let binary = "";
    for (let i = 0; i < 16; i++) binary += String.fromCharCode(this.int(0, 255));
    return btoa(binary);
  }
}

export const BASE_TIME: Millis = 1_700_000_000_000;

/**
 * Uhr mit künstlicher Zeitquelle. `lockstep`: jede Abfrage genau 1 s weiter – zwei Geräte
 * im Gleichschritt erzeugen dann dieselben Zeitstempel (Gleichstand-Regel wird geprüft).
 * Sonst zufällige Schritte (auch 0 und 1 ms).
 */
function stepClock(vault: Vault, start: Millis, prng: Prng, lockstep = false): VaultClock {
  let time = start;
  return new VaultClock(vault, () => {
    time += lockstep ? 1000 : prng.pick([0, 0, 1, 1000, 1000, 2500]);
    return time;
  });
}

const FIELD_NAMES = ["Title", "UserName", "Password", "URL", "Notes", "PIN", "Frage", "Antwort"];
const VALUES = ["a", "b", "geheim", "äöü", "x\r\ny", "x\ny", "", "lang-" + "z".repeat(40)];

function allEntries(vault: Vault): { entry: Entry; group: Group }[] {
  const result: { entry: Entry; group: Group }[] = [];
  forEachGroup(vault.root, (group) => group.entries.forEach((entry) => result.push({ entry, group })));
  return result;
}

function allGroups(vault: Vault): Group[] {
  const result: Group[] = [];
  forEachGroup(vault.root, (group) => result.push(group));
  return result;
}

/** Zufällige Ausgangs-Datenbank, komplett über vault-ops angelegt. */
function baseVault(prng: Prng): Vault {
  const root: Group = {
    uuid: prng.uuid(),
    name: "Root",
    notes: "",
    iconId: 48,
    times: { creation: BASE_TIME, lastModification: BASE_TIME, lastAccess: BASE_TIME, expiry: BASE_TIME, expires: false, usageCount: 0, locationChanged: BASE_TIME },
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
  };
  const vault: Vault = {
    settings: { versionMinor: 0, cipher: "aes256", compression: true, kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 } },
    meta: {
      generator: "Ownwarden",
      databaseName: "Zufall",
      databaseNameChanged: BASE_TIME,
      recycleBinEnabled: prng.chance(0.7),
      recycleBinUuid: NULL_UUID,
      recycleBinChanged: BASE_TIME,
      historyMaxItems: prng.pick([-1, 2, 5, 10]),
      historyMaxSize: prng.pick([-1, -1, 100_000]),
      customIcons: [],
      customData: new Map(),
      unknown: [],
    },
    root,
    deletedObjects: [],
    rootUnknown: [],
  };
  const clock = stepClock(vault, BASE_TIME + 1000, prng);
  for (let i = prng.int(1, 4); i > 0; i--) {
    createGroup(vault, prng.pick(allGroups(vault)).uuid, `Gruppe ${i}`, clock, { uuid: prng.uuid() });
  }
  for (let i = prng.int(2, 8); i > 0; i--) {
    const fields: Record<string, string> = { Title: `Eintrag ${i}` };
    for (const name of FIELD_NAMES) if (prng.chance(0.4)) fields[name] = prng.pick(VALUES);
    const entry = createEntry(vault, prng.pick(allGroups(vault)).uuid, fields, clock, { uuid: prng.uuid() });
    if (prng.chance(0.3)) setAttachment(vault, entry.uuid, prng.pick(["a.txt", "b.bin"]), Uint8Array.of(9, 9), {}, clock);
    if (prng.chance(0.2)) setPasskey(vault, entry.uuid, { KPEX_PASSKEY_USERNAME: "u", KPEX_PASSKEY_PRIVATE_KEY_PEM: "k0" }, clock);
  }
  // Einige Einträge sind „von KeePassXC angelegt“: ohne FieldTimes.
  for (const { entry } of allEntries(vault)) if (prng.chance(0.25)) entry.customData.delete(FIELD_TIMES_KEY);
  return vault;
}

/** Eine zufällige Änderung, wie Ownwarden sie macht (vault-ops). */
function ownwardenEdit(vault: Vault, clock: VaultClock, prng: Prng): void {
  const entries = allEntries(vault);
  const groups = allGroups(vault);
  const entry = entries.length > 0 ? prng.pick(entries).entry.uuid : undefined;
  const op = prng.int(0, 17);
  try {
    if (entry === undefined || op === 0) {
      createEntry(vault, prng.pick(groups).uuid, { Title: prng.pick(VALUES), Password: prng.pick(VALUES) }, clock, { uuid: prng.uuid() });
    } else if (op <= 4) {
      setField(vault, entry, prng.pick(FIELD_NAMES), prng.pick(VALUES), prng.chance(0.2) ? { protected: prng.chance(0.5) } : {}, clock);
    } else if (op === 5) {
      removeField(vault, entry, prng.pick(FIELD_NAMES), clock);
    } else if (op === 6) {
      setAttachment(vault, entry, prng.pick(["a.txt", "b.bin"]), Uint8Array.of(prng.int(0, 3), 1, 2), {}, clock);
    } else if (op === 7) {
      removeAttachment(vault, entry, prng.pick(["a.txt", "b.bin"]), clock);
    } else if (op === 8) {
      setTags(vault, entry, prng.pick([[], ["A"], ["B", "A"], ["Passkey"]]), clock);
    } else if (op === 9) {
      if (prng.chance(0.7)) setPasskey(vault, entry, { KPEX_PASSKEY_USERNAME: prng.pick(VALUES), KPEX_PASSKEY_PRIVATE_KEY_PEM: prng.pick(["k1", "k2"]) }, clock);
      else removePasskey(vault, entry, clock);
    } else if (op === 10) {
      moveEntry(vault, entry, prng.pick(groups).uuid, clock);
    } else if (op === 11) {
      if (prng.chance(0.5)) deleteEntry(vault, entry, clock);
      else recycleEntry(vault, entry, clock);
    } else if (op === 12) {
      editEntry(vault, entry, (draft) => {
        draft.iconId = prng.int(0, 3);
        draft.times.expires = prng.chance(0.3);
        if (prng.chance(0.3)) draft.customData.set("Typ", { value: prng.pick(["login", "karte"]) });
      }, clock);
    } else if (op === 13) {
      createGroup(vault, prng.pick(groups).uuid, prng.pick(["Neu", "Bank", "Privat"]), clock, { uuid: prng.uuid() });
    } else if (op === 14) {
      const group = prng.pick(groups);
      if (prng.chance(0.5)) renameGroup(vault, group.uuid, prng.pick(["X", "Y", "Bank"]), clock);
      else moveGroup(vault, group.uuid, prng.pick(groups).uuid, clock);
    } else if (op === 15) {
      deleteGroup(vault, prng.pick(groups).uuid, clock);
    } else {
      moveGroup(vault, prng.pick(groups).uuid, prng.pick(groups).uuid, clock);
    }
  } catch (error) {
    // Unzulässige Operationen (Wurzel löschen, Gruppe in sich selbst …) einfach auslassen.
    if (!(error instanceof Error)) throw error;
  }
}

/**
 * Eine zufällige Änderung „durch KeePassXC“: direkt am Modell, ohne FieldTimes anzufassen,
 * mit sekundengenauer lastModification; manchmal mit Verlaufseintrag (ohne CustomData).
 */
function externalEdit(vault: Vault, clock: VaultClock, prng: Prng): void {
  const entries = allEntries(vault);
  if (entries.length === 0) return;
  const { entry, group } = prng.pick(entries);
  const time = toSeconds(clock.now()) * 1000;
  if (prng.chance(0.5)) {
    const strings = new Map([...entry.strings].map(([name, value]) => [name, { ...value }]));
    const snapshot: Entry = { ...entry, strings, customData: new Map(), history: [], times: { ...entry.times } };
    entry.history.push(snapshot);
  }
  const op = prng.int(0, 3);
  if (op === 0) entry.strings.set(prng.pick(FIELD_NAMES), { value: prng.pick(VALUES), protected: false });
  else if (op === 1) entry.strings.delete(prng.pick(FIELD_NAMES));
  else if (op === 2) entry.tags = prng.pick([["K"], []]);
  else {
    const target = prng.pick(allGroups(vault));
    if (target !== group) {
      group.entries.splice(group.entries.indexOf(entry), 1);
      target.entries.push(entry);
      entry.times.locationChanged = time;
    }
  }
  entry.times.lastModification = time;
}

/** Laden+Speichern in KeePassXC: Umformungen ohne inhaltliche Änderung. */
function keepassxcResave(vault: Vault): void {
  for (const { entry } of allEntries(vault)) {
    materializeStandardFields(entry);
    if (!entry.unknown.some((xml) => xml.startsWith("<AutoType>"))) {
      entry.unknown.push("<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>");
    }
    entry.tags = [...entry.tags].sort();
    entry.attachments = entry.attachments.map((a) => ({ ...a, protected: true }));
    for (const [name, value] of entry.strings) entry.strings.set(name, { ...value, value: value.value.replace(/\r\n?/g, "\n") });
  }
}

export interface Scenario {
  base: Vault;
  a: Vault;
  b: Vault;
  now: Millis;
}

/** Ein reproduzierbares Szenario zum Seed. */
export function randomScenario(seed: number): Scenario {
  const prng = new Prng(seed);
  const base = baseVault(prng);
  const start = BASE_TIME + 100_000;
  // Beide Geräte starten mit derselben Zeit: So entstehen auch gleiche Zeitstempel.
  const lockstep = prng.chance(0.4);
  const sides = [cloneVault(base), cloneVault(base)].map((vault) => {
    const clock = stepClock(vault, start, prng, lockstep);
    // Im Gleichschritt ändern beide Geräte zuerst dasselbe Feld zur selben Zeit (Gleichstand).
    const first = allEntries(vault)[0]?.entry.uuid;
    if (lockstep && first !== undefined && prng.chance(0.6)) {
      setField(vault, first, "Password", prng.pick(["eins", "zwei", "drei"]), {}, clock);
    }
    for (let i = prng.int(0, 10); i > 0; i--) {
      if (prng.chance(0.2)) externalEdit(vault, clock, prng);
      else ownwardenEdit(vault, clock, prng);
    }
    if (prng.chance(0.2)) keepassxcResave(vault);
    return vault;
  });
  return { base, a: sides[0]!, b: sides[1]!, now: start + 10_000_000 };
}

// ---------------------------------------------------------------------------
// Inhaltliche Sicht
// ---------------------------------------------------------------------------

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

/**
 * Eine Verlaufsfassung mit ALLEN Rohdaten (auch Rohwerten nicht vorhandener Felder wie dem
 * Standard-<AutoType>), nur ohne Map-Reihenfolge. Sonst sähen die Tests nicht, wenn zwei
 * Geräte verschiedene Rohfassungen desselben Verlaufseintrags behalten und sich deshalb bei
 * jedem Abgleich gegenseitig ihre Fassung zurückschreiben (Review merge-1).
 */
function rawHistoryItem(item: Entry): unknown {
  const sorted = <T>(map: Map<string, T>): [string, T][] => [...map].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return { ...item, strings: sorted(item.strings), customData: sorted(item.customData), history: item.history.length };
}

/**
 * Inhalt einer Datenbank ohne Reihenfolge der Geschwister und ohne Rohdaten-Kleinkram, der
 * nach den Regeln keine Bedeutung hat (FieldTimes-Text, _LAST_MODIFIED, Map-Reihenfolge):
 * Gruppen und Einträge nach UUID sortiert, Felder kanonisch UND exakt, wirksame
 * Feld-Zeitstempel, Zeiten, Verlauf (Zeit, Inhalts-Fingerabdruck und alle Rohdaten),
 * Lösch-Vermerke.
 */
export function semanticView(vault: Vault): unknown {
  const groups: unknown[] = [];
  const entries: unknown[] = [];
  forEachGroup(vault.root, (group, parent) => {
    groups.push({
      uuid: group.uuid,
      parent: parent?.uuid ?? null,
      properties: hex(groupCanonical(group)),
      times: { ...group.times, lastAccess: undefined, usageCount: undefined },
    });
    for (const entry of group.entries) {
      const fields = entryFields(entry, group.uuid);
      const effective = effectiveFieldTimes(entry, group.uuid);
      entries.push({
        uuid: entry.uuid,
        parent: group.uuid,
        fields: Object.fromEntries([...fields].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [k, [hex(v.canonical), hex(v.exact)]])),
        times: Object.fromEntries([...effective.times].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => [k, [v.t, v.present]])),
        entryTimes: entry.times,
        tags: normalizeTags(entry.tags),
        history: entry.history.map((item) => [item.times.lastModification, contentFingerprint(item), rawHistoryItem(item)]),
        lastModifiedMarker: entry.customData.has(LAST_MODIFIED_KEY),
      });
    }
  });
  const byUuid = (a: unknown, b: unknown) => ((a as { uuid: string }).uuid < (b as { uuid: string }).uuid ? -1 : 1);
  return {
    groups: groups.sort(byUuid),
    entries: entries.sort(byUuid),
    deleted: [...vault.deletedObjects].sort(byUuid),
    meta: {
      databaseName: vault.meta.databaseName,
      recycleBin: [vault.meta.recycleBinEnabled, vault.meta.recycleBinUuid, vault.meta.recycleBinChanged],
      icons: vault.meta.customIcons.map((icon) => icon.uuid).sort(),
    },
  };
}

/** Alle UUIDs von Gruppen und Einträgen (ohne Verlauf), mit Wiederholungen. */
export function presentUuids(vault: Vault): Uuid[] {
  const result: Uuid[] = [];
  forEachGroup(vault.root, (group) => {
    result.push(group.uuid);
    for (const entry of group.entries) result.push(entry.uuid);
  });
  return result;
}

/** UUIDs aller Einträge. */
export function entryUuids(vault: Vault): Set<Uuid> {
  return new Set(allEntries(vault).map(({ entry }) => entry.uuid));
}
