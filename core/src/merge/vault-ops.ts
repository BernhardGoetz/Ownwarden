/**
 * Bearbeiten einer Datenbank – der EINZIGE Weg, auf dem Ownwarden Einträge und Gruppen
 * ändert. Nur so bleiben die Feld-Zeitstempel (Ownwarden.FieldTimes) richtig, auf denen der
 * Feld-Merge beruht.
 *
 * Jede Änderung an einem Eintrag
 *   1. ermittelt die wirksamen Feld-Zeitstempel VOR der Änderung (übernimmt also auch
 *      Änderungen, die KeePassXC inzwischen gemacht hat),
 *   2. legt die bisherige Fassung in den Verlauf (Grenzen aus Meta; nicht bei Verschieben),
 *   3. setzt times.lastModification und für JEDES geänderte Feld t = clock.now(),
 *   4. versiegelt FieldTimes neu.
 * Ändert sich nichts, bleibt der Eintrag unverändert (kein Verlauf, keine neuen Zeiten).
 *
 * Die Funktionen ändern das übergebene Vault-Objekt direkt (in place). Der Uhr wird vorher
 * jede beteiligte Zeit gemeldet (observe), damit neue Zeitstempel immer die neuesten sind.
 *
 * Passkeys werden nur als Ganzes geschrieben (setPasskey/removePasskey), nie Attribut für
 * Attribut – sonst könnten beim Zusammenführen Teile zweier Passkeys gemischt werden.
 *
 * Texte mit Zeichen, die KDBX nicht speichern kann (Steuerzeichen außer Tab/LF/CR, U+FFFE,
 * U+FFFF, einzelne Surrogate; in geschützten Werten nur einzelne Surrogate), werden mit einem
 * RangeError abgelehnt und nie still verändert (checkStorable).
 */
import type { FieldKey } from "../contracts";
import type { DeletedObject, Entry, Group, Millis, ProtectedString, Uuid, Vault } from "../model";
import { cloneEntry } from "./clone";
import type { MonotonicClock } from "./clock";
import { MAX_KDBX_TIME, sameBytes, toSeconds } from "./encoding";
import { effectiveFieldTimes, newestFieldTime, sealFieldTimes, type FieldTime } from "./field-times";
import {
  COLORS_FIELD,
  entryFields,
  exactFieldBytes,
  fieldKind,
  isPasskeyAttribute,
  isStandardField,
  materializeStandardFields,
  OVERRIDE_URL_FIELD,
  PARENT_FIELD,
  PROPERTY_FIELDS,
  TAGS_FIELD,
  trimTag,
} from "./fields";
import { historySnapshot, truncateHistory } from "./history";
import { containsGroup, findEntryLocation, findGroupLocation, forEachGroup, type EntryLocation } from "./tree";

export { findEntry, findEntryLocation, findGroup, findGroupLocation } from "./tree";

/** Tag, das KeePassXC Einträgen mit Passkey gibt. */
export const PASSKEY_TAG = "Passkey";

/** Ordner-Icon (KeePass-Standard für Gruppen). */
const FOLDER_ICON = 48;

/** Eingabe für Text-Felder: einfacher Text oder Wert mit Schutz-Flag. */
export type FieldInput = string | ProtectedString;

// ---------------------------------------------------------------------------
// Einträge
// ---------------------------------------------------------------------------

export interface CreateEntryOptions {
  /** Feste UUID (sonst zufällig). */
  uuid?: Uuid;
  tags?: string[];
  iconId?: number;
}

/**
 * Legt einen Eintrag in der Gruppe `groupUuid` an. `fields` sind Text-Felder; ein einfacher
 * String ist ungeschützt, außer bei "Password". Fehlende Standardfelder werden leer angelegt
 * (wie bei KeePass). Passkey-Attribute bitte danach mit setPasskey setzen.
 */
export function createEntry(
  vault: Vault,
  groupUuid: Uuid,
  fields: Record<string, FieldInput>,
  clock: MonotonicClock,
  options: CreateEntryOptions = {},
): Entry {
  const group = requireGroup(vault, groupUuid);
  for (const name of Object.keys(fields)) checkFieldName(name);
  const uuid = options.uuid ?? newUuid();
  checkUuidFree(vault, uuid);

  const now = clock.now();
  const entry: Entry = {
    uuid,
    iconId: options.iconId ?? 0,
    foregroundColor: "",
    backgroundColor: "",
    overrideUrl: "",
    tags: sanitizeTags(options.tags ?? []),
    times: { creation: now, lastModification: now, lastAccess: now, expiry: now, expires: false, usageCount: 0, locationChanged: now },
    strings: new Map(Object.entries(fields).map(([name, value]) => [name, toProtectedString(name, value)])),
    attachments: [],
    customData: new Map(),
    history: [],
    unknown: [],
  };
  materializeStandardFields(entry);
  const times = new Map<FieldKey, FieldTime>();
  for (const key of entryFields(entry, group.uuid).keys()) times.set(key, { t: now, present: true });
  sealFieldTimes(entry, times, group.uuid);
  group.entries.push(entry);
  return entry;
}

/**
 * Allgemeine Änderung eines Eintrags: `mutate` bekommt eine KOPIE und darf daran alles ändern
 * außer UUID, Verlauf und Zeiten (die setzt editEntry; nur Ablauf/Ablaufzeit werden
 * übernommen). Welche Felder sich geändert haben, ermittelt editEntry selbst durch
 * Vergleich. Das Ergebnis wird in das BESTEHENDE Entry-Objekt übertragen (es bleibt dasselbe
 * Objekt im Baum) und zurückgegeben.
 */
export function editEntry(vault: Vault, entryUuid: Uuid, mutate: (draft: Entry) => void, clock: MonotonicClock): Entry {
  const { entry, group } = requireEntry(vault, entryUuid);
  const before = effectiveFieldTimes(entry, group.uuid);

  const draft = cloneEntry(entry);
  mutate(draft);
  draft.uuid = entry.uuid;
  draft.history = entry.history.map(cloneEntry);
  draft.times = { ...entry.times, expires: draft.times.expires, expiry: draft.times.expiry };

  const after = entryFields(draft, group.uuid);
  const changed = changedKeys(entry, draft, before.values, after);
  if (changed.length === 0) return entry;
  checkStorableFields(draft, changed);

  clock.observe(Math.max(newestFieldTime(before.times), entry.times.lastModification));
  const now = clock.now();
  draft.history = truncateHistory([...draft.history, historySnapshot(entry)], vault.meta.historyMaxItems, vault.meta.historyMaxSize);
  draft.times = { ...draft.times, lastModification: now, lastAccess: Math.max(draft.times.lastAccess, now) };
  const times = new Map(before.times);
  for (const key of changed) times.set(key, { t: now, present: after.has(key) });
  sealFieldTimes(draft, times, group.uuid);
  return replaceEntryContents(entry, draft);
}

/** Überträgt alle Eigenschaften von `source` auf `target` (fehlende werden entfernt). */
function replaceEntryContents(target: Entry, source: Entry): Entry {
  const record = target as unknown as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!(key in source)) delete record[key];
  Object.assign(target, source);
  return target;
}

export interface SetFieldOptions {
  /** Schutz-Flag; Standard: bisheriges Flag, bei neuen Feldern true nur für "Password". */
  protected?: boolean;
}

/** Setzt ein Text-Feld (nicht für Passkey-Attribute, siehe setPasskey). */
export function setField(
  vault: Vault,
  entryUuid: Uuid,
  name: string,
  value: string,
  options: SetFieldOptions,
  clock: MonotonicClock,
): Entry {
  checkFieldName(name);
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      const isProtected = options.protected ?? draft.strings.get(name)?.protected ?? name === "Password";
      draft.strings.set(name, { value, protected: isProtected });
    },
    clock,
  );
}

/** Entfernt ein Text-Feld. Standardfelder bleiben leer bestehen (wie bei KeePass). */
export function removeField(vault: Vault, entryUuid: Uuid, name: string, clock: MonotonicClock): Entry {
  checkFieldName(name);
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      const existing = draft.strings.get(name);
      if (isStandardField(name)) {
        if (existing !== undefined) draft.strings.set(name, { ...existing, value: "" });
      } else {
        draft.strings.delete(name);
      }
    },
    clock,
  );
}

export interface SetAttachmentOptions {
  /** Schutz-Flag im Binär-Pool; Standard true (wie KeePassXC). */
  protected?: boolean;
}

/** Setzt (oder ersetzt) einen Anhang. Die Bytes werden kopiert. */
export function setAttachment(
  vault: Vault,
  entryUuid: Uuid,
  name: string,
  data: Uint8Array,
  options: SetAttachmentOptions,
  clock: MonotonicClock,
): Entry {
  if (name === "") throw new RangeError("Ein Anhang braucht einen Namen.");
  checkStorable("Der Name des Anhangs", name);
  const copy = data.slice();
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      const existing = draft.attachments.find((item) => item.name === name);
      // Gleiche Bytes: altes (geteiltes) Array behalten, damit nichts als geändert gilt.
      const bytes = existing !== undefined && sameBytes(existing.data, copy) ? existing.data : copy;
      const attachment = { name, data: bytes, protected: options.protected ?? true };
      const index = draft.attachments.findIndex((item) => item.name === name);
      if (index >= 0) draft.attachments[index] = attachment;
      else draft.attachments.push(attachment);
    },
    clock,
  );
}

export function removeAttachment(vault: Vault, entryUuid: Uuid, name: string, clock: MonotonicClock): Entry {
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      draft.attachments = draft.attachments.filter((item) => item.name !== name);
    },
    clock,
  );
}

/**
 * Setzt die Tags. Leerraum am Rand wird entfernt, leere und doppelte Tags fallen weg.
 * Tags mit "," oder ";" sind nicht erlaubt (KeePass/KeePassXC trennen daran – aus einem Tag
 * würden beim nächsten Lesen zwei).
 */
export function setTags(vault: Vault, entryUuid: Uuid, tags: readonly string[], clock: MonotonicClock): Entry {
  const clean = sanitizeTags(tags);
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      draft.tags = clean;
    },
    clock,
  );
}

/**
 * Setzt den Passkey eines Eintrags als EINE Einheit: Alle bisherigen KPEX_PASSKEY_*- und
 * KPXC_PASSKEY_*-Attribute werden durch `attributes` ersetzt; dazu kommt das Tag "Passkey"
 * (wie bei KeePassXC). Einfache Strings sind ungeschützt, außer dem privaten Schlüssel
 * (KPEX_PASSKEY_PRIVATE_KEY_PEM).
 */
export function setPasskey(vault: Vault, entryUuid: Uuid, attributes: Record<string, FieldInput>, clock: MonotonicClock): Entry {
  const names = Object.keys(attributes);
  if (names.length === 0) throw new RangeError("setPasskey braucht mindestens ein Attribut (zum Entfernen: removePasskey).");
  for (const name of names) {
    if (!isPasskeyAttribute(name)) throw new RangeError(`"${name}" ist kein Passkey-Attribut (KPEX_PASSKEY_* oder KPXC_PASSKEY_*).`);
  }
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      for (const name of [...draft.strings.keys()]) if (isPasskeyAttribute(name)) draft.strings.delete(name);
      for (const [name, value] of Object.entries(attributes)) {
        const isProtected = typeof value === "string" ? name === "KPEX_PASSKEY_PRIVATE_KEY_PEM" : value.protected;
        draft.strings.set(name, { value: typeof value === "string" ? value : value.value, protected: isProtected });
      }
      if (!draft.tags.includes(PASSKEY_TAG)) draft.tags = [...draft.tags, PASSKEY_TAG];
    },
    clock,
  );
}

/** Entfernt den Passkey (alle Passkey-Attribute und das Tag "Passkey"). */
export function removePasskey(vault: Vault, entryUuid: Uuid, clock: MonotonicClock): Entry {
  return editEntry(
    vault,
    entryUuid,
    (draft) => {
      for (const name of [...draft.strings.keys()]) if (isPasskeyAttribute(name)) draft.strings.delete(name);
      draft.tags = draft.tags.filter((tag) => tag !== PASSKEY_TAG);
    },
    clock,
  );
}

/**
 * Verschiebt einen Eintrag in eine andere Gruppe. Kein Verlaufseintrag; lastModification und
 * locationChanged = jetzt (wie KeePassXC), Feld "parent" bekommt die neue Zeit.
 */
export function moveEntry(vault: Vault, entryUuid: Uuid, groupUuid: Uuid, clock: MonotonicClock): Entry {
  const location = requireEntry(vault, entryUuid);
  const target = requireGroup(vault, groupUuid);
  if (target === location.group) return location.entry;
  const { entry } = location;
  const before = effectiveFieldTimes(entry, location.group.uuid);
  clock.observe(Math.max(newestFieldTime(before.times), entry.times.lastModification, entry.times.locationChanged));
  const now = clock.now();

  entry.times = { ...entry.times, lastModification: now, locationChanged: now };
  const times = new Map(before.times);
  times.set(PARENT_FIELD, { t: now, present: true });
  sealFieldTimes(entry, times, target.uuid);
  location.group.entries.splice(location.index, 1);
  target.entries.push(entry);
  return entry;
}

/**
 * Löscht einen Eintrag endgültig: Er verschwindet samt Verlauf und bekommt einen
 * Lösch-Vermerk (DeletedObjects), damit er beim Zusammenführen nicht zurückkommt.
 * (Für „in den Papierkorb“ siehe recycleEntry.)
 */
export function deleteEntry(vault: Vault, entryUuid: Uuid, clock: MonotonicClock): void {
  const location = requireEntry(vault, entryUuid);
  observeEntry(clock, location.entry, location.group.uuid);
  const now = clock.now();
  location.group.entries.splice(location.index, 1);
  addDeletion(vault, entryUuid, now);
}

/**
 * „Löschen“ wie in KeePass: Ist der Papierkorb eingeschaltet, wird der Eintrag dorthin
 * verschoben (der Papierkorb wird bei Bedarf angelegt); liegt er schon im Papierkorb oder
 * ist der Papierkorb aus, wird er endgültig gelöscht. Liefert true, wenn verschoben wurde.
 */
export function recycleEntry(vault: Vault, entryUuid: Uuid, clock: MonotonicClock): boolean {
  const location = requireEntry(vault, entryUuid);
  if (!vault.meta.recycleBinEnabled) {
    deleteEntry(vault, entryUuid, clock);
    return false;
  }
  let bin = findGroupLocation(vault, vault.meta.recycleBinUuid)?.group;
  if (bin !== undefined && containsGroup(bin, location.group.uuid)) {
    deleteEntry(vault, entryUuid, clock);
    return false;
  }
  if (bin === undefined) {
    bin = createGroup(vault, vault.root.uuid, "Papierkorb", clock, { iconId: 43 });
    vault.meta.recycleBinUuid = bin.uuid;
    // Meta-Zeiten werden sekundengenau verglichen: mindestens die nächste ganze Sekunde.
    observeWholeSecond(clock, vault.meta.recycleBinChanged);
    vault.meta.recycleBinChanged = clock.now();
  }
  moveEntry(vault, entryUuid, bin.uuid, clock);
  return true;
}

// ---------------------------------------------------------------------------
// Gruppen
// ---------------------------------------------------------------------------

export interface CreateGroupOptions {
  uuid?: Uuid;
  iconId?: number;
}

/** Legt eine Gruppe unter `parentUuid` an. */
export function createGroup(vault: Vault, parentUuid: Uuid, name: string, clock: MonotonicClock, options: CreateGroupOptions = {}): Group {
  const parent = requireGroup(vault, parentUuid);
  checkStorable("Der Gruppenname", name);
  const uuid = options.uuid ?? newUuid();
  checkUuidFree(vault, uuid);
  const now = clock.now();
  const group: Group = {
    uuid,
    name,
    notes: "",
    iconId: options.iconId ?? FOLDER_ICON,
    times: { creation: now, lastModification: now, lastAccess: now, expiry: now, expires: false, usageCount: 0, locationChanged: now },
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
  };
  parent.groups.push(group);
  return group;
}

/**
 * Meldet der Uhr die letzte GANZE Millisekunde der Sekunde von `time`: Das nächste now() liegt
 * dann mindestens in der folgenden Sekunde. Nötig für alles, was nur sekundengenau verglichen
 * wird (Gruppen, Meta-Zeiten): Eine Änderung in derselben Sekunde wie die vorherige wäre sonst
 * ein Gleichstand und könnte gegen die ältere Fassung verlieren. In der letzten Sekunde des
 * KDBX-Bereichs gibt es keine folgende mehr: dann höchstens MAX_KDBX_TIME (sonst ignorierte die
 * Uhr den Wert als ungültig).
 */
function observeWholeSecond(clock: MonotonicClock, time: Millis): void {
  clock.observe(Math.min((toSeconds(time) + 1) * 1000 - 1, MAX_KDBX_TIME));
}

/** Benennt eine Gruppe um (lastModification = jetzt, mindestens die nächste ganze Sekunde). */
export function renameGroup(vault: Vault, groupUuid: Uuid, name: string, clock: MonotonicClock): Group {
  const group = requireGroup(vault, groupUuid);
  if (group.name === name) return group;
  checkStorable("Der Gruppenname", name);
  observeWholeSecond(clock, group.times.lastModification);
  const now = clock.now();
  group.name = name;
  group.times = { ...group.times, lastModification: now, lastAccess: Math.max(group.times.lastAccess, now) };
  return group;
}

/**
 * Verschiebt eine Gruppe (nicht die Wurzel, nicht in sich selbst oder eigene Untergruppen).
 * locationChanged = jetzt, mindestens die nächste ganze Sekunde (Gruppen werden sekundengenau
 * verglichen, siehe observeWholeSecond).
 */
export function moveGroup(vault: Vault, groupUuid: Uuid, newParentUuid: Uuid, clock: MonotonicClock): Group {
  const location = findGroupLocation(vault, groupUuid);
  if (location === undefined) throw new Error(`Gruppe ${groupUuid} nicht gefunden.`);
  if (location.parent === undefined) throw new Error("Die Wurzelgruppe lässt sich nicht verschieben.");
  const target = requireGroup(vault, newParentUuid);
  if (containsGroup(location.group, target.uuid)) throw new Error("Eine Gruppe kann nicht in sich selbst verschoben werden.");
  if (target === location.parent) return location.group;
  observeWholeSecond(clock, location.group.times.locationChanged);
  const now = clock.now();
  location.parent.groups.splice(location.index, 1);
  location.group.times = { ...location.group.times, locationChanged: now };
  target.groups.push(location.group);
  return location.group;
}

/**
 * Löscht eine Gruppe endgültig mit allem darin: Lösch-Vermerke für die Gruppe und für jeden
 * Eintrag und jede Untergruppe darin (wie KeePassXC).
 */
export function deleteGroup(vault: Vault, groupUuid: Uuid, clock: MonotonicClock): void {
  const location = findGroupLocation(vault, groupUuid);
  if (location === undefined) throw new Error(`Gruppe ${groupUuid} nicht gefunden.`);
  if (location.parent === undefined) throw new Error("Die Wurzelgruppe lässt sich nicht löschen.");
  const deleted: Uuid[] = [];
  forEachGroup(location.group, (group) => {
    clock.observe(Math.max(group.times.lastModification, group.times.locationChanged));
    deleted.push(group.uuid);
    for (const entry of group.entries) {
      observeEntry(clock, entry, group.uuid);
      deleted.push(entry.uuid);
    }
  });
  const now = clock.now();
  location.parent.groups.splice(location.index, 1);
  for (const uuid of deleted) addDeletion(vault, uuid, now);
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/**
 * Gruppen und Einträge teilen sich EINEN Namensraum für UUIDs (wie bei KeePass und beim
 * KDBX-Leser, spec/README.md 5.2); mergeVaults bricht bei doppelten UUIDs ab.
 */
function checkUuidFree(vault: Vault, uuid: Uuid): void {
  if (findEntryLocation(vault, uuid) !== undefined) throw new Error(`Es gibt schon einen Eintrag mit der UUID ${uuid}.`);
  if (findGroupLocation(vault, uuid) !== undefined) throw new Error(`Es gibt schon eine Gruppe mit der UUID ${uuid}.`);
}

function requireEntry(vault: Vault, entryUuid: Uuid): EntryLocation {
  const location = findEntryLocation(vault, entryUuid);
  if (location === undefined) throw new Error(`Eintrag ${entryUuid} nicht gefunden.`);
  return location;
}

function requireGroup(vault: Vault, groupUuid: Uuid): Group {
  const group = findGroupLocation(vault, groupUuid)?.group;
  if (group === undefined) throw new Error(`Gruppe ${groupUuid} nicht gefunden.`);
  return group;
}

function checkFieldName(name: string): void {
  if (name === "") throw new RangeError("Ein Feld braucht einen Namen.");
  checkStorable("Der Feldname", name);
  if (isPasskeyAttribute(name)) throw new RangeError(`"${name}" ist ein Passkey-Attribut – bitte setPasskey/removePasskey benutzen.`);
}

/**
 * Zeichen, die KDBX in Text nicht speichern kann – genau die, die der Writer still entfernt
 * (kdbx/xml-dom.ts, stripInvalidXmlChars): Steuerzeichen außer Tab, LF und CR (z. B. U+000B,
 * der „manuelle Zeilenumbruch“ aus Word), U+FFFE, U+FFFF und einzelne (ungepaarte)
 * UTF-16-Surrogate.
 */
const UNSTORABLE_TEXT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Geschützte Werte stehen verschlüsselt (Base64) in der Datei; dort geht nur ein einzelnes
 * Surrogat verloren: UTF-8 kennt es nicht, TextEncoder macht daraus U+FFFD.
 */
const UNSTORABLE_PROTECTED = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Lehnt Text mit Zeichen ab, die KDBX nicht speichern kann (UNSTORABLE_TEXT bzw. bei
 * geschützten Werten UNSTORABLE_PROTECTED). Still entfernen oder ersetzen kommt nicht in Frage:
 * Der Nutzer verlöre unbemerkt Daten, und das Modell im Speicher wiche von der Datei ab – jeder
 * Abgleich schriebe dann erneut (mit Sicherungskopie). Die Meldung nennt nie den Wert selbst.
 */
function checkStorable(what: string, text: string, isProtected = false): void {
  const match = (isProtected ? UNSTORABLE_PROTECTED : UNSTORABLE_TEXT).exec(text);
  if (match === null) return;
  const code = `U+${match[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
  const forbidden = isProtected
    ? "In geschützten Werten sind einzelne UTF-16-Surrogate nicht erlaubt."
    : "Nicht erlaubt sind Steuerzeichen außer Tabulator und Zeilenumbruch, U+FFFE, U+FFFF und einzelne UTF-16-Surrogate.";
  throw new RangeError(`${what} enthält das Zeichen ${code}, das KDBX nicht speichern kann. ${forbidden}`);
}

/** Prüft alle Texte eines Eintrags, die zu den geänderten Feldern `keys` gehören (checkStorable). */
function checkStorableFields(entry: Entry, keys: readonly FieldKey[]): void {
  const checkString = (name: string): void => {
    const value = entry.strings.get(name);
    if (value === undefined) return;
    checkStorable("Der Feldname", name);
    checkStorable(`Das Feld "${name}"`, value.value, value.protected);
  };
  for (const key of keys) {
    const kind = fieldKind(key);
    if (kind.kind === "string") {
      checkString(kind.name);
    } else if (kind.kind === "passkey") {
      for (const name of entry.strings.keys()) if (isPasskeyAttribute(name)) checkString(name);
    } else if (kind.kind === "attachment") {
      checkStorable("Der Name des Anhangs", kind.name);
    } else if (kind.kind === "customData") {
      const item = entry.customData.get(kind.name);
      if (item === undefined) continue;
      checkStorable("Der CustomData-Schlüssel", kind.name);
      checkStorable(`Der CustomData-Wert "${kind.name}"`, item.value);
    } else if (key === TAGS_FIELD) {
      for (const tag of entry.tags) checkStorable("Ein Tag", tag);
    } else if (key === COLORS_FIELD) {
      checkStorable("Die Vordergrundfarbe", entry.foregroundColor);
      checkStorable("Die Hintergrundfarbe", entry.backgroundColor);
    } else if (key === OVERRIDE_URL_FIELD) {
      checkStorable("Die OverrideURL", entry.overrideUrl);
    }
  }
}

/** Eingabe -> ProtectedString; ein einfacher String ist nur beim Feld "Password" geschützt. */
function toProtectedString(name: string, value: FieldInput): ProtectedString {
  const result = typeof value === "string" ? { value, protected: name === "Password" } : { ...value };
  checkStorable(`Das Feld "${name}"`, result.value, result.protected);
  return result;
}

/** Bereinigt Tags (siehe setTags); wirft bei Trennzeichen und bei Zeichen, die KDBX nicht speichern kann. */
export function sanitizeTags(tags: readonly string[]): string[] {
  const result: string[] = [];
  for (const raw of tags) {
    const tag = trimTag(raw);
    if (/[,;]/.test(tag)) throw new RangeError(`Tag "${tag}" enthält "," oder ";" – das ist in KDBX nicht möglich.`);
    checkStorable("Ein Tag", tag);
    if (tag !== "" && !result.includes(tag)) result.push(tag);
  }
  return result;
}

/** Felder, die sich geändert haben (Wert, Vorhandensein oder Rohdaten). */
function changedKeys(
  before: Entry,
  after: Entry,
  beforeValues: ReturnType<typeof entryFields>,
  afterValues: ReturnType<typeof entryFields>,
): FieldKey[] {
  const keys = new Set<FieldKey>([...beforeValues.keys(), ...afterValues.keys(), ...PROPERTY_FIELDS]);
  const changed: FieldKey[] = [];
  for (const key of keys) {
    const a = beforeValues.get(key);
    const b = afterValues.get(key);
    if ((a === undefined) !== (b === undefined)) changed.push(key);
    else if (!sameBytes(exactFieldBytes(before, key, beforeValues), exactFieldBytes(after, key, afterValues))) changed.push(key);
  }
  return changed;
}

/** Meldet der Uhr alle Zeiten eines Eintrags (für Löschen: Löschzeit > jede Änderung). */
function observeEntry(clock: MonotonicClock, entry: Entry, parentUuid: Uuid): void {
  const times = effectiveFieldTimes(entry, parentUuid).times;
  clock.observe(Math.max(newestFieldTime(times), entry.times.lastModification, entry.times.locationChanged));
}

function addDeletion(vault: Vault, uuid: Uuid, time: Millis): void {
  const existing = vault.deletedObjects.find((item: DeletedObject) => item.uuid === uuid);
  if (existing !== undefined) existing.deletionTime = Math.max(existing.deletionTime, time);
  else vault.deletedObjects.push({ uuid, deletionTime: time });
}

/** Neue zufällige UUID (16 Byte aus crypto.getRandomValues, Base64). */
function newUuid(): Uuid {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
