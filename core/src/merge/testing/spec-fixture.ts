/**
 * NUR FÜR TESTS: Übersetzt die sprachneutralen Merge-Testfälle aus spec/merge-cases/*.json
 * in Modell-Objekte und das Ergebnis eines Merge zurück in eine vergleichbare Form.
 * Das JSON-Format ist in spec/README.md beschrieben; die Kotlin-Implementierung baut ihren
 * eigenen Läufer nach derselben Beschreibung.
 *
 * Kein Node-API (liegt unter src/), Dateien liest der Test selbst.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { FIELD_TIMES_KEY, type MergeReport } from "../../contracts";
import { NULL_UUID, type Attachment, type CustomData, type Entry, type Group, type Uuid, type Vault } from "../../model";
import { effectiveFieldTimes, sealFieldTimes, type FieldTime } from "../field-times";
import { entryFields, IGNORED_CUSTOM_DATA_KEYS, isStandardField, normalizeTags, significantUnknown } from "../fields";
import { historySnapshot } from "../history";
import { RECOVERY_GROUP_UUID } from "../merge";

// ---------------------------------------------------------------------------
// JSON-Format (siehe spec/README.md)
// ---------------------------------------------------------------------------

export interface SpecCase {
  name: string;
  description: string;
  now?: number;
  local: SpecVault;
  remote: SpecVault;
  expected: SpecVault;
  expectedReport?: SpecReport;
  /** Bericht, wenn local und remote vertauscht sind (optional). */
  expectedReportSwapped?: SpecReport;
}

export interface SpecVault {
  root?: string;
  rootName?: string;
  rootLastModification?: number;
  databaseName?: string;
  databaseNameChanged?: number;
  recycleBin?: string | null;
  recycleBinChanged?: number;
  historyMaxItems?: number;
  historyMaxSize?: number;
  groups?: SpecGroup[];
  entries?: SpecEntry[];
  deleted?: SpecDeleted[];
}

export interface SpecGroup {
  uuid: string;
  name?: string;
  parent?: string;
  notes?: string;
  lastModification?: number;
  locationChanged?: number;
}

export interface SpecDeleted {
  uuid: string;
  time: number;
}

/** Inhalt eines Eintrags bzw. einer Fassung im Verlauf. */
export interface SpecContent {
  fields?: Record<string, string>;
  protected?: string[];
  attachments?: Record<string, string>;
  tags?: string[];
  iconId?: number;
  customIcon?: string;
  expiry?: number;
  customData?: Record<string, string>;
  foregroundColor?: string;
  backgroundColor?: string;
  overrideUrl?: string;
  /** Standard true; false = Passwortqualität nicht prüfen (KDBX 4.1). */
  qualityCheck?: boolean;
  /** Unbekannte XML-Elemente (z. B. AutoType), kompakt als Text. */
  unknown?: string[];
}

export interface SpecHistoryItem extends SpecContent {
  lastModification: number;
}

export interface SpecEntry extends SpecContent {
  uuid: string;
  parent?: string;
  creation?: number;
  lastModification?: number;
  locationChanged?: number;
  fieldTimes?: Record<string, number> | null;
  external?: SpecExternal;
  history?: SpecHistoryItem[];
}

export interface SpecExternal {
  lastModification: number;
  parent?: string;
  locationChanged?: number;
  set?: Record<string, string>;
  protected?: string[];
  remove?: string[];
  attachments?: Record<string, string | null>;
  tags?: string[];
  iconId?: number;
  addHistory?: boolean;
}

export interface SpecReport {
  entriesAddedFromRemote?: number;
  entriesUpdated?: number;
  entriesDeleted?: number;
  entriesResurrected?: number;
  groupsChanged?: number;
  orphansRecovered?: number;
  fieldConflicts?: { entry: string; field: string; winner: "local" | "remote"; tieBreak: boolean }[];
  externalEdits?: string[];
}

/** Standardwerte (siehe spec/README.md). */
export const SPEC_DEFAULT_NOW = 1_700_001_000_000;
const DEFAULT_ROOT = "root";
const DEFAULT_ROOT_TIME = 1_600_000_000_000;
const RECOVERY_NAME = "@recovery";

// ---------------------------------------------------------------------------
// Namen <-> UUIDs
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** Lesbarer Name -> UUID: "@recovery" = Wiederherstellungsgruppe, "b64:…" wörtlich, sonst SHA-256. */
export function specUuid(name: string): Uuid {
  if (name === RECOVERY_NAME) return RECOVERY_GROUP_UUID;
  if (name.startsWith("b64:")) return name.slice(4);
  return toBase64(sha256(new TextEncoder().encode(name)).subarray(0, 16));
}

/** Rückrichtung für lesbare Testausgaben. */
export class SpecNames {
  private readonly byUuid = new Map<Uuid, string>([
    [RECOVERY_GROUP_UUID, RECOVERY_NAME],
    [specUuid(DEFAULT_ROOT), DEFAULT_ROOT],
  ]);

  name(uuid: Uuid): string {
    return this.byUuid.get(uuid) ?? `b64:${uuid}`;
  }

  /** Merkt sich alle Texte eines Testfalls als mögliche Namen (zu viele schaden nicht). */
  learn(value: unknown): void {
    if (typeof value === "string") {
      if (!value.startsWith("b64:") && value !== RECOVERY_NAME) this.byUuid.set(specUuid(value), value);
    } else if (Array.isArray(value)) {
      value.forEach((item) => this.learn(item));
    } else if (typeof value === "object" && value !== null) {
      Object.values(value).forEach((item) => this.learn(item));
    }
  }
}

/** Anhang-Inhalt: UTF-8-Text, oder Bytes mit Präfix "base64:". */
function attachmentBytes(value: string): Uint8Array {
  return value.startsWith("base64:") ? fromBase64(value.slice(7)) : new TextEncoder().encode(value);
}

function attachmentText(data: Uint8Array): string {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
    if (!text.startsWith("base64:")) return text;
  } catch {
    // keine gültige UTF-8-Folge -> Base64
  }
  return `base64:${toBase64(data)}`;
}

// ---------------------------------------------------------------------------
// JSON -> Modell
// ---------------------------------------------------------------------------

/** Baut die Datenbank einer Seite. */
export function buildSpecVault(spec: SpecVault): Vault {
  const rootUuid = specUuid(spec.root ?? DEFAULT_ROOT);
  const rootTime = spec.rootLastModification ?? DEFAULT_ROOT_TIME;
  const root = emptyGroup(rootUuid, spec.rootName ?? "Root", rootTime, rootTime);
  const groups = new Map<Uuid, Group>([[rootUuid, root]]);

  // Gruppen: erst alle anlegen, dann einhängen (Reihenfolge im JSON = Geschwister-Reihenfolge).
  for (const g of spec.groups ?? []) {
    const lastModification = g.lastModification ?? DEFAULT_ROOT_TIME;
    const group = emptyGroup(specUuid(g.uuid), g.name ?? g.uuid, lastModification, g.locationChanged ?? lastModification);
    group.notes = g.notes ?? "";
    groups.set(group.uuid, group);
  }
  for (const g of spec.groups ?? []) {
    const parent = groups.get(specUuid(g.parent ?? spec.root ?? DEFAULT_ROOT));
    if (parent === undefined) throw new Error(`Testfall: Elterngruppe ${g.parent} von ${g.uuid} fehlt`);
    parent.groups.push(groups.get(specUuid(g.uuid))!);
  }
  for (const e of spec.entries ?? []) {
    const parentName = e.external?.parent ?? e.parent ?? spec.root ?? DEFAULT_ROOT;
    const parent = groups.get(specUuid(parentName));
    if (parent === undefined) throw new Error(`Testfall: Gruppe ${parentName} von Eintrag ${e.uuid} fehlt`);
    parent.entries.push(buildSpecEntry(e, specUuid(e.parent ?? spec.root ?? DEFAULT_ROOT)));
  }

  return {
    settings: {
      versionMinor: 0,
      cipher: "aes256",
      compression: true,
      kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 },
    },
    meta: {
      generator: "Ownwarden",
      databaseName: spec.databaseName ?? "",
      databaseNameChanged: spec.databaseNameChanged ?? DEFAULT_ROOT_TIME,
      recycleBinEnabled: spec.recycleBin !== null,
      recycleBinUuid: spec.recycleBin ? specUuid(spec.recycleBin) : NULL_UUID,
      recycleBinChanged: spec.recycleBinChanged ?? DEFAULT_ROOT_TIME,
      historyMaxItems: spec.historyMaxItems ?? 10,
      historyMaxSize: spec.historyMaxSize ?? -1,
      customIcons: [],
      customData: new Map(),
      unknown: [],
    },
    root,
    deletedObjects: (spec.deleted ?? []).map((d) => ({ uuid: specUuid(d.uuid), deletionTime: d.time })),
    rootUnknown: [],
  };
}

function emptyGroup(uuid: Uuid, name: string, lastModification: number, locationChanged: number): Group {
  return {
    uuid,
    name,
    notes: "",
    iconId: 48,
    times: {
      creation: Math.min(lastModification, locationChanged),
      lastModification,
      lastAccess: lastModification,
      expiry: lastModification,
      expires: false,
      usageCount: 0,
      locationChanged,
    },
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
  };
}

/** Inhalt (Felder, Anhänge, …) auf einen Eintrag anwenden. */
function applyContent(entry: Entry, content: SpecContent): void {
  const protectedNames = new Set(content.protected ?? []);
  entry.strings = new Map(Object.entries(content.fields ?? {}).map(([name, value]) => [name, { value, protected: protectedNames.has(name) }]));
  entry.attachments = Object.entries(content.attachments ?? {}).map(
    ([name, value]): Attachment => ({ name, data: attachmentBytes(value), protected: true }),
  );
  entry.tags = [...(content.tags ?? [])];
  entry.iconId = content.iconId ?? 0;
  if (content.customIcon !== undefined) entry.customIconUuid = specUuid(content.customIcon);
  if (content.expiry !== undefined) entry.times = { ...entry.times, expires: true, expiry: content.expiry };
  entry.customData = new Map(Object.entries(content.customData ?? {}).map(([key, value]) => [key, { value }]));
  entry.foregroundColor = content.foregroundColor ?? "";
  entry.backgroundColor = content.backgroundColor ?? "";
  entry.overrideUrl = content.overrideUrl ?? "";
  if (content.qualityCheck === false) entry.qualityCheck = false;
  entry.unknown = [...(content.unknown ?? [])];
}

function baseEntry(uuid: Uuid, lastModification: number): Entry {
  return {
    uuid,
    iconId: 0,
    foregroundColor: "",
    backgroundColor: "",
    overrideUrl: "",
    tags: [],
    times: {
      creation: lastModification,
      lastModification,
      lastAccess: lastModification,
      expiry: lastModification,
      expires: false,
      usageCount: 0,
      locationChanged: lastModification,
    },
    strings: new Map(),
    attachments: [],
    customData: new Map(),
    history: [],
    unknown: [],
  };
}

/** Baut einen Eintrag (Ablauf siehe spec/README.md: Inhalt, Verlauf, Versiegeln, externe Änderung). */
export function buildSpecEntry(spec: SpecEntry, parentUuid: Uuid): Entry {
  const uuid = specUuid(spec.uuid);
  const lastModification = spec.lastModification ?? DEFAULT_ROOT_TIME;
  const locationChanged = spec.locationChanged ?? lastModification;
  const entry = baseEntry(uuid, lastModification);
  entry.times = { ...entry.times, creation: spec.creation ?? Math.min(lastModification, locationChanged), locationChanged };
  applyContent(entry, spec);
  entry.history = (spec.history ?? []).map((item) => {
    const historyEntry = baseEntry(uuid, item.lastModification);
    applyContent(historyEntry, item);
    return historyEntry;
  });

  if (spec.fieldTimes !== undefined && spec.fieldTimes !== null) {
    const values = entryFields(entry, parentUuid);
    const times = new Map<string, FieldTime>();
    for (const [key, t] of Object.entries(spec.fieldTimes)) times.set(key, { t, present: values.has(key) });
    sealFieldTimes(entry, times, parentUuid);
  }
  if (spec.external !== undefined) applyExternal(entry, spec.external);
  return entry;
}

/** Simuliert eine Änderung durch ein anderes Programm NACH dem Versiegeln (FieldTimes bleiben). */
function applyExternal(entry: Entry, external: SpecExternal): void {
  if (external.addHistory) {
    const snapshot = historySnapshot(entry);
    snapshot.customData = new Map(); // KeePassXC übernimmt CustomData nicht in den Verlauf
    entry.history.push(snapshot);
  }
  const protectedNames = new Set(external.protected ?? []);
  for (const [name, value] of Object.entries(external.set ?? {})) entry.strings.set(name, { value, protected: protectedNames.has(name) });
  for (const name of external.remove ?? []) entry.strings.delete(name);
  for (const [name, value] of Object.entries(external.attachments ?? {})) {
    entry.attachments = entry.attachments.filter((a) => a.name !== name);
    if (value !== null) entry.attachments.push({ name, data: attachmentBytes(value), protected: true });
  }
  if (external.tags !== undefined) entry.tags = [...external.tags];
  if (external.iconId !== undefined) entry.iconId = external.iconId;
  entry.times = { ...entry.times, lastModification: external.lastModification };
  if (external.parent !== undefined) entry.times.locationChanged = external.locationChanged ?? external.lastModification;
}

// ---------------------------------------------------------------------------
// Ergebnis -> vergleichbare Form
// ---------------------------------------------------------------------------

/** Vergleichbare Beschreibung einer Datenbank (siehe describeSpec). */
export interface Described {
  groups: Record<string, Record<string, unknown>>;
  entries: Record<string, Record<string, unknown>>;
  deleted: Record<string, number>;
  recycleBin?: string | null;
  databaseName?: string;
}

/**
 * Beschreibt das tatsächliche Ergebnis in der Form, in der `describeExpected` die Erwartung
 * beschreibt. Zeiten, Feld-Zeitstempel und Verlauf nur, soweit die Erwartung sie nennt.
 */
export function describeActual(vault: Vault, expected: SpecVault, names: SpecNames): Described {
  const expectedGroups = new Map((expected.groups ?? []).map((g) => [specUuid(g.uuid), g]));
  const expectedEntries = new Map((expected.entries ?? []).map((e) => [specUuid(e.uuid), e]));
  const groups: Described["groups"] = {};
  const entries: Described["entries"] = {};

  const walk = (group: Group): void => {
    for (const child of group.groups) {
      const template = expectedGroups.get(child.uuid);
      const described: Record<string, unknown> = { name: child.name, parent: names.name(group.uuid) };
      if (child.notes !== "") described.notes = child.notes;
      if (template?.lastModification !== undefined) described.lastModification = child.times.lastModification;
      if (template?.locationChanged !== undefined) described.locationChanged = child.times.locationChanged;
      groups[names.name(child.uuid)] = described;
      walk(child);
    }
    for (const entry of group.entries) {
      entries[names.name(entry.uuid)] = describeEntry(entry, group.uuid, expectedEntries.get(entry.uuid), names);
    }
  };
  walk(vault.root);

  const result: Described = {
    groups,
    entries,
    deleted: Object.fromEntries(vault.deletedObjects.map((d) => [names.name(d.uuid), d.deletionTime])),
  };
  if (expected.recycleBin !== undefined) {
    result.recycleBin = vault.meta.recycleBinEnabled ? names.name(vault.meta.recycleBinUuid) : null;
  }
  if (expected.databaseName !== undefined) result.databaseName = vault.meta.databaseName;
  return result;
}

function describeContent(entry: Entry, names: SpecNames): Record<string, unknown> {
  const fields: Record<string, string> = {};
  const protectedNames: string[] = [];
  for (const [name, value] of entry.strings) {
    if (value.value === "" && isStandardField(name)) continue; // leeres Standardfeld = nicht vorhanden
    fields[name] = value.value;
    if (value.protected) protectedNames.push(name);
  }
  return {
    fields,
    protected: protectedNames.sort(),
    attachments: Object.fromEntries(entry.attachments.map((a) => [a.name, attachmentText(a.data)])),
    tags: normalizeTags(entry.tags),
    icon: entry.customIconUuid !== undefined ? `custom:${names.name(entry.customIconUuid)}` : entry.iconId,
    expiry: entry.times.expires ? entry.times.expiry : null,
    customData: describeCustomData(entry.customData),
    colors: [entry.foregroundColor, entry.backgroundColor],
    overrideUrl: entry.overrideUrl,
    qualityCheck: entry.qualityCheck !== false,
    unknown: significantUnknown(entry.unknown),
  };
}

function describeCustomData(customData: CustomData): Record<string, string> {
  return Object.fromEntries([...customData].filter(([key]) => !IGNORED_CUSTOM_DATA_KEYS.has(key)).map(([key, item]) => [key, item.value]));
}

function describeEntry(entry: Entry, parent: Uuid, template: SpecEntry | undefined, names: SpecNames): Record<string, unknown> {
  const described: Record<string, unknown> = { parent: names.name(parent), ...describeContent(entry, names) };
  if (template?.lastModification !== undefined) described.lastModification = entry.times.lastModification;
  if (template?.locationChanged !== undefined) described.locationChanged = entry.times.locationChanged;
  if (template?.creation !== undefined) described.creation = entry.times.creation;
  if (template?.fieldTimes) {
    const times = effectiveFieldTimes(entry, parent).times;
    described.fieldTimes = Object.fromEntries(
      Object.keys(template.fieldTimes).map((key) => {
        const time = times.get(key);
        return [key, time === undefined ? "fehlt" : time.present ? time.t : { deleted: time.t }];
      }),
    );
    described.sealed = entry.customData.has(FIELD_TIMES_KEY);
  }
  if (template?.history !== undefined) {
    const expectedHistory = template.history;
    described.history = entry.history.map((item, i) => ({
      lastModification: item.times.lastModification,
      fields: describeContent(item, names).fields,
      // Nennt die Erwartung unbekannte Elemente, zählen sie ROH (auch das Standard-AutoType).
      ...(expectedHistory[i]?.unknown !== undefined ? { unknown: item.unknown } : {}),
    }));
  }
  return described;
}

/** Die Erwartung in derselben Form wie describeActual. */
export function describeExpected(expected: SpecVault): Described {
  const root = expected.root ?? DEFAULT_ROOT;
  const groups: Described["groups"] = {};
  for (const g of expected.groups ?? []) {
    const described: Record<string, unknown> = { name: g.name ?? g.uuid, parent: g.parent ?? root };
    if (g.notes !== undefined && g.notes !== "") described.notes = g.notes;
    if (g.lastModification !== undefined) described.lastModification = g.lastModification;
    if (g.locationChanged !== undefined) described.locationChanged = g.locationChanged;
    groups[g.uuid] = described;
  }
  const entries: Described["entries"] = {};
  for (const e of expected.entries ?? []) {
    const described: Record<string, unknown> = { parent: e.parent ?? root, ...expectedContent(e) };
    if (e.lastModification !== undefined) described.lastModification = e.lastModification;
    if (e.locationChanged !== undefined) described.locationChanged = e.locationChanged;
    if (e.creation !== undefined) described.creation = e.creation;
    if (e.fieldTimes) {
      const fields = e.fields ?? {};
      described.fieldTimes = Object.fromEntries(
        Object.entries(e.fieldTimes).map(([key, t]) => [key, isExpectedPresent(e, key, fields) ? t : { deleted: t }]),
      );
      described.sealed = true;
    }
    if (e.history !== undefined) {
      described.history = e.history.map((item) => ({
        lastModification: item.lastModification,
        fields: withoutEmptyStandard(item.fields ?? {}),
        ...(item.unknown !== undefined ? { unknown: item.unknown } : {}),
      }));
    }
    entries[e.uuid] = described;
  }
  const result: Described = {
    groups,
    entries,
    deleted: Object.fromEntries((expected.deleted ?? []).map((d) => [d.uuid, d.time])),
  };
  if (expected.recycleBin !== undefined) result.recycleBin = expected.recycleBin;
  if (expected.databaseName !== undefined) result.databaseName = expected.databaseName;
  return result;
}

function withoutEmptyStandard(fields: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(fields).filter(([name, value]) => !(value === "" && isStandardField(name))));
}

function expectedContent(content: SpecContent): Record<string, unknown> {
  const fields = withoutEmptyStandard(content.fields ?? {});
  return {
    fields,
    protected: (content.protected ?? []).filter((name) => name in fields).sort(),
    attachments: { ...(content.attachments ?? {}) },
    tags: normalizeTags(content.tags ?? []),
    icon: content.customIcon !== undefined ? `custom:${content.customIcon}` : (content.iconId ?? 0),
    expiry: content.expiry ?? null,
    customData: { ...(content.customData ?? {}) },
    colors: [content.foregroundColor ?? "", content.backgroundColor ?? ""],
    overrideUrl: content.overrideUrl ?? "",
    qualityCheck: content.qualityCheck !== false,
    unknown: significantUnknown(content.unknown ?? []),
  };
}

/** Ist das Feld `key` in der Erwartung vorhanden (sonst ist ein Lösch-Marker gemeint)? */
function isExpectedPresent(e: SpecEntry, key: string, fields: Record<string, string>): boolean {
  if (key === "parent") return true;
  if (key.startsWith("s:")) {
    const name = key.slice(2);
    return name in fields && !(fields[name] === "" && isStandardField(name));
  }
  if (key.startsWith("a:")) return key.slice(2) in (e.attachments ?? {});
  if (key.startsWith("cd:")) return key.slice(3) in (e.customData ?? {});
  if (key === "passkey") return Object.keys(fields).some((name) => /^KP(EX|XC)_PASSKEY_/.test(name));
  if (key === "tags") return (e.tags ?? []).length > 0;
  if (key === "icon") return e.customIcon !== undefined || (e.iconId ?? 0) !== 0;
  if (key === "expiry") return e.expiry !== undefined;
  if (key === "colors") return (e.foregroundColor ?? "") !== "" || (e.backgroundColor ?? "") !== "";
  if (key === "overrideUrl") return (e.overrideUrl ?? "") !== "";
  if (key === "misc") return e.qualityCheck === false || significantUnknown(e.unknown ?? []).length > 0;
  throw new Error(`Testfall: Feld-Zeitstempel für "${key}" in der Erwartung wird nicht unterstützt`);
}

// ---------------------------------------------------------------------------
// Bericht
// ---------------------------------------------------------------------------

/**
 * Der Bericht in der Form der Erwartung (nur die dort genannten Angaben). `swapped`: Der
 * Testfall lief mit vertauschten Seiten – dann ist der erwartete Gewinner die andere Seite.
 */
export function describeReport(report: MergeReport, expected: SpecReport, names: SpecNames): SpecReport {
  const result: SpecReport = {};
  for (const key of ["entriesAddedFromRemote", "entriesUpdated", "entriesDeleted", "entriesResurrected", "groupsChanged", "orphansRecovered"] as const) {
    if (expected[key] !== undefined) result[key] = report[key];
  }
  if (expected.fieldConflicts !== undefined) {
    result.fieldConflicts = report.fieldConflicts
      .map((c) => ({ entry: names.name(c.entryUuid), field: c.field, winner: c.winner, tieBreak: c.tieBreak }))
      .sort(compareConflicts);
  }
  if (expected.externalEdits !== undefined) result.externalEdits = report.externalEdits.map((uuid) => names.name(uuid)).sort();
  return result;
}

/**
 * Erwarteter Bericht für eine Richtung. Mit vertauschten Seiten (und ohne eigenes
 * expectedReportSwapped) gelten nur die richtungsunabhängigen Angaben, die Gewinner der
 * Feldkonflikte werden getauscht.
 */
export function expectedReportFor(testCase: SpecCase, swapped: boolean): SpecReport | undefined {
  if (swapped && testCase.expectedReportSwapped !== undefined) return normalizeReport(testCase.expectedReportSwapped, false);
  if (testCase.expectedReport === undefined) return undefined;
  if (!swapped) return normalizeReport(testCase.expectedReport, false);
  const { entriesDeleted, entriesResurrected, orphansRecovered, fieldConflicts, externalEdits } = testCase.expectedReport;
  const symmetric = Object.fromEntries(
    Object.entries({ entriesDeleted, entriesResurrected, orphansRecovered, fieldConflicts, externalEdits }).filter(([, v]) => v !== undefined),
  ) as SpecReport;
  return normalizeReport(symmetric, true);
}

function normalizeReport(expected: SpecReport, swapped: boolean): SpecReport {
  const result: SpecReport = { ...expected };
  if (expected.fieldConflicts !== undefined) {
    result.fieldConflicts = expected.fieldConflicts
      .map((c) => ({ ...c, winner: swapped ? (c.winner === "local" ? "remote" : "local") : c.winner }))
      .sort(compareConflicts);
  }
  if (expected.externalEdits !== undefined) result.externalEdits = [...expected.externalEdits].sort();
  return result;
}

function compareConflicts(a: { entry: string; field: string }, b: { entry: string; field: string }): number {
  return a.entry < b.entry ? -1 : a.entry > b.entry ? 1 : a.field < b.field ? -1 : a.field > b.field ? 1 : 0;
}
