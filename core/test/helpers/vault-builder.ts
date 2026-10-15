/**
 * Bausteine für Tests: Vault-, Gruppen- und Eintrags-Objekte mit VOLLSTÄNDIGEN Standardwerten
 * (alle Pflichtfelder aus model.ts gesetzt), damit Tests nur das angeben müssen, worum es geht.
 *
 * Benutzt von den Tests in src/merge/ und gedacht für alle weiteren Tests (sync/, cli/ …).
 * Nur für Tests: Diese Datei darf Node-APIs benutzen (tut es aber nicht).
 *
 * Beispiele:
 *   const vault = newVault({
 *     root: newGroup({ name: "Root", entries: [newEntry({ title: "Mail", fields: { Password: "geheim" } })] }),
 *   });
 *   const entry = newEntry({ uuid: uuidFromName("e1"), at: T0 + 5000, fields: { Title: "Bank", UserName: "bob" } });
 *
 * Zeiten: Alle Zeiten sind Millisekunden. `at` setzt alle Zeiten eines Objekts auf einmal
 * (Erstellung, Änderung, letzter Zugriff, Verschiebung). Standard ist T0.
 *
 * UUIDs: `uuidFromName("e1")` liefert eine feste, gut wiedererkennbare UUID – dieselbe
 * Abbildung benutzt der Läufer der Merge-Testfälle in spec/ (siehe spec/README.md):
 * Base64 der ersten 16 Byte von SHA-256(UTF-8(name)).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import {
  NULL_UUID,
  STANDARD_FIELDS,
  type Attachment,
  type Entry,
  type Group,
  type KdbxSettings,
  type KdbxTimes,
  type Meta,
  type Millis,
  type ProtectedString,
  type Uuid,
  type Vault,
} from "../../src/model";

/** Bezugszeitpunkt für Tests: 2023-11-14T22:13:20Z. */
export const T0: Millis = 1_700_000_000_000;

// ---------------------------------------------------------------------------
// UUIDs
// ---------------------------------------------------------------------------

/** Bytes -> Base64 (ohne Node-Buffer, damit die Datei überall läuft). */
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Feste UUID zu einem lesbaren Namen: Base64 der ersten 16 Byte von SHA-256(UTF-8(name)).
 * Gleicher Name -> gleiche UUID, in jedem Test und in jeder Implementierung (Kotlin).
 */
export function uuidFromName(name: string): Uuid {
  return toBase64(sha256(new TextEncoder().encode(name)).subarray(0, 16));
}

/** Zufällige UUID (16 Byte aus crypto.getRandomValues). */
export function randomUuid(): Uuid {
  return toBase64(crypto.getRandomValues(new Uint8Array(16)));
}

// ---------------------------------------------------------------------------
// Einzelteile
// ---------------------------------------------------------------------------

/** <Times> mit allen Zeiten = `at` (Ablauf aus, Zähler 0); `overrides` ersetzt Einzelwerte. */
export function newTimes(at: Millis = T0, overrides: Partial<KdbxTimes> = {}): KdbxTimes {
  return {
    creation: at,
    lastModification: at,
    lastAccess: at,
    expiry: at,
    expires: false,
    usageCount: 0,
    locationChanged: at,
    ...overrides,
  };
}

/** Ungeschützter Text-Wert. */
export function plain(value: string): ProtectedString {
  return { value, protected: false };
}

/** Geschützter Text-Wert (in der Datei mit dem inneren Strom verschlüsselt). */
export function secret(value: string): ProtectedString {
  return { value, protected: true };
}

/** Anhang aus Text (UTF-8) oder Bytes; Schutz-Flag wie bei KeePassXC standardmäßig an. */
export function attachment(name: string, data: string | Uint8Array, isProtected = true): Attachment {
  return { name, data: typeof data === "string" ? new TextEncoder().encode(data) : data, protected: isProtected };
}

/**
 * Text-Felder als Map. Ein einfacher String ist ungeschützt – außer beim Feld "Password",
 * das (wie bei KeePass) geschützt angelegt wird. Ein ProtectedString wird übernommen.
 */
export function stringsFrom(fields: Record<string, string | ProtectedString>): Map<string, ProtectedString> {
  const strings = new Map<string, ProtectedString>();
  for (const [name, value] of Object.entries(fields)) {
    strings.set(name, typeof value === "string" ? { value, protected: name === "Password" } : { ...value });
  }
  return strings;
}

// ---------------------------------------------------------------------------
// Einträge, Gruppen, Datenbank
// ---------------------------------------------------------------------------

export interface EntryOptions extends Partial<Entry> {
  /** Alle Zeiten des Eintrags (überschreibbar über `times`). Standard T0. */
  at?: Millis;
  /** Kurzform für das Feld "Title". */
  title?: string;
  /** Text-Felder (siehe stringsFrom); werden zu `strings` hinzugefügt. */
  fields?: Record<string, string | ProtectedString>;
  /** true: fehlende Standardfelder (Title, UserName, Password, URL, Notes) leer anlegen – wie KeePassXC. */
  materialize?: boolean;
}

/**
 * Neuer Eintrag mit Standardwerten: zufällige UUID, Icon 0, keine Farben/Tags/Anhänge,
 * alle Zeiten = `at`. Felder über `title`/`fields` oder direkt über `strings`.
 */
export function newEntry(options: EntryOptions = {}): Entry {
  const { at = T0, title, fields, materialize = false, ...overrides } = options;
  const strings = new Map(overrides.strings ?? []);
  if (title !== undefined) strings.set("Title", plain(title));
  for (const [name, value] of stringsFrom(fields ?? {})) strings.set(name, value);
  if (materialize) {
    for (const name of STANDARD_FIELDS) if (!strings.has(name)) strings.set(name, { value: "", protected: name === "Password" });
  }
  return {
    uuid: randomUuid(),
    iconId: 0,
    foregroundColor: "",
    backgroundColor: "",
    overrideUrl: "",
    tags: [],
    attachments: [],
    customData: new Map(),
    history: [],
    unknown: [],
    ...overrides,
    times: { ...newTimes(at), ...overrides.times },
    strings,
  };
}

export interface GroupOptions extends Partial<Group> {
  /** Alle Zeiten der Gruppe (überschreibbar über `times`). Standard T0. */
  at?: Millis;
}

/** Neue Gruppe mit Standardwerten: zufällige UUID, Name "Gruppe", Ordner-Icon 48, leer. */
export function newGroup(options: GroupOptions = {}): Group {
  const { at = T0, ...overrides } = options;
  return {
    uuid: randomUuid(),
    name: "Gruppe",
    notes: "",
    iconId: 48,
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
    ...overrides,
    times: { ...newTimes(at), ...overrides.times },
  };
}

/** Schnelle, aber gültige KDBX-Einstellungen für Tests (Argon2id mit 1 MiB, 2 Runden). */
export function newSettings(overrides: Partial<KdbxSettings> = {}): KdbxSettings {
  return {
    versionMinor: 0,
    cipher: "aes256",
    compression: true,
    kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 1 << 20, iterations: 2, version: 0x13 },
    ...overrides,
  };
}

/** <Meta> mit Standardwerten wie bei KeePassXC (Verlauf: 10 Einträge, 6 MiB). */
export function newMeta(overrides: Partial<Meta> = {}): Meta {
  return {
    generator: "Ownwarden",
    databaseName: "",
    databaseNameChanged: T0,
    recycleBinEnabled: true,
    recycleBinUuid: NULL_UUID,
    recycleBinChanged: T0,
    historyMaxItems: 10,
    historyMaxSize: 6 * 1024 * 1024,
    customIcons: [],
    customData: new Map(),
    unknown: [],
    ...overrides,
  };
}

export interface VaultOptions {
  root?: Group;
  meta?: Partial<Meta>;
  settings?: Partial<KdbxSettings>;
  deletedObjects?: Vault["deletedObjects"];
  rootUnknown?: string[];
}

/** Neue Datenbank; ohne `root` mit einer leeren Wurzelgruppe "Root". */
export function newVault(options: VaultOptions = {}): Vault {
  return {
    settings: newSettings(options.settings),
    meta: newMeta(options.meta),
    root: options.root ?? newGroup({ name: "Root" }),
    deletedObjects: options.deletedObjects ?? [],
    rootUnknown: options.rootUnknown ?? [],
  };
}

// ---------------------------------------------------------------------------
// Suchen
// ---------------------------------------------------------------------------

/** Alle Einträge der Datenbank (ohne Verlauf), in Baum-Reihenfolge. */
export function allEntries(vault: Vault): Entry[] {
  const result: Entry[] = [];
  const walk = (group: Group): void => {
    result.push(...group.entries);
    group.groups.forEach(walk);
  };
  walk(vault.root);
  return result;
}

/** Alle Gruppen der Datenbank einschließlich der Wurzel, in Baum-Reihenfolge. */
export function allGroups(vault: Vault): Group[] {
  const result: Group[] = [];
  const walk = (group: Group): void => {
    result.push(group);
    group.groups.forEach(walk);
  };
  walk(vault.root);
  return result;
}

/** Der erste Eintrag mit diesem Titel; wirft, wenn es keinen gibt. */
export function entryByTitle(vault: Vault, title: string): Entry {
  const entry = allEntries(vault).find((e) => e.strings.get("Title")?.value === title);
  if (entry === undefined) throw new Error(`Kein Eintrag mit Titel "${title}"`);
  return entry;
}

/** Die erste Gruppe mit diesem Namen; wirft, wenn es keine gibt. */
export function groupByName(vault: Vault, name: string): Group {
  const group = allGroups(vault).find((g) => g.name === name);
  if (group === undefined) throw new Error(`Keine Gruppe mit Namen "${name}"`);
  return group;
}
