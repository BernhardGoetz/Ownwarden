/**
 * Das Feld-Modell der Sync-Regel „neueste Änderung gewinnt – pro Feld“.
 *
 * Ein Eintrag wird in „Felder“ zerlegt; jedes Feld hat einen Schlüssel (FieldKey, siehe
 * contracts.ts) und einen KANONISCHEN Wert (Bytes). Zwei Fassungen eines Felds gelten als
 * gleich, wenn ihre kanonischen Werte gleich sind.
 *
 *   "s:<Name>"     ein <String>-Feld (außer Passkey-Attributen)
 *   "passkey"      alle KPEX_PASSKEY_* / KPXC_PASSKEY_* Felder zusammen (EINE Einheit, sonst
 *                  könnten beim Zusammenführen Teile zweier Passkeys gemischt werden)
 *   "a:<Name>"     ein Anhang
 *   "cd:<Key>"     ein CustomData-Eintrag (außer Ownwarden.FieldTimes und _LAST_MODIFIED)
 *   "tags" "icon" "colors" "overrideUrl" "expiry" "misc"   Eigenschaften des Eintrags
 *   "parent"       die Elterngruppe (Position im Baum, nicht Teil des Entry-Objekts)
 *
 * „Nicht vorhanden“ ist ein eigener Zustand: Ein Feld fehlt, wenn es nicht existiert bzw.
 * seinen Standardwert hat (z. B. keine Tags, Icon 0, kein Ablaufdatum). Das Entfernen eines
 * Felds ist damit dasselbe wie das Zurücksetzen auf den Standardwert.
 *
 * Kanonisch heißt: unempfindlich gegen Umformungen, die KeePassXC 2.7.6 beim Speichern
 * vornimmt, ohne dass der Nutzer etwas geändert hat (sonst sähe jedes Laden+Speichern in
 * KeePassXC wie eine Änderung aus):
 *   - leere Standardfelder (Title, UserName, Password, URL, Notes) legt KeePassXC immer an
 *     -> ein leeres Standardfeld zählt als „nicht vorhanden“;
 *   - "\r" schreibt KeePassXC roh, jeder XML-Leser macht daraus "\n" -> Zeilenenden
 *     werden zu "\n" vereinheitlicht;
 *   - ein U+FEFF am Anfang eines geschützten Werts geht in KeePassXC verloren -> entfernt;
 *   - Anhänge bekommen immer das Schutz-Flag -> Flag zählt bei Anhängen nicht;
 *   - Tags werden sortiert -> Tags als sortierte Menge;
 *   - mit eigenem Icon setzt KeePassXC die IconID auf 0 -> dann zählt nur das eigene Icon;
 *   - QualityCheck=True wird nicht geschrieben -> fehlend = true;
 *   - jeder Eintrag bekommt ein Standard-<AutoType> -> das zählt wie „kein AutoType“;
 *   - Zeiten nur sekundengenau -> Ablaufzeit in ganzen Sekunden.
 *
 * Neben dem kanonischen Wert gibt es den EXAKTEN Wert (Rohdaten ohne Vereinheitlichung).
 * Er dient nur als letzte Gleichstand-Regel, damit das Ergebnis auch dann von der
 * Reihenfolge local/remote unabhängig ist, wenn sich zwei Fassungen nur in solchen
 * Kleinigkeiten unterscheiden. Beide Formate sind in spec/README.md beschrieben.
 */
import { FIELD_TIMES_KEY, type FieldKey } from "../contracts";
import { STANDARD_FIELDS, type Entry, type ProtectedString, type Uuid } from "../model";
import { compareText, decimal, encodeParts, toSeconds, type Part } from "./encoding";

// ---------------------------------------------------------------------------
// Schlüssel
// ---------------------------------------------------------------------------

export const PASSKEY_FIELD = "passkey";
export const PARENT_FIELD = "parent";
export const TAGS_FIELD = "tags";
export const ICON_FIELD = "icon";
export const COLORS_FIELD = "colors";
export const OVERRIDE_URL_FIELD = "overrideUrl";
export const EXPIRY_FIELD = "expiry";
export const MISC_FIELD = "misc";

/** Eigenschafts-Felder: immer aus genau einer Seite übernommen (auch ihr Standardwert). */
export const PROPERTY_FIELDS: readonly FieldKey[] = [TAGS_FIELD, ICON_FIELD, COLORS_FIELD, OVERRIDE_URL_FIELD, EXPIRY_FIELD, MISC_FIELD];

/** CustomData-Eintrag, den KeePassXC bei JEDEM Laden neu setzt – wird immer ignoriert. */
export const LAST_MODIFIED_KEY = "_LAST_MODIFIED";

/** CustomData-Schlüssel, die keine Felder sind. */
export const IGNORED_CUSTOM_DATA_KEYS: ReadonlySet<string> = new Set([FIELD_TIMES_KEY, LAST_MODIFIED_KEY]);

const PASSKEY_PREFIXES = ["KPEX_PASSKEY_", "KPXC_PASSKEY_"];

/** true für Passkey-Attribute (KeePassXC, Strongbox, KeePassDX). */
export function isPasskeyAttribute(name: string): boolean {
  return PASSKEY_PREFIXES.some((prefix) => name.startsWith(prefix));
}

/** true für Title, UserName, Password, URL, Notes. */
export function isStandardField(name: string): boolean {
  return (STANDARD_FIELDS as readonly string[]).includes(name);
}

export const stringKey = (name: string): FieldKey => `s:${name}`;
export const attachmentKey = (name: string): FieldKey => `a:${name}`;
export const customDataKey = (key: string): FieldKey => `cd:${key}`;

/** Art eines Feldschlüssels und – bei s:/a:/cd: – der Name dahinter. */
export type FieldKind =
  | { kind: "string"; name: string }
  | { kind: "attachment"; name: string }
  | { kind: "customData"; name: string }
  | { kind: "passkey" }
  | { kind: "parent" }
  | { kind: "property"; name: FieldKey }
  | { kind: "unknown" };

export function fieldKind(key: FieldKey): FieldKind {
  if (key.startsWith("s:")) return { kind: "string", name: key.slice(2) };
  if (key.startsWith("a:")) return { kind: "attachment", name: key.slice(2) };
  if (key.startsWith("cd:")) return { kind: "customData", name: key.slice(3) };
  if (key === PASSKEY_FIELD) return { kind: "passkey" };
  if (key === PARENT_FIELD) return { kind: "parent" };
  if (PROPERTY_FIELDS.includes(key)) return { kind: "property", name: key };
  return { kind: "unknown" };
}

// ---------------------------------------------------------------------------
// Vereinheitlichung (siehe Kopfkommentar)
// ---------------------------------------------------------------------------

/** Zeilenenden vereinheitlichen: "\r\n" und einzelnes "\r" werden zu "\n". */
export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n?/g, "\n");
}

/** Kanonische Form eines Text-Werts. */
export function normalizeStringValue(value: ProtectedString): string {
  const text = value.protected && value.value.startsWith("\ufeff") ? value.value.slice(1) : value.value;
  return normalizeLineEndings(text);
}

/** Das Standard-<AutoType>, das KeePassXC jedem Eintrag ohne AutoType hinzufügt. */
const DEFAULT_AUTO_TYPE =
  /^<AutoType><Enabled>True<\/Enabled><DataTransferObfuscation>0<\/DataTransferObfuscation>(?:<DefaultSequence\/>|<DefaultSequence><\/DefaultSequence>)?<\/AutoType>$/;

/** Unbekannte XML-Elemente ohne das Standard-<AutoType> von KeePassXC. */
export function significantUnknown(unknown: readonly string[]): string[] {
  return unknown.filter((xml) => !DEFAULT_AUTO_TYPE.test(xml));
}

/**
 * Leerraum, der am Rand eines Tags entfernt wird – FEST aufgezählt (genau die Zeichen, die
 * String.prototype.trim in JavaScript heute entfernt). Nicht einfach trim() benutzen: Kotlins
 * trim() entfernt andere Zeichen (z. B. nicht U+FEFF), und die Unicode-Tabellen der Laufzeit
 * können sich ändern. Dann bekäme dasselbe Tag auf zwei Plattformen verschiedene
 * Fingerabdrücke. Die Liste steht auch in spec/README.md.
 */
const TAG_EDGE_WHITESPACE = /^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+|[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+$/g;

/** Ein Tag ohne Leerraum am Rand (siehe TAG_EDGE_WHITESPACE). */
export function trimTag(tag: string): string {
  return tag.replace(TAG_EDGE_WHITESPACE, "");
}

/** Tags als sortierte Menge (ohne Leerraum am Rand, ohne leere und doppelte). */
export function normalizeTags(tags: readonly string[]): string[] {
  const unique = new Set(tags.map(trimTag).filter((tag) => tag !== ""));
  return [...unique].sort(compareText);
}

const flag = (value: boolean): string => (value ? "1" : "0");

/** Ein leeres Standardfeld zählt als „nicht vorhanden“ (KeePassXC legt sie immer an). */
function isPresentString(name: string, value: ProtectedString): boolean {
  return !(value.value === "" && isStandardField(name));
}

/** Passkey-Attribute, sortiert nach Namen (UTF-8-Bytes). */
function passkeyAttributes(entry: Entry): [string, ProtectedString][] {
  return [...entry.strings].filter(([name]) => isPasskeyAttribute(name)).sort(([a], [b]) => compareText(a, b));
}

// ---------------------------------------------------------------------------
// Felder eines Eintrags
// ---------------------------------------------------------------------------

/** Ein vorhandenes Feld: kanonischer und exakter Wert. */
export interface FieldValue {
  readonly canonical: Uint8Array;
  /** Wird erst bei Bedarf berechnet (nur für Gleichstände und den Verlauf nötig). */
  readonly exact: Uint8Array;
}

/** FieldValue mit erst bei Bedarf kodiertem exakten Wert. */
function fieldValue(canonical: Uint8Array, exactParts: () => Part[]): FieldValue {
  let exact: Uint8Array | undefined;
  return {
    canonical,
    get exact() {
      return (exact ??= encodeParts(exactParts()));
    },
  };
}

/**
 * Alle VORHANDENEN Felder eines Eintrags in fester Reihenfolge: Texte (Passkey an der Stelle
 * seines ersten Attributs), Anhänge, CustomData, Eigenschaften, Elterngruppe.
 * `parentUuid` fehlt bei Verlaufseinträgen – dann gibt es kein Feld "parent".
 */
export function entryFields(entry: Entry, parentUuid?: Uuid): Map<FieldKey, FieldValue> {
  const fields = new Map<FieldKey, FieldValue>();
  for (const [name, value] of entry.strings) {
    if (isPasskeyAttribute(name)) {
      if (!fields.has(PASSKEY_FIELD)) fields.set(PASSKEY_FIELD, passkeyValue(entry));
    } else if (isPresentString(name, value)) {
      fields.set(stringKey(name), stringValue(value));
    }
  }
  for (const item of entry.attachments) {
    fields.set(attachmentKey(item.name), fieldValue(encodeParts(["a", item.data]), () => ["a", item.data, flag(item.protected)]));
  }
  for (const [key, item] of entry.customData) {
    if (IGNORED_CUSTOM_DATA_KEYS.has(key)) continue;
    fields.set(
      customDataKey(key),
      fieldValue(encodeParts(["cd", normalizeLineEndings(item.value)]), () => [
        "cd",
        item.value,
        item.lastModified === undefined ? "" : decimal(item.lastModified),
      ]),
    );
  }
  for (const key of PROPERTY_FIELDS) {
    const canonical = propertyCanonical(entry, key);
    if (canonical !== undefined) fields.set(key, fieldValue(encodeParts(canonical), () => propertyExact(entry, key)));
  }
  if (parentUuid !== undefined) {
    const bytes = encodeParts(["parent", parentUuid]);
    fields.set(PARENT_FIELD, { canonical: bytes, exact: bytes });
  }
  return fields;
}

function stringValue(value: ProtectedString): FieldValue {
  const { value: text, protected: isProtected } = value;
  return fieldValue(encodeParts(["s", normalizeStringValue(value), flag(isProtected)]), () => ["s", text, flag(isProtected)]);
}

function passkeyValue(entry: Entry): FieldValue {
  const attributes = passkeyAttributes(entry);
  return fieldValue(
    encodeParts(["passkey", ...attributes.flatMap(([name, v]) => [name, normalizeStringValue(v), flag(v.protected)])]),
    () => ["passkey", ...attributes.flatMap(([name, v]) => [name, v.value, flag(v.protected)])],
  );
}

/** Kanonische Teile eines Eigenschafts-Felds oder undefined, wenn es den Standardwert hat. */
function propertyCanonical(entry: Entry, key: FieldKey): Part[] | undefined {
  switch (key) {
    case TAGS_FIELD: {
      const tags = normalizeTags(entry.tags);
      return tags.length > 0 ? ["tags", ...tags] : undefined;
    }
    case ICON_FIELD:
      if (entry.customIconUuid !== undefined) return ["icon", "c", entry.customIconUuid];
      return entry.iconId !== 0 ? ["icon", "i", decimal(entry.iconId)] : undefined;
    case COLORS_FIELD:
      return entry.foregroundColor !== "" || entry.backgroundColor !== ""
        ? ["colors", entry.foregroundColor, entry.backgroundColor]
        : undefined;
    case OVERRIDE_URL_FIELD:
      return entry.overrideUrl !== "" ? ["overrideUrl", entry.overrideUrl] : undefined;
    case EXPIRY_FIELD:
      return entry.times.expires ? ["expiry", decimal(toSeconds(entry.times.expiry))] : undefined;
    case MISC_FIELD: {
      const unknown = significantUnknown(entry.unknown);
      const hasMisc = entry.qualityCheck === false || entry.previousParentGroup !== undefined || unknown.length > 0;
      return hasMisc ? ["misc", flag(entry.qualityCheck !== false), entry.previousParentGroup ?? "", ...unknown] : undefined;
    }
    default:
      throw new Error(`Unbekanntes Eigenschafts-Feld ${key}`);
  }
}

/** Exakte Teile eines Eigenschafts-Felds (auch für den Standardwert). */
function propertyExact(entry: Entry, key: FieldKey): Part[] {
  switch (key) {
    case TAGS_FIELD:
      return ["tags", ...entry.tags];
    case ICON_FIELD:
      return ["icon", decimal(entry.iconId), entry.customIconUuid ?? ""];
    case COLORS_FIELD:
      return ["colors", entry.foregroundColor, entry.backgroundColor];
    case OVERRIDE_URL_FIELD:
      return ["overrideUrl", entry.overrideUrl];
    case EXPIRY_FIELD:
      return ["expiry", flag(entry.times.expires), decimal(entry.times.expiry)];
    case MISC_FIELD: {
      const qualityCheck = entry.qualityCheck === undefined ? "u" : flag(entry.qualityCheck);
      return ["misc", qualityCheck, entry.previousParentGroup ?? "", ...entry.unknown];
    }
    default:
      throw new Error(`Unbekanntes Eigenschafts-Feld ${key}`);
  }
}

/** Leere Bytes: exakter Wert eines nicht vorhandenen Text-/Anhang-/CustomData-/Passkey-Felds. */
const EMPTY = new Uint8Array(0);

/**
 * Exakter Wert eines Felds, auch wenn es nicht vorhanden ist. Für Eigenschafts-Felder
 * enthält er den Rohwert (z. B. die Ablaufzeit bei abgeschaltetem Ablauf), für alle anderen
 * nicht vorhandenen Felder ist er leer.
 */
export function exactFieldBytes(entry: Entry, key: FieldKey, fields: Map<FieldKey, FieldValue>): Uint8Array {
  const present = fields.get(key);
  if (present !== undefined) return present.exact;
  return PROPERTY_FIELDS.includes(key) ? encodeParts(propertyExact(entry, key)) : EMPTY;
}

// ---------------------------------------------------------------------------
// Felder übertragen (Aufbau des zusammengeführten Eintrags)
// ---------------------------------------------------------------------------

/**
 * Übernimmt das Feld `key` von `source` nach `target` (Rohwerte, keine Vereinheitlichung).
 * Fehlt das Feld in `source`, wird es in `target` entfernt bzw. auf den Standardwert von
 * `source` gesetzt. "parent" wird hier nicht behandelt (Baumposition).
 * Anhang-Bytes werden geteilt, nicht kopiert: Sie gelten im ganzen Kern als unveränderlich.
 */
export function copyField(target: Entry, source: Entry, key: FieldKey): void {
  const kind = fieldKind(key);
  switch (kind.kind) {
    case "string": {
      if (isPasskeyAttribute(kind.name)) return; // gehört zum Feld "passkey"
      const value = source.strings.get(kind.name);
      if (value !== undefined && isPresentString(kind.name, value)) target.strings.set(kind.name, { ...value });
      else target.strings.delete(kind.name);
      return;
    }
    case "passkey":
      for (const name of [...target.strings.keys()]) if (isPasskeyAttribute(name)) target.strings.delete(name);
      for (const [name, value] of source.strings) if (isPasskeyAttribute(name)) target.strings.set(name, { ...value });
      return;
    case "attachment": {
      const others = target.attachments.filter((item) => item.name !== kind.name);
      const item = source.attachments.find((a) => a.name === kind.name);
      target.attachments = item === undefined ? others : [...others, { ...item }];
      return;
    }
    case "customData": {
      const item = source.customData.get(kind.name);
      if (item !== undefined) target.customData.set(kind.name, { ...item });
      else target.customData.delete(kind.name);
      return;
    }
    case "property":
      copyProperty(target, source, kind.name);
      return;
    case "parent":
    case "unknown":
      return;
  }
}

function copyProperty(target: Entry, source: Entry, key: FieldKey): void {
  switch (key) {
    case TAGS_FIELD:
      target.tags = [...source.tags];
      return;
    case ICON_FIELD:
      target.iconId = source.iconId;
      if (source.customIconUuid !== undefined) target.customIconUuid = source.customIconUuid;
      else delete target.customIconUuid;
      return;
    case COLORS_FIELD:
      target.foregroundColor = source.foregroundColor;
      target.backgroundColor = source.backgroundColor;
      return;
    case OVERRIDE_URL_FIELD:
      target.overrideUrl = source.overrideUrl;
      return;
    case EXPIRY_FIELD:
      target.times = { ...target.times, expires: source.times.expires, expiry: source.times.expiry };
      return;
    case MISC_FIELD:
      if (source.qualityCheck !== undefined) target.qualityCheck = source.qualityCheck;
      else delete target.qualityCheck;
      if (source.previousParentGroup !== undefined) target.previousParentGroup = source.previousParentGroup;
      else delete target.previousParentGroup;
      target.unknown = [...source.unknown];
      return;
  }
}

/**
 * Legt fehlende Standardfelder leer an (Password geschützt) und stellt sie an den Anfang –
 * so, wie KeePass und KeePassXC Einträge immer speichern.
 */
export function materializeStandardFields(entry: Entry): void {
  const strings = new Map<string, ProtectedString>();
  for (const name of STANDARD_FIELDS) {
    strings.set(name, entry.strings.get(name) ?? { value: "", protected: name === "Password" });
  }
  for (const [name, value] of entry.strings) if (!strings.has(name)) strings.set(name, value);
  entry.strings = strings;
}
