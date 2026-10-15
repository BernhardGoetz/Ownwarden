/**
 * Feld-Zeitstempel: Wann wurde welches Feld eines Eintrags zuletzt geändert?
 *
 * KDBX kennt Zeiten nur pro Eintrag. Ownwarden speichert deshalb pro Eintrag EINEN
 * CustomData-Eintrag "Ownwarden.FieldTimes" mit kompaktem JSON (Schlüssel sortiert):
 *
 *   {"v":1,"w":1700000000000,"f":{"s:Password":{"t":1700000000000,"h":"q8Zr…"},"s:URL":{"t":1690000000000,"d":1}}}
 *
 *   v  Formatversion (immer 1; andere Versionen werden wie „keine FieldTimes“ behandelt)
 *   w  entry.times.lastModification zum Zeitpunkt des Schreibens („Versiegeln“)
 *   f  pro Feld: t = Zeitpunkt der letzten Änderung (ms),
 *               h = Fingerabdruck des kanonischen Werts (fields.ts, encoding.ts), oder
 *               d = 1: Lösch-Marker („Feld wurde zum Zeitpunkt t entfernt“)
 *
 * Der Fingerabdruck verrät, ob ein ANDERES Programm (z. B. KeePassXC) das Feld seit dem
 * Versiegeln geändert hat: Dann passt er nicht mehr zum aktuellen Wert. Die
 * LastModificationTime einzelner CustomData-Einträge wird bewusst NICHT benutzt (KeePassXC
 * verwirft sie beim Speichern).
 *
 * effectiveFieldTimes() liefert für jedes Feld den Zeitpunkt, der beim Zusammenführen zählt.
 * Die Regeln stehen an der Funktion und in spec/README.md.
 */
import { FIELD_TIMES_KEY, type FieldKey } from "../contracts";
import type { Entry, Millis, Uuid } from "../model";
import { compareText, fingerprint, isKdbxTime, sameBytes, toSeconds } from "./encoding";
import { entryFields, fieldKind, IGNORED_CUSTOM_DATA_KEYS, isPasskeyAttribute, PARENT_FIELD, type FieldValue } from "./fields";

/** Zeitpunkt eines Felds: vorhanden (geändert um t) oder entfernt (Lösch-Marker von t). */
export interface FieldTime {
  t: Millis;
  present: boolean;
}

/** Ein gespeicherter Feld-Eintrag aus Ownwarden.FieldTimes. */
export type StoredField = { t: Millis; deleted: false; hash: string } | { t: Millis; deleted: true };

/** Inhalt von Ownwarden.FieldTimes nach dem Einlesen. */
export interface StoredFieldTimes {
  /** lastModification des Eintrags beim Versiegeln. */
  sealedAt: Millis;
  fields: Map<FieldKey, StoredField>;
}

const FORMAT_VERSION = 1;

// ---------------------------------------------------------------------------
// Lesen und Schreiben des JSON
// ---------------------------------------------------------------------------

/**
 * Liest Ownwarden.FieldTimes eines Eintrags. undefined, wenn der Eintrag keine hat oder der
 * Inhalt ungültig ist (kaputtes JSON, andere Version, falsche Typen, Zeiten außerhalb des
 * KDBX-Bereichs): Dann gilt der Eintrag als „nie von Ownwarden geschrieben“. Unbekannte
 * Feldschlüssel werden übersprungen.
 */
export function readFieldTimes(entry: Entry): StoredFieldTimes | undefined {
  const text = entry.customData.get(FIELD_TIMES_KEY)?.value;
  if (text === undefined) return undefined;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return undefined;
  }
  // Zeiten müssen ganze Zahlen im KDBX-Zeitbereich sein (Jahr 1 bis 9999). Eine unsinnige Zeit
  // (z. B. Jahr 33658) würde sonst jeden Vergleich gewinnen und das Ergebnis unspeicherbar machen.
  if (!isObject(data) || data.v !== FORMAT_VERSION || !isKdbxTime(data.w) || !isObject(data.f)) return undefined;

  const fields = new Map<FieldKey, StoredField>();
  for (const [key, record] of Object.entries(data.f)) {
    if (!isObject(record) || !isKdbxTime(record.t)) return undefined;
    const t = record.t as number;
    let stored: StoredField;
    if (record.d === 1) stored = { t, deleted: true };
    else if (typeof record.h === "string") stored = { t, deleted: false, hash: record.h };
    else return undefined;
    if (isTrackedKey(key)) fields.set(key, stored);
  }
  return { sealedAt: data.w as number, fields };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Nur Schlüssel, die das Feld-Modell kennt (fremde/kaputte Schlüssel werden ignoriert). */
function isTrackedKey(key: FieldKey): boolean {
  const kind = fieldKind(key);
  if (kind.kind === "unknown") return false;
  if (kind.kind === "string") return !isPasskeyAttribute(kind.name);
  if (kind.kind === "customData") return !IGNORED_CUSTOM_DATA_KEYS.has(kind.name);
  return true;
}

/** Erzeugt das kompakte JSON (Feldschlüssel nach UTF-8-Bytes sortiert, deterministisch). */
export function formatFieldTimes(stored: StoredFieldTimes): string {
  const fields: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of [...stored.fields.keys()].sort(compareText)) {
    const field = stored.fields.get(key)!;
    fields[key] = field.deleted ? { t: field.t, d: 1 } : { t: field.t, h: field.hash };
  }
  return JSON.stringify({ v: FORMAT_VERSION, w: stored.sealedAt, f: fields });
}

// ---------------------------------------------------------------------------
// Wirksame Feld-Zeitstempel
// ---------------------------------------------------------------------------

export interface EffectiveFieldTimes {
  /** Zeitpunkt jedes vorhandenen Felds und jedes bekannten Lösch-Markers. */
  times: Map<FieldKey, FieldTime>;
  /** Die vorhandenen Felder mit ihren Werten (aus entryFields). */
  values: Map<FieldKey, FieldValue>;
  /** true, wenn gültige Ownwarden.FieldTimes vorhanden waren. */
  sealed: boolean;
  /** Felder, die laut Fingerabdruck außerhalb von Ownwarden geändert/entfernt wurden. */
  externalFields: FieldKey[];
  /** true, wenn der Eintrag laut FieldTimes außerhalb von Ownwarden geändert wurde. */
  externallyEdited: boolean;
}

/** KDBX-Zeit auf ganze Sekunden abgerundet (in ms). */
function wholeSecond(millis: Millis): Millis {
  return toSeconds(millis) * 1000;
}

/**
 * Basiszeit eines Felds: entry.times.lastModification, für "parent" locationChanged – auf
 * GANZE SEKUNDEN abgerundet (PROJECT-CONTEXT: KDBX-Zeiten werden beim Vergleich mit
 * Feld-Zeitstempeln auf Sekunden abgerundet). Sonst bekäme dasselbe Feld im Speicher (ms)
 * eine andere Zeit als nach dem Laden aus der Datei (s), und zwei Geräte entschieden
 * denselben Abgleich verschieden.
 */
function kdbxBaseTime(entry: Entry, key: FieldKey): Millis {
  return wholeSecond(key === PARENT_FIELD ? entry.times.locationChanged : entry.times.lastModification);
}

/**
 * Die beim Zusammenführen geltenden Feld-Zeitstempel eines Eintrags.
 *
 * `parentUuid` ist die Gruppe, in der der Eintrag liegt (fehlt bei Verlaufseinträgen; dann
 * gibt es kein Feld "parent"). Basiszeit eines Felds: entry.times.lastModification, für
 * "parent" entry.times.locationChanged, jeweils auf ganze Sekunden abgerundet (kdbxBaseTime).
 *
 * Mit gültigen FieldTimes:
 *   - Feld vorhanden, Fingerabdruck passt          -> t aus FieldTimes
 *   - Feld vorhanden, Fingerabdruck passt nicht,
 *     Feld unbekannt oder dort als entfernt markiert -> extern geändert:
 *                                                     t = max(Basiszeit, gespeichertes t + 1)
 *   - Feld fehlt, Lösch-Marker vorhanden             -> entfernt zum Zeitpunkt des Markers
 *   - Feld fehlt, laut FieldTimes vorhanden          -> extern entfernt:
 *                                                     Lösch-Marker bei max(Basiszeit, t + 1)
 * Ohne (gültige) FieldTimes: siehe timesWithoutFieldTimes.
 */
export function effectiveFieldTimes(entry: Entry, parentUuid?: Uuid): EffectiveFieldTimes {
  const values = entryFields(entry, parentUuid);
  const stored = readFieldTimes(entry);
  if (stored === undefined) {
    return { times: timesWithoutFieldTimes(entry, values), values, sealed: false, externalFields: [], externallyEdited: false };
  }

  const baseTime = (key: FieldKey): Millis => kdbxBaseTime(entry, key);
  const times = new Map<FieldKey, FieldTime>();
  const externalFields: FieldKey[] = [];

  for (const [key, value] of values) {
    const record = stored.fields.get(key);
    if (record !== undefined && !record.deleted && record.hash === fingerprint(value.canonical)) {
      times.set(key, { t: record.t, present: true });
    } else {
      times.set(key, { t: record === undefined ? baseTime(key) : Math.max(baseTime(key), record.t + 1), present: true });
      externalFields.push(key);
    }
  }
  for (const [key, record] of stored.fields) {
    if (values.has(key)) continue;
    if (key === PARENT_FIELD && parentUuid === undefined) continue; // Verlaufseintrag: keine Position
    if (record.deleted) {
      times.set(key, { t: record.t, present: false });
    } else {
      times.set(key, { t: Math.max(baseTime(key), record.t + 1), present: false });
      externalFields.push(key);
    }
  }
  // Auch ohne erkennbare Feldänderung: Eine neuere Änderungszeit als beim Versiegeln heißt,
  // dass ein anderes Programm den Eintrag gespeichert hat (nur für den Bericht).
  const touched = toSeconds(entry.times.lastModification) > toSeconds(stored.sealedAt);
  return { times, values, sealed: true, externalFields, externallyEdited: externalFields.length > 0 || touched };
}

/**
 * Feld-Zeitstempel eines Eintrags OHNE FieldTimes (nie von Ownwarden geschrieben, z. B. in
 * KeePassXC angelegt). Grundregel: Jedes Feld gilt als zuletzt geändert, als der Eintrag
 * zuletzt geändert wurde (lastModification; "parent": locationChanged).
 *
 * Verfeinerung über den Verlauf: KeePassXC legt bei jeder Änderung die vorherige Fassung in
 * den Verlauf. Hat ein Feld in den letzten Fassungen durchgehend denselben Wert, wurde es
 * nicht bei der letzten Änderung geändert, sondern bei der Änderung, mit der dieser Wert
 * entstand: t = lastModification der ältesten Fassung dieser ununterbrochenen Reihe. Ebenso
 * bekommt ein Feld, das in einer früheren Fassung vorhanden war und jetzt fehlt, einen
 * Lösch-Marker zum Zeitpunkt der Fassung, ab der es fehlt. Ohne Verlauf gilt die Grundregel.
 * So überschreibt z. B. eine Benutzernamen-Änderung in KeePassXC nicht ein Passwort, das
 * Ownwarden auf einem anderen Gerät später geändert hat. Kein t liegt nach lastModification.
 */
function timesWithoutFieldTimes(entry: Entry, values: Map<FieldKey, FieldValue>): Map<FieldKey, FieldTime> {
  const lastModification = wholeSecond(entry.times.lastModification);
  const history = entry.history;
  const historyFields = history.map((item) => entryFields(item));
  /** Änderungszeit der Fassung `index` (history[0..n-1], dann der Eintrag selbst), ganze Sekunden. */
  const versionTime = (index: number): Millis =>
    index < history.length ? Math.min(wholeSecond(history[index]!.times.lastModification), lastModification) : lastModification;

  const times = new Map<FieldKey, FieldTime>();
  for (const [key, value] of values) {
    if (key === PARENT_FIELD) {
      times.set(key, { t: kdbxBaseTime(entry, PARENT_FIELD), present: true });
      continue;
    }
    // Rückwärts durch den Verlauf, solange der Wert gleich bleibt.
    let start = history.length;
    while (start > 0 && sameValue(historyFields[start - 1]!.get(key), value)) start--;
    times.set(key, { t: versionTime(start), present: true });
  }

  const removedKeys = new Set<FieldKey>();
  for (const fields of historyFields) for (const key of fields.keys()) if (!values.has(key)) removedKeys.add(key);
  for (const key of removedKeys) {
    let start = history.length;
    while (start > 0 && !historyFields[start - 1]!.has(key)) start--;
    times.set(key, { t: versionTime(start), present: false });
  }
  return times;
}

function sameValue(a: FieldValue | undefined, b: FieldValue): boolean {
  return a !== undefined && sameBytes(a.canonical, b.canonical);
}

// ---------------------------------------------------------------------------
// Versiegeln
// ---------------------------------------------------------------------------

/**
 * Schreibt Ownwarden.FieldTimes für den aktuellen Zustand des Eintrags: frische
 * Fingerabdrücke für alle vorhandenen Felder, Lösch-Marker für entfernte Felder,
 * w = entry.times.lastModification. Verändert `entry`.
 *
 * `times` liefert die Zeitpunkte. Fehlt darin ein vorhandenes Feld, gilt die Basiszeit
 * (lastModification bzw. locationChanged). Einträge mit present=true für ein Feld, das es
 * nicht (mehr) gibt, werden zu Lösch-Markern.
 */
export function sealFieldTimes(entry: Entry, times: ReadonlyMap<FieldKey, FieldTime>, parentUuid?: Uuid): void {
  const values = entryFields(entry, parentUuid);
  const fields = new Map<FieldKey, StoredField>();
  for (const [key, value] of values) {
    const base = key === PARENT_FIELD ? entry.times.locationChanged : entry.times.lastModification;
    fields.set(key, { t: times.get(key)?.t ?? base, deleted: false, hash: fingerprint(value.canonical) });
  }
  for (const [key, time] of times) {
    if (values.has(key) || !isTrackedKey(key)) continue;
    if (key === PARENT_FIELD && parentUuid === undefined) continue;
    if (Number.isFinite(time.t)) fields.set(key, { t: time.t, deleted: true });
  }
  entry.customData.set(FIELD_TIMES_KEY, {
    value: formatFieldTimes({ sealedAt: entry.times.lastModification, fields }),
  });
}

/** Der neueste Zeitpunkt (Änderung oder Löschung) aller Felder; -Infinity ohne Felder. */
export function newestFieldTime(times: ReadonlyMap<FieldKey, FieldTime>): Millis {
  let newest = -Infinity;
  for (const time of times.values()) newest = Math.max(newest, time.t);
  return newest;
}
