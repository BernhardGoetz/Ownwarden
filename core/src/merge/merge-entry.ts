/**
 * Zusammenführen zweier Fassungen EINES Eintrags (gleiche UUID) – Feld für Feld.
 *
 * Für jedes Feld (fields.ts) gewinnt die Fassung mit dem neueren wirksamen Zeitstempel
 * (field-times.ts), egal ob „Wert“ oder „entfernt“. Bei gleichem Zeitstempel entscheidet
 * eine feste Regel, die nicht davon abhängt, welche Seite local und welche remote ist:
 *
 *   1. neuerer Zeitstempel t
 *   2. vorhanden schlägt entfernt
 *   3. größerer kanonischer Wert (Bytes lexikografisch)
 *   4. größerer exakter Wert (Rohdaten, z. B. "\r\n" gegen "\n")
 *   Sind alle vier gleich, sind die Fassungen gleich (es wird local genommen).
 * Haben beide Fassungen keine FieldTimes, entscheidet die neuere Fassung, welche Felder
 * fehlen (markRemovalsOfNewerUnsealedSide).
 *
 * Danach:
 *   - Zeiten: creation = min, lastModification = max (beider Seiten und aller
 *     Gewinner-Zeitstempel), lastAccess = max, usageCount = max, locationChanged = t des
 *     gewinnenden "parent", Ablauf aus dem Feld "expiry".
 *   - Ownwarden.FieldTimes wird neu versiegelt (frische Fingerabdrücke).
 *   - Verlauf: beide Verläufe + die aktuelle Fassung jeder Seite, deren Inhalt vom Ergebnis
 *     abweicht (history.ts).
 */
import type { FieldConflict, FieldKey } from "../contracts";
import type { Entry, Meta, Uuid } from "../model";
import { compareBytes, sameBytes, toSeconds } from "./encoding";
import { effectiveFieldTimes, sealFieldTimes, type EffectiveFieldTimes, type FieldTime } from "./field-times";
import { copyField, exactFieldBytes, materializeStandardFields, PARENT_FIELD, PROPERTY_FIELDS } from "./fields";
import { contentFingerprint, historySnapshot, mergeHistory } from "./history";

/** Ein Eintrag zusammen mit der UUID der Gruppe, in der er liegt. */
export interface PlacedEntry {
  entry: Entry;
  parent: Uuid;
}

/** Ergebnis für einen Eintrag. */
export interface MergedEntry extends PlacedEntry {
  /** Wirksame Feld-Zeitstempel des Ergebnisses (für Löschen-gegen-Ändern). */
  times: Map<FieldKey, FieldTime>;
  /** Felder, deren Inhalt sich zwischen den Seiten unterschied. */
  conflicts: FieldConflict[];
  /** Welche Eingabe laut FieldTimes außerhalb von Ownwarden geändert wurde. */
  externallyEdited: { local: boolean; remote: boolean };
}

const EMPTY = new Uint8Array(0);

/** Entscheidung für ein Feld. */
interface FieldDecision {
  key: FieldKey;
  winner: "local" | "remote";
  /** Zeitpunkt des Gewinners; undefined, wenn keine Seite das Feld je kannte. */
  time: FieldTime | undefined;
  differs: boolean;
  tieBreak: boolean;
  /** Beide Seiten kannten das Feld (Wert oder Lösch-Marker). */
  bothKnown: boolean;
}

/** Wirksame Feld-Zeitstempel einer Fassung (mit Eintrag, für den exakten Vergleich). */
interface Side {
  entry: Entry;
  parent: Uuid;
  effective: EffectiveFieldTimes;
}

/**
 * Führt zwei Fassungen desselben Eintrags zusammen. Verändert die Eingaben nicht.
 * `meta` liefert die Verlaufsgrenzen.
 */
export function mergeEntryVersions(
  local: PlacedEntry,
  remote: PlacedEntry,
  meta: Pick<Meta, "historyMaxItems" | "historyMaxSize">,
): MergedEntry {
  const l: Side = { ...local, effective: effectiveFieldTimes(local.entry, local.parent) };
  const r: Side = { ...remote, effective: effectiveFieldTimes(remote.entry, remote.parent) };
  markRemovalsOfNewerUnsealedSide(l, r);
  const decisions = fieldKeys(l, r).map((key) => decide(key, l, r));

  const merged = emptyEntryLike(local.entry);
  let parent = local.parent;
  const times = new Map<FieldKey, FieldTime>();
  for (const decision of decisions) {
    const source = decision.winner === "local" ? l : r;
    if (decision.time !== undefined) times.set(decision.key, decision.time);
    if (decision.key === PARENT_FIELD) parent = source.parent;
    else copyField(merged, source.entry, decision.key);
  }
  materializeStandardFields(merged);
  merged.times = mergedTimes(local.entry, remote.entry, merged, times);
  sealFieldTimes(merged, times, parent);

  const mergedContent = contentFingerprint(merged);
  const snapshots = [l, r]
    .filter((side) => contentFingerprint(side.entry) !== mergedContent)
    .map((side) => historySnapshot(side.entry));
  merged.history = mergeHistory([...local.entry.history, ...remote.entry.history, ...snapshots], meta);

  const conflicts: FieldConflict[] = decisions
    .filter((d) => d.differs && d.bothKnown)
    .map((d) => ({ entryUuid: local.entry.uuid, field: d.key, winner: d.winner, tieBreak: d.tieBreak }));
  const externallyEdited = { local: l.effective.externallyEdited, remote: r.effective.externallyEdited };
  return { entry: merged, parent, times, conflicts, externallyEdited };
}

/**
 * Haben BEIDE Fassungen keine (gültigen) FieldTimes, ist die Fassung mit der neueren
 * lastModification (ganze Sekunden) maßgeblich dafür, welche Felder FEHLEN: Jedes Feld, das ihr
 * fehlt, die ältere Fassung aber hat, bekommt bei ihr einen Lösch-Marker zu ihrer Basiszeit
 * (spec/README.md, Abschnitt 5.1). Die ältere Fassung kann das Feld nicht über Ownwarden
 * angelegt haben (dann wäre sie versiegelt). Ohne diese Regel hätte ein Feld, das z. B. in
 * KeePassXC ohne Verlaufseintrag entfernt wurde (HistoryMaxItems = 0, Verlauf gelöscht), auf
 * der neueren Seite gar keine Zeit, und jede ältere Kopie brächte es zurück – samt Geheimnis.
 * Verändert die Feld-Zeitstempel der neueren Seite.
 */
function markRemovalsOfNewerUnsealedSide(l: Side, r: Side): void {
  if (l.effective.sealed || r.effective.sealed) return;
  const lSecond = toSeconds(l.entry.times.lastModification);
  const rSecond = toSeconds(r.entry.times.lastModification);
  if (lSecond === rSecond) return;
  const [newer, older] = lSecond > rSecond ? [l, r] : [r, l];
  const removedAt = toSeconds(newer.entry.times.lastModification) * 1000;
  for (const key of older.effective.values.keys()) {
    if (!newer.effective.values.has(key)) newer.effective.times.set(key, { t: removedAt, present: false });
  }
}

/**
 * Alle Feldschlüssel beider Seiten in fester Reihenfolge (erst local, dann remote): Felder
 * mit Wert oder Lösch-Marker, dazu immer die Eigenschafts-Felder (deren Standardwert muss
 * auch von einer Seite übernommen werden).
 */
function fieldKeys(l: Side, r: Side): FieldKey[] {
  const keys = new Set<FieldKey>();
  for (const side of [l, r]) for (const key of side.effective.times.keys()) keys.add(key);
  for (const key of PROPERTY_FIELDS) keys.add(key);
  keys.add(PARENT_FIELD);
  return [...keys];
}

function decide(key: FieldKey, l: Side, r: Side): FieldDecision {
  const lt = l.effective.times.get(key);
  const rt = r.effective.times.get(key);
  const lValue = l.effective.values.get(key);
  const rValue = r.effective.values.get(key);
  const lCanonical = lValue?.canonical ?? EMPTY;
  const rCanonical = rValue?.canonical ?? EMPTY;

  const lTime = lt?.t ?? -Infinity;
  const rTime = rt?.t ?? -Infinity;
  let order = Math.sign(lTime - rTime);
  if (lTime === rTime) order = 0; // -Infinity - -Infinity wäre NaN
  if (order === 0) order = Number(lValue !== undefined) - Number(rValue !== undefined);
  if (order === 0) order = Math.sign(compareBytes(lCanonical, rCanonical));
  if (order === 0) {
    order = Math.sign(
      compareBytes(exactFieldBytes(l.entry, key, l.effective.values), exactFieldBytes(r.entry, key, r.effective.values)),
    );
  }

  const winner = order >= 0 ? "local" : "remote";
  const differs = (lValue === undefined) !== (rValue === undefined) || !sameBytes(lCanonical, rCanonical);
  return {
    key,
    winner,
    time: winner === "local" ? lt : rt,
    differs,
    tieBreak: differs && lTime === rTime,
    bothKnown: lt !== undefined && rt !== undefined,
  };
}

/** Leerer Eintrag mit UUID und (vorläufigen) Zeiten von `like`; Felder kommen per copyField. */
function emptyEntryLike(like: Entry): Entry {
  return {
    uuid: like.uuid,
    iconId: 0,
    foregroundColor: "",
    backgroundColor: "",
    overrideUrl: "",
    tags: [],
    times: { ...like.times },
    strings: new Map(),
    attachments: [],
    customData: new Map(),
    history: [],
    unknown: [],
  };
}

/** Zeiten des Ergebnisses (Ablauf wurde schon über das Feld "expiry" in `merged` gesetzt). */
function mergedTimes(a: Entry, b: Entry, merged: Entry, times: Map<FieldKey, FieldTime>): Entry["times"] {
  let lastModification = Math.max(a.times.lastModification, b.times.lastModification);
  for (const time of times.values()) lastModification = Math.max(lastModification, time.t);
  return {
    creation: Math.min(a.times.creation, b.times.creation),
    lastModification,
    lastAccess: Math.max(a.times.lastAccess, b.times.lastAccess),
    expiry: merged.times.expiry,
    expires: merged.times.expires,
    usageCount: Math.max(a.times.usageCount, b.times.usageCount),
    locationChanged: times.get(PARENT_FIELD)?.t ?? Math.max(a.times.locationChanged, b.times.locationChanged),
  };
}
