/**
 * Verlauf (frühere Fassungen) eines Eintrags.
 *
 * Regeln (siehe PROJECT-CONTEXT.md, „Verlauf“):
 *   - Verlaufseinträge haben selbst keinen Verlauf und (wie bei KeePassXC) keine
 *     Ownwarden.FieldTimes – die gelten nur für die aktuelle Fassung.
 *   - Beim Zusammenführen werden die Verläufe beider Seiten vereinigt; doppelte Fassungen
 *     (gleiche Änderungszeit in ganzen Sekunden UND gleicher Inhalt) fallen weg; sortiert
 *     älteste zuerst.
 *   - Die Grenzen der Datei gelten: HistoryMaxItems (Anzahl) und HistoryMaxSize (Byte,
 *     grob geschätzt); -1 = unbegrenzt. Es fallen immer die ÄLTESTEN Fassungen heraus.
 */
import type { Entry, Meta } from "../model";
import { cloneEntry, deepEqual } from "./clone";
import { compareText, encodeParts, fingerprint, decimal, toSeconds, type Part } from "./encoding";
import { entryFields, IGNORED_CUSTOM_DATA_KEYS } from "./fields";

/**
 * Eine Fassung für den Verlauf: Kopie ohne eigenen Verlauf und ohne Ownwarden.FieldTimes
 * bzw. _LAST_MODIFIED (beides beschreibt nur die aktuelle Fassung).
 */
export function historySnapshot(entry: Entry): Entry {
  const copy = cloneEntry({ ...entry, history: [] });
  for (const key of IGNORED_CUSTOM_DATA_KEYS) copy.customData.delete(key);
  return copy;
}

/**
 * Fingerabdruck des INHALTS einer Fassung: alle vorhandenen Felder (kanonisch, ohne
 * Elterngruppe), nach Schlüssel sortiert. Zeiten zählen nicht.
 */
export function contentFingerprint(entry: Entry, options: { withoutCustomData?: boolean } = {}): string {
  const fields = entryFields(entry);
  const parts: Part[] = [...fields.keys()]
    .filter((key) => !(options.withoutCustomData && key.startsWith("cd:")))
    .sort(compareText)
    .flatMap((key) => [key, fields.get(key)!.canonical]);
  return fingerprint(encodeParts(parts));
}

/**
 * Kopie einer Fassung mit allen Zeiten auf ganze Sekunden abgerundet – so, wie sie nach dem
 * Speichern und Laden aussähe (auch Ablaufzeit und LastModificationTime von CustomData).
 */
function withWholeSecondTimes(entry: Entry): Entry {
  const second = (millis: number): number => toSeconds(millis) * 1000;
  const t = entry.times;
  const customData = new Map(
    [...entry.customData].map(([key, item]) => [key, item.lastModified === undefined ? item : { ...item, lastModified: second(item.lastModified) }]),
  );
  return {
    ...entry,
    customData,
    times: { ...t, creation: second(t.creation), lastModification: second(t.lastModification), lastAccess: second(t.lastAccess), expiry: second(t.expiry), locationChanged: second(t.locationChanged) },
  };
}

/** Fingerabdruck der Rohdaten einer Fassung (exakte Feldwerte und alle Zeiten). */
function exactFingerprint(entry: Entry): string {
  const fields = entryFields(entry);
  const parts: Part[] = [...fields.keys()].sort(compareText).flatMap((key) => [key, fields.get(key)!.exact]);
  const t = entry.times;
  const times = [t.creation, t.lastModification, t.lastAccess, t.expiry, t.usageCount, t.locationChanged].map(decimal);
  return fingerprint(encodeParts([...parts, ...times, t.expires ? "1" : "0"]));
}

/**
 * Ungefähre Größe einer Fassung in Byte (für HistoryMaxSize): Länge aller Texte (Namen und
 * Werte, als UTF-16-Zeichen gezählt), aller CustomData-Einträge und aller Anhänge.
 */
export function approximateSize(entry: Entry): number {
  let size = 0;
  for (const [name, value] of entry.strings) size += name.length + value.value.length;
  for (const [key, item] of entry.customData) size += key.length + item.value.length;
  for (const item of entry.attachments) size += item.name.length + item.data.length;
  return size;
}

/**
 * Kürzt einen Verlauf (älteste zuerst) auf die Grenzen: erst die Anzahl, dann die Größe
 * (von der neuesten Fassung rückwärts summiert; ab der ersten Fassung, mit der die Summe
 * die Grenze überschreitet, fallen sie und alle älteren weg – wie bei KeePassXC).
 */
export function truncateHistory(history: Entry[], maxItems: number, maxSize: number): Entry[] {
  let kept = maxItems >= 0 ? history.slice(Math.max(0, history.length - maxItems)) : [...history];
  if (maxSize >= 0) {
    let total = 0;
    let firstKept = kept.length;
    while (firstKept > 0) {
      total += approximateSize(kept[firstKept - 1]!);
      if (total > maxSize) break;
      firstKept--;
    }
    kept = kept.slice(firstKept);
  }
  return kept;
}

/**
 * Eine Fassung beim Vereinigen von Verläufen. Die Rohdaten-Fingerabdrücke werden erst
 * berechnet, wenn zwei Fassungen auf denselben Platz kommen (Doppelte) – das spart viel
 * Rechenzeit, denn beide Seiten bringen meist denselben Verlauf mit.
 */
class HistoryCandidate {
  readonly second: number;
  readonly content: string;
  private stableValue: string | undefined;
  private exactValue: string | undefined;

  constructor(readonly item: Entry) {
    this.second = toSeconds(item.times.lastModification);
    this.content = contentFingerprint(item, { withoutCustomData: true });
  }

  /** Rohdaten-Fingerabdruck mit Zeiten in ganzen Sekunden (wie nach Speichern und Laden). */
  get stable(): string {
    return (this.stableValue ??= exactFingerprint(withWholeSecondTimes(this.item)));
  }

  /** Rohdaten-Fingerabdruck mit den genauen Zeiten. */
  get exact(): string {
    return (this.exactValue ??= exactFingerprint(this.item));
  }

  /**
   * true, wenn diese Fassung statt `other` behalten wird. Strukturell gleiche Fassungen haben
   * gleiche Fingerabdrücke – dann bleibt die vorhandene, ohne etwas zu berechnen.
   */
  preferredOver(other: HistoryCandidate): boolean {
    if (deepEqual(this.item, other.item)) return false;
    return (compareText(this.stable, other.stable) || compareText(this.exact, other.exact)) > 0;
  }
}

/**
 * Vereinigt Fassungen zu einem Verlauf: ohne Doppelte (gleiche lastModification in GANZEN
 * SEKUNDEN und gleicher Inhalt OHNE CustomData), sortiert nach lastModification (ganze
 * Sekunden), dann Inhalts-Fingerabdruck, dann gekürzt nach den Grenzen aus `meta`.
 * Von Doppelten bleibt die mit dem größten Rohdaten-Fingerabdruck über die auf ganze Sekunden
 * abgerundeten Zeiten; erst wenn der gleich ist, entscheidet der über die genauen Zeiten.
 * So hängt die Wahl weder von der Reihenfolge noch davon ab, ob eine Fassung aus dem Speicher
 * (ms) oder aus der Datei (s) kommt.
 *
 * Warum ohne CustomData? KeePassXC übernimmt CustomData nicht in seine Verlaufseinträge;
 * dieselbe Fassung kann also einmal mit und einmal ohne ankommen.
 * Warum ganze Sekunden? Dieselbe Fassung kommt beim Abgleich oft zweimal an: aus dem Speicher
 * (Zeit in ms) und aus der Datei (nur Sekunden). Mit Millisekunden stünde sie doppelt im
 * Verlauf, und zwei Geräte entschieden verschieden, welche Fassung bleibt.
 */
export function mergeHistory(items: readonly Entry[], meta: Pick<Meta, "historyMaxItems" | "historyMaxSize">): Entry[] {
  const byKey = new Map<string, HistoryCandidate>();
  for (const item of items) {
    const candidate = new HistoryCandidate(item);
    const key = `${candidate.second}|${candidate.content}`;
    const existing = byKey.get(key);
    if (existing === undefined || candidate.preferredOver(existing)) byKey.set(key, candidate);
  }
  // (Sekunde, Inhalt) ist nach dem Entfernen der Doppelten eindeutig – die Reihenfolge steht fest.
  const sorted = [...byKey.values()].sort((a, b) => a.second - b.second || compareText(a.content, b.content));
  const history = sorted.map(({ item }) => {
    const copy = cloneEntry(item);
    copy.history = [];
    return copy;
  });
  return truncateHistory(history, meta.historyMaxItems, meta.historyMaxSize);
}
