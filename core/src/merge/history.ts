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
import { compareBytes, compareText, encodeParts, fingerprint, decimal, toSeconds, type Part } from "./encoding";
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

/** Die Zeiten einer Fassung als Teile (Reihenfolge wie in spec/README.md, Abschnitt 5.1). */
function timeParts(entry: Entry): Part[] {
  const t = entry.times;
  return [...[t.creation, t.lastModification, t.lastAccess, t.expiry, t.usageCount, t.locationChanged].map(decimal), t.expires ? "1" : "0"];
}

/** Fingerabdruck der Rohdaten einer Fassung (exakte Werte der VORHANDENEN Felder und alle Zeiten). */
function exactFingerprint(entry: Entry): string {
  const fields = entryFields(entry);
  const parts: Part[] = [...fields.keys()].sort(compareText).flatMap((key) => [key, fields.get(key)!.exact]);
  return fingerprint(encodeParts([...parts, ...timeParts(entry)]));
}

const flag = (value: boolean): string => (value ? "1" : "0");

/** Einträge einer Map nach Schlüssel sortiert (UTF-8-Bytes). */
function sortedByKey<T>(map: ReadonlyMap<string, T>): [string, T][] {
  return [...map].sort(([a], [b]) => compareText(a, b));
}

/**
 * Vollständige Kodierung ALLER Rohdaten einer Fassung – auch dessen, was der
 * Rohdaten-Fingerabdruck nicht sieht: Rohwerte nicht vorhandener Felder (z. B. das
 * Standard-<AutoType>, das KeePassXC 2.7.6 beim Speichern auch in Verlaufseinträge schreibt),
 * leere Standardfelder samt Schutz-Flag, Ownwarden.FieldTimes und _LAST_MODIFIED. Nur ihr
 * eigener Verlauf fehlt (im Verlauf haben Fassungen keinen). Maps (Felder, CustomData) nach
 * Schlüssel sortiert – ihre Reihenfolge zählt auch sonst nicht (deepEqual) –, Listen (Tags,
 * Anhänge, unbekannte Elemente) in ihrer Reihenfolge. Format: spec/README.md, Abschnitt 5.1.
 */
function rawEncoding(entry: Entry): Uint8Array {
  return encodeParts([
    entry.uuid,
    decimal(entry.iconId),
    entry.customIconUuid ?? "",
    entry.foregroundColor,
    entry.backgroundColor,
    entry.overrideUrl,
    entry.tags,
    timeParts(entry),
    sortedByKey(entry.strings).flatMap(([name, value]) => [name, value.value, flag(value.protected)]),
    entry.attachments.flatMap((item) => [item.name, item.data, flag(item.protected)]),
    sortedByKey(entry.customData).flatMap(([key, item]) => [key, item.value, item.lastModified === undefined ? "" : decimal(item.lastModified)]),
    entry.qualityCheck === undefined ? "u" : flag(entry.qualityCheck),
    entry.previousParentGroup ?? "",
    entry.unknown,
  ]);
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
 * Eine Fassung beim Vereinigen von Verläufen. Die Rohdaten-Fingerabdrücke und -Kodierungen
 * werden erst berechnet, wenn zwei Fassungen auf denselben Platz kommen (Doppelte) – das
 * spart viel Rechenzeit, denn beide Seiten bringen meist denselben Verlauf mit.
 */
class HistoryCandidate {
  readonly second: number;
  readonly content: string;
  private stableValue: string | undefined;
  private stableRawValue: Uint8Array | undefined;
  private rawValue: Uint8Array | undefined;

  constructor(readonly item: Entry) {
    this.second = toSeconds(item.times.lastModification);
    this.content = contentFingerprint(item, { withoutCustomData: true });
  }

  /** Rohdaten-Fingerabdruck mit Zeiten in ganzen Sekunden (wie nach Speichern und Laden). */
  get stable(): string {
    return (this.stableValue ??= exactFingerprint(withWholeSecondTimes(this.item)));
  }

  /** Vollständige Kodierung mit Zeiten in ganzen Sekunden. */
  get stableRaw(): Uint8Array {
    return (this.stableRawValue ??= rawEncoding(withWholeSecondTimes(this.item)));
  }

  /** Vollständige Kodierung mit den genauen Zeiten. */
  get raw(): Uint8Array {
    return (this.rawValue ??= rawEncoding(this.item));
  }

  /**
   * true, wenn diese Fassung statt `other` behalten wird – eine feste Reihenfolge über ALLE
   * Rohdaten, unabhängig davon, welche Fassung zuerst kam (sonst behielte jedes Gerät seine
   * eigene Fassung und lüde sie bei jedem Abgleich wieder hoch). Erst alles, was nach dem
   * Speichern und Laden noch zu sehen ist (ganze Sekunden), dann die Millisekunden: Sonst
   * entschiede ein Gerät mit der Fassung aus dem Speicher anders als eines mit derselben
   * Fassung aus der Datei. Strukturell gleiche Fassungen haben gleiche Kodierungen – dann
   * bleibt die vorhandene, ohne etwas zu berechnen.
   */
  preferredOver(other: HistoryCandidate): boolean {
    if (deepEqual(this.item, other.item)) return false;
    return (
      compareText(this.stable, other.stable) ||
      compareBytes(this.stableRaw, other.stableRaw) ||
      compareBytes(this.raw, other.raw)
    ) > 0;
  }
}

/**
 * Vereinigt Fassungen zu einem Verlauf: ohne Doppelte (gleiche lastModification in GANZEN
 * SEKUNDEN und gleicher Inhalt OHNE CustomData), sortiert nach lastModification (ganze
 * Sekunden), dann Inhalts-Fingerabdruck, dann gekürzt nach den Grenzen aus `meta`.
 * Von Doppelten bleibt die mit dem größten Rohdaten-Fingerabdruck über die auf ganze Sekunden
 * abgerundeten Zeiten; ist der gleich, die mit der größeren vollständigen Kodierung (alle
 * Rohdaten) über die abgerundeten, dann über die genauen Zeiten (HistoryCandidate).
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
