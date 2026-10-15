/**
 * Zusammenführen zweier Fassungen EINER Gruppe (gleiche UUID).
 *
 * Gruppen haben keine Feld-Zeitstempel. Es gibt zwei Entscheidungen:
 *   - Eigenschaften (Name, Notizen, Icon, Tags, CustomData, Ablauf, unbekannte
 *     XML-Elemente, PreviousParentGroup) als EINE Einheit: die Fassung mit der neueren
 *     times.lastModification gewinnt.
 *   - Elterngruppe: die Fassung mit der neueren times.locationChanged gewinnt.
 * Zeiten werden in ganzen Sekunden verglichen (KDBX speichert nur Sekunden).
 * Gleichstand: größere kanonische Bytes, dann größere exakte Bytes (wie bei Feldern;
 * Format in spec/README.md), sonst local. Unterscheiden sich die Fassungen nur in den
 * Kindern, ist das hier egal – Kinder werden über IHRE Elterngruppe zugeordnet.
 */
import type { Group, Uuid } from "../model";
import { compareBytes, compareText, decimal, encodeParts, sameBytes, toSeconds } from "./encoding";
import { IGNORED_CUSTOM_DATA_KEYS, normalizeLineEndings, normalizeTags } from "./fields";
import { cloneGroupShallow } from "./clone";

/** Eine Gruppe (ohne Kinder) zusammen mit ihrer Elterngruppe (undefined = Wurzel). */
export interface PlacedGroup {
  group: Group;
  parent: Uuid | undefined;
}

/** Kanonischer Wert der Eigenschaften einer Gruppe. */
export function groupCanonical(group: Group): Uint8Array {
  const customData = [...group.customData]
    .filter(([key]) => !IGNORED_CUSTOM_DATA_KEYS.has(key))
    .sort(([a], [b]) => compareText(a, b))
    .flatMap(([key, item]) => [key, normalizeLineEndings(item.value)]);
  return encodeParts([
    "group",
    group.name,
    normalizeLineEndings(group.notes),
    group.customIconUuid !== undefined ? ["c", group.customIconUuid] : ["i", decimal(group.iconId)],
    normalizeTags(group.tags),
    customData,
    group.unknown,
    group.previousParentGroup ?? "",
    group.times.expires ? decimal(toSeconds(group.times.expiry)) : "",
  ]);
}

/** Exakter Wert (Rohdaten) der Eigenschaften einer Gruppe – nur für den Gleichstand. */
function groupExact(group: Group): Uint8Array {
  return encodeParts([
    "group",
    group.name,
    group.notes,
    [decimal(group.iconId), group.customIconUuid ?? ""],
    group.tags,
    [...group.customData].flatMap(([key, item]) => [key, item.value, item.lastModified === undefined ? "" : decimal(item.lastModified)]),
    group.unknown,
    group.previousParentGroup ?? "",
    [group.times.expires ? "1" : "0", decimal(group.times.expiry)],
  ]);
}

/** true, wenn sich die Eigenschaften (kanonisch) unterscheiden. */
export function groupPropertiesDiffer(a: Group, b: Group): boolean {
  return !sameBytes(groupCanonical(a), groupCanonical(b));
}

/**
 * >= 0: local gewinnt die Eigenschaften, < 0: remote.
 *
 * Verglichen wird in GANZEN SEKUNDEN: Gruppen haben keine millisekundengenauen
 * Feld-Zeitstempel, und beim Abgleich liegt eine Seite meist im Speicher (ms), die andere kommt
 * frisch aus der Datei (nur Sekunden). Mit Millisekunden entschiede jedes Gerät zugunsten
 * seiner eigenen Fassung und beide schrieben sich gegenseitig ihre Fassung zurück.
 */
function compareProperties(local: Group, remote: Group): number {
  return (
    Math.sign(toSeconds(local.times.lastModification) - toSeconds(remote.times.lastModification)) ||
    Math.sign(compareBytes(groupCanonical(local), groupCanonical(remote))) ||
    Math.sign(compareBytes(groupExact(local), groupExact(remote)))
  );
}

/** >= 0: local gewinnt die Elterngruppe, < 0: remote. Ganze Sekunden (siehe compareProperties). */
function compareParent(local: PlacedGroup, remote: PlacedGroup): number {
  return (
    Math.sign(toSeconds(local.group.times.locationChanged) - toSeconds(remote.group.times.locationChanged)) ||
    Math.sign(compareText(local.parent ?? "", remote.parent ?? ""))
  );
}

/**
 * Führt zwei Fassungen einer Gruppe zusammen. Ergebnis ohne Kinder. Zeiten: creation = min,
 * lastModification/lastAccess/usageCount = max, locationChanged vom Gewinner der
 * Elterngruppe, Ablauf vom Gewinner der Eigenschaften.
 */
export function mergeGroupVersions(local: PlacedGroup, remote: PlacedGroup): PlacedGroup {
  const properties = compareProperties(local.group, remote.group) >= 0 ? local.group : remote.group;
  const position = compareParent(local, remote) >= 0 ? local : remote;
  const merged = cloneGroupShallow(properties);
  const a = local.group.times;
  const b = remote.group.times;
  merged.times = {
    ...merged.times,
    creation: Math.min(a.creation, b.creation),
    lastModification: Math.max(a.lastModification, b.lastModification),
    lastAccess: Math.max(a.lastAccess, b.lastAccess),
    usageCount: Math.max(a.usageCount, b.usageCount),
    // Gleiche Elterngruppe auf beiden Seiten: die spätere Zeit (sonst hinge die Millisekunde
    // bei Gleichstand in derselben Sekunde davon ab, welche Seite local ist).
    locationChanged: local.parent === remote.parent ? Math.max(a.locationChanged, b.locationChanged) : position.group.times.locationChanged,
  };
  return { group: merged, parent: position.parent };
}
