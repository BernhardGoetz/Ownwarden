/**
 * Zusammenführen der datenbankweiten Angaben (<Meta>).
 *
 *   - Datenbankname: die Seite mit der neueren DatabaseNameChanged gewinnt.
 *   - Papierkorb (an/aus + Gruppe): die Seite mit der neueren RecycleBinChanged gewinnt.
 *   - Eigene Icons: Vereinigung nach UUID; gibt es ein Icon auf beiden Seiten, gewinnt das
 *     mit der neueren LastModificationTime. Ein Icon mit einem neueren Lösch-Vermerk fällt
 *     weg – außer es wird noch von einem Eintrag/einer Gruppe benutzt (sonst zeigte dessen
 *     Icon ins Leere); dann bleibt es und der Lösch-Vermerk fällt weg.
 *   - CustomData: Vereinigung; bei gleichem Schlüssel gewinnt die neuere
 *     LastModificationTime, bei Gleichstand der größere Wert (unabhängig von der Seite).
 *   - Verlaufsgrenzen, unbekannte Elemente: von local. Generator: "Ownwarden".
 * Alle Zeiten werden in ganzen Sekunden verglichen (siehe compareSeconds).
 * Gleichstand bei Name/Papierkorb/Icons: größere Bytes gewinnen (unabhängig von der Seite).
 */
import type { CustomData, CustomDataItem, CustomIcon, Meta, Millis, Uuid } from "../model";
import { cloneCustomData } from "./clone";
import { compareBytes, compareText, decimal, encodeParts, toSeconds } from "./encoding";

export const GENERATOR = "Ownwarden";

export interface MetaMergeResult {
  meta: Meta;
  /** UUIDs der behaltenen Icons (deren Lösch-Vermerke entfallen). */
  keptIcons: Set<Uuid>;
}

/**
 * @param deletions    Lösch-Vermerke beider Seiten (UUID -> späteste Löschzeit)
 * @param usedIcons    Icons, auf die das Ergebnis verweist
 */
export function mergeMeta(local: Meta, remote: Meta, deletions: ReadonlyMap<Uuid, Millis>, usedIcons: ReadonlySet<Uuid>): MetaMergeResult {
  const nameFromLocal =
    (compareSeconds(local.databaseNameChanged, remote.databaseNameChanged) || Math.sign(compareText(local.databaseName, remote.databaseName))) >= 0;
  const recycleBinKey = (meta: Meta) => encodeParts([meta.recycleBinEnabled ? "1" : "0", meta.recycleBinUuid]);
  const binFromLocal =
    (compareSeconds(local.recycleBinChanged, remote.recycleBinChanged) || Math.sign(compareBytes(recycleBinKey(local), recycleBinKey(remote)))) >= 0;
  const nameSource = nameFromLocal ? local : remote;
  const binSource = binFromLocal ? local : remote;
  const icons = mergeIcons(local.customIcons, remote.customIcons, deletions, usedIcons);
  // Gleicher Wert auf beiden Seiten: die spätere Zeit (unabhängig davon, welche Seite local ist).
  const sameName = local.databaseName === remote.databaseName;
  const sameBin = compareBytes(recycleBinKey(local), recycleBinKey(remote)) === 0;

  return {
    meta: {
      ...local,
      generator: GENERATOR,
      databaseName: nameSource.databaseName,
      databaseNameChanged: sameName ? Math.max(local.databaseNameChanged, remote.databaseNameChanged) : nameSource.databaseNameChanged,
      recycleBinEnabled: binSource.recycleBinEnabled,
      recycleBinUuid: binSource.recycleBinUuid,
      recycleBinChanged: sameBin ? Math.max(local.recycleBinChanged, remote.recycleBinChanged) : binSource.recycleBinChanged,
      customIcons: icons,
      customData: mergeMetaCustomData(local.customData, remote.customData),
      unknown: [...local.unknown],
    },
    keptIcons: new Set(icons.map((icon) => icon.uuid)),
  };
}

/**
 * Vergleicht zwei Zeiten in GANZEN SEKUNDEN (-1, 0, 1); fehlend (undefined) = -∞.
 * Meta-Zeiten stehen in der Datei nur sekundengenau. Beim Abgleich liegt eine Seite im
 * Speicher (ms), die andere kommt aus der Datei – mit Millisekunden hielte jedes Gerät seine
 * eigene Fassung für neuer, und beide schrieben sich gegenseitig ihre Fassung zurück.
 */
function compareSeconds(a: Millis | undefined, b: Millis | undefined): number {
  const sa = a === undefined ? -Infinity : toSeconds(a);
  const sb = b === undefined ? -Infinity : toSeconds(b);
  return sa === sb ? 0 : sa > sb ? 1 : -1;
}

function iconKey(icon: CustomIcon): Uint8Array {
  return encodeParts([icon.data, icon.name ?? "", icon.lastModified === undefined ? "" : decimal(icon.lastModified)]);
}

function mergeIcons(
  local: readonly CustomIcon[],
  remote: readonly CustomIcon[],
  deletions: ReadonlyMap<Uuid, Millis>,
  usedIcons: ReadonlySet<Uuid>,
): CustomIcon[] {
  const byUuid = new Map<Uuid, CustomIcon>();
  for (const icon of [...local, ...remote]) {
    const existing = byUuid.get(icon.uuid);
    if (existing === undefined) {
      byUuid.set(icon.uuid, icon);
      continue;
    }
    const order = compareSeconds(icon.lastModified, existing.lastModified) || Math.sign(compareBytes(iconKey(icon), iconKey(existing)));
    if (order > 0) byUuid.set(icon.uuid, icon);
  }
  const result: CustomIcon[] = [];
  for (const icon of byUuid.values()) {
    const deletedAt = deletions.get(icon.uuid);
    const deleted = deletedAt !== undefined && toSeconds(deletedAt) > toSeconds(icon.lastModified ?? -Infinity);
    if (!deleted || usedIcons.has(icon.uuid)) result.push({ ...icon });
  }
  return result;
}

/**
 * CustomData: Vereinigung nach Schlüssel. Gibt es einen Schlüssel auf beiden Seiten, gewinnt
 * die neuere LastModificationTime (ganze Sekunden, fehlend = -∞). Gleichstand – auch der
 * Normalfall in KDBX 4.0, wo es gar keine Zeiten gibt – entscheidet NICHT die Rolle der Seite,
 * sondern der größere Wert (Bytes): Sonst behielte jedes Gerät beim Abgleich seinen eigenen Wert
 * und schriebe ihn immer wieder zurück.
 */
function mergeMetaCustomData(local: CustomData, remote: CustomData): CustomData {
  const result = cloneCustomData(local);
  for (const [key, item] of remote) {
    const mine = result.get(key);
    if (mine === undefined) {
      result.set(key, { ...item });
      continue;
    }
    const order = compareSeconds(item.lastModified, mine.lastModified) || Math.sign(compareBytes(customDataKey(item), customDataKey(mine)));
    if (order > 0) result.set(key, { ...item });
  }
  return result;
}

/** Gleichstand-Wert eines CustomData-Eintrags: encodeParts([Wert, LastModificationTime oder ""]). */
function customDataKey(item: CustomDataItem): Uint8Array {
  return encodeParts([item.value, item.lastModified === undefined ? "" : decimal(item.lastModified)]);
}
