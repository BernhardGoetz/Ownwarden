/**
 * vaultsEquivalent: Sind zwei Fassungen einer Datenbank INHALTLICH gleich?
 *
 * syncVault schreibt nur, wenn das Ergebnis des Zusammenführens sich inhaltlich von der Datei
 * auf dem Server unterscheidet. Ein reiner Strukturvergleich wäre zu streng – dann würde bei
 * JEDEM Abgleich neu geschrieben (mit Sicherungskopie), obwohl sich nichts geändert hat:
 *
 *   1. Zeiten: Im Speicher stehen Millisekunden, in der Datei nur ganze Sekunden. Eine eben
 *      bearbeitete Fassung (…:05.123) und dieselbe Fassung aus der Datei (…:05.000) sind gleich.
 *      -> Alle KDBX-Zeiten werden auf ganze Sekunden abgerundet (wie beim Speichern).
 *   2. Reihenfolge von Geschwistern: mergeVaults ordnet Einträge und Gruppen in der
 *      Reihenfolge von local. Zwei Geräte mit verschiedener Reihenfolge würden sich sonst
 *      gegenseitig endlos ihre Reihenfolge zurückschreiben („Ping-Pong“).
 *      -> Einträge/Gruppen einer Gruppe, Lösch-Vermerke, eigene Icons und Anhänge werden nach
 *         UUID bzw. Namen sortiert verglichen. Folge: Eine reine Umsortierung wird nicht
 *         hochgeladen (Ownwarden bietet in Version 1 kein manuelles Sortieren an).
 *   3. KDF-Salt bzw. -Seed: werden bei jedem Speichern neu erzeugt, sagen nichts über den Inhalt.
 *   4. Meta "Generator": Name des zuletzt speichernden Programms ("KeePassXC"/"Ownwarden").
 *   5. CustomData "_LAST_MODIFIED": setzt KeePassXC bei jedem Öffnen neu; laut Sync-Regel
 *      zu ignorieren (mergeVaults lässt es teils weg).
 *   6. Reihenfolge in Maps (Felder, CustomData): egal.
 *
 * Alles andere zählt: Werte, Schutz-Flags, Anhang-Bytes, Verlauf (in seiner Reihenfolge –
 * die ist zeitlich), Tags (Reihenfolge wie gespeichert), unbekannte XML-Elemente,
 * Ownwarden.FieldTimes usw.
 *
 * Umsetzung: beide Fassungen in eine „kanonische“ Form bringen und mit deepEqual
 * (merge/clone.ts: Maps, Byte-Arrays, Arrays, Objekte) vergleichen.
 */
import type { CustomData, CustomIcon, Entry, Group, KdbxSettings, KdbxTimes, Meta, Millis, Vault } from "../model";
import { deepEqual } from "../merge/clone";
import { compareText, toSeconds } from "../merge/encoding";
import { LAST_MODIFIED_KEY } from "../merge/fields";

/** true, wenn `a` und `b` inhaltlich dieselbe Datenbank sind (siehe Kopfkommentar). */
export function vaultsEquivalent(a: Vault, b: Vault): boolean {
  return deepEqual(canonicalVault(a), canonicalVault(b));
}

/** Kanonische Form einer Datenbank (nur zum Vergleichen; nicht speicherbar). */
export function canonicalVault(vault: Vault): unknown {
  return {
    settings: canonicalSettings(vault.settings),
    meta: canonicalMeta(vault.meta),
    root: canonicalGroup(vault.root),
    deletedObjects: [...vault.deletedObjects]
      .sort((x, y) => compareText(x.uuid, y.uuid) || x.deletionTime - y.deletionTime)
      .map((item) => ({ uuid: item.uuid, deletionTime: seconds(item.deletionTime) })),
    rootUnknown: vault.rootUnknown,
  };
}

function canonicalSettings(settings: KdbxSettings): unknown {
  const { kdf, ...rest } = settings;
  // Salt/Seed weglassen: bei jedem Speichern neu (siehe Kopfkommentar, Punkt 3).
  const kdfParams = kdf.type === "aes" ? { type: kdf.type, rounds: kdf.rounds } : { ...kdf, salt: undefined };
  return { ...rest, kdf: kdfParams };
}

function canonicalMeta(meta: Meta): unknown {
  return {
    ...meta,
    generator: undefined,
    databaseNameChanged: seconds(meta.databaseNameChanged),
    recycleBinChanged: seconds(meta.recycleBinChanged),
    customIcons: [...meta.customIcons].sort((x, y) => compareText(x.uuid, y.uuid)).map(canonicalIcon),
    customData: canonicalCustomData(meta.customData),
  };
}

function canonicalIcon(icon: CustomIcon): unknown {
  return { ...icon, lastModified: optionalSeconds(icon.lastModified) };
}

function canonicalGroup(group: Group): unknown {
  return {
    ...group,
    times: canonicalTimes(group.times),
    customData: canonicalCustomData(group.customData),
    groups: [...group.groups].sort((x, y) => compareText(x.uuid, y.uuid)).map(canonicalGroup),
    entries: [...group.entries].sort((x, y) => compareText(x.uuid, y.uuid)).map(canonicalEntry),
  };
}

function canonicalEntry(entry: Entry): unknown {
  return {
    ...entry,
    times: canonicalTimes(entry.times),
    customData: canonicalCustomData(entry.customData),
    // Anhang-Namen sind pro Eintrag eindeutig; KeePassXC sortiert sie beim Speichern.
    attachments: [...entry.attachments].sort((x, y) => compareText(x.name, y.name)),
    history: entry.history.map(canonicalEntry),
  };
}

function canonicalTimes(times: KdbxTimes): KdbxTimes {
  return {
    ...times,
    creation: seconds(times.creation),
    lastModification: seconds(times.lastModification),
    lastAccess: seconds(times.lastAccess),
    expiry: seconds(times.expiry),
    locationChanged: seconds(times.locationChanged),
  };
}

/** CustomData ohne _LAST_MODIFIED, Zeiten in ganzen Sekunden. */
function canonicalCustomData(customData: CustomData): Map<string, unknown> {
  const result = new Map<string, unknown>();
  for (const [key, item] of customData) {
    if (key === LAST_MODIFIED_KEY) continue;
    result.set(key, { value: item.value, lastModified: optionalSeconds(item.lastModified) });
  }
  return result;
}

function seconds(time: Millis): number {
  return toSeconds(time);
}

function optionalSeconds(time: Millis | undefined): number | undefined {
  return time === undefined ? undefined : toSeconds(time);
}
