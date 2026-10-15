/**
 * mergeVaults: führt zwei Fassungen derselben Datenbank zusammen (Vertrag MergeVaults in
 * contracts.ts). Reine Funktion – `local` und `remote` bleiben unverändert; das Ergebnis
 * teilt mit ihnen höchstens die (unveränderlichen) Bytes von Anhängen und Icons.
 *
 * Ablauf:
 *   1. Beide Bäume flach erfassen: UUID -> (Objekt, Elterngruppe, Reihenfolge).
 *      Doppelte UUIDs innerhalb EINER Datei (der XML-Leser erkennt sie nicht) werden dabei
 *      wie zwei Fassungen desselben Objekts zusammengeführt – es geht nichts verloren.
 *   2. Einträge (über den ganzen Baum per UUID zugeordnet) Feld für Feld zusammenführen
 *      (merge-entry.ts), dann Löschen gegen Ändern: Ein Eintrag mit Lösch-Vermerk bleibt
 *      nur, wenn seine neueste Änderung (ganze Sekunden) NACH der Löschung liegt.
 *   3. Gruppen zusammenführen (merge-group.ts); Zyklen in den Elterngruppen auflösen.
 *   4. Gelöschte Gruppen: Die Löschung gewinnt nur, wenn sie neuer ist als die Gruppe UND
 *      als jede Änderung an Einträgen/Gruppen darin, die selbst bestehen bleiben.
 *   5. Waisen (Elterngruppe existiert nicht mehr) kommen in die Wiederherstellungsgruppe.
 *   6. Baum neu aufbauen: Geschwister in der Reihenfolge von local, dann die nur in remote
 *      vorhandenen in der Reihenfolge von remote.
 *   7. Lösch-Vermerke vereinigen (späteste Zeit), ohne die wieder vorhandenen UUIDs.
 *   8. Meta zusammenführen (merge-meta.ts) und Bericht erstellen.
 *
 * Inhaltlich ist das Ergebnis von der Rolle der Seiten unabhängig: merge(a, b) und
 * merge(b, a) enthalten dieselben Einträge, Felder, Gruppen und Lösch-Vermerke. Nur die
 * Reihenfolge von Geschwistern, die von local übernommenen Meta-Angaben (Verlaufsgrenzen,
 * unbekannte Elemente, KDBX-Einstellungen) und das Feld `winner` im Bericht hängen davon ab.
 */
import type { FieldConflict, FieldKey, MergeReport, MergeVaults } from "../contracts";
import type { Entry, Group, Millis, Uuid, Vault } from "../model";
import { cloneEntry, cloneGroupShallow, cloneSettings, deepEqual } from "./clone";
import { compareText, isKdbxTime, toSeconds } from "./encoding";
import { effectiveFieldTimes, newestFieldTime, sealFieldTimes, type FieldTime } from "./field-times";
import { LAST_MODIFIED_KEY, PARENT_FIELD } from "./fields";
import { contentFingerprint } from "./history";
import { mergeEntryVersions, type PlacedEntry } from "./merge-entry";
import { groupPropertiesDiffer, mergeGroupVersions, type PlacedGroup } from "./merge-group";
import { mergeMeta } from "./merge-meta";

/**
 * Feste UUID der Wiederhergestellt-Gruppe: die 16 ASCII-Bytes "OwnwardenRecover".
 * Fest, damit zwei Geräte, die unabhängig Waisen retten, dieselbe Gruppe anlegen.
 */
export const RECOVERY_GROUP_UUID: Uuid = "T3dud2FyZGVuUmVjb3Zlcg==";
export const RECOVERY_GROUP_NAME = "Wiederhergestellt (Ownwarden)";

/** Ordner-Icon von KeePass. */
const FOLDER_ICON = 48;

/** Ein Objekt im flachen Verzeichnis einer Datenbank. */
interface Indexed {
  /** Laufende Nummer in Baum-Reihenfolge (für die Sortierung). */
  order: number;
}

/** Flaches Verzeichnis einer Datenbank (Schritt 1). */
interface VaultIndex {
  entries: Map<Uuid, PlacedEntry & Indexed>;
  /** Alle Gruppen außer der Wurzel. */
  groups: Map<Uuid, PlacedGroup & Indexed>;
  /** Elterngruppe -> UUIDs der Kind-Einträge bzw. -Gruppen in Datei-Reihenfolge. */
  childEntries: Map<Uuid, Uuid[]>;
  childGroups: Map<Uuid, Uuid[]>;
}

/** Ein Eintrag im Ergebnis samt wirksamen Feld-Zeitstempeln. */
interface ResultEntry extends PlacedEntry {
  times: Map<FieldKey, FieldTime>;
  /** true, wenn der Eintrag aus zwei verschiedenen Fassungen neu aufgebaut wurde. */
  rebuilt?: boolean;
}

export const mergeVaults: MergeVaults = (local, remote, options) => {
  // `now` landet in Zeiten und FieldTimes (Wiederherstellungsgruppe, Verschiebungen durch den
  // Merge). Ein ungültiger Wert (NaN, Jahr > 9999) würde dort still Unsinn hinterlassen.
  if (!isKdbxTime(Math.floor(options.now))) throw new RangeError(`mergeVaults: ungültige Zeit now = ${options.now}`);
  return new VaultMerger(local, remote, Math.floor(options.now)).merge();
};

class VaultMerger {
  /** UUID der Wurzelgruppe im Ergebnis (bei verschiedenen Wurzeln die kleinere, siehe unten). */
  private readonly rootUuid: Uuid;
  private readonly l: VaultIndex;
  private readonly r: VaultIndex;
  /** Lösch-Vermerke beider Seiten: UUID -> späteste Löschzeit, Reihenfolge local, dann remote. */
  private readonly deletions = new Map<Uuid, Millis>();

  private readonly entries = new Map<Uuid, ResultEntry>();
  private readonly groups = new Map<Uuid, PlacedGroup>();
  private root!: Group;

  private readonly conflicts: FieldConflict[] = [];
  private readonly externalEdits = new Set<Uuid>();
  private readonly resurrectedEntries = new Set<Uuid>();
  private orphansRecovered = 0;

  constructor(
    private readonly local: Vault,
    private readonly remote: Vault,
    private readonly now: Millis,
  ) {
    // Normalerweise haben beide Fassungen dieselbe Wurzel. Wenn nicht, gelten beide Wurzeln
    // als dieselbe Gruppe; ihre UUID im Ergebnis ist (unabhängig von der Seite) die kleinere.
    this.rootUuid = compareText(local.root.uuid, remote.root.uuid) <= 0 ? local.root.uuid : remote.root.uuid;
    this.l = this.indexVault(local);
    this.r = this.indexVault(remote);
    for (const deleted of [...local.deletedObjects, ...remote.deletedObjects]) {
      const known = this.deletions.get(deleted.uuid);
      if (known === undefined || deleted.deletionTime > known) this.deletions.set(deleted.uuid, deleted.deletionTime);
    }
  }

  merge(): { vault: Vault; report: MergeReport } {
    this.mergeEntries();
    this.mergeGroups();
    this.breakCycles();
    this.removeDeletedGroups();
    this.recoverOrphans();
    this.breakCycles(); // Sicherheitsnetz, falls die Wiederherstellungsgruppe selbst verschoben war
    const root = this.buildTree();
    const usedIcons = collectIconUuids(root);
    const { meta, keptIcons } = mergeMeta(this.local.meta, this.remote.meta, this.deletions, usedIcons);
    const present = new Set<Uuid>([this.rootUuid, ...this.entries.keys(), ...this.groups.keys(), ...keptIcons]);
    const vault: Vault = {
      settings: {
        ...cloneSettings(this.local.settings),
        versionMinor: Math.max(this.local.settings.versionMinor, this.remote.settings.versionMinor) as 0 | 1,
      },
      meta,
      root,
      deletedObjects: [...this.deletions]
        .filter(([uuid]) => !present.has(uuid))
        .map(([uuid, deletionTime]) => ({ uuid, deletionTime })),
      rootUnknown: [...this.local.rootUnknown],
    };
    return { vault, report: this.report() };
  }

  // -------------------------------------------------------------------------
  // 1. Flaches Verzeichnis
  // -------------------------------------------------------------------------

  private indexVault(vault: Vault): VaultIndex {
    const index: VaultIndex = { entries: new Map(), groups: new Map(), childEntries: new Map(), childGroups: new Map() };
    let order = 0;
    const walk = (group: Group, groupUuid: Uuid): void => {
      for (const entry of group.entries) {
        pushChild(index.childEntries, groupUuid, entry.uuid);
        const placed = { entry, parent: groupUuid };
        const existing = index.entries.get(entry.uuid);
        if (existing === undefined) {
          index.entries.set(entry.uuid, { ...placed, order: order++ });
        } else {
          // Doppelte UUID in derselben Datei: wie zwei Fassungen zusammenführen.
          const merged = mergeEntryVersions(existing, placed, this.local.meta);
          index.entries.set(entry.uuid, { entry: merged.entry, parent: merged.parent, order: existing.order });
        }
      }
      for (const child of group.groups) {
        // Eine Untergruppe mit der UUID der Wurzel wird Teil der Wurzel (sonst Zyklus).
        if (child.uuid === vault.root.uuid || child.uuid === this.rootUuid) {
          walk(child, this.rootUuid);
          continue;
        }
        pushChild(index.childGroups, groupUuid, child.uuid);
        const placed = { group: child, parent: groupUuid };
        const existing = index.groups.get(child.uuid);
        if (existing === undefined) {
          index.groups.set(child.uuid, { ...placed, order: order++ });
        } else {
          index.groups.set(child.uuid, { ...mergeGroupVersions(existing, placed), order: existing.order });
        }
        walk(child, child.uuid);
      }
    };
    walk(vault.root, this.rootUuid);
    return index;
  }

  // -------------------------------------------------------------------------
  // 2. Einträge
  // -------------------------------------------------------------------------

  private mergeEntries(): void {
    for (const uuid of unionKeys(this.l.entries, this.r.entries)) {
      const result = this.mergeEntry(this.l.entries.get(uuid), this.r.entries.get(uuid));
      const deletedAt = this.deletions.get(uuid);
      if (deletedAt !== undefined) {
        // Löschen gegen Ändern: sekundengenau vergleichen (KDBX-Zeiten haben nur Sekunden);
        // bei Gleichstand gewinnt die Löschung.
        if (toSeconds(entryChangeTime(result)) <= toSeconds(deletedAt)) continue;
        this.resurrectedEntries.add(uuid);
      }
      this.entries.set(uuid, result);
    }
  }

  private mergeEntry(l: PlacedEntry | undefined, r: PlacedEntry | undefined): ResultEntry {
    if (l !== undefined && r !== undefined) {
      if (l.parent === r.parent && sameIgnoringLastModified(l.entry, r.entry)) {
        const entry = cloneEntry(l.entry);
        // KeePassXC setzt _LAST_MODIFIED bei jedem Laden neu; ist das der einzige
        // Unterschied, fällt es weg (KeePassXC legt es beim nächsten Laden wieder an).
        if (!deepEqual(l.entry.customData.get(LAST_MODIFIED_KEY), r.entry.customData.get(LAST_MODIFIED_KEY))) {
          entry.customData.delete(LAST_MODIFIED_KEY);
        }
        return { entry, parent: l.parent, times: this.observeEffectiveTimes(entry, l.parent) };
      }
      const merged = mergeEntryVersions(l, r, this.local.meta);
      if (merged.externallyEdited.local || merged.externallyEdited.remote) this.externalEdits.add(l.entry.uuid);
      this.conflicts.push(...merged.conflicts);
      return { entry: merged.entry, parent: merged.parent, times: merged.times, rebuilt: true };
    }
    const side = (l ?? r)!;
    const entry = cloneEntry(side.entry);
    return { entry, parent: side.parent, times: this.observeEffectiveTimes(entry, side.parent) };
  }

  /** Wirksame Feld-Zeitstempel; merkt sich dabei extern geänderte Einträge für den Bericht. */
  private observeEffectiveTimes(entry: Entry, parent: Uuid): Map<FieldKey, FieldTime> {
    const effective = effectiveFieldTimes(entry, parent);
    if (effective.externallyEdited) this.externalEdits.add(entry.uuid);
    return effective.times;
  }

  // -------------------------------------------------------------------------
  // 3. Gruppen
  // -------------------------------------------------------------------------

  private mergeGroups(): void {
    for (const uuid of unionKeys(this.l.groups, this.r.groups)) {
      const l = this.l.groups.get(uuid);
      const r = this.r.groups.get(uuid);
      const merged =
        l !== undefined && r !== undefined
          ? mergeGroupVersions(l, r)
          : { group: cloneGroupShallow((l ?? r)!.group), parent: (l ?? r)!.parent };
      this.groups.set(uuid, merged);
    }
    this.root = mergeGroupVersions({ group: this.local.root, parent: undefined }, { group: this.remote.root, parent: undefined }).group;
    this.root.uuid = this.rootUuid;
  }

  /**
   * Zyklen auflösen: Hat local A unter B verschoben und remote B unter A, ergäbe das einen
   * Kreis ohne Verbindung zur Wurzel. In jedem Kreis kommt die Gruppe mit der ÄLTEREN
   * Verschiebung (kleinste locationChanged, dann kleinste UUID) direkt unter die Wurzel.
   */
  private breakCycles(): void {
    const state = new Map<Uuid, "path" | "done">();
    for (const start of this.groups.keys()) {
      const path: Uuid[] = [];
      let current: Uuid | undefined = start;
      while (current !== undefined && this.groups.has(current) && !state.has(current)) {
        state.set(current, "path");
        path.push(current);
        current = this.groups.get(current)!.parent;
      }
      if (current !== undefined && state.get(current) === "path") {
        const cycle = path.slice(path.indexOf(current));
        const victim = cycle.reduce((a, b) => (this.olderMove(a, b) ? a : b));
        this.relocateGroup(victim, this.rootUuid);
      }
      for (const uuid of path) state.set(uuid, "done");
    }
  }

  /**
   * true, wenn Gruppe `a` älter verschoben wurde als `b` (ganze Sekunden wie bei allen
   * Gruppen-Zeiten; Gleichstand: kleinere UUID).
   */
  private olderMove(a: Uuid, b: Uuid): boolean {
    const ta = toSeconds(this.groups.get(a)!.group.times.locationChanged);
    const tb = toSeconds(this.groups.get(b)!.group.times.locationChanged);
    return ta !== tb ? ta < tb : compareText(a, b) < 0;
  }

  /**
   * Verschiebt eine Gruppe im Ergebnis. Die neue Verschiebezeit liegt mindestens eine ganze
   * Sekunde nach der alten (Gruppen werden sekundengenau verglichen) und mindestens bei
   * `now`, damit ein weiterer Abgleich mit einer Eingabe dieselbe Entscheidung trifft.
   */
  private relocateGroup(uuid: Uuid, parent: Uuid): void {
    const placed = this.groups.get(uuid)!;
    placed.parent = parent;
    const nextSecond = (toSeconds(placed.group.times.locationChanged) + 1) * 1000;
    placed.group.times = { ...placed.group.times, locationChanged: Math.max(this.now, nextSecond) };
  }

  /** Wie relocateGroup, für einen Eintrag (Feld "parent" bekommt die neue Zeit, neu versiegelt). */
  private relocateEntry(item: ResultEntry, parent: Uuid): void {
    const previous = item.times.get(PARENT_FIELD)?.t ?? item.entry.times.locationChanged;
    const time = Math.max(this.now, previous + 1);
    item.parent = parent;
    item.entry.times = {
      ...item.entry.times,
      locationChanged: time,
      lastModification: Math.max(item.entry.times.lastModification, time),
    };
    item.times.set(PARENT_FIELD, { t: time, present: true });
    sealFieldTimes(item.entry, item.times, parent);
  }

  // -------------------------------------------------------------------------
  // 4. Gelöschte Gruppen
  // -------------------------------------------------------------------------

  private removeDeletedGroups(): void {
    const childEntries = groupBy(this.entries, (item) => item.parent);
    const childGroups = groupBy(this.groups, (item) => item.parent);
    const survives = new Map<Uuid, boolean>();
    const subtreeChange = new Map<Uuid, number>();

    /** Neueste Änderung aller bestehen bleibenden Nachfahren (-Infinity, wenn keine). */
    const newestDescendantChange = (uuid: Uuid): number => {
      let newest = subtreeChange.get(uuid);
      if (newest !== undefined) return newest;
      newest = -Infinity;
      for (const child of childEntries.get(uuid) ?? []) newest = Math.max(newest, entryChangeTime(this.entries.get(child)!));
      for (const child of childGroups.get(uuid) ?? []) {
        if (groupSurvives(child)) newest = Math.max(newest, groupChangeTime(this.groups.get(child)!.group), newestDescendantChange(child));
      }
      subtreeChange.set(uuid, newest);
      return newest;
    };
    const groupSurvives = (uuid: Uuid): boolean => {
      let result = survives.get(uuid);
      if (result !== undefined) return result;
      const deletedAt = this.deletions.get(uuid);
      result =
        deletedAt === undefined ||
        toSeconds(groupChangeTime(this.groups.get(uuid)!.group)) > toSeconds(deletedAt) ||
        toSeconds(newestDescendantChange(uuid)) > toSeconds(deletedAt);
      survives.set(uuid, result);
      return result;
    };

    for (const uuid of [...this.groups.keys()]) if (!groupSurvives(uuid)) this.groups.delete(uuid);
  }

  // -------------------------------------------------------------------------
  // 5. Waisen
  // -------------------------------------------------------------------------

  private recoverOrphans(): void {
    const exists = (uuid: Uuid | undefined) => uuid === this.rootUuid || (uuid !== undefined && this.groups.has(uuid));
    const orphanGroups = [...this.groups].filter(([, item]) => !exists(item.parent)).map(([uuid]) => uuid);
    const orphanEntries = [...this.entries.values()].filter((item) => !exists(item.parent));
    if (orphanGroups.length === 0 && orphanEntries.length === 0) return;

    if (!this.groups.has(RECOVERY_GROUP_UUID)) {
      // Neu anlegen (bzw. wieder anlegen, falls sie früher gelöscht wurde: dann nach der Löschung).
      const deletedAt = this.deletions.get(RECOVERY_GROUP_UUID);
      const time = Math.max(this.now, deletedAt === undefined ? -Infinity : (toSeconds(deletedAt) + 1) * 1000);
      this.groups.set(RECOVERY_GROUP_UUID, { group: recoveryGroup(time), parent: this.rootUuid });
    }
    for (const uuid of orphanGroups) {
      if (uuid === RECOVERY_GROUP_UUID) {
        this.relocateGroup(uuid, this.rootUuid);
      } else {
        this.relocateGroup(uuid, RECOVERY_GROUP_UUID);
        this.orphansRecovered++;
      }
    }
    for (const item of orphanEntries) {
      this.relocateEntry(item, RECOVERY_GROUP_UUID);
      this.orphansRecovered++;
    }
  }

  // -------------------------------------------------------------------------
  // 6. Baum aufbauen
  // -------------------------------------------------------------------------

  private buildTree(): Group {
    const childEntries = groupBy(this.entries, (item) => item.parent);
    const childGroups = groupBy(this.groups, (item) => item.parent);
    let placedEntries = 0;
    let placedGroups = 0;
    const build = (group: Group): Group => {
      const entryUuids = this.siblingOrder(group.uuid, childEntries.get(group.uuid) ?? [], this.l.childEntries, this.r.childEntries, "entries");
      const groupUuids = this.siblingOrder(group.uuid, childGroups.get(group.uuid) ?? [], this.l.childGroups, this.r.childGroups, "groups");
      placedEntries += entryUuids.length;
      placedGroups += groupUuids.length;
      group.entries = entryUuids.map((uuid) => this.entries.get(uuid)!.entry);
      group.groups = groupUuids.map((uuid) => build(this.groups.get(uuid)!.group));
      return group;
    };
    const root = build(this.root);
    // Nach Schritt 3–5 hängt alles an der Wurzel. Falls nicht, ist das ein Programmfehler –
    // lieber abbrechen, als still Daten zu verlieren.
    if (placedEntries !== this.entries.size || placedGroups !== this.groups.size) {
      throw new Error("Merge: Nicht alle Einträge/Gruppen sind mit der Wurzel verbunden (Programmfehler).");
    }
    return root;
  }

  /** Reihenfolge der Kinder einer Gruppe: wie in local, dann wie in remote, dann der Rest. */
  private siblingOrder(
    parent: Uuid,
    children: Uuid[],
    localChildren: Map<Uuid, Uuid[]>,
    remoteChildren: Map<Uuid, Uuid[]>,
    kind: "entries" | "groups",
  ): Uuid[] {
    const wanted = new Set(children);
    const ordered: Uuid[] = [];
    const take = (uuid: Uuid): void => {
      if (wanted.delete(uuid)) ordered.push(uuid);
    };
    (localChildren.get(parent) ?? []).forEach(take);
    (remoteChildren.get(parent) ?? []).forEach(take);
    const position = (index: VaultIndex, uuid: Uuid) => (kind === "entries" ? index.entries : index.groups).get(uuid)?.order ?? Infinity;
    const rest = [...wanted].sort(
      (a, b) => position(this.l, a) - position(this.l, b) || position(this.r, a) - position(this.r, b) || compareText(a, b),
    );
    return [...ordered, ...rest];
  }

  // -------------------------------------------------------------------------
  // 8. Bericht
  // -------------------------------------------------------------------------

  private report(): MergeReport {
    let added = 0;
    let updated = 0;
    for (const [uuid, item] of this.entries) {
      const before = this.l.entries.get(uuid);
      if (before === undefined) {
        if (!this.resurrectedEntries.has(uuid)) added++;
      } else if (before.parent !== item.parent) {
        updated++;
      } else if (item.rebuilt && contentFingerprint(before.entry) !== contentFingerprint(item.entry)) {
        // Nicht neu aufgebaute Einträge aus local haben unveränderten Inhalt.
        updated++;
      }
    }
    let deleted = 0;
    for (const uuid of unionKeys(this.l.entries, this.r.entries)) if (!this.entries.has(uuid)) deleted++;

    let groupsChanged = groupPropertiesDiffer(this.local.root, this.root) ? 1 : 0;
    for (const uuid of unionKeys(this.l.groups, this.groups)) {
      const before = this.l.groups.get(uuid);
      const after = this.groups.get(uuid);
      if (before === undefined || after === undefined || before.parent !== after.parent || groupPropertiesDiffer(before.group, after.group)) {
        groupsChanged++;
      }
    }

    return {
      entriesAddedFromRemote: added,
      entriesUpdated: updated,
      entriesDeleted: deleted,
      entriesResurrected: this.resurrectedEntries.size,
      groupsChanged,
      orphansRecovered: this.orphansRecovered,
      fieldConflicts: this.conflicts,
      externalEdits: [...this.externalEdits],
    };
  }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/** Neueste Änderung eines Eintrags: neuester Feld-Zeitstempel, Änderungs- oder Verschiebezeit. */
function entryChangeTime(item: ResultEntry): Millis {
  return Math.max(newestFieldTime(item.times), item.entry.times.lastModification, item.entry.times.locationChanged);
}

/** Neueste Änderung einer Gruppe (Eigenschaften oder Verschiebung). */
function groupChangeTime(group: Group): Millis {
  return Math.max(group.times.lastModification, group.times.locationChanged);
}

/** Gleich bis auf _LAST_MODIFIED (auch in Verlaufseinträgen). */
function sameIgnoringLastModified(a: Entry, b: Entry): boolean {
  const strip = (entry: Entry): Entry => {
    const customData = new Map(entry.customData);
    customData.delete(LAST_MODIFIED_KEY);
    return { ...entry, customData, history: entry.history.map(strip) };
  };
  return deepEqual(strip(a), strip(b));
}

function recoveryGroup(time: Millis): Group {
  return {
    uuid: RECOVERY_GROUP_UUID,
    name: RECOVERY_GROUP_NAME,
    notes: "",
    iconId: FOLDER_ICON,
    times: {
      creation: time,
      lastModification: time,
      lastAccess: time,
      expiry: time,
      expires: false,
      usageCount: 0,
      locationChanged: time,
    },
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
  };
}

/** Alle Schlüssel zweier Maps: erst die der ersten, dann die übrigen der zweiten. */
function unionKeys<K>(a: Map<K, unknown>, b: Map<K, unknown>): K[] {
  const keys = [...a.keys()];
  for (const key of b.keys()) if (!a.has(key)) keys.push(key);
  return keys;
}

function pushChild(map: Map<Uuid, Uuid[]>, parent: Uuid, child: Uuid): void {
  const list = map.get(parent);
  if (list === undefined) map.set(parent, [child]);
  else if (!list.includes(child)) list.push(child);
}

/** Gruppiert die Schlüssel einer Map nach einem Merkmal ihrer Werte. */
function groupBy<T>(map: Map<Uuid, T>, keyOf: (value: T) => Uuid | undefined): Map<Uuid, Uuid[]> {
  const result = new Map<Uuid, Uuid[]>();
  for (const [uuid, value] of map) {
    const key = keyOf(value);
    if (key !== undefined) pushChild(result, key, uuid);
  }
  return result;
}

/** Alle eigenen Icons, auf die Einträge (auch im Verlauf) und Gruppen verweisen. */
function collectIconUuids(root: Group): Set<Uuid> {
  const used = new Set<Uuid>();
  const visitEntry = (entry: Entry): void => {
    if (entry.customIconUuid !== undefined) used.add(entry.customIconUuid);
    entry.history.forEach(visitEntry);
  };
  const visitGroup = (group: Group): void => {
    if (group.customIconUuid !== undefined) used.add(group.customIconUuid);
    group.entries.forEach(visitEntry);
    group.groups.forEach(visitGroup);
  };
  visitGroup(root);
  return used;
}
