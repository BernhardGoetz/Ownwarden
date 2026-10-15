/**
 * Suchen im Gruppenbaum einer Datenbank.
 *
 * Hinweis: Der XML-Leser erkennt doppelte UUIDs nicht. Diese Funktionen liefern dann den
 * ERSTEN Treffer in Baum-Reihenfolge (Gruppe: erst ihre Einträge, dann ihre Untergruppen).
 */
import type { Entry, Group, Uuid, Vault } from "../model";

/** Fundort eines Eintrags: die Gruppe, in der er liegt, und seine Position darin. */
export interface EntryLocation {
  entry: Entry;
  group: Group;
  index: number;
}

/** Fundort einer Gruppe: ihre Elterngruppe (undefined für die Wurzel) und Position darin. */
export interface GroupLocation {
  group: Group;
  parent: Group | undefined;
  index: number;
}

/** Ruft `visit` für jede Gruppe auf (Wurzel zuerst, dann Tiefensuche). */
export function forEachGroup(root: Group, visit: (group: Group, parent: Group | undefined) => void): void {
  const walk = (group: Group, parent: Group | undefined): void => {
    visit(group, parent);
    for (const child of group.groups) walk(child, group);
  };
  walk(root, undefined);
}

export function findEntryLocation(vault: Vault, uuid: Uuid): EntryLocation | undefined {
  let found: EntryLocation | undefined;
  forEachGroup(vault.root, (group) => {
    if (found !== undefined) return;
    const index = group.entries.findIndex((entry) => entry.uuid === uuid);
    if (index >= 0) found = { entry: group.entries[index]!, group, index };
  });
  return found;
}

export function findGroupLocation(vault: Vault, uuid: Uuid): GroupLocation | undefined {
  if (vault.root.uuid === uuid) return { group: vault.root, parent: undefined, index: 0 };
  let found: GroupLocation | undefined;
  forEachGroup(vault.root, (group) => {
    if (found !== undefined) return;
    const index = group.groups.findIndex((child) => child.uuid === uuid);
    if (index >= 0) found = { group: group.groups[index]!, parent: group, index };
  });
  return found;
}

/** Der Eintrag mit dieser UUID (ohne Verlaufseinträge) oder undefined. */
export function findEntry(vault: Vault, uuid: Uuid): Entry | undefined {
  return findEntryLocation(vault, uuid)?.entry;
}

/** Die Gruppe mit dieser UUID (auch die Wurzel) oder undefined. */
export function findGroup(vault: Vault, uuid: Uuid): Group | undefined {
  return findGroupLocation(vault, uuid)?.group;
}

/** true, wenn `uuid` die Gruppe selbst oder eine ihrer Untergruppen (beliebig tief) ist. */
export function containsGroup(group: Group, uuid: Uuid): boolean {
  if (group.uuid === uuid) return true;
  return group.groups.some((child) => containsGroup(child, uuid));
}
