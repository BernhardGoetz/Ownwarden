/**
 * Tiefe Kopien und Strukturvergleich für Modell-Objekte.
 *
 * Der Merge ist eine reine Funktion: Er darf seine Eingaben nicht verändern. Deshalb wird
 * alles, was ins Ergebnis übernommen und dort evtl. geändert wird, vorher kopiert.
 * Ausnahme: Byte-Arrays von Anhängen und Icons werden GETEILT, nicht kopiert. Sie gelten im
 * ganzen Kern als unveränderlich (der XML-Leser teilt sie ebenfalls zwischen Einträgen);
 * Anhänge können groß sein, und Kopieren würde nur Speicher kosten.
 */
import type { CustomData, Entry, Group, KdbxSettings, Meta, Vault } from "../model";

export function cloneCustomData(customData: CustomData): CustomData {
  return new Map([...customData].map(([key, item]) => [key, { ...item }]));
}

/** Kopie eines Eintrags samt Verlauf (Anhang-Bytes geteilt). */
export function cloneEntry(entry: Entry): Entry {
  return {
    ...entry,
    tags: [...entry.tags],
    times: { ...entry.times },
    strings: new Map([...entry.strings].map(([name, value]) => [name, { ...value }])),
    attachments: entry.attachments.map((item) => ({ ...item })),
    customData: cloneCustomData(entry.customData),
    history: entry.history.map(cloneEntry),
    unknown: [...entry.unknown],
  };
}

/** Kopie einer Gruppe OHNE Kinder (groups/entries leer). */
export function cloneGroupShallow(group: Group): Group {
  return {
    ...group,
    times: { ...group.times },
    tags: [...group.tags],
    customData: cloneCustomData(group.customData),
    groups: [],
    entries: [],
    unknown: [...group.unknown],
  };
}

/** Kopie einer Gruppe mit allen Untergruppen und Einträgen. */
export function cloneGroup(group: Group): Group {
  return { ...cloneGroupShallow(group), groups: group.groups.map(cloneGroup), entries: group.entries.map(cloneEntry) };
}

export function cloneSettings(settings: KdbxSettings): KdbxSettings {
  const kdf = settings.kdf.type === "aes" ? { ...settings.kdf, seed: settings.kdf.seed.slice() } : { ...settings.kdf, salt: settings.kdf.salt.slice() };
  const copy: KdbxSettings = { ...settings, kdf };
  if (settings.publicCustomData !== undefined) copy.publicCustomData = settings.publicCustomData.slice();
  return copy;
}

export function cloneMeta(meta: Meta): Meta {
  return {
    ...meta,
    customIcons: meta.customIcons.map((icon) => ({ ...icon })),
    customData: cloneCustomData(meta.customData),
    unknown: [...meta.unknown],
  };
}

export function cloneVault(vault: Vault): Vault {
  return {
    settings: cloneSettings(vault.settings),
    meta: cloneMeta(vault.meta),
    root: cloneGroup(vault.root),
    deletedObjects: vault.deletedObjects.map((item) => ({ ...item })),
    rootUnknown: [...vault.rootUnknown],
  };
}

/**
 * Struktureller Vergleich für Modell-Objekte: Zahlen, Texte, Arrays, Maps (unabhängig von
 * der Reihenfolge), Byte-Arrays und einfache Objekte. Eigenschaften mit dem Wert undefined
 * zählen wie fehlende Eigenschaften.
 */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    if (!(a instanceof Uint8Array && b instanceof Uint8Array) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!(Array.isArray(a) && Array.isArray(b)) || a.length !== b.length) return false;
    return a.every((item, i) => deepEqual(item, b[i]));
  }
  if (a instanceof Map || b instanceof Map) {
    if (!(a instanceof Map && b instanceof Map) || a.size !== b.size) return false;
    for (const [key, value] of a) if (!b.has(key) || !deepEqual(value, b.get(key))) return false;
    return true;
  }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const key of keys) {
    if (!deepEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key])) return false;
  }
  return true;
}
