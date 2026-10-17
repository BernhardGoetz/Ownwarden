/**
 * Zeitstempel aus der Zukunft (Review merge-2/sync-2, Entscheidung des Eigentümers 2026-10-17).
 *
 * Bearbeitet ein Gerät offline, während seine Uhr vorgeht, tragen die Änderungen Zeiten aus der
 * Zukunft. Wird die Uhr vor dem Abgleich gestellt (Netzwerkzeit), bemerkt die Uhrprüfung
 * (ClockSkewError) nichts – sie vergleicht nur die Uhr IM MOMENT des Abgleichs. Hochgeladen
 * gewönnen diese Zeiten jeden Vergleich „neueste Änderung gewinnt“: gegen echte neuere
 * Änderungen anderer Geräte, gegen Löschungen in KeePassXC, und über die Uhr (VaultClock)
 * stempelten danach alle Geräte in die Zukunft.
 *
 * Deshalb verweigert syncVault den Abgleich (FutureTimestampsError, siehe sync.ts), und
 * restampFutureTimes repariert die lokale Datenbank: Die betroffenen Änderungen gelten danach
 * als „jetzt“ gemacht.
 *
 * Läuft auch im Service Worker (keine Node-APIs).
 */
import { FIELD_TIMES_KEY } from "../contracts";
import type { CustomData, Entry, Group, KdbxTimes, Millis, Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { isKdbxTime } from "../merge/encoding";

export interface RestampResult {
  /** Die reparierte Kopie; die übergebene Datenbank bleibt unverändert. */
  vault: Vault;
  /** Wie viele Zeitstempel auf `now` gesetzt wurden (0: es gab nichts zu reparieren). */
  restamped: number;
}

/**
 * Setzt jeden Zeitstempel, der später als `limit` ist, auf `now` (abgerundet auf ganze ms).
 * Reine Funktion: `vault` bleibt unverändert.
 *
 * Betroffen sind alle Zeiten, die latestVaultTime (merge/clock.ts) zählt – also alles, was beim
 * Zusammenführen verglichen wird: Änderungs- und Verschiebezeiten von Einträgen (samt Verlauf)
 * und Gruppen, die Zeiten in Ownwarden.FieldTimes ("w" und jedes "t"), LastModificationTime von
 * CustomData und eigenen Icons, Datenbankname- und Papierkorb-Zeit, Löschzeiten. Dazu Erstellung
 * und letzter Zugriff (sonst lägen sie nach der Änderung). NICHT: das Ablaufdatum – das liegt oft
 * absichtlich in der Zukunft. Wie bei latestVaultTime zählen nur Zeiten im KDBX-Bereich.
 *
 * Die Feld-Zeitstempel bleiben gültig: Ihre Fingerabdrücke ("h") hängen nur von den Werten ab,
 * und die bleiben unverändert. Danach gilt latestVaultTime(result.vault) ≤ limit.
 *
 * Typischer Aufruf (z. B. nach FutureTimestampsError, Uhr ist wieder richtig):
 *   const now = Date.now();
 *   const { vault: repaired } = restampFutureTimes(vault, now + DEFAULT_SYNC_SETTINGS.maxClockSkewMs, now);
 *
 * @throws RangeError, wenn `now` keine gültige KDBX-Zeit ist oder nach `limit` liegt.
 */
export function restampFutureTimes(vault: Vault, limit: Millis, now: Millis): RestampResult {
  const stamp = Math.floor(now);
  if (!isKdbxTime(stamp) || !(stamp <= limit)) {
    throw new RangeError("restampFutureTimes: now muss eine gültige Zeit sein und darf nicht nach limit liegen.");
  }
  const result = cloneVault(vault);
  let restamped = 0;
  const isFuture = (time: unknown): time is number => typeof time === "number" && time > limit && isKdbxTime(Math.floor(time));
  const fix = (time: Millis): Millis => {
    if (!isFuture(time)) return time;
    restamped += 1;
    return stamp;
  };

  const fixTimes = (times: KdbxTimes): void => {
    times.creation = fix(times.creation);
    times.lastModification = fix(times.lastModification);
    times.lastAccess = fix(times.lastAccess);
    times.locationChanged = fix(times.locationChanged);
  };
  const fixCustomData = (customData: CustomData): void => {
    for (const item of customData.values()) if (item.lastModified !== undefined) item.lastModified = fix(item.lastModified);
  };
  /**
   * Ownwarden.FieldTimes: dieselben Zahlen wie latestVaultTime (bewusst tolerant, auch aus
   * Fassungen, die readFieldTimes als ungültig verwirft). Geschrieben wird nur bei einer
   * Änderung; Aufbau und Schlüsselreihenfolge des JSON bleiben dabei erhalten.
   */
  const fixFieldTimes = (entry: Entry): void => {
    const item = entry.customData.get(FIELD_TIMES_KEY);
    if (item === undefined) return;
    let data: unknown;
    try {
      data = JSON.parse(item.value);
    } catch {
      return;
    }
    if (typeof data !== "object" || data === null) return;
    const before = restamped;
    const record = data as { w?: unknown; f?: unknown };
    if (isFuture(record.w)) record.w = fix(record.w);
    if (typeof record.f === "object" && record.f !== null) {
      for (const field of Object.values(record.f as Record<string, unknown>)) {
        if (typeof field !== "object" || field === null) continue;
        const withTime = field as { t?: unknown };
        if (isFuture(withTime.t)) withTime.t = fix(withTime.t);
      }
    }
    if (restamped !== before) entry.customData.set(FIELD_TIMES_KEY, { ...item, value: JSON.stringify(data) });
  };
  const fixEntry = (entry: Entry): void => {
    fixTimes(entry.times);
    fixCustomData(entry.customData);
    fixFieldTimes(entry);
    entry.history.forEach(fixEntry);
  };
  const fixGroup = (group: Group): void => {
    fixTimes(group.times);
    fixCustomData(group.customData);
    group.entries.forEach(fixEntry);
    group.groups.forEach(fixGroup);
  };

  result.meta.databaseNameChanged = fix(result.meta.databaseNameChanged);
  result.meta.recycleBinChanged = fix(result.meta.recycleBinChanged);
  for (const icon of result.meta.customIcons) if (icon.lastModified !== undefined) icon.lastModified = fix(icon.lastModified);
  fixCustomData(result.meta.customData);
  for (const deleted of result.deletedObjects) deleted.deletionTime = fix(deleted.deletionTime);
  fixGroup(result.root);
  return { vault: result, restamped };
}
