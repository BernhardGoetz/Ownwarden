/**
 * Monotone Uhr für Änderungen: Jeder neue Zeitstempel ist größer als
 *   - jeder Zeitstempel, den die Uhr schon geliefert hat, und
 *   - jeder Zeitstempel, den sie in der Datenbank gesehen hat (observe/observeVault).
 *
 * Warum? „Neueste Änderung gewinnt“ funktioniert nur, wenn eine Änderung auch wirklich
 * einen neueren Zeitstempel bekommt als alles, was sie überschreibt – selbst wenn die
 * Geräteuhr nachgeht oder ein anderes Gerät mit vorgehender Uhr geschrieben hat
 * (PROJECT-CONTEXT.md: „nie kleiner als der größte bekannte Zeitstempel + 1 ms“).
 *
 * Gezählt werden nur Zeiten, die beim Zusammenführen verglichen werden: Änderungs- und
 * Verschiebezeiten von Einträgen, Verlaufseinträgen und Gruppen, alle Feld-Zeitstempel
 * (Ownwarden.FieldTimes), Löschzeiten, Meta-Zeiten (Name, Papierkorb, Icons, CustomData).
 * NICHT gezählt: Ablaufdatum (liegt oft absichtlich in der Zukunft), letzter Zugriff und
 * Erstellung.
 */
import { FIELD_TIMES_KEY } from "../contracts";
import type { CustomData, Entry, Group, Millis, Vault } from "../model";
import { isKdbxTime } from "./encoding";

export interface MonotonicClock {
  /** Nächster Zeitstempel (ms); jeder Aufruf liefert einen größeren Wert als alle vorherigen. */
  now(): Millis;
  /** Meldet einen bekannten Zeitstempel: Künftige now()-Werte liegen darüber. */
  observe(time: Millis): void;
}

/** Uhr, die eine Datenbank kennt. Zeitquelle standardmäßig Date.now. */
export class VaultClock implements MonotonicClock {
  /** Kleinster Wert, den now() als Nächstes liefern darf. */
  private floor = -Infinity;

  constructor(
    vault?: Vault,
    private readonly timeSource: () => Millis = () => Date.now(),
  ) {
    if (vault !== undefined) this.observeVault(vault);
  }

  now(): Millis {
    const time = Math.max(Math.floor(this.timeSource()), this.floor);
    this.floor = time + 1;
    return time;
  }

  /**
   * Zeiten außerhalb des KDBX-Bereichs (Jahr 1 bis 9999, z. B. aus kaputten FieldTimes) werden
   * ignoriert: Sonst lieferte die Uhr danach nur noch Zeiten, die sich nicht speichern lassen,
   * und ab 2^53 nicht einmal mehr steigende.
   */
  observe(time: Millis): void {
    const whole = Math.floor(time);
    if (isKdbxTime(whole)) this.floor = Math.max(this.floor, whole + 1);
  }

  /** Meldet alle relevanten Zeitstempel einer Datenbank (z. B. nach dem Zusammenführen). */
  observeVault(vault: Vault): void {
    this.observe(latestVaultTime(vault));
  }
}

/** Uhr für eine Datenbank (Kurzform für new VaultClock). */
export function createVaultClock(vault: Vault, timeSource?: () => Millis): VaultClock {
  return new VaultClock(vault, timeSource);
}

/**
 * Der größte für die Uhr relevante Zeitstempel einer Datenbank (-Infinity, wenn keiner).
 * Zeiten außerhalb des KDBX-Bereichs zählen nicht (siehe VaultClock.observe).
 */
export function latestVaultTime(vault: Vault): Millis {
  let latest = -Infinity;
  const see = (time: Millis | undefined): void => {
    if (time !== undefined && isKdbxTime(Math.floor(time)) && time > latest) latest = time;
  };
  const seeCustomData = (customData: CustomData): void => {
    for (const item of customData.values()) see(item.lastModified);
  };
  const seeEntry = (entry: Entry): void => {
    see(entry.times.lastModification);
    see(entry.times.locationChanged);
    seeCustomData(entry.customData);
    for (const time of fieldTimesValues(entry)) see(time);
    entry.history.forEach(seeEntry);
  };
  const seeGroup = (group: Group): void => {
    see(group.times.lastModification);
    see(group.times.locationChanged);
    seeCustomData(group.customData);
    group.entries.forEach(seeEntry);
    group.groups.forEach(seeGroup);
  };

  see(vault.meta.databaseNameChanged);
  see(vault.meta.recycleBinChanged);
  for (const icon of vault.meta.customIcons) see(icon.lastModified);
  seeCustomData(vault.meta.customData);
  for (const deleted of vault.deletedObjects) see(deleted.deletionTime);
  seeGroup(vault.root);
  return latest;
}

/**
 * Alle Zahlen "t" und "w" aus Ownwarden.FieldTimes – bewusst tolerant (auch aus Fassungen,
 * die readFieldTimes als ungültig verwirft), denn hier geht es nur um „größter bekannter
 * Zeitstempel“.
 */
function fieldTimesValues(entry: Entry): Millis[] {
  const text = entry.customData.get(FIELD_TIMES_KEY)?.value;
  if (text === undefined) return [];
  try {
    const data: unknown = JSON.parse(text);
    if (typeof data !== "object" || data === null) return [];
    const record = data as { w?: unknown; f?: unknown };
    const times: Millis[] = typeof record.w === "number" ? [record.w] : [];
    if (typeof record.f === "object" && record.f !== null) {
      for (const field of Object.values(record.f as Record<string, unknown>)) {
        const t = (field as { t?: unknown } | null)?.t;
        if (typeof t === "number") times.push(t);
      }
    }
    return times;
  } catch {
    return [];
  }
}
