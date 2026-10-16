/**
 * syncVault: gleicht die lokale Fassung mit der Datei im Speicher ab (Vertrag SyncVault in
 * contracts.ts). Ablauf eines Versuchs:
 *
 *   1. Datei lesen.
 *      - Gibt es keine: lokale Fassung mit "If-None-Match: *" anlegen. Kam ein anderes Gerät
 *        zuvor (412), nächster Versuch. (Die Uhr wird hier nicht geprüft: Ohne Datei gibt es
 *        vorher keinen Date-Header, und ohne Zusammenführen entscheidet keine Uhrzeit etwas.)
 *   2. Ohne ETag abbrechen: Ohne ETag ist kein bedingtes Schreiben möglich.
 *   3. Geräteuhr gegen den Date-Header prüfen; bei zu großer Abweichung abbrechen
 *      (ClockSkewError), BEVOR irgendetwas geschrieben wird.
 *   4. Datei entschlüsseln und mit der lokalen Fassung zusammenführen (options.merge).
 *      Einstellungen ohne Zeitstempel übernimmt Ownwarden vorher vom Server (siehe
 *      adoptServerSettings).
 *   5. Ist das Ergebnis inhaltlich gleich der Datei (vaultsEquivalent), nichts schreiben.
 *   6. Sonst: verschlüsseln, Sicherungskopie der Server-Fassung anlegen (scheitert sie,
 *      wird NICHT geschrieben; scheitert nur das Aufräumen ALTER Kopien, geht es weiter und
 *      result.warnings nennt das Problem), dann mit "If-Match: <ETag>" schreiben. Bei 412 hat ein
 *      anderes Gerät dazwischen geschrieben: nächster Versuch (neu lesen, neu zusammenführen).
 *
 * Nach options.maxAttempts Versuchen ohne Erfolg: PreconditionFailedError.
 *
 * Hinweis für Aufrufer: result.vault ist die neue lokale Fassung. Wer danach weiter
 * bearbeitet, meldet sie vorher seiner Uhr (createVaultClock(result.vault) bzw.
 * clock.observeVault(result.vault)), damit neue Zeitstempel die neuesten sind.
 */
import {
  ClockSkewError,
  PreconditionFailedError,
  StorageAuthError,
  StorageError,
  type RemoteFile,
  type StorageAdapter,
  type SyncOptions,
  type SyncResult,
  type SyncVault,
  type VaultCodec,
} from "../contracts";
import type { Vault } from "../model";
import { vaultsEquivalent } from "./vault-equal";

/**
 * Vorschläge für SyncOptions (Prototyp-Festlegung, siehe PROJECT-CONTEXT „im Prototyp festlegen“):
 *   - 5 Versuche: Bei zwei, drei Geräten reicht das selbst bei gleichzeitigem Schreiben.
 *   - 2 Minuten Uhr-Abweichung: Geräte mit Netzwerkzeit liegen wenige Sekunden auseinander;
 *     ein falsch gestelltes Datum oder eine falsche Zeitzone fällt sofort auf. Der Date-Header
 *     ist nur sekundengenau, darum kein kleinerer Wert.
 *   - 20 Sicherungskopien.
 */
export const DEFAULT_SYNC_SETTINGS = {
  maxAttempts: 5,
  maxClockSkewMs: 2 * 60 * 1000,
  backupsToKeep: 20,
} as const satisfies Pick<SyncOptions, "maxAttempts" | "maxClockSkewMs" | "backupsToKeep">;

/** Ergebnis eines Versuchs: fertig oder „412 – noch einmal“. */
type AttemptOutcome = SyncResult | "retry";

export const syncVault: SyncVault = async (local, adapter, codec, options) => {
  checkOptions(options);
  // Hinweise aus ALLEN Versuchen sammeln: Auch ein Versuch, der danach 412 bekam, hat schon
  // gesichert und aufgeräumt (bzw. es nicht geschafft).
  const warnings: string[] = [];
  for (let attempt = 1; attempt <= options.maxAttempts; attempt++) {
    const outcome = await syncAttempt(local, adapter, codec, options, attempt, warnings);
    if (outcome !== "retry") return warnings.length === 0 ? outcome : { ...outcome, warnings: [...new Set(warnings)] };
  }
  throw new PreconditionFailedError(
    `Abgleich mit ${adapter.describe()} nicht möglich: Die Datei wurde bei jedem der ${options.maxAttempts} Versuche ` +
      "gleichzeitig von einem anderen Gerät geändert (412). Bitte später erneut synchronisieren.",
  );
};

async function syncAttempt(
  local: Vault,
  adapter: StorageAdapter,
  codec: VaultCodec,
  options: SyncOptions,
  attempt: number,
  warnings: string[],
): Promise<AttemptOutcome> {
  const remote = await adapter.read();
  if (remote === null) return createRemote(local, adapter, codec, attempt);

  requireEtag(remote, adapter);
  const now = options.now();
  checkClockSkew(remote, now, options.maxClockSkewMs);

  const remoteVault = await codec.decode(remote.data);
  const { vault: merged, report } = options.merge(adoptServerSettings(local, remoteVault), remoteVault, { now });
  if (vaultsEquivalent(merged, remoteVault)) {
    return { vault: merged, etag: remote.etag, attempts: attempt, created: false, written: false, report };
  }

  // Erst verschlüsseln, dann sichern: Scheitert das Verschlüsseln, entsteht keine unnötige
  // Sicherungskopie; und zwischen Sicherung und Schreiben liegt so wenig Zeit wie möglich.
  const data = await codec.encode(merged);
  warnings.push(...(await backupOrAbort(adapter, remote, options.backupsToKeep)));
  try {
    const written = await adapter.write(data, { ifMatch: remote.etag });
    return { vault: merged, etag: written.etag, attempts: attempt, created: false, written: true, report };
  } catch (error) {
    if (error instanceof PreconditionFailedError) return "retry";
    throw error;
  }
}

/** Erstes Hochladen: Die Datei gibt es noch nicht. */
async function createRemote(local: Vault, adapter: StorageAdapter, codec: VaultCodec, attempt: number): Promise<AttemptOutcome> {
  const data = await codec.encode(local);
  try {
    // "If-None-Match: *": Legt ein anderes Gerät die Datei gerade gleichzeitig an, gewinnt
    // nur einer; der andere bekommt 412 und führt im nächsten Versuch zusammen.
    const written = await adapter.write(data, { ifNoneMatch: "*" });
    return { vault: local, etag: written.etag, attempts: attempt, created: true, written: true };
  } catch (error) {
    if (error instanceof PreconditionFailedError) return "retry";
    throw error;
  }
}

/**
 * Ohne ETag kann Ownwarden nicht bedingt schreiben ("If-Match"). Ein unbedingtes Schreiben
 * könnte die Änderung eines anderen Geräts, die zwischen Lesen und Schreiben ankommt, still
 * überschreiben – das wäre Datenverlust. Daher lieber gar nicht schreiben.
 */
function requireEtag(remote: RemoteFile, adapter: StorageAdapter): void {
  if (remote.etag !== "") return;
  throw new StorageError(
    `${adapter.describe()} liefert keinen ETag (Versionskennung) für die Tresor-Datei. Ohne ETag kann Ownwarden nicht ` +
      "sicher schreiben: Die Änderung eines anderen Geräts könnte unbemerkt überschrieben werden. Es wurde nichts " +
      "geschrieben. Bitte einen WebDAV-Server mit ETag-Unterstützung verwenden (z. B. Nextcloud).",
  );
}

/**
 * Feld-Zeitstempel entscheiden beim Zusammenführen, welche Änderung gewinnt. Geht die
 * Geräteuhr deutlich falsch, gewönne eine alte Änderung (Uhr vor) bzw. verlöre eine neue
 * (Uhr nach). Deshalb nicht still schreiben, sondern melden (PROJECT-CONTEXT, „Uhren“).
 * ClockSkewError.skewMs > 0 heißt: Die Geräteuhr geht vor.
 */
function checkClockSkew(remote: RemoteFile, now: number, maxClockSkewMs: number): void {
  if (remote.serverDate === undefined) return;
  const skew = now - remote.serverDate;
  if (Math.abs(skew) > maxClockSkewMs) throw new ClockSkewError(skew);
}

/**
 * Datenbank-Einstellungen ohne Zeitstempel: Die Fassung auf dem Server gewinnt
 * (PROJECT-CONTEXT, entschieden 2026-10-15). Das sind die KDBX-Einstellungen
 * (Verschlüsselung, Schlüsselableitung, Kompression), die Verlaufsgrenzen, unbekannte
 * Meta-Angaben (z. B. Beschreibung, MemoryProtection) und unbekannte Elemente unter <Root>.
 *
 * mergeVaults übernimmt genau diese Angaben von `local`. Darum setzt syncVault sie in einer
 * flachen Kopie von `local` vorher auf die Server-Werte. So kann ein Gerät mit älterer Kopie
 * eine Änderung aus KeePassXC (z. B. stärkere Schlüsselableitung) nicht still zurückdrehen,
 * und die Verlaufsgrenzen des Servers gelten schon beim Zusammenführen.
 * `local` selbst bleibt unverändert.
 */
export function adoptServerSettings(local: Vault, remote: Vault): Vault {
  return {
    ...local,
    settings: remote.settings,
    meta: {
      ...local.meta,
      historyMaxItems: remote.meta.historyMaxItems,
      historyMaxSize: remote.meta.historyMaxSize,
      unknown: remote.meta.unknown,
    },
    rootUnknown: remote.rootUnknown,
  };
}

/**
 * Sicherungskopie anlegen; scheitert sie, wird mit klarer Meldung abgebrochen (nichts
 * geschrieben). Liefert die Hinweise des Adapters, z. B. wenn sich alte Sicherungskopien nicht
 * löschen ließen – das Aufräumen ist „best effort“ und blockiert den Abgleich nicht
 * (StorageAdapter.backup in contracts.ts).
 */
async function backupOrAbort(adapter: StorageAdapter, remote: RemoteFile, keep: number): Promise<string[]> {
  try {
    const result = await adapter.backup(remote, keep);
    return result?.warnings ?? [];
  } catch (error) {
    // Abgelehnte Anmeldung unverändert weiterreichen: Die Oberfläche fragt dann nach dem Passwort.
    if (error instanceof StorageAuthError) throw error;
    const reason = error instanceof Error ? error.message : String(error);
    const wrapped = new StorageError(
      `Die Sicherungskopie auf ${adapter.describe()} konnte nicht angelegt werden. Ohne Sicherung schreibt Ownwarden ` +
        `nicht – es wurde nichts geändert. Ursache: ${reason}`,
      error instanceof StorageError ? error.status : undefined,
    );
    wrapped.cause = error;
    throw wrapped;
  }
}

function checkOptions(options: SyncOptions): void {
  if (!Number.isInteger(options.maxAttempts) || options.maxAttempts < 1) {
    throw new RangeError("syncVault: maxAttempts muss eine ganze Zahl ≥ 1 sein.");
  }
  if (!Number.isInteger(options.backupsToKeep) || options.backupsToKeep < 1) {
    throw new RangeError("syncVault: backupsToKeep muss eine ganze Zahl ≥ 1 sein (ohne Sicherung wird nie geschrieben).");
  }
  if (!(options.maxClockSkewMs >= 0)) {
    throw new RangeError("syncVault: maxClockSkewMs muss ≥ 0 sein.");
  }
}
