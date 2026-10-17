/**
 * Schnittstellen zwischen den Teilen des Kerns. Jede Teilaufgabe implementiert genau die
 * hier beschriebenen Funktionen unter genau diesen Namen, damit die Teile unabhängig
 * voneinander gebaut und danach zusammengesteckt werden können.
 *
 *   kdbx/container.ts   decryptContainer, encryptContainer      (äußere Hülle, Krypto)
 *   kdbx/inner-stream.ts createInnerStream, newInnerStreamKey   (Schutz einzelner Werte)
 *   kdbx/xml.ts         parseVaultXml, serializeVaultXml        (XML <-> Modell)
 *   merge/merge.ts      mergeVaults                              (Feld-Merge)
 *   merge/field-times.ts, merge/vault-ops.ts                     (Feld-Zeitstempel, Bearbeiten)
 *   sync/sync.ts        syncVault                                (Abgleich mit Speicher)
 *   sync/webdav.ts      WebDavAdapter                            (WebDAV-Speicher)
 */
import type { Credentials, KdbxSettings, Millis, Uuid, Vault } from "./model";

// ---------------------------------------------------------------------------
// Fehler
// ---------------------------------------------------------------------------

export type KdbxErrorCode =
  | "BadSignature" // keine KDBX-Datei
  | "UnsupportedVersion" // nicht KDBX 4.x
  | "UnsupportedCipher" // z. B. Twofish
  | "UnsupportedKdf"
  | "UnsupportedInnerStream"
  | "InvalidCredentials" // Header-HMAC passt nicht: falsches Passwort/Schlüssel
  | "Corrupt"; // Datei beschädigt (Block-HMAC, Länge, XML ...)

export class KdbxError extends Error {
  constructor(
    readonly code: KdbxErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "KdbxError";
  }
}

// ---------------------------------------------------------------------------
// KDBX-Container (kdbx/container.ts, kdbx/inner-stream.ts)
// ---------------------------------------------------------------------------

export type InnerStreamId = "chacha20" | "salsa20";

/**
 * Schlüsselstrom für geschützte Werte. Alle geschützten Werte einer Datei werden in
 * Dokumentreihenfolge nacheinander mit demselben, fortlaufenden Strom per XOR ver- bzw.
 * entschlüsselt. `process` ist daher zustandsbehaftet.
 */
export interface InnerStreamCipher {
  process(data: Uint8Array): Uint8Array;
}

/** Ein Eintrag im Binär-Pool des inneren Headers (Anhänge werden per Index referenziert). */
export interface PoolBinary {
  data: Uint8Array;
  protected: boolean;
}

/** Inhalt einer KDBX4-Datei nach dem Entschlüsseln der äußeren Hülle. */
export interface DecryptedPayload {
  settings: KdbxSettings;
  innerStreamId: InnerStreamId;
  innerStreamKey: Uint8Array;
  binaries: PoolBinary[];
  /** Die XML-Datenbank als UTF-8-Bytes; geschützte Werte sind darin noch verschlüsselt. */
  xml: Uint8Array;
}

/** kdbx/container.ts: Datei -> Payload. Prüft Signatur, Header-Hash, Header-HMAC, Block-HMACs. */
export type DecryptContainer = (file: Uint8Array, credentials: Credentials) => Promise<DecryptedPayload>;

/**
 * kdbx/container.ts: Payload -> Datei. Erzeugt bei JEDEM Aufruf neuen Master-Seed, neuen IV
 * und neuen KDF-Salt/-Seed (die übrigen KDF-Parameter bleiben).
 */
export type EncryptContainer = (payload: DecryptedPayload, credentials: Credentials) => Promise<Uint8Array>;

/** kdbx/inner-stream.ts */
export type CreateInnerStream = (id: InnerStreamId, key: Uint8Array) => InnerStreamCipher;

// ---------------------------------------------------------------------------
// XML (kdbx/xml.ts)
// ---------------------------------------------------------------------------

/**
 * XML -> Modell. Entschlüsselt geschützte Werte mit `stream` in Dokumentreihenfolge und löst
 * Anhang-Referenzen (<Binary><Value Ref="n"/>) über `binaries` auf.
 */
export type ParseVaultXml = (
  xml: Uint8Array,
  binaries: PoolBinary[],
  stream: InnerStreamCipher,
  settings: KdbxSettings,
) => Vault;

/**
 * Modell -> XML. Baut den Binär-Pool neu auf (gleiche Inhalte nur einmal) und verschlüsselt
 * geschützte Werte mit `stream` in Dokumentreihenfolge.
 */
export type SerializeVaultXml = (
  vault: Vault,
  stream: InnerStreamCipher,
) => { xml: Uint8Array; binaries: PoolBinary[] };

// ---------------------------------------------------------------------------
// Feld-Merge (merge/)
// ---------------------------------------------------------------------------

/** Schlüssel des CustomData-Eintrags, in dem Ownwarden Feld-Zeitstempel speichert. */
export const FIELD_TIMES_KEY = "Ownwarden.FieldTimes";

/**
 * Schlüssel für ein „Feld“ im Sinne der Sync-Regel:
 *   "s:<Name>"   ein <String>-Feld (Title, UserName, Password, URL, Notes, eigene Felder)
 *                außer den Passkey-Attributen
 *   "passkey"    alle KPEX_PASSKEY_* / KPXC_PASSKEY_* Felder zusammen (eine Einheit)
 *   "a:<Name>"   ein Anhang
 *   "cd:<Key>"   ein CustomData-Eintrag (außer Ownwarden.FieldTimes und _LAST_MODIFIED)
 *   "tags" | "icon" | "colors" | "overrideUrl" | "expiry" | "parent" | "misc"
 *   ("misc" = alles Übrige, z. B. AutoType, QualityCheck)
 */
export type FieldKey = string;

export interface FieldConflict {
  entryUuid: Uuid;
  field: FieldKey;
  winner: "local" | "remote";
  /** true, wenn die Zeitstempel gleich waren und die feste Regel entschieden hat. */
  tieBreak: boolean;
}

export interface MergeReport {
  entriesAddedFromRemote: number;
  entriesUpdated: number;
  entriesDeleted: number;
  entriesResurrected: number;
  groupsChanged: number;
  orphansRecovered: number;
  fieldConflicts: FieldConflict[];
  /** Einträge, die (laut Feld-Zeitstempeln) außerhalb von Ownwarden geändert wurden. */
  externalEdits: Uuid[];
}

export interface MergeOptions {
  /** Aktuelle Zeit (für neu angelegte Hilfsobjekte wie die Wiederherstellungsgruppe). */
  now: Millis;
}

export interface MergeResult {
  vault: Vault;
  report: MergeReport;
}

/**
 * merge/merge.ts: führt zwei Fassungen derselben Datenbank zusammen. Reine Funktion:
 * verändert `local` und `remote` nicht.
 *
 * Unabhängig davon, welche Seite `local` und welche `remote` ist (merge(a, b) und merge(b, a)
 * liefern dasselbe): welche Einträge, Gruppen und Lösch-Vermerke das Ergebnis enthält, jedes
 * Feld eines Eintrags samt Feld-Zeitstempeln, der Verlauf, die Eigenschaften und die Position
 * jeder Gruppe, die Meta-Angaben mit Zeitstempel (Datenbankname, Papierkorb, eigene Icons,
 * Meta-CustomData), die UUID der Wurzel (die kleinere) und versionMinor (das Maximum).
 *
 * Von der Rolle der Seiten abhängig:
 *   - die Reihenfolge von Geschwistern (erst wie in `local`, dann die nur in `remote`);
 *   - von `local` übernommen: die KDBX-Einstellungen außer versionMinor (Verschlüsselung,
 *     Schlüsselableitung, Kompression, publicCustomData), die Verlaufsgrenzen
 *     (historyMaxItems, historyMaxSize), unbekannte Meta-Elemente (meta.unknown) und unbekannte
 *     Elemente unter <Root> (rootUnknown);
 *   - das Feld `winner` im Bericht.
 * syncVault setzt die von `local` übernommenen Angaben vorher auf die Werte des Servers
 * (adoptServerSettings in sync/sync.ts): Beim Abgleich gewinnt dort die Datei auf dem Server.
 */
export type MergeVaults = (local: Vault, remote: Vault, options: MergeOptions) => MergeResult;

// ---------------------------------------------------------------------------
// Speicher und Sync (sync/)
// ---------------------------------------------------------------------------

export class PreconditionFailedError extends Error {
  constructor(message = "Die Datei wurde inzwischen von einem anderen Gerät geändert (412).") {
    super(message);
    this.name = "PreconditionFailedError";
  }
}

export class StorageAuthError extends Error {
  constructor(message = "Anmeldung am Speicher fehlgeschlagen (401/403).") {
    super(message);
    this.name = "StorageAuthError";
  }
}

export class StorageError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "StorageError";
  }
}

export class ClockSkewError extends Error {
  constructor(readonly skewMs: number) {
    super(`Die Geräteuhr weicht um ${Math.round(skewMs / 1000)} s von der Serverzeit ab.`);
    this.name = "ClockSkewError";
  }
}

/**
 * Die lokale Datenbank enthält Zeitstempel aus der Zukunft: später als die Serverzeit (beim
 * ersten Hochladen: die Gerätezeit) plus SyncOptions.maxClockSkewMs. Typisch: Das Gerät hat
 * offline mit falsch gehender Uhr bearbeitet, die Uhr wurde vor dem Abgleich gestellt. Solche
 * Änderungen würden jede echte neuere Änderung anderer Geräte und jede Löschung in KeePassXC
 * still schlagen, bis die echte Zeit sie eingeholt hat (Entscheidung des Eigentümers,
 * 2026-10-17). syncVault schreibt dann nichts. Reparatur: restampFutureTimes (sync/future-times.ts).
 */
export class FutureTimestampsError extends Error {
  constructor(
    /** Der späteste Zeitstempel der lokalen Datenbank (wie latestVaultTime). */
    readonly latestTime: Millis,
    /** Spätester erlaubter Zeitstempel. */
    readonly limit: Millis,
  ) {
    super(
      `Die lokale Datenbank enthält Zeitstempel aus der Zukunft (bis ${isoTime(latestTime)}, erlaubt sind höchstens ` +
        `${isoTime(limit)}). Vermutlich ging die Geräteuhr beim Bearbeiten falsch. So gleicht Ownwarden nicht ab: Diese ` +
        "Änderungen würden sonst neuere Änderungen anderer Geräte und Löschungen in KeePassXC still überschreiben. Es " +
        "wurde nichts geschrieben. Abhilfe: Geräteuhr prüfen, dann die Zeitstempel reparieren (Reparatur-Befehl bzw. " +
        "restampFutureTimes). Die betroffenen Änderungen gelten danach als jetzt gemacht.",
    );
    this.name = "FutureTimestampsError";
  }
}

/** Zeit für Meldungen (UTC, ISO 8601); bei ungültiger Zeit die Zahl. */
function isoTime(time: Millis): string {
  const date = new Date(time);
  return Number.isNaN(date.getTime()) ? String(time) : date.toISOString();
}

export interface RemoteFile {
  data: Uint8Array;
  /** ETag genau so, wie der Server ihn geliefert hat (inkl. Anführungszeichen/W/). */
  etag: string;
  /** Aus dem Date-Header der Antwort, falls vorhanden. */
  serverDate?: Millis;
}

export type WriteCondition = { ifMatch: string } | { ifNoneMatch: "*" };

/** Ergebnis von StorageAdapter.backup und StorageAdapter.pruneBackups (Ergänzung vom 2026-10-16). */
export interface BackupResult {
  /** Hinweise, die den Abgleich NICHT aufhalten (deutsch, ohne Zugangsdaten). Leer: keine. */
  warnings: string[];
}

/**
 * Speicher für die Tresor-Datei samt Sicherungskopien.
 *
 * Sicherungskopien (geändert 2026-10-17, Review xc-1): Früher hat backup() gleich auch alte
 * Kopien gelöscht – VOR dem Schreiben. Scheiterte das Schreiben danach immer wieder (z. B. 423
 * bei einer hängenden Dateisperre), legte jeder Versuch eine weitere Kopie derselben Fassung an
 * und löschte dafür eine ältere, andere: Nach wenigen Abgleichen gab es nur noch Kopien EINER
 * Fassung. Deshalb jetzt in zwei Schritten:
 *   1. backup(current) vor dem Schreiben: legt die Kopie an, aber nur EINMAL pro Fassung
 *      (erkannt am ETag; gibt es schon eine vollständige Kopie dieser Fassung, passiert nichts).
 *   2. pruneBackups(current, keep) erst NACH einem erfolgreichen Schreiben: räumt auf.
 * Gescheiterte Schreibversuche verringern so nie die Zahl der verschiedenen gesicherten Fassungen.
 */
export interface StorageAdapter {
  /** Für Meldungen, ohne Zugangsdaten. */
  describe(): string;
  /** null, wenn die Datei noch nicht existiert. */
  read(): Promise<RemoteFile | null>;
  /** Wirft PreconditionFailedError bei 412. Liefert den neuen ETag, falls der Server ihn nennt. */
  write(data: Uint8Array, condition: WriteCondition): Promise<{ etag: string | null; serverDate?: Millis }>;
  /**
   * Stellt sicher, dass es eine Sicherungskopie der Fassung `current` gibt (gelesen mit read(),
   * erkannt an current.etag), und legt sie sonst an. Wiederholte Aufrufe für dieselbe Fassung
   * legen keine weiteren Kopien an. Löscht nichts.
   *
   * Pflicht: Lässt sich die Kopie nicht anlegen, wirft backup (syncVault schreibt dann nicht).
   * Rückgabe `void` heißt: keine Hinweise.
   */
  backup(current: RemoteFile): Promise<BackupResult | void>;
  /**
   * Räumt alte Sicherungskopien auf, bis nur noch die neuesten `keep` übrig sind; die Kopie der
   * Fassung `current` (eben überschrieben) bleibt immer. syncVault ruft das nur nach einem
   * ERFOLGREICHEN Schreiben auf.
   *
   * „Best effort“ (Entscheidung des Eigentümers, 2026-10-16): Lässt sich der Sicherungsordner
   * nicht auflisten oder eine alte Kopie nicht löschen (z. B. 403/423), wirft pruneBackups
   * NICHT, sondern meldet es in `warnings`. Rückgabe `void` heißt: keine Hinweise.
   */
  pruneBackups(current: RemoteFile, keep: number): Promise<BackupResult | void>;
}

/** Wandelt Datei-Bytes und Modell ineinander um (schließt die Zugangsdaten ein). */
export interface VaultCodec {
  decode(file: Uint8Array): Promise<Vault>;
  encode(vault: Vault): Promise<Uint8Array>;
}

export interface SyncOptions {
  now(): Millis;
  merge: MergeVaults;
  /** Wie oft bei 412 neu geladen und zusammengeführt wird. */
  maxAttempts: number;
  /**
   * Erlaubte Abweichung der Geräteuhr vom Date-Header des Servers. Zugleich die Grenze für
   * Zeitstempel in der lokalen Datenbank: keiner später als Serverzeit (beim ersten Hochladen:
   * now()) plus maxClockSkewMs, sonst FutureTimestampsError (siehe sync/sync.ts).
   */
  maxClockSkewMs: number;
  backupsToKeep: number;
}

export interface SyncResult {
  vault: Vault;
  /** ETag der geschriebenen bzw. gelesenen Fassung (null, wenn der Server keinen liefert). */
  etag: string | null;
  attempts: number;
  /** true, wenn die Datei neu angelegt wurde. */
  created: boolean;
  /** true, wenn geschrieben wurde. */
  written: boolean;
  report?: MergeReport;
  /**
   * Hinweise, die den Abgleich nicht verhindert haben, z. B. „alte Sicherungskopie ließ sich
   * nicht löschen“ (siehe StorageAdapter.pruneBackups). Fehlt, wenn es keine gibt. Optional, damit
   * bestehende Aufrufer und Tests unverändert gültig bleiben (Ergänzung vom 2026-10-16).
   */
  warnings?: string[];
}

/** sync/sync.ts */
export type SyncVault = (
  local: Vault,
  adapter: StorageAdapter,
  codec: VaultCodec,
  options: SyncOptions,
) => Promise<SyncResult>;
