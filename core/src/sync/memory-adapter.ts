/**
 * InMemoryAdapter: ein Speicher im Arbeitsspeicher, der sich wie ein guter WebDAV-Server
 * (Nextcloud) verhält. Für Tests und zum Ausprobieren ohne Server.
 *
 * Nachgebildet wird, worauf syncVault sich verlässt:
 *   - Jede gespeicherte Fassung bekommt einen neuen, starken ETag – auch bei gleichem Inhalt.
 *   - write() prüft die Bedingung wie ein Server: "If-None-Match: *" scheitert (412), wenn
 *     die Datei existiert; "If-Match" scheitert, wenn sie fehlt oder der ETag nicht passt.
 *   - read() liefert eine Kopie der Bytes, den ETag und die Serverzeit (Date-Header).
 *   - backup() legt Kopien an und behält nur die neuesten `keep`.
 *
 * Mehrere Geräte: Alle Adapter mit derselben InMemoryStorage („Server“) sehen dieselbe
 * Datei, z. B.
 *   const server = new InMemoryStorage();
 *   const vivaldi = new InMemoryAdapter({ storage: server, name: "Vivaldi" });
 *   const chrome = new InMemoryAdapter({ storage: server, name: "Chrome" });
 *
 * Gleichzeitige Änderungen einspielen: `beforeWrite` läuft in write() VOR der Prüfung der
 * Bedingung. Ein Test kann dort z. B. ein anderes Gerät schreiben lassen
 * (storage.put(...) oder ein ganzes syncVault eines zweiten Adapters) – genau der Fall
 * „zwischen Lesen und Schreiben hat jemand anderes geschrieben“.
 */
import { PreconditionFailedError, type RemoteFile, type StorageAdapter, type WriteCondition } from "../contracts";
import type { Millis } from "../model";

/** Eine gespeicherte Fassung. */
export interface StoredFile {
  data: Uint8Array;
  etag: string;
}

/** Eine Sicherungskopie. */
export interface StoredBackup extends StoredFile {
  /** Laufende Nummer (aufsteigend in Anlege-Reihenfolge). */
  sequence: number;
}

export interface InMemoryStorageOptions {
  /** Uhr des „Servers“ für serverDate (Date-Header); null = Server schickt keinen. Standard Date.now. */
  serverClock?: (() => Millis) | null;
  /** true: read() nennt keinen ETag (etag ""), wie ein Server ohne ETag-Unterstützung. */
  withholdEtag?: boolean;
}

/** Der gemeinsame „Server“: eine Datei plus Sicherungskopien. */
export class InMemoryStorage {
  serverClock: (() => Millis) | null;
  withholdEtag: boolean;
  /** Sicherungskopien, älteste zuerst. */
  readonly backups: StoredBackup[] = [];
  private file: StoredFile | null = null;
  private version = 0;
  private backupSequence = 0;

  constructor(options: InMemoryStorageOptions = {}) {
    this.serverClock = options.serverClock === undefined ? () => Date.now() : options.serverClock;
    this.withholdEtag = options.withholdEtag ?? false;
  }

  /** Aktuelle Fassung (Kopie) oder null. */
  current(): StoredFile | null {
    return this.file === null ? null : { data: this.file.data.slice(), etag: this.file.etag };
  }

  /** Schreibt OHNE Bedingung (z. B. „ein anderes Gerät“ in Tests); liefert den neuen ETag. */
  put(data: Uint8Array): string {
    this.version += 1;
    // Stark, eindeutig, undurchsichtig – wie bei Nextcloud.
    const random = Array.from(crypto.getRandomValues(new Uint8Array(4)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const etag = `"mem-${this.version}-${random}"`;
    this.file = { data: data.slice(), etag };
    return etag;
  }

  /** Löscht die Datei. */
  remove(): void {
    this.file = null;
  }

  /** Legt eine Sicherungskopie an und behält nur die neuesten `keep`. */
  addBackup(file: StoredFile, keep: number): void {
    this.backupSequence += 1;
    this.backups.push({ data: file.data.slice(), etag: file.etag, sequence: this.backupSequence });
    if (this.backups.length > keep) this.backups.splice(0, this.backups.length - keep);
  }

  /** Serverzeit für den „Date-Header“ (ganze Sekunden, wie bei HTTP) oder undefined. */
  date(): Millis | undefined {
    return this.serverClock === null ? undefined : Math.floor(this.serverClock() / 1000) * 1000;
  }
}

export interface InMemoryAdapterOptions {
  /** Gemeinsamer „Server“; Standard: ein eigener, neuer. */
  storage?: InMemoryStorage;
  /** Name für describe(), z. B. das Gerät. */
  name?: string;
}

/** Wird in write() vor der Prüfung der Bedingung aufgerufen. */
export type BeforeWriteHook = (data: Uint8Array, condition: WriteCondition) => void | Promise<void>;

/** Zählerstände eines Adapters (für Tests). */
export interface InMemoryAdapterStats {
  reads: number;
  /** Erfolgreiche Schreibvorgänge. */
  writes: number;
  /** Mit 412 abgelehnte Schreibvorgänge. */
  rejectedWrites: number;
  backups: number;
}

export class InMemoryAdapter implements StorageAdapter {
  readonly storage: InMemoryStorage;
  readonly stats: InMemoryAdapterStats = { reads: 0, writes: 0, rejectedWrites: 0, backups: 0 };
  /** Siehe Kopfkommentar: hier gleichzeitige Änderungen einspielen. */
  beforeWrite: BeforeWriteHook | undefined;
  /** Ist ein Fehler gesetzt, wirft das nächste backup() ihn (einmalig). */
  nextBackupError: Error | undefined;
  private readonly name: string;

  constructor(options: InMemoryAdapterOptions = {}) {
    this.storage = options.storage ?? new InMemoryStorage();
    this.name = options.name ?? "Arbeitsspeicher";
  }

  describe(): string {
    return `Speicher im Arbeitsspeicher (${this.name})`;
  }

  async read(): Promise<RemoteFile | null> {
    this.stats.reads += 1;
    const file = this.storage.current();
    if (file === null) return null;
    const serverDate = this.storage.date();
    const etag = this.storage.withholdEtag ? "" : file.etag;
    return serverDate === undefined ? { data: file.data, etag } : { data: file.data, etag, serverDate };
  }

  async write(data: Uint8Array, condition: WriteCondition): Promise<{ etag: string | null; serverDate?: Millis }> {
    await this.beforeWrite?.(data, condition);
    const existing = this.storage.current();
    const rejected = "ifMatch" in condition ? existing === null || existing.etag !== condition.ifMatch : existing !== null;
    if (rejected) {
      this.stats.rejectedWrites += 1;
      throw new PreconditionFailedError();
    }
    const etag = this.storage.put(data);
    this.stats.writes += 1;
    const serverDate = this.storage.date();
    return serverDate === undefined ? { etag } : { etag, serverDate };
  }

  async backup(current: RemoteFile, keep: number): Promise<void> {
    if (!Number.isInteger(keep) || keep < 1) throw new RangeError("backup: keep muss eine ganze Zahl ≥ 1 sein.");
    const failure = this.nextBackupError;
    if (failure !== undefined) {
      this.nextBackupError = undefined;
      throw failure;
    }
    this.storage.addBackup({ data: current.data, etag: current.etag }, keep);
    this.stats.backups += 1;
  }
}
