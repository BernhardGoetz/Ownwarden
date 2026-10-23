/**
 * WebDavAdapter: die Tresor-Datei auf einem WebDAV-Server (Nextcloud, MagentaCLOUD).
 * Implementiert StorageAdapter aus contracts.ts.
 *
 * Grundsätze (siehe PROJECT-CONTEXT.md, „Schreiben“):
 *   - Lesen per GET. Den ETag genau so übernehmen, wie der Server ihn schickt (inkl.
 *     Anführungszeichen und "W/"). ETags sind undurchsichtige Kennungen: nie selbst bilden,
 *     nie umformen.
 *   - Schreiben nur bedingt: PUT mit "If-Match: <ETag>" (ersetzen) bzw. "If-None-Match: *"
 *     (neu anlegen). Hat ein anderes Gerät inzwischen geschrieben, antwortet der Server mit
 *     412 – dann muss syncVault neu lesen und zusammenführen.
 *   - Vor dem Überschreiben eine Sicherungskopie im Sicherungsordner (COPY, sonst PUT der
 *     gelesenen Bytes), pro Fassung nur einmal (backup). Alte Kopien dieser Datei werden erst
 *     nach erfolgreichem Schreiben aufgeräumt (pruneBackups; best effort: scheitert das
 *     Aufräumen, gibt es nur einen Hinweis).
 *   - Zeitlimit (timeoutMs) gegen Stillstand, nicht für die ganze Übertragung: Es greift, wenn
 *     der Server so lange nicht antwortet bzw. beim Lesen so lange keine Daten kommen. Für das
 *     Hochladen eines Inhalts kommt die Zeit hinzu, die er bei MIN_UPLOAD_BYTES_PER_SECOND
 *     braucht (siehe TransferDeadline) – große Tresore scheitern so nicht an langsamen Leitungen.
 *     Beim Herunterladen gilt dasselbe umgekehrt (Sicherheitsaudit dos-5): Das Lesen einer
 *     Antwort darf höchstens timeoutMs plus die Zeit dauern, die die schon angekommenen Byte bei
 *     MIN_DOWNLOAD_BYTES_PER_SECOND brauchen. Ein Server, der kurz vor jedem Zeitlimit ein Byte
 *     schickt, hält eine Übertragung so nicht beliebig lange offen.
 *     Zusätzlich gilt eine feste Obergrenze je Anfrage samt Lesen der Antwort (maxRequestMs,
 *     Standard MAX_REQUEST_MS = 30 min), beim Lesen ohne ETag-Header für alle Anfragen zusammen
 *     (Sicherheitsaudit dos-5, Nachprüfung). Gemessen wird mit performance.now(): Stellt jemand
 *     die Geräteuhr, verlängert das keine Frist.
 *     Achtung Service Worker: Chrome beendet ihn, wenn eine Antwort länger als 30 s braucht.
 *     Das Zeitlimit gegen Stillstand bleibt darunter (DEFAULT_WEBDAV_TIMEOUT_MS), aber ein
 *     großer Upload auf langsamer Leitung kann trotzdem länger dauern; dann bricht der Abgleich
 *     ohne Meldung ab (Daten bleiben sicher, geschrieben wird nur bedingt).
 *
 * Sicherheit:
 *   - Nur https://, außer http:// auf den eigenen Rechner (Testserver), siehe parseStorageUrl.
 *   - Anfragen (mit Zugangsdaten) gehen nur an den Server der Tresor-Datei; send() prüft das
 *     für jede Anfrage und jedes COPY-Ziel (Sicherheitsaudit network-3).
 *   - Antworten werden nur bis zu einer Obergrenze gelesen (MAX_VAULT_FILE_BYTES,
 *     MAX_PROPFIND_BYTES; Sicherheitsaudit dos-1), gezählt nach dem Entpacken.
 *   - Passwort und Authorization-Header erscheinen in keiner Fehlermeldung. Text vom Server
 *     (Location, Parserfehler, Netzwerkfehler) erscheint nur über displayText (Sicherheitsaudit
 *     leak-1).
 *   - Weiterleitungen werden NICHT verfolgt (redirect: "manual"): Sonst landeten Zugangsdaten
 *     und Tresor evtl. bei einer anderen Adresse, und ein PUT könnte unbemerkt woanders
 *     schreiben. Der Nutzer soll die endgültige Adresse eintragen.
 *   - cache: "no-store": Im Browser darf GET nie eine zwischengespeicherte (veraltete)
 *     Fassung liefern – mit deren ETag gäbe es bei jedem Schreiben 412.
 *   - credentials: "omit": keine Cookies des Browsers (z. B. einer Nextcloud-Sitzung)
 *     mitschicken; angemeldet wird nur mit dem eingetragenen Gerätepasswort.
 *
 * Läuft auch im Service Worker der Browser-Erweiterung (nur fetch & Co.).
 */
import {
  PreconditionFailedError,
  StorageAuthError,
  StorageError,
  type BackupResult,
  type RemoteFile,
  type StorageAdapter,
  type WriteCondition,
} from "../contracts";
import { displayText } from "../display-text";
import { MAX_PAYLOAD_BYTES } from "../kdbx/constants";
import type { Millis } from "../model";
import { backupFileName, backupsToDelete, backupVersionTag, parseBackupName } from "./backup-names";
import {
  basicAuthorization,
  bytesBody,
  describeUrl,
  discardBody,
  fetchFailureReason,
  headerValue,
  isRedirect,
  parseHttpDate,
  parseStorageUrl,
} from "./http";
import { parseMultistatus, type DavResource } from "./multistatus";

/** Name des Sicherungsordners neben der Tresor-Datei (Standard). */
export const BACKUP_FOLDER_NAME = "ownwarden-backups";

/**
 * Standard-Zeitlimit gegen Stillstand: so lange darf der Server nicht antworten bzw. beim Lesen
 * keine Daten schicken (siehe Kopfkommentar). Unter 30 s, weil Chrome den Service Worker der
 * Erweiterung beendet, wenn eine Antwort länger als 30 s braucht (PROJECT-CONTEXT); so endet
 * eine hängende Anfrage vorher mit einer klaren Meldung (StorageError).
 */
export const DEFAULT_WEBDAV_TIMEOUT_MS = 25_000;

/**
 * Angenommene Mindestrate beim Hochladen (16 KiB/s ≈ 130 kbit/s, sehr langsames Mobilnetz).
 * Fortschritt beim Senden lässt sich mit fetch nicht beobachten; deshalb verlängert sich die
 * Frist eines Uploads um die Zeit, die sein Inhalt bei dieser Rate braucht.
 */
export const MIN_UPLOAD_BYTES_PER_SECOND = 16 * 1024;

/**
 * Mindestrate beim Herunterladen, wie beim Hochladen (Sicherheitsaudit dos-5, siehe
 * Kopfkommentar). Ein 20-MB-Tresor darf bei dieser Rate etwa 21 Minuten brauchen.
 */
export const MIN_DOWNLOAD_BYTES_PER_SECOND = MIN_UPLOAD_BYTES_PER_SECOND;

/**
 * Feste Obergrenze für eine Anfrage samt Lesen der Antwort (Sicherheitsaudit dos-5,
 * Nachprüfung): Die Mindestrate allein erlaubte für die größte Tresor-Datei (MAX_VAULT_FILE_BYTES
 * bei 16 KiB/s) über 4 Stunden. 30 Minuten reichen für 256 MiB ab etwa 1,2 Mbit/s und bei der
 * Mindestrate für etwa 28 MiB – in beide Richtungen, auch beim Hochladen.
 */
export const MAX_REQUEST_MS = 30 * 60 * 1000;

/**
 * Obergrenze für die gelesene Tresor-Datei (Sicherheitsaudit dos-1): der größte Inhalt, den
 * readKdbx annimmt (MAX_PAYLOAD_BYTES), plus 1 MiB für Header und Blockstruktur. Ohne Grenze
 * könnte ein Server den Speicher füllen, bevor irgendein Schlüssel geprüft ist.
 */
export const MAX_VAULT_FILE_BYTES = MAX_PAYLOAD_BYTES + 1024 * 1024;

/**
 * Obergrenze für eine PROPFIND-Antwort (Sicherheitsaudit dos-1). Ein Eintrag braucht etwa ein
 * halbes KiB; 4 MiB reichen für Tausende Sicherungskopien. Der XML-Parser braucht ein Vielfaches
 * davon an Speicher.
 */
export const MAX_PROPFIND_BYTES = 4 * 1024 * 1024;

export interface WebDavAdapterOptions {
  /** Vollständige Adresse der .kdbx-Datei, z. B. https://magentacloud.de/remote.php/webdav/Ownwarden/tresor.kdbx */
  fileUrl: string;
  username: string;
  /** Am besten ein eigenes App-/Gerätepasswort pro Client (Nextcloud, MagentaCLOUD). */
  password: string;
  /** Ordner für Sicherungskopien; Standard: "<Ordner der Datei>/ownwarden-backups/". Muss auf demselben Server liegen. */
  backupFolderUrl?: string;
  /** Eigene fetch-Funktion (Tests, Erweiterung); Standard: globalThis.fetch. */
  fetch?: typeof fetch;
  /**
   * Zeitlimit gegen Stillstand in ms (siehe Kopfkommentar); Standard DEFAULT_WEBDAV_TIMEOUT_MS.
   * Im Service Worker der Erweiterung unter 30 000 bleiben. Uploads bekommen zusätzlich Zeit
   * je nach Größe (MIN_UPLOAD_BYTES_PER_SECOND).
   */
  timeoutMs?: number;
  /** Mindestrate beim Herunterladen in Byte/s (siehe Kopfkommentar); Standard MIN_DOWNLOAD_BYTES_PER_SECOND. */
  minDownloadBytesPerSecond?: number;
  /**
   * Feste Obergrenze je Anfrage samt Lesen der Antwort in ms (siehe Kopfkommentar); beim Lesen
   * ohne ETag-Header für alle Anfragen zusammen. Standard MAX_REQUEST_MS.
   */
  maxRequestMs?: number;
  /** Höchstens so viele Byte liest read() von der Tresor-Datei; Standard MAX_VAULT_FILE_BYTES. */
  maxFileBytes?: number;
  /** Höchstens so viele Byte einer PROPFIND-Antwort; Standard MAX_PROPFIND_BYTES. */
  maxPropfindBytes?: number;
  /** Uhr für die Zeit im Namen der Sicherungskopien (Tests); Standard Date.now. */
  now?: () => Millis;
}

/** PROPFIND-Anfrage: nur ETag, Größe und Typ (Datei/Ordner) abfragen, nicht alle Eigenschaften. */
const PROPFIND_BODY =
  '<?xml version="1.0" encoding="utf-8"?>\n<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:getcontentlength/><d:resourcetype/></d:prop></d:propfind>';

/** Wie oft read() ohne ETag-Header versucht, Inhalt und ETag passend zueinander zu lesen. */
const ETAG_FALLBACK_ATTEMPTS = 3;

/** Wie oft backup() bei einem Namenszusammenstoß (gleiche Millisekunde) einen neuen Namen probiert. */
const BACKUP_NAME_ATTEMPTS = 5;

type RequestBody = Uint8Array<ArrayBuffer> | string;

export class WebDavAdapter implements StorageAdapter {
  private readonly fileUrl: URL;
  private readonly fileName: string;
  private readonly backupFolderUrl: URL;
  // Zugangsdaten in echten privaten Feldern (#): Sie erscheinen so weder in JSON.stringify
  // noch in util.inspect/console.log des Adapters, falls jemand ihn zur Fehlersuche ausgibt.
  readonly #authorization: string;
  /** Werte, die nie in einer Meldung auftauchen dürfen. */
  readonly #secrets: string[];
  /** Frist jeder noch nicht zu Ende gelesenen bzw. verworfenen Antwort (siehe send). */
  readonly #deadlines = new WeakMap<Response, TransferDeadline>();
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
  private readonly minDownloadBytesPerSecond: number;
  private readonly maxRequestMs: number;
  private readonly maxFileBytes: number;
  private readonly maxPropfindBytes: number;
  private readonly now: () => Millis;

  constructor(options: WebDavAdapterOptions) {
    this.fileUrl = parseStorageUrl(options.fileUrl, "Adresse der Tresor-Datei");
    if (this.fileUrl.pathname.endsWith("/")) {
      throw new TypeError("Adresse der Tresor-Datei: Sie zeigt auf einen Ordner; bitte die .kdbx-Datei angeben.");
    }
    this.fileName = decodeSegment(lastSegment(this.fileUrl.pathname));

    const backupRaw = options.backupFolderUrl ?? new URL(`${BACKUP_FOLDER_NAME}/`, this.fileUrl).href;
    this.backupFolderUrl = parseStorageUrl(backupRaw, "Adresse des Sicherungsordners");
    if (!this.backupFolderUrl.pathname.endsWith("/")) this.backupFolderUrl.pathname += "/";
    // Gleicher Server: COPY funktioniert nur innerhalb eines Servers, und die Zugangsdaten
    // sollen an keinen anderen Server gehen.
    if (this.backupFolderUrl.origin !== this.fileUrl.origin) {
      throw new TypeError("Der Sicherungsordner muss auf demselben Server liegen wie die Tresor-Datei.");
    }

    this.#authorization = basicAuthorization(options.username, options.password);
    this.#secrets = [options.password, this.#authorization, this.#authorization.slice("Basic ".length)];

    // Immer über eine Pfeilfunktion aufrufen: Im Browser wirft fetch "Illegal invocation",
    // wenn es als Methode eines anderen Objekts (this.fetchFn(...)) aufgerufen wird.
    const customFetch = options.fetch;
    this.fetchFn = customFetch !== undefined ? (input, init) => customFetch(input, init) : (input, init) => globalThis.fetch(input, init);

    this.timeoutMs = positiveNumber(options.timeoutMs ?? DEFAULT_WEBDAV_TIMEOUT_MS, "timeoutMs");
    this.minDownloadBytesPerSecond = positiveNumber(options.minDownloadBytesPerSecond ?? MIN_DOWNLOAD_BYTES_PER_SECOND, "minDownloadBytesPerSecond");
    this.maxRequestMs = positiveNumber(options.maxRequestMs ?? MAX_REQUEST_MS, "maxRequestMs");
    this.maxFileBytes = positiveNumber(options.maxFileBytes ?? MAX_VAULT_FILE_BYTES, "maxFileBytes");
    this.maxPropfindBytes = positiveNumber(options.maxPropfindBytes ?? MAX_PROPFIND_BYTES, "maxPropfindBytes");
    this.now = options.now ?? (() => Date.now());
  }

  describe(): string {
    return `WebDAV ${describeUrl(this.fileUrl)}`;
  }

  // -------------------------------------------------------------------------
  // Lesen
  // -------------------------------------------------------------------------

  async read(): Promise<RemoteFile | null> {
    const response = await this.send("GET", this.fileUrl);
    if (response.status === 404) {
      await this.discard(response);
      return null;
    }
    await this.expectSuccess(response, "Lesen der Tresor-Datei", this.fileUrl);
    const data = await this.readBytes(response, this.fileUrl, this.maxFileBytes);
    const etag = headerValue(response.headers, "ETag");
    if (etag === null) return this.readWithEtagFromPropfind();
    return remoteFile(data, etag, response);
  }

  /**
   * Ausweg, wenn GET keinen ETag-Header liefert: ETag per PROPFIND (Eigenschaft getetag).
   *
   * Inhalt und ETag müssen zur SELBEN Fassung gehören. Deshalb wird eingerahmt:
   *   PROPFIND (ETag A) -> GET mit If-Match: A -> PROPFIND (ETag B), nur bei A = B gültig.
   * ETags ändern sich bei jedem Schreiben; ist A = B, hat dazwischen niemand geschrieben.
   * Ohne diesen Rahmen könnte der ETag zu einer NEUEREN Fassung gehören als der Inhalt – das
   * nächste bedingte Schreiben würde dann die Änderung eines anderen Geräts überschreiben.
   *
   * Kennt der Server gar keinen ETag, ist etag "" (syncVault schreibt dann nicht).
   *
   * Alle Anfragen zusammen dürfen höchstens maxRequestMs dauern (Sicherheitsaudit dos-5,
   * Nachprüfung), sonst wären es bis zu neunmal so viel.
   */
  private async readWithEtagFromPropfind(): Promise<RemoteFile | null> {
    const until = performance.now() + this.maxRequestMs;
    for (let attempt = 0; attempt < ETAG_FALLBACK_ATTEMPTS; attempt++) {
      const before = await this.propfindEtag(until);
      if (before === undefined) return null; // inzwischen gelöscht

      const headers: Record<string, string> = before === null ? {} : { "If-Match": before };
      const response = await this.send("GET", this.fileUrl, headers, undefined, until);
      if (response.status === 404) {
        await this.discard(response);
        return null;
      }
      if (response.status === 412) {
        await this.discard(response); // zwischen PROPFIND und GET geändert: noch einmal
        continue;
      }
      await this.expectSuccess(response, "Lesen der Tresor-Datei", this.fileUrl);
      const data = await this.readBytes(response, this.fileUrl, this.maxFileBytes);
      if (before === null) return remoteFile(data, "", response);

      const after = await this.propfindEtag(until);
      if (after === before) return remoteFile(data, before, response);
    }
    throw new StorageError("Die Tresor-Datei wurde während des Lesens mehrfach geändert. Bitte später erneut synchronisieren.");
  }

  /**
   * ETag der Datei per PROPFIND (Depth 0): Wert, null (Server nennt keinen) oder undefined (Datei fehlt).
   * `until`: Zeitpunkt (performance.now()), bis zu dem die Anfrage spätestens fertig sein muss.
   */
  private async propfindEtag(until: number): Promise<string | null | undefined> {
    const resources = await this.propfind(this.fileUrl, "0", until);
    if (resources === null) return undefined;
    const etag = resources.find((resource) => !resource.isCollection)?.props.get("getetag");
    return etag === undefined || etag === "" ? null : etag;
  }

  // -------------------------------------------------------------------------
  // Schreiben
  // -------------------------------------------------------------------------

  async write(data: Uint8Array, condition: WriteCondition): Promise<{ etag: string | null; serverDate?: Millis }> {
    const headers: Record<string, string> = { "Content-Type": "application/octet-stream" };
    if ("ifMatch" in condition) {
      // Ein leerer If-Match-Header ist ungültig; manche Server würden ihn ignorieren und
      // OHNE Bedingung schreiben. Lieber hier abbrechen.
      if (condition.ifMatch === "") throw new TypeError("write: If-Match ohne ETag ist nicht erlaubt.");
      headers["If-Match"] = condition.ifMatch;
    } else {
      headers["If-None-Match"] = "*";
    }
    const response = await this.send("PUT", this.fileUrl, headers, bytesBody(data));
    await this.discard(response);
    if (response.status === 412) throw new PreconditionFailedError();
    await this.expectSuccess(response, "Schreiben der Tresor-Datei", this.fileUrl);
    // Nextcloud nennt den neuen ETag in "ETag" und in "OC-ETag"; manche Server in keinem.
    const etag = headerValue(response.headers, "ETag") ?? headerValue(response.headers, "OC-ETag");
    const serverDate = parseHttpDate(response.headers.get("Date"));
    return serverDate === undefined ? { etag } : { etag, serverDate };
  }

  // -------------------------------------------------------------------------
  // Sicherungskopien
  // -------------------------------------------------------------------------

  /**
   * Stellt die Sicherungskopie der Fassung `current` sicher (Pflicht: Fehler werden geworfen;
   * siehe StorageAdapter.backup). Gelöscht wird hier nichts – das macht pruneBackups, und zwar
   * erst nach erfolgreichem Schreiben.
   *
   * Pro Fassung nur EINE Kopie (Review xc-1): Liegt im Sicherungsordner schon eine Kopie mit der
   * Kennung dieser Fassung im Namen (backupVersionTag) und passender Größe, wird keine weitere
   * angelegt – etwa bei jedem neuen Versuch, solange das Schreiben der Tresor-Datei scheitert
   * (423, 5xx, Zeitlimit, 412). Die vorhandene Kopie enthält genau diese Fassung: Ein Gerät hat
   * sie angelegt, nachdem es diese Fassung gelesen hatte. Gelingt danach unser Schreiben mit
   * If-Match genau auf deren ETag, hat seither niemand geschrieben – die Datei war also auch
   * beim Kopieren diese Fassung. Gelingt es nicht, wird nichts überschrieben. Die Größe fängt
   * eine abgebrochene Übertragung (PUT-Ausweg) ab, die eine unvollständige Datei hinterließ.
   * Lässt sich der Ordner nicht auflisten, wird sicherheitshalber eine neue Kopie angelegt.
   */
  async backup(current: RemoteFile): Promise<BackupResult> {
    await this.ensureBackupFolder();
    if (!(await this.hasBackupOf(current))) await this.storeBackup(current);
    return { warnings: [] };
  }

  /** true, wenn im Sicherungsordner schon eine vollständige Kopie der Fassung `current` liegt (siehe backup). */
  private async hasBackupOf(current: RemoteFile): Promise<boolean> {
    let backups: Map<string, BackupFile> | null;
    try {
      backups = await this.listBackups();
    } catch {
      return false;
    }
    const tag = backupVersionTag(current.etag);
    for (const [name, file] of backups ?? []) {
      if (parseBackupName(this.fileName, name)?.versionTag !== tag) continue;
      // Größe nur vergleichen, wenn der Server sie nennt.
      if (file.contentLength === undefined || file.contentLength === current.data.length) return true;
    }
    return false;
  }

  private async ensureBackupFolder(): Promise<void> {
    const response = await this.send("MKCOL", this.backupFolderUrl);
    await this.discard(response);
    // 201 = angelegt; 405 = gibt es schon (RFC 4918); eine Weiterleitung (301) schicken
    // manche Server (z. B. Apache) für einen vorhandenen Ordner.
    if (response.status === 201 || response.status === 405 || isRedirect(response)) return;
    await this.expectSuccess(response, "Anlegen des Sicherungsordners", this.backupFolderUrl);
  }

  /**
   * Legt die Kopie an: bevorzugt per COPY (der Server kopiert selbst, nichts wird erneut
   * hochgeladen). Kann der Server kein COPY (405/501), werden die gelesenen Bytes per PUT
   * hochgeladen. "Overwrite: F" bzw. "If-None-Match: *" verhindern, dass eine vorhandene
   * Sicherung gleichen Namens (gleiche Millisekunde, anderes Gerät) überschrieben wird.
   * Liefert den (unkodierten) Namen der angelegten Sicherung.
   */
  private async storeBackup(current: RemoteFile): Promise<string> {
    const start = this.now();
    for (let attempt = 0; attempt < BACKUP_NAME_ATTEMPTS; attempt++) {
      const name = backupFileName(this.fileName, start + attempt, current.etag);
      const target = withPath(this.backupFolderUrl, this.backupFolderUrl.pathname + encodeURIComponent(name));
      const outcome = await this.copyFileTo(target);
      if (outcome === "copied") return name;
      if (outcome === "exists") continue;

      const response = await this.send(
        "PUT",
        target,
        { "Content-Type": "application/octet-stream", "If-None-Match": "*" },
        bytesBody(current.data),
      );
      await this.discard(response);
      if (response.status === 412) continue;
      await this.expectSuccess(response, "Hochladen der Sicherungskopie", target);
      return name;
    }
    throw new StorageError("Für die Sicherungskopie wurde kein freier Dateiname gefunden.");
  }

  private async copyFileTo(target: URL): Promise<"copied" | "exists" | "unsupported"> {
    const response = await this.send("COPY", this.fileUrl, { Destination: target.href, Overwrite: "F" });
    await this.discard(response);
    if (response.ok) return "copied";
    if (response.status === 412) return "exists";
    if (response.status === 405 || response.status === 501) return "unsupported";
    throw this.httpError(response, "Sicherungskopie per COPY", target);
  }

  /**
   * Löscht die ältesten Sicherungen DIESER Datei, bis nur noch `keep` übrig sind. syncVault ruft
   * das erst nach dem erfolgreichen Schreiben auf (siehe StorageAdapter.pruneBackups).
   *
   * Die Sicherung der eben überschriebenen Fassung `current` (erkannt an der Kennung im Namen)
   * wird NIE gelöscht, auch wenn sie nach dem Namen nicht zu den neuesten gehört: Geht die Uhr
   * eines anderen Geräts etwas vor (das ist bis maxClockSkewMs erlaubt), tragen dessen
   * Sicherungen spätere Zeiten im Namen. Ohne diese Ausnahme könnte das Aufräumen genau die
   * Sicherung der Fassung löschen, die syncVault eben überschrieben hat – dann gäbe es von ihr
   * keine Sicherung mehr. Behalten werden deshalb diese Sicherung plus die neuesten `keep - 1`
   * übrigen.
   *
   * Aufräumen ist „best effort“ (Entscheidung des Eigentümers, 2026-10-16): Lässt sich der
   * Ordner nicht auflisten oder eine ALTE Kopie nicht löschen (z. B. 403 bei einer Freigabe ohne
   * Löschrecht, 423 bei einer gesperrten Datei), soll das den Abgleich nicht dauerhaft
   * blockieren. Statt zu werfen, liefert die Funktion Hinweise; die übrigen alten Kopien werden
   * trotzdem gelöscht. Folge: Im Sicherungsordner können dann mehr als `keep` Kopien liegen.
   */
  async pruneBackups(current: RemoteFile, keep: number): Promise<BackupResult> {
    if (!Number.isInteger(keep) || keep < 1) throw new RangeError("pruneBackups: keep muss eine ganze Zahl ≥ 1 sein.");
    let children: Map<string, BackupFile> | null;
    try {
      children = await this.listBackups();
    } catch (error) {
      return { warnings: [`Alte Sicherungskopien wurden nicht aufgeräumt: Der Sicherungsordner ließ sich nicht auflisten (${errorText(error)}).`] };
    }
    if (children === null) {
      return { warnings: [`Alte Sicherungskopien wurden nicht aufgeräumt: Sicherungsordner ${describeUrl(this.backupFolderUrl)} nicht gefunden (HTTP 404).`] };
    }
    const tag = backupVersionTag(current.etag);
    // Gibt es (etwa nach einem Wettlauf zweier Geräte) mehrere Kopien dieser Fassung, bleibt die neueste.
    const protectedName = [...children.keys()]
      .filter((name) => parseBackupName(this.fileName, name)?.versionTag === tag)
      .sort()
      .at(-1);
    const others = [...children.keys()].filter((name) => name !== protectedName);
    const warnings: string[] = [];
    // backup() hat diese Sicherung eben sichergestellt. Fehlt sie in der Liste, versteht das
    // Aufräumen die Ordnerliste dieses Servers nicht (z. B. Dateien unter einem anderen Pfad)
    // und löscht nie etwas – das soll nicht still bleiben (Review probe-2).
    if (protectedName === undefined) {
      warnings.push(
        `Die Sicherung der eben überschriebenen Fassung fehlt in der Liste des Sicherungsordners ${describeUrl(this.backupFolderUrl)}. ` +
          "Vermutlich nennt der Server die Dateien unter einem anderen Pfad; dann werden alte Sicherungskopien nie gelöscht. " +
          "Bitte bei Gelegenheit im Sicherungsordner aufräumen (der WebDAV-Servertest prüft das).",
      );
    }
    for (const name of backupsToDelete(this.fileName, others, protectedName === undefined ? keep : keep - 1)) {
      const url = children.get(name)!.url;
      try {
        const response = await this.send("DELETE", url);
        await this.discard(response);
        // 404: schon weg (z. B. hat ein anderes Gerät gleichzeitig aufgeräumt).
        if (response.status !== 404) await this.expectSuccess(response, "Löschen einer alten Sicherungskopie", url);
      } catch (error) {
        warnings.push(`Alte Sicherungskopie "${name}" ließ sich nicht löschen (${errorText(error)}). Bitte bei Gelegenheit im Sicherungsordner aufräumen.`);
      }
    }
    return { warnings };
  }

  /** Dateien direkt im Sicherungsordner (Name unkodiert -> Adresse, Größe); null bei 404. */
  private async listBackups(): Promise<Map<string, BackupFile> | null> {
    const resources = await this.propfind(this.backupFolderUrl, "1");
    if (resources === null) return null;
    const children = new Map<string, BackupFile>();
    for (const resource of resources) {
      if (resource.isCollection) continue;
      const url = this.backupFolderChild(resource.href);
      if (url === null) continue;
      const length = resource.props.get("getcontentlength");
      const contentLength = length !== undefined && /^\d+$/.test(length) ? Number(length) : undefined;
      children.set(decodeSegment(lastSegment(url.pathname)), { url, contentLength });
    }
    return children;
  }

  /**
   * href aus der PROPFIND-Antwort -> Adresse, aber nur, wenn sie DIREKT im Sicherungsordner
   * liegt; sonst null. Vom href zählt nur der Pfad (Server liefern teils absolute URLs, teils
   * Pfade, hinter einem Proxy evtl. mit "http:"); gelöscht wird immer auf unserem Server.
   * So kann eine seltsame Server-Antwort nie zum Löschen außerhalb des Ordners führen.
   */
  private backupFolderChild(href: string): URL | null {
    let path: string;
    try {
      path = new URL(href, this.backupFolderUrl).pathname;
    } catch {
      return null;
    }
    const slash = path.lastIndexOf("/");
    const parent = path.slice(0, slash + 1);
    if (path.slice(slash + 1) === "" || decodePath(parent) !== decodePath(this.backupFolderUrl.pathname)) return null;
    return withPath(this.backupFolderUrl, path);
  }

  // -------------------------------------------------------------------------
  // HTTP
  // -------------------------------------------------------------------------

  /** PROPFIND mit `depth`; null bei 404. `until` wie bei send. */
  private async propfind(url: URL, depth: "0" | "1", until = Infinity): Promise<DavResource[] | null> {
    const response = await this.send("PROPFIND", url, { Depth: depth, "Content-Type": "application/xml; charset=utf-8" }, PROPFIND_BODY, until);
    if (response.status === 404) {
      await this.discard(response);
      return null;
    }
    if (response.status !== 207) {
      await this.expectSuccess(response, "PROPFIND", url);
      await this.discard(response);
      throw new StorageError(`PROPFIND ${describeUrl(url)}: unerwartete Antwort HTTP ${response.status} (erwartet 207 Multi-Status).`, response.status);
    }
    const text = new TextDecoder().decode(await this.readBytes(response, url, this.maxPropfindBytes));
    try {
      return parseMultistatus(text);
    } catch (error) {
      // Die Meldung des Parsers kann einen Ausschnitt der Antwort enthalten (leak-1).
      throw new StorageError(`PROPFIND ${describeUrl(url)}: ${displayText(errorText(error), 160)}`);
    }
  }

  /**
   * Eine Anfrage mit Anmeldung. Netzwerkfehler und Zeitüberschreitung werden zu StorageError.
   *
   * Nur an den Server der Tresor-Datei (Sicherheitsaudit network-3): Liegt `url` oder das Ziel
   * einer Kopie (Destination) woanders, wird nichts gesendet. Die Adressen werden so gebildet,
   * dass das nie vorkommen sollte; dies ist die letzte Sperre vor den Zugangsdaten.
   *
   * Zeitlimit (siehe Kopfkommentar): Bis die Antwort da ist, gilt timeoutMs plus die Zeit, die
   * der Inhalt `body` bei MIN_UPLOAD_BYTES_PER_SECOND zum Hochladen braucht. Danach läuft die
   * Frist weiter, bis der Körper gelesen (readBytes) oder verworfen (discard) ist; jedes beim
   * Lesen ankommende Stück verlängert sie wieder um timeoutMs, höchstens bis zur Gesamtfrist
   * aus MIN_DOWNLOAD_BYTES_PER_SECOND. Nie länger als maxRequestMs ab jetzt und nie über `until`
   * (performance.now(); Gesamtgrenze beim Lesen ohne ETag) hinaus.
   */
  private async send(
    method: string,
    url: URL,
    headers: Record<string, string> = {},
    body?: RequestBody,
    until = Infinity,
  ): Promise<Response> {
    const allHeaders = new Headers(headers);
    const destination = allHeaders.get("Destination");
    if (url.origin !== this.fileUrl.origin || (destination !== null && !isSameOrigin(destination, this.fileUrl))) {
      throw new StorageError(`${method} verweigert: Die Adresse liegt nicht auf dem Server der Tresor-Datei (${this.fileUrl.origin}).`);
    }
    allHeaders.set("Authorization", this.#authorization);
    // Text-Körper sind nur die kurzen PROPFIND-Anfragen (ASCII): Zeichen = Bytes.
    const bodyBytes = body === undefined ? 0 : typeof body === "string" ? body.length : body.byteLength;
    const limitMs = this.timeoutMs + Math.ceil((bodyBytes * 1000) / MIN_UPLOAD_BYTES_PER_SECOND);
    const ceiling = performance.now() + this.maxRequestMs;
    const deadline = new TransferDeadline(
      Math.min(ceiling, until),
      until < ceiling
        ? `Zeitüberschreitung: Das Lesen ohne ETag-Header (PROPFIND, GET, PROPFIND) dauerte zusammen länger als ${duration(this.maxRequestMs)}`
        : `Zeitüberschreitung: Die Übertragung dauerte länger als die Obergrenze von ${duration(this.maxRequestMs)} je Anfrage`,
    );
    deadline.restart(limitMs);
    let response: Response;
    try {
      response = await this.fetchFn(url.href, {
        method,
        headers: allHeaders,
        body,
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        signal: deadline.signal,
      });
    } catch (error) {
      deadline.stop();
      const reason = deadline.expired
        ? deadline.atCeiling
          ? deadline.ceilingText
          : typeof body !== "string" && bodyBytes > 0
            ? `Zeitüberschreitung bei der Übertragung: Hochladen samt Antwort des Servers dauerte länger als ${seconds(limitMs)} s (Zeitlimit ${seconds(this.timeoutMs)} s plus Zeit für ${bodyBytes} Byte bei mindestens ${MIN_UPLOAD_BYTES_PER_SECOND / 1024} KiB/s)`
            : `Zeitüberschreitung: Der Server hat nicht innerhalb von ${seconds(limitMs)} s geantwortet`
        : `keine Antwort vom Server (${fetchFailureReason(error, this.#secrets)})`;
      throw new StorageError(`${method} ${describeUrl(url)}: ${reason}.`);
    }
    deadline.restart(this.timeoutMs);
    this.#deadlines.set(response, deadline);
    return response;
  }

  /**
   * Liest den Antwort-Körper Stück für Stück, höchstens `maxBytes` (Sicherheitsaudit dos-1).
   * Gezählt wird nach dem Entpacken: fetch entpackt Content-Encoding (gzip, br) selbst, wenige KiB
   * auf der Leitung können so Gigabyte ergeben. "Accept-Encoding: identity" hilft dagegen nicht
   * (fetch entpackt trotzdem, im Browser ist der Header gesperrt). Ein zu großes Content-Length
   * wird gleich abgelehnt; sonst endet das Lesen, sobald mehr ankommt.
   *
   * Jedes Stück verlängert die Frist um timeoutMs (Zeitlimit gegen Stillstand), aber nie über die
   * Gesamtfrist hinaus (dos-5): timeoutMs plus die Zeit, die die schon gelesenen Byte bei
   * minDownloadBytesPerSecond brauchen, und nie über die Obergrenze aus send (maxRequestMs).
   * Ein Abbruch (Netz, Zeitlimit, Obergrenze) wird zu StorageError.
   *
   * Speicher (dos-1, Nachprüfung): Nennt der Server ein passendes Content-Length (ohne
   * Content-Encoding), wird das Ergebnis einmal in dieser Größe angelegt und gefüllt – sonst lägen
   * am Ende alle Stücke UND das zusammengesetzte Ergebnis im Speicher. Kommen mehr Byte als
   * angekündigt, geht es mit gesammelten Stücken weiter; Obergrenze und Mindestrate zählen immer
   * die tatsächlich angekommenen Byte.
   */
  private async readBytes(response: Response, url: URL, maxBytes: number): Promise<Uint8Array> {
    const deadline = this.#deadlines.get(response);
    const aborted = (reason: string) => new StorageError(`Lesen von ${describeUrl(url)} abgebrochen (${reason}).`);
    const tooLarge = `die Antwort des Servers ist größer als ${sizeText(maxBytes)}`;
    const tooSlow = `Zeitüberschreitung: Die Daten kamen im Schnitt langsamer als ${sizeText(this.minDownloadBytesPerSecond)}/s`;
    const declared = contentLength(response);
    if (declared !== undefined && declared > maxBytes) {
      await this.discard(response);
      throw aborted(tooLarge);
    }
    const started = performance.now();
    /** true, wenn die laufende Frist die Gesamtfrist ist (nicht das Zeitlimit gegen Stillstand). */
    let atOverallLimit = false;
    try {
      if (response.body === null) return new Uint8Array(await response.arrayBuffer());
      const reader = response.body.getReader();
      let buffer = declared !== undefined && !isEncoded(response) ? new Uint8Array(declared) : undefined;
      const chunks: Uint8Array[] = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (buffer !== undefined && total + value.byteLength <= buffer.length) {
          buffer.set(value, total);
        } else {
          if (buffer !== undefined) chunks.push(buffer.subarray(0, total)); // mehr als angekündigt
          buffer = undefined;
          chunks.push(value);
        }
        total += value.byteLength;
        const remainingMs = started + this.timeoutMs + (total * 1000) / this.minDownloadBytesPerSecond - performance.now();
        const atCeiling = deadline !== undefined && deadline.remainingMs() <= 0;
        if (total > maxBytes || remainingMs <= 0 || atCeiling) {
          await reader.cancel().catch(() => undefined); // Übertragung beenden, den Rest nicht lesen
          throw aborted(total > maxBytes ? tooLarge : remainingMs <= 0 ? tooSlow : deadline!.ceilingText);
        }
        atOverallLimit = remainingMs < this.timeoutMs;
        deadline?.restart(Math.min(this.timeoutMs, remainingMs));
      }
      // Weniger als angekündigt: nur die gelesenen Byte, ohne den Rest des Puffers.
      if (buffer !== undefined) return total === buffer.length ? buffer : buffer.slice(0, total);
      const data = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        data.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return data;
    } catch (error) {
      if (error instanceof StorageError) throw error;
      const reason = deadline?.expired
        ? deadline.atCeiling
          ? deadline.ceilingText
          : atOverallLimit
            ? tooSlow
            : `Zeitüberschreitung: ${seconds(this.timeoutMs)} s lang keine Daten`
        : fetchFailureReason(error, this.#secrets);
      throw aborted(reason);
    } finally {
      deadline?.stop();
    }
  }

  /** Verwirft den Antwort-Körper und beendet die Frist der Anfrage (siehe send). */
  private async discard(response: Response): Promise<void> {
    this.#deadlines.get(response)?.stop();
    await discardBody(response);
  }

  /** Wirft bei jedem Status außer 2xx den passenden Fehler. */
  private async expectSuccess(response: Response, action: string, url: URL): Promise<void> {
    if (response.ok) return;
    await this.discard(response);
    throw this.httpError(response, action, url);
  }

  private httpError(response: Response, action: string, url: URL): Error {
    const where = describeUrl(url);
    if (response.status === 401 || response.status === 403) {
      return new StorageAuthError(
        `${action}: Anmeldung an ${where} abgelehnt (HTTP ${response.status}). Benutzername und App-/Gerätepasswort prüfen – ` +
          "vielleicht wurde das Gerätepasswort widerrufen.",
      );
    }
    if (isRedirect(response)) {
      // Location bestimmt der Server: nur entschärft und gekürzt in die Meldung (leak-1).
      const location = response.headers.get("Location");
      return new StorageError(
        `${action}: Der Server leitet ${where} weiter${location !== null ? ` nach ${displayText(location, 100)}` : ""}. Bitte die endgültige Adresse eintragen.`,
        response.status === 0 ? undefined : response.status,
      );
    }
    return new StorageError(`${action} (${where}) fehlgeschlagen: HTTP ${response.status}${statusHint(response.status)}`, response.status);
  }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/** Eine Datei im Sicherungsordner. */
interface BackupFile {
  url: URL;
  /** Größe laut PROPFIND (getcontentlength), falls der Server sie nennt. */
  contentLength: number | undefined;
}

/**
 * Frist einer Anfrage, die sich bei Fortschritt verlängern lässt (Review webdav-1: Ein festes
 * Zeitlimit für die ganze Übertragung ließe große Tresore auf langsamen Leitungen nie durch).
 * Läuft sie ab, wird die Anfrage mit einem TimeoutError abgebrochen. Nach dem Ende einer
 * Anfrage immer stop() aufrufen, damit kein Zeitgeber übrig bleibt.
 *
 * Verlängern lässt sie sich nie über eine feste Obergrenze `end` hinaus (Sicherheitsaudit dos-5,
 * Nachprüfung). Zeitpunkte sind performance.now(): unabhängig von der Geräteuhr.
 */
class TransferDeadline {
  private readonly controller = new AbortController();
  private handle: ReturnType<typeof setTimeout> | undefined;
  /** true, sobald die Frist abgelaufen ist (und die Anfrage deshalb abgebrochen wurde). */
  expired = false;
  /** true, wenn die laufende Frist von der Obergrenze `end` bestimmt wird. */
  atCeiling = false;

  /**
   * @param end         Obergrenze (performance.now()), über die keine Frist hinausgeht
   * @param ceilingText Grund für Meldungen, wenn die Obergrenze erreicht ist
   */
  constructor(
    private readonly end: number,
    readonly ceilingText: string,
  ) {}

  get signal(): AbortSignal {
    return this.controller.signal;
  }

  /** Zeit bis zur Obergrenze in ms (≤ 0: erreicht). */
  remainingMs(): number {
    return this.end - performance.now();
  }

  /** Frist neu setzen: `ms` ab jetzt, höchstens bis zur Obergrenze. */
  restart(ms: number): void {
    this.stop();
    const remaining = this.remainingMs();
    this.atCeiling = remaining <= ms;
    this.handle = setTimeout(
      () => {
        this.expired = true;
        this.controller.abort(new DOMException("Zeitüberschreitung", "TimeoutError"));
      },
      Math.max(0, Math.min(ms, remaining)),
    );
  }

  stop(): void {
    if (this.handle !== undefined) clearTimeout(this.handle);
    this.handle = undefined;
  }
}

/** Millisekunden als ganze Sekunden (mindestens 1) für Meldungen. */
function seconds(ms: number): number {
  return Math.max(1, Math.round(ms / 1000));
}

/** Dauer für Meldungen: "30 min" bei vollen Minuten, sonst "45 s". */
function duration(ms: number): string {
  return ms >= 60_000 && ms % 60_000 === 0 ? `${ms / 60_000} min` : `${seconds(ms)} s`;
}

/** Content-Length der Antwort, falls der Server eine gültige Zahl nennt. */
function contentLength(response: Response): number | undefined {
  const raw = response.headers.get("Content-Length");
  return raw !== null && /^\s*\d+\s*$/.test(raw) ? Number(raw) : undefined;
}

/** true, wenn fetch den Körper entpackt: Content-Length nennt dann die Größe VOR dem Entpacken. */
function isEncoded(response: Response): boolean {
  const encoding = response.headers.get("Content-Encoding");
  return encoding !== null && encoding.trim().toLowerCase() !== "identity";
}

/** Größe für Meldungen: "4 MiB", "16 KiB" oder "1000 Byte". */
function sizeText(bytes: number): string {
  if (bytes % (1024 * 1024) === 0) return `${bytes / (1024 * 1024)} MiB`;
  if (bytes % 1024 === 0) return `${bytes / 1024} KiB`;
  return `${bytes} Byte`;
}

function positiveNumber(value: number, name: string): number {
  if (!Number.isFinite(value) || value <= 0) throw new RangeError(`${name} muss eine positive Zahl sein.`);
  return value;
}

/**
 * Adresse auf dem Server von `base` mit dem Pfad `path` (Sicherheitsaudit network-3). Der Pfad
 * wird gesetzt, nicht als relative Adresse aufgelöst: "//rechner/…" würde sonst zur Adresse eines
 * anderen Rechners.
 */
function withPath(base: URL, path: string): URL {
  const url = new URL(base.href);
  url.pathname = path;
  return url;
}

/** true, wenn `raw` eine absolute Adresse mit demselben Ursprung (Schema, Rechner, Port) wie `base` ist. */
function isSameOrigin(raw: string, base: URL): boolean {
  try {
    return new URL(raw).origin === base.origin;
  } catch {
    return false;
  }
}

/** Meldungstext eines Fehlers (die Meldungen dieses Adapters enthalten nie Zugangsdaten). */
function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function remoteFile(data: Uint8Array, etag: string, response: Response): RemoteFile {
  const serverDate = parseHttpDate(response.headers.get("Date"));
  return serverDate === undefined ? { data, etag } : { data, etag, serverDate };
}

/** Kurze Erklärung häufiger Fehlercodes. */
function statusHint(status: number): string {
  switch (status) {
    case 404:
      return " (nicht gefunden)";
    case 409:
      return " (der übergeordnete Ordner existiert nicht)";
    case 423:
      return " (die Datei ist auf dem Server gesperrt)";
    case 507:
      return " (kein Speicherplatz mehr frei)";
    default:
      return status >= 500 ? " (Fehler auf dem Server)" : "";
  }
}

function lastSegment(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

/** Prozentkodierung eines Pfad-Abschnitts auflösen; bei ungültiger Kodierung bleibt er, wie er ist. */
function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Ganzen Pfad abschnittsweise dekodieren (Server kodieren z. B. "(" oder "@" unterschiedlich). */
function decodePath(path: string): string {
  return path.split("/").map(decodeSegment).join("/");
}
