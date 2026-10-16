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
 *     gelesenen Bytes); alte Kopien dieser Datei werden aufgeräumt (best effort: scheitert
 *     das Aufräumen, gibt es nur einen Hinweis, siehe pruneBackups).
 *
 * Sicherheit:
 *   - Nur https://, außer http:// auf den eigenen Rechner (Testserver), siehe parseStorageUrl.
 *   - Passwort und Authorization-Header erscheinen in keiner Fehlermeldung.
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
import type { Millis } from "../model";
import { backupFileName, backupsToDelete } from "./backup-names";
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

/** Standard-Zeitlimit pro Anfrage (inkl. Übertragung des Inhalts). */
export const DEFAULT_WEBDAV_TIMEOUT_MS = 60_000;

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
  /** Zeitlimit pro Anfrage in ms; Standard DEFAULT_WEBDAV_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Uhr für die Zeit im Namen der Sicherungskopien (Tests); Standard Date.now. */
  now?: () => Millis;
}

/** PROPFIND-Anfrage: nur ETag und Typ (Datei/Ordner) abfragen, nicht alle Eigenschaften. */
const PROPFIND_BODY =
  '<?xml version="1.0" encoding="utf-8"?>\n<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:resourcetype/></d:prop></d:propfind>';

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
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;
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

    this.timeoutMs = options.timeoutMs ?? DEFAULT_WEBDAV_TIMEOUT_MS;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) throw new RangeError("timeoutMs muss eine positive Zahl sein.");
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
      await discardBody(response);
      return null;
    }
    await this.expectSuccess(response, "Lesen der Tresor-Datei", this.fileUrl);
    const data = await this.readBytes(response, this.fileUrl);
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
   */
  private async readWithEtagFromPropfind(): Promise<RemoteFile | null> {
    for (let attempt = 0; attempt < ETAG_FALLBACK_ATTEMPTS; attempt++) {
      const before = await this.propfindEtag();
      if (before === undefined) return null; // inzwischen gelöscht

      const headers: Record<string, string> = before === null ? {} : { "If-Match": before };
      const response = await this.send("GET", this.fileUrl, headers);
      if (response.status === 404) {
        await discardBody(response);
        return null;
      }
      if (response.status === 412) {
        await discardBody(response); // zwischen PROPFIND und GET geändert: noch einmal
        continue;
      }
      await this.expectSuccess(response, "Lesen der Tresor-Datei", this.fileUrl);
      const data = await this.readBytes(response, this.fileUrl);
      if (before === null) return remoteFile(data, "", response);

      const after = await this.propfindEtag();
      if (after === before) return remoteFile(data, before, response);
    }
    throw new StorageError("Die Tresor-Datei wurde während des Lesens mehrfach geändert. Bitte später erneut synchronisieren.");
  }

  /** ETag der Datei per PROPFIND (Depth 0): Wert, null (Server nennt keinen) oder undefined (Datei fehlt). */
  private async propfindEtag(): Promise<string | null | undefined> {
    const resources = await this.propfind(this.fileUrl, "0");
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
    await discardBody(response);
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
   * Sicherungskopie anlegen (Pflicht: Fehler werden geworfen), danach alte Kopien aufräumen
   * („best effort“: Fehler werden zu Hinweisen, siehe StorageAdapter.backup und pruneBackups).
   */
  async backup(current: RemoteFile, keep: number): Promise<BackupResult> {
    if (!Number.isInteger(keep) || keep < 1) throw new RangeError("backup: keep muss eine ganze Zahl ≥ 1 sein.");
    await this.ensureBackupFolder();
    const createdName = await this.storeBackup(current);
    return { warnings: await this.pruneBackups(keep, createdName) };
  }

  private async ensureBackupFolder(): Promise<void> {
    const response = await this.send("MKCOL", this.backupFolderUrl);
    await discardBody(response);
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
      const name = backupFileName(this.fileName, start + attempt);
      const target = new URL(encodeURIComponent(name), this.backupFolderUrl);
      const outcome = await this.copyFileTo(target);
      if (outcome === "copied") return name;
      if (outcome === "exists") continue;

      const response = await this.send(
        "PUT",
        target,
        { "Content-Type": "application/octet-stream", "If-None-Match": "*" },
        bytesBody(current.data),
      );
      await discardBody(response);
      if (response.status === 412) continue;
      await this.expectSuccess(response, "Hochladen der Sicherungskopie", target);
      return name;
    }
    throw new StorageError("Für die Sicherungskopie wurde kein freier Dateiname gefunden.");
  }

  private async copyFileTo(target: URL): Promise<"copied" | "exists" | "unsupported"> {
    const response = await this.send("COPY", this.fileUrl, { Destination: target.href, Overwrite: "F" });
    await discardBody(response);
    if (response.ok) return "copied";
    if (response.status === 412) return "exists";
    if (response.status === 405 || response.status === 501) return "unsupported";
    throw this.httpError(response, "Sicherungskopie per COPY", target);
  }

  /**
   * Löscht die ältesten Sicherungen DIESER Datei, bis nur noch `keep` übrig sind.
   *
   * Die eben angelegte Sicherung (`createdName`) wird NIE gelöscht, auch wenn sie nach dem
   * Namen nicht zu den neuesten gehört: Geht die Uhr eines anderen Geräts etwas vor (das ist
   * bis maxClockSkewMs erlaubt), tragen dessen Sicherungen spätere Zeiten im Namen. Ohne diese
   * Ausnahme könnte das Aufräumen genau die Sicherung der Fassung löschen, die syncVault gleich
   * überschreibt – dann gäbe es von ihr keine Sicherung mehr. Behalten werden deshalb die
   * eigene neue Sicherung plus die neuesten `keep - 1` übrigen.
   *
   * Aufräumen ist „best effort“ (Entscheidung des Eigentümers, 2026-10-16): Die wichtige
   * Sicherung ist in diesem Moment schon angelegt. Lässt sich der Ordner nicht auflisten oder
   * eine ALTE Kopie nicht löschen (z. B. 403 bei einer Freigabe ohne Löschrecht, 423 bei einer
   * gesperrten Datei), soll das den Abgleich nicht dauerhaft blockieren. Statt zu werfen,
   * liefert die Funktion Hinweise; die übrigen alten Kopien werden trotzdem gelöscht.
   * Folge: Im Sicherungsordner können dann mehr als `keep` Kopien liegen.
   */
  private async pruneBackups(keep: number, createdName: string): Promise<string[]> {
    let resources: DavResource[] | null;
    try {
      resources = await this.propfind(this.backupFolderUrl, "1");
    } catch (error) {
      return [`Alte Sicherungskopien wurden nicht aufgeräumt: Der Sicherungsordner ließ sich nicht auflisten (${errorText(error)}).`];
    }
    if (resources === null) {
      return [`Alte Sicherungskopien wurden nicht aufgeräumt: Sicherungsordner ${describeUrl(this.backupFolderUrl)} nicht gefunden (HTTP 404).`];
    }
    const children = new Map<string, URL>();
    for (const resource of resources) {
      if (resource.isCollection) continue;
      const url = this.backupFolderChild(resource.href);
      if (url !== null) children.set(decodeSegment(lastSegment(url.pathname)), url);
    }
    const others = [...children.keys()].filter((name) => name !== createdName);
    const warnings: string[] = [];
    for (const name of backupsToDelete(this.fileName, others, keep - 1)) {
      const url = children.get(name)!;
      try {
        const response = await this.send("DELETE", url);
        await discardBody(response);
        // 404: schon weg (z. B. hat ein anderes Gerät gleichzeitig aufgeräumt).
        if (response.status !== 404) await this.expectSuccess(response, "Löschen einer alten Sicherungskopie", url);
      } catch (error) {
        warnings.push(`Alte Sicherungskopie "${name}" ließ sich nicht löschen (${errorText(error)}). Bitte bei Gelegenheit im Sicherungsordner aufräumen.`);
      }
    }
    return warnings;
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
    return new URL(path, this.backupFolderUrl.origin);
  }

  // -------------------------------------------------------------------------
  // HTTP
  // -------------------------------------------------------------------------

  /** PROPFIND mit `depth`; null bei 404. */
  private async propfind(url: URL, depth: "0" | "1"): Promise<DavResource[] | null> {
    const response = await this.send("PROPFIND", url, { Depth: depth, "Content-Type": "application/xml; charset=utf-8" }, PROPFIND_BODY);
    if (response.status === 404) {
      await discardBody(response);
      return null;
    }
    if (response.status !== 207) {
      await this.expectSuccess(response, "PROPFIND", url);
      await discardBody(response);
      throw new StorageError(`PROPFIND ${describeUrl(url)}: unerwartete Antwort HTTP ${response.status} (erwartet 207 Multi-Status).`, response.status);
    }
    const text = new TextDecoder().decode(await this.readBytes(response, url));
    try {
      return parseMultistatus(text);
    } catch (error) {
      throw new StorageError(`PROPFIND ${describeUrl(url)}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /** Eine Anfrage mit Anmeldung. Netzwerkfehler und Zeitüberschreitung werden zu StorageError. */
  private async send(method: string, url: URL, headers: Record<string, string> = {}, body?: RequestBody): Promise<Response> {
    const allHeaders = new Headers(headers);
    allHeaders.set("Authorization", this.#authorization);
    try {
      return await this.fetchFn(url.href, {
        method,
        headers: allHeaders,
        body,
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new StorageError(`${method} ${describeUrl(url)}: keine Antwort vom Server (${fetchFailureReason(error, this.#secrets)}).`);
    }
  }

  /** Liest den Antwort-Körper; ein Abbruch (Netz, Zeitlimit) wird zu StorageError. */
  private async readBytes(response: Response, url: URL): Promise<Uint8Array> {
    try {
      return new Uint8Array(await response.arrayBuffer());
    } catch (error) {
      throw new StorageError(`Lesen von ${describeUrl(url)} abgebrochen (${fetchFailureReason(error, this.#secrets)}).`);
    }
  }

  /** Wirft bei jedem Status außer 2xx den passenden Fehler. */
  private async expectSuccess(response: Response, action: string, url: URL): Promise<void> {
    if (response.ok) return;
    await discardBody(response);
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
      const location = response.headers.get("Location");
      return new StorageError(
        `${action}: Der Server leitet ${where} weiter${location !== null ? ` nach ${location}` : ""}. Bitte die endgültige Adresse eintragen.`,
        response.status === 0 ? undefined : response.status,
      );
    }
    return new StorageError(`${action} (${where}) fehlgeschlagen: HTTP ${response.status}${statusHint(response.status)}`, response.status);
  }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

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
