/**
 * WebDAV-Servertest für Ownwarden: Prüft Schritt für Schritt, ob ein WebDAV-Server alles
 * kann, worauf sich der sichere Abgleich verlässt (bedingtes Schreiben mit ETags usw.).
 * Gedacht für MagentaCLOUD und Nextcloud – bitte mit einem TEST-Zugang bzw. Testordner.
 *
 * Aufruf (im Ordner core/):
 *   npx tsx src/cli/webdav-probe.ts --url https://magentacloud.de/remote.php/webdav/Ownwarden-Test/ --user name@t-online.de
 *   Optionen:  --abort-test           zusätzlich einen abgebrochenen Upload testen
 *              --max-skew-seconds N   erlaubte Abweichung der Geräteuhr (Standard 120)
 *
 * Das Passwort kommt aus der Umgebungsvariable OWNWARDEN_WEBDAV_PASSWORD oder wird verdeckt
 * abgefragt. Es wird nie ausgegeben.
 *
 * Ablauf: Unter der angegebenen Adresse entsteht ein neuer Ordner "ownwarden-probe-<zufall>/".
 * Alle Tests laufen nur darin; am Ende wird er wieder gelöscht – auch wenn etwas schiefgeht.
 *
 * Aufbau: runWebDavProbe() ist die eigentliche Prüfung (auch aus Tests aufrufbar, siehe
 * webdav-probe.test.ts); main() ist nur die Kommandozeile drumherum.
 */
import { createInterface } from "node:readline";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { DEFAULT_SYNC_SETTINGS } from "../sync/sync";
import {
  basicAuthorization,
  bytesBody,
  describeUrl,
  fetchFailureReason,
  headerValue,
  isRedirect,
  isWeakEtag,
  parseHttpDate,
  parseStorageUrl,
} from "../sync/http";
import { parseMultistatus } from "../sync/multistatus";

/**
 * Hinweis für PROPFIND/DELETE-Probleme: Sie betreffen nur das Aufräumen alter Sicherungen,
 * das seit 2026-10-16 „best effort“ ist – der Abgleich selbst bleibt sicher.
 */
const PRUNING_ONLY =
  "Der Abgleich funktioniert trotzdem; alte Sicherungskopien werden dann aber nicht automatisch gelöscht (bitte gelegentlich von Hand aufräumen).";

// ---------------------------------------------------------------------------
// Ergebnis-Typen
// ---------------------------------------------------------------------------

/** ok = ✅, warn = ⚠️ (geht, aber mit Einschränkung), fail = ❌, skip = nicht ausgeführt. */
export type CheckStatus = "ok" | "warn" | "fail" | "skip";

export interface ProbeCheck {
  /** Kurzname, z. B. "stale-if-match". */
  id: string;
  /** Was geprüft wird (deutsch). */
  title: string;
  status: CheckStatus;
  /** Ergebnis bzw. Erklärung (deutsch). */
  detail: string;
}

export interface ProbeReport {
  /** Adresse des Testordners. */
  probeFolderUrl: string;
  checks: ProbeCheck[];
  /** true, wenn keine Prüfung fehlgeschlagen ist: Ownwarden kann mit dem Server sicher abgleichen. */
  safe: boolean;
}

export interface ProbeOptions {
  /** Ordner, unter dem der Testordner angelegt wird. */
  folderUrl: string;
  username: string;
  password: string;
  /** Zusätzlich einen abgebrochenen Upload testen. */
  abortTest?: boolean;
  /** Erlaubte Abweichung der Geräteuhr; Standard wie beim Abgleich. */
  maxClockSkewMs?: number;
  /** Zeitlimit pro Anfrage; Standard 60 s. */
  timeoutMs?: number;
  /** Eigene fetch-Funktion (Tests). */
  fetch?: typeof fetch;
  /** Wird nach jeder Prüfung aufgerufen (für die Fortschrittsanzeige). */
  onCheck?: (check: ProbeCheck) => void;
}

// ---------------------------------------------------------------------------
// HTTP-Sitzung
// ---------------------------------------------------------------------------

interface ProbeResponse {
  status: number;
  headers: Headers;
  data: Uint8Array;
  redirected: boolean;
  /** Ortszeit beim Eintreffen der Antwort (für den Uhrenvergleich). */
  receivedAt: number;
}

/** Netzwerkfehler (keine HTTP-Antwort). */
class NoResponseError extends Error {}

/** Abbruch der restlichen Prüfungen (z. B. Anmeldung abgelehnt). */
class StopProbe extends Error {}

class ProbeSession {
  private readonly authorization: string;
  private readonly secrets: string[];
  private readonly fetchFn: typeof fetch;
  /** Date-Header-Abweichungen (Ortszeit minus Serverzeit) aller Antworten. */
  readonly skews: number[] = [];

  constructor(
    private readonly options: ProbeOptions,
    private readonly timeoutMs: number,
  ) {
    this.authorization = basicAuthorization(options.username, options.password);
    this.secrets = [options.password, this.authorization, this.authorization.slice("Basic ".length)];
    const custom = options.fetch;
    this.fetchFn = custom !== undefined ? (input, init) => custom(input, init) : (input, init) => globalThis.fetch(input, init);
  }

  async request(method: string, url: URL, headers: Record<string, string> = {}, body?: Uint8Array | string, signal?: AbortSignal): Promise<ProbeResponse> {
    const allHeaders = new Headers(headers);
    allHeaders.set("Authorization", this.authorization);
    const timeout = AbortSignal.timeout(this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchFn(url.href, {
        method,
        headers: allHeaders,
        body: typeof body === "string" || body === undefined ? body : bytesBody(body),
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        signal: signal === undefined ? timeout : AbortSignal.any([timeout, signal]),
      });
      const data = new Uint8Array(await response.arrayBuffer());
      const receivedAt = Date.now();
      const serverDate = parseHttpDate(response.headers.get("Date"));
      if (serverDate !== undefined) this.skews.push(receivedAt - serverDate);
      return { status: response.status, headers: response.headers, data, redirected: isRedirect(response), receivedAt };
    } catch (error) {
      throw new NoResponseError(`${method} ${describeUrl(url)}: keine Antwort (${this.scrub(error)})`);
    }
  }

  /** Fehlertext ohne Geheimnisse. */
  scrub(error: unknown): string {
    return fetchFailureReason(error, this.secrets);
  }

  /** Läuft ein Upload, der mittendrin abgebrochen wird: erst ein Teil, dann Abbruch. */
  async abortedUpload(url: URL, ifMatch: string): Promise<string> {
    const controller = new AbortController();
    const chunk = new Uint8Array(256 * 1024).fill(0x58);
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        stream.enqueue(chunk); // erster Teil; der Rest kommt nie
      },
    });
    const upload = this.fetchFn(url.href, {
      method: "PUT",
      body,
      headers: { Authorization: this.authorization, "If-Match": ifMatch, "Content-Type": "application/octet-stream" },
      signal: controller.signal,
      credentials: "omit",
      redirect: "manual",
      duplex: "half", // für Stream-Körper in Node nötig
    } as RequestInit);
    await sleep(1000);
    controller.abort();
    try {
      const response = await upload;
      await response.body?.cancel();
      return `Server hat schon vor dem Abbruch geantwortet (HTTP ${response.status})`;
    } catch {
      return "Upload nach 256 KiB abgebrochen";
    }
  }
}

// ---------------------------------------------------------------------------
// Die Prüfung
// ---------------------------------------------------------------------------

const ICONS: Record<CheckStatus, string> = { ok: "✅", warn: "⚠️", fail: "❌", skip: "⏭️" };

/**
 * Führt alle Prüfungen aus und liefert den Bericht. Wirft nur bei ungültigen Eingaben
 * (z. B. http:// auf einen fremden Rechner); Serverprobleme stehen im Bericht.
 */
export async function runWebDavProbe(options: ProbeOptions): Promise<ProbeReport> {
  const base = parseStorageUrl(options.folderUrl, "Ordner-Adresse");
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  const folder = new URL(`ownwarden-probe-${randomHex(4)}/`, base);
  const session = new ProbeSession(options, options.timeoutMs ?? 60_000);
  const maxSkew = options.maxClockSkewMs ?? DEFAULT_SYNC_SETTINGS.maxClockSkewMs;
  const checks: ProbeCheck[] = [];
  const report = (check: ProbeCheck) => {
    checks.push(check);
    options.onCheck?.(check);
  };

  const { steps, state } = probeSteps(session, folder, maxSkew, options.abortTest ?? false);
  let stopped: string | null = null;
  let cleanupCheck: ProbeCheck;
  try {
    for (const step of steps) {
      if (stopped !== null) {
        report({ id: step.id, title: step.title, status: "skip", detail: `übersprungen (${stopped})` });
        continue;
      }
      let check: ProbeCheck;
      try {
        const [status, detail] = await step.run();
        check = { id: step.id, title: step.title, status, detail };
      } catch (error) {
        const detail = error instanceof StopProbe || error instanceof NoResponseError ? error.message : `unerwarteter Fehler: ${session.scrub(error)}`;
        check = { id: step.id, title: step.title, status: "fail", detail };
        if (error instanceof StopProbe || error instanceof NoResponseError || step.blocking) {
          stopped = `vorher fehlgeschlagen: ${step.title}`;
        }
      }
      if (check.status === "fail" && step.blocking) stopped ??= `vorher fehlgeschlagen: ${step.title}`;
      report(check);
    }
  } finally {
    // Aufräumen – immer, auch nach Fehlern und auch dann, wenn report()/onCheck selbst
    // wirft (z. B. kaputte Ausgabe). Erst danach geht ein solcher Fehler an den Aufrufer.
    cleanupCheck = await cleanup(session, folder, state.folderMayExist);
  }
  report(cleanupCheck);
  return { probeFolderUrl: folder.href, checks, safe: checks.every((check) => check.status !== "fail") };
}

type StepResult = [CheckStatus, string];

interface Step {
  id: string;
  title: string;
  /** Scheitert dieser Schritt, sind die folgenden sinnlos. */
  blocking: boolean;
  run(): Promise<StepResult>;
}

/** Zustand, den die Schritte untereinander weitergeben. */
interface ProbeState {
  /**
   * true, wenn der Testordner auf dem Server existieren KÖNNTE: nach 201 auf MKCOL, aber auch,
   * wenn MKCOL gar keine Antwort bekam (Verbindung abgerissen, Zeitlimit) – der Server kann
   * den Ordner trotzdem angelegt haben. Der Name ist zufällig, ein fremder Ordner kann es nicht sein.
   */
  folderMayExist: boolean;
  /** Erwarteter aktueller Inhalt der Testdatei. */
  content: Uint8Array;
  /** Aktueller ETag der Testdatei. */
  etag: string;
  /** Ein ETag, der nicht mehr aktuell ist. */
  staleEtag: string;
  /** Der Server nennt den ETag nur per PROPFIND, nicht im GET. */
  etagOnlyViaPropfind: boolean;
}

/** Die Prüfschritte in ihrer Reihenfolge. */
function probeSteps(session: ProbeSession, folder: URL, maxSkew: number, abortTest: boolean): { steps: Step[]; state: ProbeState } {
  const file = new URL("probe.kdbx", folder);
  const state: ProbeState = { folderMayExist: false, content: new Uint8Array(), etag: "", staleEtag: "", etagOnlyViaPropfind: false };
  const sameLength = (tag: string) => text(`Ownwarden-Probe-${tag}-${randomHex(8)}`);

  /** GET der Testdatei; liefert Inhalt und ETag (ggf. per PROPFIND). */
  const readFile = async (): Promise<{ data: Uint8Array; etag: string | null; response: ProbeResponse }> => {
    const response = expectHttp(await session.request("GET", file), "GET");
    if (response.status !== 200) throw new StopProbe(`GET: HTTP ${response.status}`);
    const etag = headerValue(response.headers, "ETag") ?? (state.etagOnlyViaPropfind ? await propfindEtag(session, file) : null);
    return { data: response.data, etag, response };
  };

  const steps: Step[] = [
    {
      id: "mkcol",
      title: "Testordner anlegen (MKCOL)",
      blocking: true,
      run: async () => {
        // Bekommt MKCOL keine Antwort (NoResponseError), bleibt folderMayExist true und das
        // Aufräumen versucht das Löschen; mit einer eindeutigen Antwort wissen wir es genau.
        state.folderMayExist = true;
        const raw = await session.request("MKCOL", folder);
        state.folderMayExist = raw.status === 201;
        const response = expectHttp(raw, "MKCOL");
        if (response.status === 201) return ["ok", `angelegt: ${describeUrl(folder)}`];
        if (response.status === 409) return ["fail", "HTTP 409: Die angegebene Ordner-Adresse gibt es nicht. Bitte einen vorhandenen Ordner angeben."];
        return ["fail", `HTTP ${response.status} – erwartet 201`];
      },
    },
    {
      id: "create",
      title: 'Neue Datei anlegen mit "If-None-Match: *"',
      blocking: true,
      run: async () => {
        state.content = sameLength("A");
        const response = expectHttp(await session.request("PUT", file, putHeaders({ "If-None-Match": "*" }), state.content), "PUT");
        if (response.status !== 201 && response.status !== 204) return ["fail", `HTTP ${response.status} – erwartet 201 oder 204`];
        const etag = headerValue(response.headers, "ETag") ?? headerValue(response.headers, "OC-ETag");
        return ["ok", `HTTP ${response.status}; neuer ETag in der Antwort: ${etag ?? "keiner (Ownwarden liest ihn dann nach)"}`];
      },
    },
    {
      id: "create-again",
      title: 'Zweites Anlegen mit "If-None-Match: *" wird abgelehnt (412)',
      blocking: false,
      run: async () => {
        const other = sameLength("B");
        const response = expectHttp(await session.request("PUT", file, putHeaders({ "If-None-Match": "*" }), other), "PUT");
        if (response.status === 412) return ["ok", "HTTP 412"];
        if (response.status >= 200 && response.status < 300) {
          state.content = other;
          return ["fail", `HTTP ${response.status}: Der Server überschreibt trotz "If-None-Match: *". Zwei Geräte könnten beim ersten Hochladen gegenseitig ihre Daten überschreiben.`];
        }
        return ["fail", `HTTP ${response.status} – erwartet 412`];
      },
    },
    {
      id: "etag",
      title: "GET liefert die Datei mit ETag",
      blocking: true,
      run: async () => {
        const response = expectHttp(await session.request("GET", file), "GET");
        if (response.status !== 200) return ["fail", `HTTP ${response.status} – erwartet 200`];
        if (!sameBytes(response.data, state.content)) return ["fail", "Der gelesene Inhalt stimmt nicht mit dem geschriebenen überein."];
        const header = headerValue(response.headers, "ETag");
        if (header !== null) {
          state.etag = header;
          return isWeakEtag(header)
            ? ["warn", `ETag ${header} ist SCHWACH (W/). "If-Match" vergleicht laut Norm stark – die nächsten Prüfungen zeigen, ob der Server ihn trotzdem annimmt.`]
            : ["ok", `ETag ${header} (stark)`];
        }
        const viaPropfind = await propfindEtag(session, file);
        if (viaPropfind === null) {
          return ["fail", "Der Server nennt weder im GET noch per PROPFIND einen ETag. Ohne ETag kann Ownwarden nicht sicher schreiben."];
        }
        state.etag = viaPropfind;
        state.etagOnlyViaPropfind = true;
        return ["warn", `kein ETag-Header im GET; per PROPFIND: ${viaPropfind}. Ownwarden kommt damit zurecht (eine Anfrage mehr pro Abgleich).`];
      },
    },
    {
      id: "update",
      title: 'Schreiben mit aktuellem "If-Match" gelingt, der ETag ändert sich',
      blocking: true,
      run: async () => {
        const next = sameLength("C");
        const response = expectHttp(await session.request("PUT", file, putHeaders({ "If-Match": state.etag }), next), "PUT");
        if (response.status === 412) {
          return ["fail", "HTTP 412: Der Server lehnt den aktuellen ETag ab – mit diesem Server würde jedes Schreiben scheitern."];
        }
        if (response.status < 200 || response.status >= 300) return ["fail", `HTTP ${response.status} – erwartet 2xx`];
        const putEtag = headerValue(response.headers, "ETag") ?? headerValue(response.headers, "OC-ETag");
        const after = await readFile();
        if (!sameBytes(after.data, next)) return ["fail", "Nach dem Schreiben liefert GET nicht den neuen Inhalt."];
        if (after.etag === null || after.etag === state.etag) return ["fail", `Der ETag hat sich nach dem Schreiben nicht geändert (${after.etag ?? "keiner"}).`];
        state.staleEtag = state.etag;
        state.etag = after.etag;
        state.content = next;
        const putNote = putEtag === null ? "PUT-Antwort ohne ETag" : putEtag === after.etag ? "PUT-Antwort nennt denselben ETag" : `PUT-Antwort nennt ${putEtag}, GET aber ${after.etag}`;
        return ["ok", `HTTP ${response.status}; neuer ETag ${after.etag} (${putNote})`];
      },
    },
    {
      id: "same-second",
      title: "Neuer ETag auch bei gleich großem Inhalt in derselben Sekunde",
      blocking: false,
      run: async () => {
        const next = sameLength("D");
        const started = Date.now();
        const response = expectHttp(await session.request("PUT", file, putHeaders({ "If-Match": state.etag }), next), "PUT");
        if (response.status < 200 || response.status >= 300) return ["fail", `HTTP ${response.status} – erwartet 2xx`];
        const after = await readFile();
        const sameSecond = Math.floor(started / 1000) === Math.floor(after.response.receivedAt / 1000) ? "in derselben Sekunde" : "knapp eine Sekunde später";
        if (after.etag === null || after.etag === state.etag) {
          return ["fail", `Der ETag blieb gleich (${after.etag ?? "keiner"}). Zwei schnelle Änderungen wären nicht unterscheidbar – eine könnte unbemerkt verloren gehen.`];
        }
        state.etag = after.etag;
        state.content = next;
        return ["ok", `ETag geändert (${sameSecond} geschrieben)`];
      },
    },
    {
      id: "stale-if-match",
      title: 'Schreiben mit veraltetem "If-Match" wird abgelehnt (412)',
      blocking: false,
      run: async () => {
        const response = expectHttp(await session.request("PUT", file, putHeaders({ "If-Match": state.staleEtag }), sameLength("E")), "PUT");
        const after = await readFile();
        if (response.status === 412 && sameBytes(after.data, state.content)) return ["ok", "HTTP 412, Inhalt unverändert"];
        if (response.status >= 200 && response.status < 300) {
          state.etag = after.etag ?? state.etag;
          state.content = after.data;
          return ["fail", `HTTP ${response.status}: Der Server überschreibt trotz veraltetem ETag. Änderungen anderer Geräte könnten verloren gehen.`];
        }
        return ["fail", `HTTP ${response.status} – erwartet 412`];
      },
    },
    {
      id: "if-match-missing",
      title: '"If-Match" auf eine fehlende Datei wird abgelehnt (412)',
      blocking: false,
      run: async () => {
        const missing = new URL("fehlt.kdbx", folder);
        const response = expectHttp(await session.request("PUT", missing, putHeaders({ "If-Match": state.etag }), sameLength("F")), "PUT");
        if (response.status === 412) return ["ok", "HTTP 412"];
        return ["warn", `HTTP ${response.status} statt 412. Unkritisch: Ownwarden legt neue Dateien immer mit "If-None-Match: *" an.`];
      },
    },
    {
      id: "date",
      title: "Date-Header und Uhrzeit des Geräts",
      blocking: false,
      run: async () => {
        if (session.skews.length === 0) {
          return ["warn", "Der Server schickt keinen Date-Header. Ownwarden kann die Geräteuhr dann nicht prüfen."];
        }
        const skew = session.skews[session.skews.length - 1]!;
        const seconds = Math.round(skew / 1000);
        const direction = skew > 0 ? "vor" : "nach";
        if (Math.abs(skew) > maxSkew) {
          return ["warn", `Die Uhr dieses Geräts geht ${Math.abs(seconds)} s ${direction} (erlaubt: ${Math.round(maxSkew / 1000)} s). Ownwarden würde den Abgleich verweigern – bitte die Uhrzeit stellen.`];
        }
        return ["ok", `Abweichung ${Math.abs(seconds)} s (erlaubt: ${Math.round(maxSkew / 1000)} s; der Date-Header ist nur sekundengenau)`];
      },
    },
    {
      id: "propfind",
      title: "PROPFIND listet den Ordner (für das Aufräumen alter Sicherungen)",
      blocking: false,
      run: async () => {
        const response = expectHttp(
          await session.request("PROPFIND", folder, { Depth: "1", "Content-Type": "application/xml; charset=utf-8" }, PROPFIND_BODY),
          "PROPFIND",
        );
        // Seit 2026-10-16 ist das Aufräumen alter Sicherungen „best effort“ (Entscheidung des
        // Eigentümers): Ohne PROPFIND bleiben nur alte Sicherungen liegen – daher Hinweis, kein Fehler.
        if (response.status !== 207) return ["warn", `HTTP ${response.status} – erwartet 207. ${PRUNING_ONLY}`];
        const resources = parseMultistatus(text(response.data));
        const entry = resources.find((resource) => decodeURIComponent(resource.href.replace(/\/$/, "").split("/").pop() ?? "") === "probe.kdbx");
        if (entry === undefined) return ["warn", `Die Testdatei fehlt in der Ordnerliste. ${PRUNING_ONLY}`];
        const etag = entry.props.get("getetag");
        const note = etag === state.etag ? "getetag stimmt mit dem ETag überein" : `getetag ${etag ?? "fehlt"} weicht vom ETag ${state.etag} ab`;
        return [etag === state.etag ? "ok" : "warn", `${resources.length} Einträge; ${note}`];
      },
    },
    {
      id: "copy",
      title: "COPY auf dem Server (für Sicherungskopien)",
      blocking: false,
      run: async () => {
        const target = new URL("kopie.kdbx", folder);
        const response = expectHttp(await session.request("COPY", file, { Destination: target.href, Overwrite: "F" }), "COPY");
        if (response.status === 405 || response.status === 501) {
          return ["warn", `HTTP ${response.status}: kein COPY. Ownwarden lädt Sicherungskopien stattdessen hoch (mehr Datenverkehr).`];
        }
        if (response.status !== 201 && response.status !== 204) return ["fail", `HTTP ${response.status} – erwartet 201 oder 204`];
        const copy = expectHttp(await session.request("GET", target), "GET");
        if (copy.status !== 200 || !sameBytes(copy.data, state.content)) return ["fail", "Die Kopie hat nicht denselben Inhalt."];
        return ["ok", `HTTP ${response.status}, Inhalt der Kopie stimmt`];
      },
    },
    {
      id: "delete",
      title: "DELETE einer Datei (für das Aufräumen alter Sicherungen)",
      blocking: false,
      run: async () => {
        const target = new URL("fehlt.kdbx", folder);
        await session.request("PUT", target, putHeaders({}), sameLength("G")); // sicherstellen, dass es sie gibt
        const raw = await session.request("DELETE", target);
        // 403 heißt hier „kein Löschrecht“ (z. B. Freigabe ohne Löschen) – die Anmeldung hat bei
        // den Anfragen davor ja geklappt. Best effort wie bei PROPFIND (siehe dort): nur Hinweis.
        if (raw.status === 403) return ["warn", `HTTP 403 (kein Löschrecht?). ${PRUNING_ONLY}`];
        const response = expectHttp(raw, "DELETE");
        if (response.status < 200 || response.status >= 300) return ["warn", `HTTP ${response.status} – erwartet 204. ${PRUNING_ONLY}`];
        const gone = expectHttp(await session.request("GET", target), "GET");
        return gone.status === 404 ? ["ok", `HTTP ${response.status}, danach 404`] : ["warn", `Nach DELETE liefert GET noch HTTP ${gone.status}. ${PRUNING_ONLY}`];
      },
    },
    {
      id: "abort",
      title: "Abgebrochener Upload lässt die alte Fassung unverändert",
      blocking: false,
      run: async () => {
        if (!abortTest) return ["skip", "nicht ausgeführt (mit --abort-test einschalten)"];
        const how = await session.abortedUpload(file, state.etag);
        await sleep(1500); // dem Server Zeit geben, den halben Upload zu verwerfen
        const after = await readFile();
        if (sameBytes(after.data, state.content) && after.etag === state.etag) return ["ok", `${how}; Inhalt und ETag unverändert`];
        return ["fail", `${how}; danach hat die Datei einen anderen Inhalt oder ETag – ein abgebrochener Upload kann die Tresor-Datei beschädigen!`];
      },
    },
  ];
  return { steps, state };
}

/** Löscht den Testordner (404 = gab es nicht, auch in Ordnung). */
async function cleanup(session: ProbeSession, folder: URL, mayExist: boolean): Promise<ProbeCheck> {
  const id = "cleanup";
  const title = "Testordner wieder löschen";
  if (!mayExist) return { id, title, status: "ok", detail: "nichts zu löschen (Ordner wurde nicht angelegt)" };
  try {
    const response = await session.request("DELETE", folder);
    if ((response.status >= 200 && response.status < 300) || response.status === 404) return { id, title, status: "ok", detail: `HTTP ${response.status}` };
    return { id, title, status: "warn", detail: `HTTP ${response.status}. Bitte von Hand löschen: ${describeUrl(folder)}` };
  } catch (error) {
    return { id, title, status: "warn", detail: `${error instanceof Error ? error.message : String(error)}. Bitte von Hand löschen: ${describeUrl(folder)}` };
  }
}

/** Anmeldefehler und Weiterleitungen beenden die Prüfung mit klarer Meldung. */
function expectHttp(response: ProbeResponse, method: string): ProbeResponse {
  if (response.status === 401 || response.status === 403) {
    throw new StopProbe(`${method}: Anmeldung abgelehnt (HTTP ${response.status}). Benutzername und App-/Gerätepasswort prüfen.`);
  }
  if (response.redirected) {
    const location = response.headers.get("Location");
    throw new StopProbe(`${method}: Der Server leitet weiter${location !== null ? ` nach ${location}` : ""}. Bitte die endgültige Adresse verwenden.`);
  }
  return response;
}

const PROPFIND_BODY =
  '<?xml version="1.0" encoding="utf-8"?>\n<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/><d:resourcetype/></d:prop></d:propfind>';

/** getetag per PROPFIND (Depth 0) oder null. */
async function propfindEtag(session: ProbeSession, file: URL): Promise<string | null> {
  const response = expectHttp(await session.request("PROPFIND", file, { Depth: "0", "Content-Type": "application/xml; charset=utf-8" }, PROPFIND_BODY), "PROPFIND");
  if (response.status !== 207) return null;
  const etag = parseMultistatus(text(response.data))[0]?.props.get("getetag");
  return etag === undefined || etag === "" ? null : etag;
}

function putHeaders(extra: Record<string, string>): Record<string, string> {
  return { "Content-Type": "application/octet-stream", ...extra };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function randomHex(byteCount: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(byteCount)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function text(value: string): Uint8Array;
function text(value: Uint8Array): string;
function text(value: string | Uint8Array): Uint8Array | string {
  return typeof value === "string" ? new TextEncoder().encode(value) : new TextDecoder().decode(value);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

// ---------------------------------------------------------------------------
// Ausgabe
// ---------------------------------------------------------------------------

/** Eine Zeile pro Prüfung, z. B. "✅ Testordner anlegen (MKCOL): angelegt: …". */
export function formatCheck(check: ProbeCheck): string {
  return `${ICONS[check.status]} ${check.title}: ${check.detail}`;
}

/** Zusammenfassung am Ende. */
export function formatSummary(report: ProbeReport): string {
  const failed = report.checks.filter((check) => check.status === "fail");
  const warnings = report.checks.filter((check) => check.status === "warn");
  const lines = [""];
  if (report.safe) {
    lines.push("✅ Ergebnis: Ownwarden kann mit diesem Server sicher synchronisieren.");
    if (warnings.length > 0) lines.push(`   Hinweise (${warnings.length}): ${warnings.map((check) => check.title).join("; ")}`);
  } else {
    lines.push("❌ Ergebnis: Mit diesem Server ist ein sicherer Abgleich NICHT gewährleistet.");
    for (const check of failed) lines.push(`   - ${check.title}`);
  }
  if (report.checks.some((check) => check.id === "abort" && check.status === "skip")) {
    lines.push("   Tipp: Mit --abort-test wird zusätzlich ein abgebrochener Upload geprüft.");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Kommandozeile
// ---------------------------------------------------------------------------

const USAGE = `Aufruf:
  npx tsx src/cli/webdav-probe.ts --url <Ordner-Adresse> --user <Benutzername> [--abort-test] [--max-skew-seconds <s>]

Beispiel (MagentaCLOUD, mit einem TEST-Zugang bzw. Testordner):
  npx tsx src/cli/webdav-probe.ts --url https://magentacloud.de/remote.php/webdav/Ownwarden-Test/ --user name@t-online.de

Das Passwort (am besten ein eigenes App-/Gerätepasswort) kommt aus der Umgebungsvariable
OWNWARDEN_WEBDAV_PASSWORD oder wird verdeckt abgefragt.`;

/** Kommandozeile; liefert den Exit-Code (0 = sicher, 1 = nicht sicher, 2 = Bedienfehler). */
export async function main(argv: string[]): Promise<number> {
  let values: { url?: string; user?: string; "abort-test"?: boolean; "max-skew-seconds"?: string; help?: boolean };
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      // Lose Argumente selbst ablehnen: Die Meldung von parseArgs würde sie wörtlich
      // wiederholen – und ein loses Argument ist oft ein versehentlich eingetipptes Passwort.
      allowPositionals: true,
      options: {
        url: { type: "string" },
        user: { type: "string" },
        "abort-test": { type: "boolean" },
        "max-skew-seconds": { type: "string" },
        help: { type: "boolean", short: "h" },
      },
    }));
  } catch (error) {
    // Eine UNBEKANNTE Option nennt parseArgs wörtlich – das kann ein versehentlich
    // eingetipptes Passwort sein, das mit „-“ beginnt. Deshalb dann ohne den Text selbst.
    // Die übrigen Meldungen nennen nur unsere eigenen Optionsnamen, keine Werte.
    const unknownOption = (error as { code?: unknown }).code === "ERR_PARSE_ARGS_UNKNOWN_OPTION";
    const message = unknownOption ? "Unbekannte Option (wird absichtlich nicht wiederholt)." : error instanceof Error ? error.message : String(error);
    console.error(`${message}\n\n${USAGE}`);
    return 2;
  }
  if (values.help === true) {
    console.log(USAGE);
    return 0;
  }
  if (positionals.length > 0) {
    console.error(`Unerwartete Argumente ohne Option (sie werden nicht angezeigt – das Passwort nie auf der Kommandozeile angeben).\n\n${USAGE}`);
    return 2;
  }
  if (values.url === undefined || values.user === undefined) {
    console.error(USAGE);
    return 2;
  }
  // Adresse prüfen, BEVOR sie ausgegeben oder ein Passwort abgefragt wird: Eine Adresse mit
  // Zugangsdaten (https://name:passwort@…) darf nie im Terminal oder in einem Log landen.
  let folderUrl: URL;
  try {
    folderUrl = parseStorageUrl(values.url, "Ordner-Adresse");
  } catch (error) {
    console.error(`❌ ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
  let maxClockSkewMs: number | undefined;
  if (values["max-skew-seconds"] !== undefined) {
    const seconds = Number(values["max-skew-seconds"]);
    if (!Number.isFinite(seconds) || seconds < 0) {
      console.error("--max-skew-seconds braucht eine Zahl ≥ 0.");
      return 2;
    }
    maxClockSkewMs = seconds * 1000;
  }

  const password = process.env.OWNWARDEN_WEBDAV_PASSWORD ?? (await promptHidden(`Passwort für ${values.user}: `));
  if (password === "") {
    console.error("Kein Passwort angegeben.");
    return 2;
  }

  console.log(`Ownwarden-WebDAV-Test für ${describeUrl(folderUrl)} (Benutzer ${values.user})\n`);
  try {
    const report = await runWebDavProbe({
      folderUrl: folderUrl.href,
      username: values.user,
      password,
      abortTest: values["abort-test"] ?? false,
      ...(maxClockSkewMs === undefined ? {} : { maxClockSkewMs }),
      onCheck: (check) => console.log(formatCheck(check)),
    });
    console.log(formatSummary(report));
    return report.safe ? 0 : 1;
  } catch (error) {
    // Nur Eingabefehler landen hier (z. B. http:// auf einen fremden Rechner); die Meldungen
    // enthalten kein Passwort.
    console.error(`❌ ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

/**
 * Fragt das Passwort ab, ohne es anzuzeigen. Kommt die Eingabe nicht von einem Terminal
 * (z. B. über eine Pipe), wird die erste Zeile gelesen.
 */
async function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    const lines = createInterface({ input: stdin });
    for await (const line of lines) {
      lines.close();
      return line;
    }
    return "";
  }
  process.stderr.write(question);
  return new Promise((resolvePromise, reject) => {
    let value = "";
    const finish = (error?: Error) => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write("\n");
      if (error === undefined) resolvePromise(value);
      else reject(error);
    };
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === "\r" || char === "\n" || char === "\u0004") return finish();
        if (char === "\u0003") return finish(new Error("Abgebrochen."));
        if (char === "\u007f" || char === "\b") {
          value = Array.from(value).slice(0, -1).join("");
          continue;
        }
        value += char;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.on("data", onData);
    stdin.resume();
  });
}

/** true, wenn diese Datei direkt gestartet wurde (nicht importiert, z. B. aus einem Test). */
function isMainModule(): boolean {
  const script = process.argv[1];
  return script !== undefined && import.meta.url === pathToFileURL(resolve(script)).href;
}

if (isMainModule()) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      console.error(`❌ ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 2;
    },
  );
}
