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
 * Grundsatz (Review probe-1, probe-2, probe-3): Jede Prüfung macht es so wie der echte Abgleich
 * und ist mindestens so streng wie er – sonst wäre der Test grün, der Abgleich aber nicht sicher.
 * Ließ sich etwas nicht prüfen (z. B. der Server antwortete vor dem Abbruch des Uploads), heißt
 * das ⚠️ „nicht geprüft“, nie ✅. Die Sicherungskopien prüft der Test mit dem WebDavAdapter selbst.
 *
 * Aufbau: runWebDavProbe() ist die eigentliche Prüfung (auch aus Tests aufrufbar, siehe
 * webdav-probe.test.ts); main() ist nur die Kommandozeile drumherum.
 */
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import type { RemoteFile } from "../contracts";
import { DEFAULT_SYNC_SETTINGS } from "../sync/sync";
import { BACKUP_FOLDER_NAME, DEFAULT_WEBDAV_TIMEOUT_MS, WebDavAdapter } from "../sync/webdav";
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
import { isMainModule } from "./main-module";
import { inputLikelyVisible, VISIBLE_INPUT_WARNING } from "./prompt";

/**
 * Hinweis für PROPFIND/DELETE-Probleme: Sie betreffen nur das Aufräumen alter Sicherungen,
 * das seit 2026-10-16 „best effort“ ist – der Abgleich selbst bleibt sicher.
 */
const PRUNING_ONLY =
  "Der Abgleich funktioniert trotzdem; alte Sicherungskopien werden dann aber nicht automatisch gelöscht (bitte gelegentlich von Hand aufräumen).";

/**
 * Abgebrochener Upload (--abort-test): So viele Bytes kündigt Content-Length an, so viele werden
 * wirklich gesendet, bevor die Verbindung getrennt wird.
 */
const ABORT_UPLOAD_BYTES = 512 * 1024;
const ABORT_SENT_BYTES = 256 * 1024;

/** So oft versucht die Prüfung „derselben Sekunde“, beide Schreibvorgänge in eine Serversekunde zu bekommen. */
const SAME_SECOND_ATTEMPTS = 5;

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
  /** Zeitlimit pro Anfrage; Standard wie beim Abgleich (DEFAULT_WEBDAV_TIMEOUT_MS, 25 s). */
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

/** Ausgang des abgebrochenen Uploads (ProbeSession.abortedUpload). */
type AbortOutcome =
  /** Ein Teil wurde gesendet, dann die Verbindung getrennt – so soll es sein. */
  | { kind: "aborted" }
  /** Der Server hat schon VOR dem Abbruch geantwortet. */
  | { kind: "answered"; status: number }
  /** Die Verbindung scheiterte vor dem Abbruch. */
  | { kind: "failed"; reason: string };

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

  /** WebDavAdapter mit denselben Zugangsdaten, demselben fetch und demselben Zeitlimit wie die Prüfung. */
  adapter(fileUrl: URL): WebDavAdapter {
    return new WebDavAdapter({
      fileUrl: fileUrl.href,
      username: this.options.username,
      password: this.options.password,
      fetch: this.fetchFn,
      timeoutMs: this.timeoutMs,
    });
  }

  /**
   * Ein Upload wie beim echten Abgleich, der mittendrin abbricht (Review probe-1/xc-2):
   * WebDavAdapter.write schickt immer eine Content-Length. Genau so hier – angekündigt werden
   * ABORT_UPLOAD_BYTES, gesendet nur ABORT_SENT_BYTES, dann wird die Verbindung getrennt.
   *
   * Absichtlich mit node:http(s) statt fetch: fetch schickt einen Körper, der erst nach und nach
   * entsteht, nur „chunked“ OHNE Content-Length. Das ist im Server ein anderer Weg (Nextcloud
   * erkennt einen unvollständigen Upload nur am Vergleich mit Content-Length), und manche Server
   * oder Vorschaltrechner lehnen ihn sofort ab (z. B. 411) – dann käme gar kein abgebrochener
   * Upload beim Server an.
   */
  abortedUpload(url: URL, ifMatch: string): Promise<AbortOutcome> {
    const send = url.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise((resolvePromise) => {
      let settled = false;
      let pause: ReturnType<typeof setTimeout> | undefined;
      const finish = (outcome: AbortOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(pause);
        clearTimeout(deadline);
        request.destroy(); // trennt die Verbindung; der Rest des Körpers kommt nie
        resolvePromise(outcome);
      };
      const request = send(url, {
        method: "PUT",
        headers: {
          Authorization: this.authorization,
          "If-Match": ifMatch,
          "Content-Type": "application/octet-stream",
          "Content-Length": String(ABORT_UPLOAD_BYTES),
        },
      });
      const deadline = setTimeout(
        () => finish({ kind: "failed", reason: `der erste Teil ging nicht innerhalb von ${Math.round(this.timeoutMs / 1000)} s hinaus` }),
        this.timeoutMs,
      );
      request.on("response", (response) => {
        response.resume();
        finish({ kind: "answered", status: response.statusCode ?? 0 });
      });
      request.on("error", (error) => finish({ kind: "failed", reason: this.scrub(error) }));
      // Erst den Teil senden; ist er hinaus, dem Server eine Sekunde geben, ihn zu empfangen.
      request.write(new Uint8Array(ABORT_SENT_BYTES).fill(0x58), (error) => {
        if (error == null) pause = setTimeout(() => finish({ kind: "aborted" }), 1000);
      });
    });
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
  const session = new ProbeSession(options, options.timeoutMs ?? DEFAULT_WEBDAV_TIMEOUT_MS);
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
  /** Die PUT-Antwort nennt denselben ETag wie das GET danach (dann spart „same-second“ ein GET). */
  putEtagMatchesGet: boolean;
}

/** Die Prüfschritte in ihrer Reihenfolge. */
function probeSteps(session: ProbeSession, folder: URL, maxSkew: number, abortTest: boolean): { steps: Step[]; state: ProbeState } {
  const file = new URL("probe.kdbx", folder);
  const state: ProbeState = { folderMayExist: false, content: new Uint8Array(), etag: "", staleEtag: "", etagOnlyViaPropfind: false, putEtagMatchesGet: false };
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
        state.putEtagMatchesGet = putEtag !== null && putEtag === after.etag;
        const putNote = putEtag === null ? "PUT-Antwort ohne ETag" : putEtag === after.etag ? "PUT-Antwort nennt denselben ETag" : `PUT-Antwort nennt ${putEtag}, GET aber ${after.etag}`;
        return ["ok", `HTTP ${response.status}; neuer ETag ${after.etag} (${putNote})`];
      },
    },
    {
      // Review probe-3/xc-9: Bilden Server den ETag nur aus Größe + Änderungszeit in ganzen
      // Sekunden, bekäme ein zweites Gerät, das in derselben Sekunde gleich viel schreibt,
      // keine 412. Geprüft werden deshalb ZWEI Schreibvorgänge mit gleich großem Inhalt, die
      // nachweislich in derselben Serversekunde lagen: Das erste Schreiben beginnt nach dem
      // Date-Header des GET davor, das zweite endet vor dem Date-Header seiner eigenen Antwort.
      // Nennen beide Header dieselbe Sekunde, lagen beide Schreibvorgänge in ihr. Sonst neuer
      // Versuch; klappt es nie (langsame Leitung), heißt das ⚠️ „nicht geprüft“, nicht ✅.
      id: "same-second",
      title: "Neuer ETag auch bei gleich großem Inhalt in derselben Sekunde",
      blocking: false,
      run: async () => {
        for (let attempt = 1; attempt <= SAME_SECOND_ATTEMPTS; attempt++) {
          const before = await readFile();
          if (before.etag === null) return ["fail", "Der Server nennt keinen ETag mehr."];
          const first = sameLength("D");
          const firstResponse = expectHttp(await session.request("PUT", file, putHeaders({ "If-Match": before.etag }), first), "PUT");
          if (firstResponse.status < 200 || firstResponse.status >= 300) return ["fail", `HTTP ${firstResponse.status} – erwartet 2xx`];
          state.content = first;
          const firstEtag = (state.putEtagMatchesGet ? putResponseEtag(firstResponse) : null) ?? (await readFile()).etag;
          if (firstEtag === null) return ["fail", "Nach dem Schreiben nennt der Server keinen ETag."];
          state.etag = firstEtag;

          const second = sameLength("D");
          const secondResponse = expectHttp(await session.request("PUT", file, putHeaders({ "If-Match": firstEtag }), second), "PUT");
          if (secondResponse.status < 200 || secondResponse.status >= 300) {
            return ["fail", `HTTP ${secondResponse.status} beim zweiten Schreiben – erwartet 2xx (If-Match mit dem ETag nach dem ersten)`];
          }
          state.content = second;
          const after = await readFile();
          if (!sameBytes(after.data, second)) return ["fail", "Nach dem Schreiben liefert GET nicht den neuen Inhalt."];
          if (after.etag === null || after.etag === firstEtag) {
            return ["fail", `Der ETag blieb gleich (${after.etag ?? "keiner"}). Zwei schnelle Änderungen wären nicht unterscheidbar – eine könnte unbemerkt verloren gehen.`];
          }
          state.etag = after.etag;

          const start = serverSecond(before.response);
          const end = serverSecond(secondResponse);
          if (start === undefined || end === undefined) {
            return ["warn", "nicht geprüft: Ohne Date-Header lässt sich nicht feststellen, ob beide Schreibvorgänge in derselben Sekunde lagen. Der ETag hat sich geändert."];
          }
          if (start === end) return ["ok", `ETag geändert; beide Schreibvorgänge lagen in derselben Serversekunde${attempt > 1 ? ` (${attempt}. Versuch)` : ""}`];
        }
        return [
          "warn",
          `nicht geprüft: In ${SAME_SECOND_ATTEMPTS} Versuchen lagen die beiden Schreibvorgänge nie in derselben Serversekunde (Antworten zu langsam). ` +
            "Der ETag hat sich jedes Mal geändert; ob er das auch bei zwei Änderungen in derselben Sekunde tut, bleibt offen.",
        ];
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
        // So streng wie beim Aufräumen (WebDavAdapter.pruneBackups, Review probe-2): Dort zählt
        // nur, was DIREKT im angefragten Ordner liegt. Nennt der Server die Datei unter einem
        // anderen Pfad (umgeschriebene Adresse, anderer DAV-Zugang), fände Ownwarden alte
        // Sicherungen nie – ohne jeden Hinweis.
        const entry = resources.find((resource) => isDirectChild(resource.href, folder, "probe.kdbx"));
        if (entry === undefined) {
          const elsewhere = resources.find((resource) => decodeSegment(resource.href.replace(/\/$/, "").split("/").pop() ?? "") === "probe.kdbx");
          if (elsewhere !== undefined) {
            return ["warn", `Die Ordnerliste nennt die Testdatei unter einem anderen Pfad (${elsewhere.href}) als den angefragten Ordner (${folder.pathname}). ${PRUNING_ONLY}`];
          }
          return ["warn", `Die Testdatei fehlt in der Ordnerliste. ${PRUNING_ONLY}`];
        }
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
      // Review probe-2: genau der Code des Abgleichs (WebDavAdapter) – MKCOL auf den schon
      // vorhandenen Sicherungsordner (das passiert bei JEDEM Abgleich und muss 201, 405 oder
      // eine Weiterleitung liefern, sonst scheitert jedes Schreiben), COPY in den Unterordner und
      // das Aufräumen. Ob das Aufräumen wirklich gelöscht hat, prüft danach eine eigene Liste.
      id: "backups",
      title: "Sicherungskopien wie beim Abgleich (Ordner, Kopie, Aufräumen)",
      blocking: false,
      run: async () => {
        const adapter = session.adapter(file);
        const backupFolder = new URL(`${BACKUP_FOLDER_NAME}/`, folder);
        let kept: RemoteFile;
        let pruneWarnings: string[];
        try {
          const first = await adapter.read();
          if (first === null) return ["fail", "Die Testdatei fehlt."];
          await adapter.backup(first); // legt den Sicherungsordner an
          await adapter.write(sameLength("H"), { ifMatch: first.etag });
          const second = await adapter.read();
          if (second === null) return ["fail", "Die Testdatei fehlt nach dem Schreiben."];
          state.content = second.data;
          state.etag = second.etag;
          await adapter.backup(second); // Sicherungsordner gibt es jetzt schon
          pruneWarnings = (await adapter.pruneBackups(second, 1)).warnings;
          kept = second;
        } catch (error) {
          // Für die folgenden Schritte festhalten, was jetzt in der Testdatei steht.
          const current = await readFile().catch(() => null);
          if (current !== null && current.etag !== null) {
            state.content = current.data;
            state.etag = current.etag;
          }
          return ["fail", `${session.scrub(error)} Ohne Sicherungskopie schreibt Ownwarden nie – mit diesem Server scheiterte jeder Abgleich, der etwas ändert.`];
        }
        const remaining = await listFiles(session, backupFolder);
        const leftOver = remaining !== null && remaining.length !== 1 ? `Nach dem Aufräumen liegen ${remaining.length} statt 1 Sicherung im Ordner. ` : "";
        if (pruneWarnings.length > 0) return ["warn", `${leftOver}${pruneWarnings.join(" ")} ${PRUNING_ONLY}`];
        if (remaining === null) return ["warn", `Der Sicherungsordner ließ sich nicht auflisten. ${PRUNING_ONLY}`];
        if (remaining.length !== 1) {
          return ["warn", `Nach dem Aufräumen liegen ${remaining.length} statt 1 Sicherung im Ordner – das Aufräumen versteht die Ordnerliste dieses Servers nicht und löscht nie etwas, ohne Hinweis. ${PRUNING_ONLY}`];
        }
        const copy = expectHttp(await session.request("GET", new URL(encodeURIComponent(remaining[0]!), backupFolder)), "GET");
        if (copy.status !== 200 || !sameBytes(copy.data, kept.data)) return ["fail", "Die übrige Sicherungskopie hat nicht den Inhalt der gesicherten Fassung."];
        return ["ok", "Sicherungsordner angelegt und wiederverwendet, zwei Fassungen gesichert, die ältere Sicherung aufgeräumt"];
      },
    },
    {
      id: "abort",
      title: "Abgebrochener Upload lässt die alte Fassung unverändert",
      blocking: false,
      run: async () => {
        if (!abortTest) return ["skip", "nicht ausgeführt (mit --abort-test einschalten)"];
        const outcome = await session.abortedUpload(file, state.etag);
        await sleep(1500); // dem Server Zeit geben, den halben Upload zu verwerfen
        const after = await readFile();
        const unchanged = sameBytes(after.data, state.content) && after.etag === state.etag;
        const partial = `${ABORT_SENT_BYTES / 1024} von angekündigten ${ABORT_UPLOAD_BYTES / 1024} KiB`;
        const damaged = "ein abgebrochener Upload kann die Tresor-Datei beschädigen!";
        if (outcome.kind === "answered" && outcome.status >= 200 && outcome.status < 300) {
          return ["fail", `Der Server hat den unvollständigen Upload (${partial}) mit HTTP ${outcome.status} angenommen – ${damaged}`];
        }
        if (!unchanged) return ["fail", `Upload nach ${partial} abgebrochen; danach hat die Datei einen anderen Inhalt oder ETag – ${damaged}`];
        if (outcome.kind === "aborted") return ["ok", `Upload nach ${partial} abgebrochen; Inhalt und ETag unverändert`];
        // Kam der abgebrochene Upload gar nicht beim Server an, ist nichts geprüft (Review probe-1/xc-2).
        if (outcome.kind === "answered") {
          return ["warn", `nicht geprüft: Der Server antwortete schon vor dem Abbruch (HTTP ${outcome.status}); ein abgebrochener Upload kam also nie bei ihm an. Inhalt und ETag sind unverändert.`];
        }
        return ["warn", `nicht geprüft: Die Verbindung scheiterte schon vor dem Abbruch (${outcome.reason}). Inhalt und ETag sind unverändert.`];
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

/** Namen der Dateien (ohne Ordner) direkt in `folderUrl` per PROPFIND (Depth 1); null, wenn keine Liste kommt. */
async function listFiles(session: ProbeSession, folderUrl: URL): Promise<string[] | null> {
  const response = expectHttp(await session.request("PROPFIND", folderUrl, { Depth: "1", "Content-Type": "application/xml; charset=utf-8" }, PROPFIND_BODY), "PROPFIND");
  if (response.status !== 207) return null;
  return parseMultistatus(text(response.data))
    .filter((resource) => !resource.isCollection)
    .map((resource) => decodeSegment(resource.href.split("/").pop() ?? ""))
    .filter((name) => name !== "");
}

/**
 * true, wenn `href` (aus einer PROPFIND-Antwort) die Datei `name` DIREKT in `folderUrl` ist – mit
 * derselben Regel wie WebDavAdapter beim Aufräumen: Pfad abschnittsweise dekodiert verglichen,
 * vom href zählt nur der Pfad.
 */
function isDirectChild(href: string, folderUrl: URL, name: string): boolean {
  let path: string;
  try {
    path = new URL(href, folderUrl).pathname;
  } catch {
    return false;
  }
  const slash = path.lastIndexOf("/");
  return decodePath(path.slice(0, slash + 1)) === decodePath(folderUrl.pathname) && decodeSegment(path.slice(slash + 1)) === name;
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function decodePath(path: string): string {
  return path.split("/").map(decodeSegment).join("/");
}

/** ETag aus einer PUT-Antwort (Nextcloud: "ETag" und "OC-ETag"). */
function putResponseEtag(response: ProbeResponse): string | null {
  return headerValue(response.headers, "ETag") ?? headerValue(response.headers, "OC-ETag");
}

/** Sekunde (Serverzeit) aus dem Date-Header einer Antwort. */
function serverSecond(response: ProbeResponse): number | undefined {
  const date = parseHttpDate(response.headers.get("Date"));
  return date === undefined ? undefined : Math.floor(date / 1000);
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
 * (z. B. über eine Pipe), wird die erste Zeile gelesen; die Frage erscheint trotzdem, in Git Bash
 * ohne Terminal mit einer Warnung, dass die Eingabe sichtbar ist (prompt.ts, Review cli-1).
 */
async function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    process.stderr.write(inputLikelyVisible(stdin.isTTY) ? `${VISIBLE_INPUT_WARNING}\n${question}` : question);
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

// Nur, wenn diese Datei direkt gestartet wurde (nicht importiert, z. B. aus einem Test); auch
// über einen Symlink (main-module.ts) – sonst endete der Test ohne Ausgabe mit Exit 0 = „sicher“.
if (isMainModule(import.meta.url)) {
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
