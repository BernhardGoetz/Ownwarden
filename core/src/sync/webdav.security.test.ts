/**
 * Regressionstests zum Sicherheitsaudit (WebDAV-Anbindung): Obergrenzen für Antworten (dos-1),
 * Mindestrate beim Herunterladen (dos-5), Anfragen nur an den eingetragenen Server (network-3)
 * und fremder Text in Meldungen (leak-1). Meist mit eingeschleustem fetch; wo es auf das echte
 * fetch ankommt (Entpacken, zweiter Rechner), mit kleinen Servern auf 127.0.0.1.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { brotliCompressSync, constants as zlibConstants, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { newVault } from "../../test/helpers/vault-builder";
import { StorageError } from "../contracts";
import { MAX_PAYLOAD_BYTES } from "../kdbx/constants";
import { mergeVaults } from "../merge/merge";
import { backupFileName } from "./backup-names";
import { parseStorageUrl } from "./http";
import { syncVault } from "./sync";
import { createJsonCodec } from "./testing/json-codec";
import {
  MAX_PROPFIND_BYTES,
  MAX_REQUEST_MS,
  MAX_VAULT_FILE_BYTES,
  MIN_DOWNLOAD_BYTES_PER_SECOND,
  MIN_UPLOAD_BYTES_PER_SECOND,
  WebDavAdapter,
  type WebDavAdapterOptions,
} from "./webdav";

const FILE_URL = "https://cloud.example/remote.php/webdav/Ownwarden/tresor.kdbx";
const FOLDER_PATH = "/remote.php/webdav/Ownwarden/ownwarden-backups/";
const PASSWORD = "Sicherheits-Pässwort-7";
const CURRENT = { data: new TextEncoder().encode("alt"), etag: '"1"' };

interface RecordedRequest {
  method: string;
  url: string;
  headers: Headers;
  init: RequestInit;
}

type Handler = (request: RecordedRequest) => Response | Promise<Response>;

function fakeAdapter(handler: Handler, overrides: Partial<WebDavAdapterOptions> = {}) {
  const requests: RecordedRequest[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const request: RecordedRequest = { method: init.method ?? "GET", url: String(input), headers: new Headers(init.headers), init };
    requests.push(request);
    return handler(request);
  }) as typeof fetch;
  const adapter = new WebDavAdapter({ fileUrl: FILE_URL, username: "jürgen", password: PASSWORD, fetch: fetchFn, ...overrides });
  return { adapter, requests };
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("Es wurde kein Fehler geworfen.");
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Antwort mit `chunks` Stücken zu je `size` Byte, alle `everyMs` ms eins; zählt, wie viele Stücke
 * gelesen wurden und ob der Leser abgebrochen hat. Bricht beim Abbruch der Anfrage ab.
 */
function streamedBody(init: RequestInit, options: { chunks: number; size: number; everyMs?: number; headers?: Record<string, string>; status?: number }) {
  const state = { pulled: 0, cancelled: false };
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      init.signal?.addEventListener("abort", () => controller.error(init.signal!.reason));
    },
    async pull(controller) {
      if (options.everyMs !== undefined) await sleep(options.everyMs);
      if (state.cancelled) return;
      if (state.pulled++ < options.chunks) controller.enqueue(new Uint8Array(options.size).fill(0x41));
      else controller.close();
    },
    cancel() {
      state.cancelled = true;
    },
  });
  const response = new Response(stream, { status: options.status ?? 200, headers: { ETag: '"e1"', ...options.headers } });
  return { response, state };
}

function multistatus(...responses: string[]): Response {
  return new Response(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${responses.join("")}</d:multistatus>`, { status: 207 });
}

function fileResponse(href: string): string {
  return `<d:response><d:href>${href}</d:href><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

/** Kleiner HTTP-Server auf 127.0.0.1 (Port vom System). */
async function listen(handler: (request: IncomingMessage, response: ServerResponse) => void) {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const close = () =>
    new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    });
  servers.push(close);
  return { port, url: `http://127.0.0.1:${port}` };
}
const servers: (() => Promise<void>)[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((close) => close()));
});

describe("Obergrenzen für Antworten (Sicherheitsaudit dos-1)", () => {
  it("Standard: Tresor-Datei höchstens MAX_PAYLOAD_BYTES + 1 MiB, PROPFIND-Antwort höchstens 4 MiB (Sicherheitsaudit dos-1)", () => {
    expect(MAX_VAULT_FILE_BYTES).toBe(MAX_PAYLOAD_BYTES + 1024 * 1024);
    expect(MAX_PROPFIND_BYTES).toBe(4 * 1024 * 1024);
  });

  it("GET ohne Content-Length: Abbruch, sobald mehr als die Obergrenze angekommen ist; der Rest wird nicht gelesen (Sicherheitsaudit dos-1)", async () => {
    let body: ReturnType<typeof streamedBody> | undefined;
    const { adapter } = fakeAdapter(
      (request) => {
        body = streamedBody(request.init, { chunks: 1000, size: 1000 });
        return body.response;
      },
      { maxFileBytes: 10_000 },
    );
    const error = await caught(adapter.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/größer als 10000 Byte/);
    expect(body!.state.cancelled).toBe(true);
    expect(body!.state.pulled).toBeLessThan(20);
  });

  it("Content-Length über der Obergrenze (auch der Standardgrenze): Abbruch, bevor der Körper gelesen wird (Sicherheitsaudit dos-1)", async () => {
    for (const [overrides, declared] of [
      [{}, MAX_VAULT_FILE_BYTES + 1],
      [{ maxFileBytes: 100 }, 101],
    ] as const) {
      let body: ReturnType<typeof streamedBody> | undefined;
      const { adapter } = fakeAdapter((request) => {
        body = streamedBody(request.init, { chunks: 3, size: 10, headers: { "Content-Length": String(declared) } });
        return body.response;
      }, overrides);
      const error = await caught(adapter.read());
      expect(error).toBeInstanceOf(StorageError);
      expect(String(error)).toMatch(/größer als/);
      expect(body!.state.cancelled).toBe(true);
    }
  });

  it("genau an der Obergrenze klappt das Lesen noch (Sicherheitsaudit dos-1)", async () => {
    const { adapter } = fakeAdapter((request) => streamedBody(request.init, { chunks: 10, size: 1000 }).response, { maxFileBytes: 10_000 });
    expect((await adapter.read())!.data).toHaveLength(10_000);
  });

  it("PROPFIND-Antwort über der Obergrenze: Aufräumen gibt nur einen Hinweis, Lesen ohne ETag scheitert (Sicherheitsaudit dos-1)", async () => {
    const listing = () => multistatus(...Array.from({ length: 100 }, (_, i) => fileResponse(`${FOLDER_PATH}tresor.20200101-000000-${String(i).padStart(3, "0")}.kdbx`)));
    const { adapter } = fakeAdapter(listing, { maxPropfindBytes: 4096 });
    const result = await adapter.pruneBackups(CURRENT, 1);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatch(/nicht aufgeräumt.*größer als 4 KiB/);

    const { adapter: reader } = fakeAdapter((request) => (request.method === "PROPFIND" ? listing() : new Response("inhalt")), { maxPropfindBytes: 4096 });
    expect(String(await caught(reader.read()))).toMatch(/größer als 4 KiB/);
  });

  it("Fehlerantworten werden nie gelesen, auch wenn ihr Körper nicht endet (Sicherheitsaudit dos-1)", async () => {
    let body: ReturnType<typeof streamedBody> | undefined;
    const { adapter } = fakeAdapter((request) => {
      body = streamedBody(request.init, { chunks: Number.MAX_SAFE_INTEGER, size: 1000, status: 500 });
      return body.response;
    });
    await expect(adapter.read()).rejects.toMatchObject({ status: 500 });
    expect(body!.state.cancelled).toBe(true);
  });

  it("echtes fetch: gezählt werden die entpackten Byte (gzip-Bombe beim GET) (Sicherheitsaudit dos-1)", async () => {
    const bomb = gzipSync(Buffer.alloc(8 * 1024 * 1024));
    const server = await listen((request, response) => {
      request.resume();
      response.writeHead(200, { "Content-Encoding": "gzip", "Content-Length": bomb.length, ETag: '"x"' });
      response.end(bomb);
    });
    expect(bomb.length).toBeLessThan(64 * 1024);
    const adapter = new WebDavAdapter({ fileUrl: `${server.url}/v/tresor.kdbx`, username: "u", password: "p", maxFileBytes: 1024 * 1024 });
    // caught statt rejects: Bei einem Fehlschlag soll vitest nicht 8 MiB Daten ausgeben.
    expect(String(await caught(adapter.read()))).toMatch(/größer als 1 MiB/);
  });

  it("echtes fetch: PROPFIND-Bombe (brotli) stößt an die Standardgrenze von 4 MiB (Sicherheitsaudit dos-1)", async () => {
    const xml = `<d:multistatus xmlns:d="DAV:">${fileResponse(`${FOLDER_PATH}x`).repeat(80_000)}</d:multistatus>`;
    const bomb = brotliCompressSync(Buffer.from(xml), { params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 5 } });
    expect(xml.length).toBeGreaterThan(MAX_PROPFIND_BYTES);
    const server = await listen((request, response) => {
      request.resume();
      response.writeHead(207, { "Content-Encoding": "br", "Content-Length": bomb.length, "Content-Type": "application/xml" });
      response.end(bomb);
    });
    const adapter = new WebDavAdapter({ fileUrl: `${server.url}/v/tresor.kdbx`, username: "u", password: "p" });
    const result = await adapter.pruneBackups(CURRENT, 1);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatch(/größer als 4 MiB/);
  });

  it("Obergrenzen und Mindestrate müssen positive Zahlen sein (Sicherheitsaudit dos-1, dos-5)", () => {
    for (const overrides of [{ maxFileBytes: 0 }, { maxPropfindBytes: -1 }, { minDownloadBytesPerSecond: Number.NaN }, { minDownloadBytesPerSecond: 0 }]) {
      expect(() => fakeAdapter(() => new Response(), overrides)).toThrow(RangeError);
    }
  });
});

describe("Mindestrate beim Herunterladen (Sicherheitsaudit dos-5)", () => {
  it("Standard wie beim Hochladen: 16 KiB/s (Sicherheitsaudit dos-5)", () => {
    expect(MIN_DOWNLOAD_BYTES_PER_SECOND).toBe(MIN_UPLOAD_BYTES_PER_SECOND);
  });

  it("ein Server, der kurz vor jedem Zeitlimit ein Byte schickt, hält den Download nicht beliebig lange offen (Sicherheitsaudit dos-5)", async () => {
    // Zeitlimit 200 ms, ein Byte alle 100 ms, 3 s lang: Ohne Gesamtgrenze käme read() nach 3 s durch.
    const { adapter } = fakeAdapter((request) => streamedBody(request.init, { chunks: 30, size: 1, everyMs: 100 }).response, {
      timeoutMs: 200,
      minDownloadBytesPerSecond: 1000,
    });
    const started = Date.now();
    const error = await caught(adapter.read());
    expect(Date.now() - started).toBeLessThan(1500);
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/Zeitüberschreitung.*im Schnitt langsamer als 1000 Byte\/s/);
  });

  it("ein Download über der Mindestrate darf länger dauern als das Zeitlimit (Sicherheitsaudit dos-5)", async () => {
    // 2000 Byte/s bei einer Mindestrate von 1000 Byte/s: 20 Stücke in etwa 1000 ms, Zeitlimit 300 ms.
    // Abstand zwischen den Stücken (50 ms) weit unter dem Zeitlimit, damit ein ausgelasteter
    // Rechner den Test nicht scheitern lässt.
    const { adapter } = fakeAdapter((request) => streamedBody(request.init, { chunks: 20, size: 100, everyMs: 50 }).response, {
      timeoutMs: 300,
      minDownloadBytesPerSecond: 1000,
    });
    const started = Date.now();
    expect((await adapter.read())!.data).toHaveLength(2000);
    expect(Date.now() - started).toBeGreaterThan(600);
  });

  it("echtes fetch: Tröpfeln über HTTP endet ebenfalls (Sicherheitsaudit dos-5)", async () => {
    const server = await listen((request, response) => {
      response.writeHead(200, { ETag: '"t"' }); // chunked, ohne Content-Length
      const started = Date.now();
      const timer = setInterval(() => (Date.now() - started > 3000 ? response.end() : response.write("x")), 80);
      response.on("close", () => clearInterval(timer));
    });
    const adapter = new WebDavAdapter({ fileUrl: `${server.url}/v/tresor.kdbx`, username: "u", password: "p", timeoutMs: 150, minDownloadBytesPerSecond: 1000 });
    const started = Date.now();
    expect(String(await caught(adapter.read()))).toMatch(/langsamer als/);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("eine vorgestellte oder zurückgestellte Geräteuhr verlängert die Frist nicht (Sicherheitsaudit dos-5, Nachprüfung)", async () => {
    // Wie oben (Zeitlimit 200 ms, ein Byte alle 100 ms), aber die Uhr springt bei jedem Ablesen
    // eine Stunde zurück. Mit Date.now() wüchse die Gesamtfrist dadurch immer weiter.
    let clock = Date.now();
    const realNow = Date.now;
    Date.now = () => (clock -= 3_600_000);
    try {
      const { adapter } = fakeAdapter((request) => streamedBody(request.init, { chunks: 30, size: 1, everyMs: 100 }).response, {
        timeoutMs: 200,
        minDownloadBytesPerSecond: 1000,
      });
      const started = performance.now();
      const error = await caught(adapter.read());
      expect(performance.now() - started).toBeLessThan(1500);
      expect(String(error)).toMatch(/im Schnitt langsamer als 1000 Byte\/s/);
    } finally {
      Date.now = realNow;
    }
  });
});

/** Antwort nach `ms` Millisekunden; bricht wie fetch ab, wenn die Anfrage abgebrochen wird. */
function delayed(init: RequestInit, ms: number, respond: () => Response): Promise<Response> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(respond()), ms);
    init.signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(init.signal!.reason);
    });
  });
}

describe("Obergrenze je Anfrage (Sicherheitsaudit dos-5, Nachprüfung)", () => {
  it("Standard: 30 Minuten; muss eine positive Zahl sein (Sicherheitsaudit dos-5)", () => {
    expect(MAX_REQUEST_MS).toBe(30 * 60 * 1000);
    for (const maxRequestMs of [0, -1, Number.NaN]) {
      expect(() => fakeAdapter(() => new Response(), { maxRequestMs })).toThrow(RangeError);
    }
  });

  it("auch ein Download über der Mindestrate endet nach maxRequestMs (Sicherheitsaudit dos-5)", async () => {
    // 5000 Byte/s, Mindestrate 1 Byte/s, kein Stillstand: Ohne Obergrenze käme read() nach 2 s durch.
    let body: ReturnType<typeof streamedBody> | undefined;
    const { adapter } = fakeAdapter(
      (request) => {
        body = streamedBody(request.init, { chunks: 100, size: 100, everyMs: 20 });
        return body.response;
      },
      { timeoutMs: 1000, minDownloadBytesPerSecond: 1, maxRequestMs: 300 },
    );
    const started = performance.now();
    const error = await caught(adapter.read());
    expect(performance.now() - started).toBeLessThan(1500);
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/Zeitüberschreitung: Die Übertragung dauerte länger als die Obergrenze von 1 s je Anfrage/);
    expect(body!.state.pulled).toBeLessThan(60);
  });

  it("auch das Warten auf die Antwort endet nach maxRequestMs (Sicherheitsaudit dos-5)", async () => {
    const { adapter } = fakeAdapter((request) => delayed(request.init, 3000, () => new Response("spät")), {
      timeoutMs: 2500,
      maxRequestMs: 200,
    });
    const started = performance.now();
    const error = await caught(adapter.read());
    expect(performance.now() - started).toBeLessThan(1500);
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/GET .*Zeitüberschreitung: Die Übertragung dauerte länger als die Obergrenze von 1 s je Anfrage/);
  });

  it("Lesen ohne ETag (PROPFIND, GET, PROPFIND, bis zu dreimal) hat insgesamt höchstens maxRequestMs (Sicherheitsaudit dos-5)", async () => {
    // Jede PROPFIND-Antwort braucht 250 ms und nennt einen neuen ETag: Ohne Gesamtgrenze liefe
    // das Lesen dreimal durch (über 1,5 s) und endete erst dann.
    let etag = 0;
    const propfind = () =>
      multistatus(
        `<d:response><d:href>/remote.php/webdav/Ownwarden/tresor.kdbx</d:href><d:propstat><d:prop><d:getetag>"${++etag}"</d:getetag><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`,
      );
    const { adapter, requests } = fakeAdapter(
      (request) => (request.method === "PROPFIND" ? delayed(request.init, 250, propfind) : new Response("inhalt")),
      { timeoutMs: 2000, maxRequestMs: 600 },
    );
    const started = performance.now();
    const error = await caught(adapter.read());
    expect(performance.now() - started).toBeLessThan(1200);
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/PROPFIND .*Zeitüberschreitung/);
    expect(requests.filter((request) => request.method === "PROPFIND").length).toBeLessThan(4);
  });
});

describe("Lesen mit bekannter Länge (Sicherheitsaudit dos-1, Nachprüfung)", () => {
  // Bei passendem Content-Length wird das Ergebnis einmal reserviert und gefüllt (halber
  // Spitzenbedarf). Die Angabe stammt vom Server und kann falsch sein.
  const content = (length: number) => Uint8Array.from({ length }, (_, i) => i & 0xff);
  function chunkedBody(data: Uint8Array, declared: number): Response {
    let offset = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset >= data.length) return controller.close();
        controller.enqueue(data.slice(offset, offset + 700));
        offset += 700;
      },
    });
    return new Response(stream, { headers: { ETag: '"e"', "Content-Length": String(declared) } });
  }

  it("Content-Length stimmt: Inhalt unverändert (Sicherheitsaudit dos-1)", async () => {
    const data = content(5000);
    const { adapter } = fakeAdapter(() => chunkedBody(data, 5000), { maxFileBytes: 5000 });
    const read = (await adapter.read())!.data;
    expect(read).toEqual(data);
    expect(read.buffer.byteLength).toBe(5000);
  });

  it("Content-Length zu klein: alles wird gelesen, die Obergrenze gilt weiter für die tatsächlichen Byte (Sicherheitsaudit dos-1)", async () => {
    const data = content(5000);
    const { adapter } = fakeAdapter(() => chunkedBody(data, 1000));
    expect((await adapter.read())!.data).toEqual(data);
    const { adapter: limited } = fakeAdapter(() => chunkedBody(data, 1000), { maxFileBytes: 4000 });
    expect(String(await caught(limited.read()))).toMatch(/größer als 4000 Byte/);
  });

  it("Content-Length zu groß: nur die gelesenen Byte, ohne den Rest des Puffers (Sicherheitsaudit dos-1)", async () => {
    const data = content(3000);
    const { adapter } = fakeAdapter(() => chunkedBody(data, 9000));
    const read = (await adapter.read())!.data;
    expect(read).toEqual(data);
    expect(read.buffer.byteLength).toBe(3000);
  });
});

describe("Anfragen nur an den eingetragenen Server (Sicherheitsaudit network-3)", () => {
  it.each([
    "https://cloud.example//remote.php/webdav/tresor.kdbx",
    "http://localhost//evil.example/x/tresor.kdbx",
    "https://cloud.example/dav//tresor.kdbx",
    "https://cloud.example/dav//",
    "https://cloud.example/%2Fevil.example/x/tresor.kdbx",
    "https://cloud.example/dav/a%2fb.kdbx",
    "https://cloud.example/dav/a%5Cb.kdbx",
    "https://cloud.example/dav/a%5cb/",
    "https://cloud.example/dav\\tresor.kdbx",
    "https://cloud.example/dav/../tresor.kdbx",
    "https://cloud.example/dav/./tresor.kdbx",
    "https://cloud.example/dav/%2e%2E/tresor.kdbx",
    "https://cloud.example/dav/.%2e/tresor.kdbx",
    "https://cloud.example/dav/..",
    "https://cloud.example/dav/.",
  ])("parseStorageUrl lehnt %s ab (Sicherheitsaudit network-3)", (raw) => {
    expect(() => parseStorageUrl(raw, "Adresse")).toThrow(TypeError);
    expect(() => new WebDavAdapter({ fileUrl: FILE_URL, username: "u", password: "p", backupFolderUrl: raw })).toThrow(TypeError);
  });

  it.each([
    "https://cloud.example",
    "https://cloud.example/",
    "https://cloud.example/dav/",
    "https://cloud.example/dav/.config/tresor.kdbx",
    "https://cloud.example/dav/tresor..kdbx",
    "https://cloud.example/dav/.../tresor.kdbx",
    "https://cloud.example/dav/Mein Tresor (neu).kdbx",
    "https://cloud.example/dav/a%20b/tresor.kdbx",
  ])("parseStorageUrl erlaubt %s (Sicherheitsaudit network-3)", (raw) => {
    expect(() => parseStorageUrl(raw, "Adresse")).not.toThrow();
  });

  it("die Meldung nennt die abgelehnte Adresse nicht (Sicherheitsaudit network-3)", () => {
    const error = caughtSync(() => parseStorageUrl("https://cloud.example//geheimer-ordner.example/tresor.kdbx", "Adresse der Tresor-Datei"));
    expect(String(error)).toMatch(/^TypeError: Adresse der Tresor-Datei: /);
    expect(String(error)).not.toContain("geheimer-ordner");
  });

  // Die öffentlichen Methoden bilden keine fremden Adressen mehr; die letzte Sperre in send() wird
  // deshalb direkt aufgerufen (private Methode, zur Laufzeit erreichbar).
  it("send() schickt nichts an einen anderen Server, auch kein COPY mit fremdem Ziel (Sicherheitsaudit network-3)", async () => {
    const { adapter, requests } = fakeAdapter(() => new Response(null, { status: 204 }));
    const send = (adapter as unknown as { send(method: string, url: URL, headers?: Record<string, string>): Promise<Response> }).send.bind(adapter);
    for (const target of ["https://evil.example/remote.php/webdav/Ownwarden/tresor.kdbx", "http://cloud.example/x.kdbx", "https://cloud.example:8443/x.kdbx"]) {
      const error = await caught(send("DELETE", new URL(target)));
      expect(error).toBeInstanceOf(StorageError);
      expect(String(error)).not.toContain("evil.example");
    }
    for (const destination of ["https://evil.example/remote.php/webdav/Ownwarden/ownwarden-backups/x.kdbx", "//evil.example/x.kdbx", "kein url"]) {
      await expect(send("COPY", new URL(FILE_URL), { Destination: destination })).rejects.toBeInstanceOf(StorageError);
    }
    expect(requests).toEqual([]);
  });

  // Szenario des Prüfers (round3/net3-e2e): Server A unter 127.0.0.1:A, „anderer Rechner“ B unter
  // 127.0.0.1:B. Eingetragen ist http://127.0.0.1:A//127.0.0.1:B/v/tresor.kdbx (bzw. /%2F…). Früher
  // gingen die DELETEs des Aufräumens samt Authorization an B.
  it("zwei Server auf 127.0.0.1: der zweite bekommt nie eine Anfrage (Sicherheitsaudit network-3)", async () => {
    const seenB: string[] = [];
    const b = await listen((request, response) => {
      seenB.push(`${request.method} ${request.url} ${request.headers.authorization ?? "-"}`);
      request.resume();
      response.writeHead(204);
      response.end();
    });
    const codec = createJsonCodec();
    const remote = newVault();
    const remoteBytes = await codec.encode(remote);
    let hrefMode: "echo" | "relative" | "foreign" = "echo";
    const seenA: string[] = [];
    const a = await listen((request, response) => {
      seenA.push(`${request.method} ${request.url}`);
      request.resume();
      const headers = { Date: new Date().toUTCString() };
      switch (request.method) {
        case "GET":
          response.writeHead(200, { ...headers, ETag: '"e1"' });
          return response.end(Buffer.from(remoteBytes));
        case "PROPFIND": {
          const names = [backupFileName("tresor.kdbx", Date.UTC(2026, 9, 1), '"e1"')];
          for (let i = 0; i < 3; i++) names.push(backupFileName("tresor.kdbx", Date.UTC(2020, 0, 1) + i * 1000, `"alt${i}"`));
          const href = (name: string) =>
            hrefMode === "echo" ? `${a.url}${request.url}${name}` : hrefMode === "relative" ? name : `${b.url}${request.url}${name}`;
          response.writeHead(207, { ...headers, "Content-Type": "application/xml" });
          return response.end(`<d:multistatus xmlns:d="DAV:">${names.map((name) => fileResponse(href(name))).join("")}</d:multistatus>`);
        }
        case "PUT":
          response.writeHead(204, { ...headers, ETag: '"e2"' });
          return response.end();
        default:
          response.writeHead(request.method === "MKCOL" ? 405 : request.method === "COPY" ? 201 : 204, headers);
          return response.end();
      }
    });

    const sync = async (fileUrl: string) => {
      let adapter: WebDavAdapter;
      try {
        adapter = new WebDavAdapter({ fileUrl, username: "u", password: "geheim" });
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        return;
      }
      const local = structuredClone(remote);
      local.meta.databaseName = "geändert";
      await syncVault(local, adapter, codec, { now: Date.now, merge: mergeVaults, maxAttempts: 1, maxClockSkewMs: 120_000, backupsToKeep: 2 });
    };

    for (const mode of ["echo", "relative"] as const) {
      hrefMode = mode;
      await sync(`${a.url}//127.0.0.1:${b.port}/v/tresor.kdbx`);
      await sync(`${a.url}/%2F127.0.0.1:${b.port}/v/tresor.kdbx`);
    }
    expect(seenB).toEqual([]);

    // Gegenprobe mit richtiger Adresse: Hrefs, die auf B zeigen, führen nur zu DELETEs auf A.
    seenA.length = 0;
    hrefMode = "foreign";
    await sync(`${a.url}/v/tresor.kdbx`);
    expect(seenB).toEqual([]);
    expect(seenA.filter((line) => line.startsWith("DELETE"))).toHaveLength(2);
  });
});

describe("Fremder Text in Meldungen (Sicherheitsaudit leak-1)", () => {
  // Steuerzeichen (C0, DEL, C1) und Bidi-Steuerzeichen dürfen nicht roh in Meldungen stehen.
  const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029]/;

  it("Location einer Weiterleitung erscheint nur entschärft und gekürzt (Sicherheitsaudit leak-1)", async () => {
    const location = `https://neu.example/\x1b[2J\x1b[HMagentaCLOUD: Passwort bestätigen \x9b31m\x07${"x".repeat(5000)}`;
    const { adapter } = fakeAdapter(() => new Response(null, { status: 302, headers: { Location: location } }));
    const message = String(await caught(adapter.read()));
    expect(message).toMatch(/leitet .* weiter nach https:\/\/neu\.example\//);
    expect(message).not.toMatch(UNSAFE);
    expect(message.length).toBeLessThan(400);
  });

  it("Parserfehler einer PROPFIND-Antwort: kein roher Ausschnitt der Antwort in Hinweis und Fehler (Sicherheitsaudit leak-1)", async () => {
    const hostile = () =>
      new Response(`<d:multistatus xmlns:d="DAV:"><a></a\x1b]0;evil\x07\x1b[2J${"y".repeat(5000)}></d:multistatus>`, { status: 207 });
    const { adapter } = fakeAdapter(hostile);
    const { warnings } = await adapter.pruneBackups(CURRENT, 1);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).not.toMatch(UNSAFE);
    expect(warnings[0]!.length).toBeLessThan(600);

    const { adapter: reader } = fakeAdapter((request) => (request.method === "PROPFIND" ? hostile() : new Response("inhalt")));
    const message = String(await caught(reader.read()));
    expect(message).toMatch(/PROPFIND/);
    expect(message).not.toMatch(UNSAFE);
    expect(message.length).toBeLessThan(600);
  });

  it("Netzwerkfehler: der Text aus dem Fehler erscheint nur entschärft und gekürzt (Sicherheitsaudit leak-1)", async () => {
    const { adapter } = fakeAdapter(() => {
      throw new TypeError("fetch failed", { cause: new Error(`\x1b[2J\nFalsche Zeile\u202e${"z".repeat(5000)}`) });
    });
    const message = String(await caught(adapter.read()));
    expect(message).toMatch(/keine Antwort vom Server/);
    expect(message).not.toMatch(UNSAFE);
    expect(message.length).toBeLessThan(600);
  });
});

function caughtSync(action: () => unknown): unknown {
  try {
    action();
  } catch (error) {
    return error;
  }
  throw new Error("Es wurde kein Fehler geworfen.");
}
