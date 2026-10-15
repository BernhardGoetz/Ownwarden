/**
 * Kritische Prüfung des WebDavAdapter (ohne echten Server, mit eingeschleustem fetch):
 * Jeder Test zielt auf einen konkreten Verdacht. Bestätigte Fehler bleiben hier als
 * Regressionstests stehen; widerlegte Verdachte, die zusätzliche Abdeckung bringen, ebenso.
 */
import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { StorageError } from "../contracts";
import { mergeVaults } from "../merge/merge";
import { newVault } from "../../test/helpers/vault-builder";
import { parseMultistatus } from "./multistatus";
import { syncVault } from "./sync";
import { createJsonCodec } from "./testing/json-codec";
import { WebDavAdapter, type WebDavAdapterOptions } from "./webdav";

const FILE_URL = "https://cloud.example/remote.php/webdav/Ownwarden/tresor.kdbx";
const FOLDER_PATH = "/remote.php/webdav/Ownwarden/ownwarden-backups/";
const PASSWORD = "Adversarial-Pässwort-42";
const FIXED_NOW = Date.UTC(2026, 9, 15, 17, 15, 0, 42);

interface RecordedRequest {
  method: string;
  url: string;
  headers: Headers;
  body: Uint8Array | string | undefined;
}

type Handler = (request: RecordedRequest) => Response | Promise<Response>;

function fakeAdapter(handler: Handler, overrides: Partial<WebDavAdapterOptions> = {}) {
  const requests: RecordedRequest[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const body = init.body;
    const request: RecordedRequest = {
      method: init.method ?? "GET",
      url: String(input),
      headers: new Headers(init.headers),
      body: typeof body === "string" || body instanceof Uint8Array ? body : undefined,
    };
    requests.push(request);
    return handler(request);
  }) as typeof fetch;
  const adapter = new WebDavAdapter({ fileUrl: FILE_URL, username: "jürgen", password: PASSWORD, fetch: fetchFn, now: () => FIXED_NOW, ...overrides });
  return { adapter, requests };
}

const bytes = (text: string) => new TextEncoder().encode(text);

function multistatus(...responses: string[]): Response {
  return new Response(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${responses.join("")}</d:multistatus>`, { status: 207 });
}

function fileResponse(href: string): string {
  return `<d:response><d:href>${href}</d:href><d:propstat><d:prop><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

describe("Verdacht: Aufräumen löscht die eben angelegte Sicherung (Geräteuhren weichen ab)", () => {
  // Gerät B (Uhr richtig) legt seine Sicherung an. Im Ordner liegt schon eine Sicherung von
  // Gerät A, dessen Uhr eine Minute vorgeht (innerhalb der erlaubten Abweichung). Nach Namen
  // sortiert gilt A's Sicherung als „neuer“. Mit keep = 1 darf trotzdem nicht die eben
  // angelegte Sicherung gelöscht werden – sonst schreibt syncVault ohne Sicherung der
  // Fassung, die es gleich überschreibt.
  const ownName = "tresor.20261015-171500-042.kdbx";
  const otherDeviceName = "tresor.20261015-171600-000.kdbx"; // Uhr von Gerät A: +60 s

  function server(): Handler {
    return (request) => {
      switch (request.method) {
        case "MKCOL":
          return new Response(null, { status: 405 });
        case "COPY":
          return new Response(null, { status: 201 });
        case "PROPFIND":
          return multistatus(fileResponse(`${FOLDER_PATH}${otherDeviceName}`), fileResponse(`${FOLDER_PATH}${ownName}`));
        case "DELETE":
          return new Response(null, { status: 204 });
        default:
          return new Response(null, { status: 500 });
      }
    };
  }

  it("keep = 1: die eigene, eben angelegte Sicherung bleibt erhalten", async () => {
    const { adapter, requests } = fakeAdapter(server());
    await adapter.backup({ data: bytes("alt"), etag: '"1"' }, 1);
    const copied = requests.find((request) => request.method === "COPY")!.headers.get("Destination");
    expect(copied).toBe(`https://cloud.example${FOLDER_PATH}${ownName}`);
    const deleted = requests.filter((request) => request.method === "DELETE").map((request) => request.url);
    expect(deleted).not.toContain(`https://cloud.example${FOLDER_PATH}${ownName}`);
    // Höchstens `keep` Sicherungen bleiben: die fremde wird gelöscht.
    expect(deleted).toEqual([`https://cloud.example${FOLDER_PATH}${otherDeviceName}`]);
  });

  it("keep = 2: beide bleiben (nichts zu löschen)", async () => {
    const { adapter, requests } = fakeAdapter(server());
    await adapter.backup({ data: bytes("alt"), etag: '"1"' }, 2);
    expect(requests.filter((request) => request.method === "DELETE")).toEqual([]);
  });
});

describe("Verdacht: Zugangsdaten lassen sich aus dem Adapter-Objekt auslesen (Logs)", () => {
  it("weder JSON.stringify noch util.inspect zeigen Passwort oder Authorization-Header", () => {
    const { adapter } = fakeAdapter(() => new Response());
    const basic = btoa(String.fromCharCode(...new TextEncoder().encode(`jürgen:${PASSWORD}`)));
    for (const text of [JSON.stringify(adapter), inspect(adapter, { depth: Infinity, showHidden: true }), String(adapter)]) {
      expect(text).not.toContain(PASSWORD);
      expect(text).not.toContain(basic);
    }
  });
});

describe("Verdacht: Adressprüfung lässt unsichere Adressen durch (widerlegt)", () => {
  const make = (fileUrl: string, extra: Partial<WebDavAdapterOptions> = {}) => () =>
    new WebDavAdapter({ fileUrl, username: "u", password: "p", ...extra });

  it.each([
    "http://localhost.evil.example/t.kdbx",
    "http://127.0.0.1.nip.io/t.kdbx",
    "http://localhost:80@evil.example/t.kdbx",
    "http://[::ffff:7f00:1]/t.kdbx",
    "http://10.0.0.1/t.kdbx",
    "ws://localhost/t.kdbx",
    "file:///etc/passwd",
    "javascript:alert(1)",
  ])("lehnt %s ab", (url) => {
    expect(make(url)).toThrow(TypeError);
  });

  it.each(["https://user@cloud.example/t.kdbx", "https://:pw@cloud.example/t.kdbx", "http://u:p@localhost/t.kdbx"])(
    "lehnt Zugangsdaten in %s ab",
    (url) => {
      expect(make(url)).toThrow(/Zugangsdaten/);
    },
  );

  it("lehnt Zugangsdaten auch in der Adresse des Sicherungsordners ab", () => {
    expect(make(FILE_URL, { backupFolderUrl: "https://u:p@cloud.example/b/" })).toThrow(/Zugangsdaten/);
  });

  it("Meldungen über ungültige Adressen enthalten die Adresse nicht (könnte ein Passwort tragen)", () => {
    try {
      make("https://bob:streng-geheim@cloud.example/t.kdbx")();
      throw new Error("kein Fehler");
    } catch (error) {
      expect(String(error)).not.toContain("streng-geheim");
    }
  });

  it("http:// auf den eigenen Rechner (auch in Kurzschreibweise) bleibt erlaubt", () => {
    expect(make("http://127.1:8080/t.kdbx")).not.toThrow();
    expect(make("http://LOCALHOST:8080/t.kdbx")).not.toThrow();
  });
});

describe("Verdacht: ETag wird verändert, bevor er im If-Match landet (widerlegt)", () => {
  it("ein ungewöhnlicher ETag (schwach, Komma, Leerzeichen) geht unverändert vom GET in If-Match und COPY-Ablauf", async () => {
    const etag = 'W/"a, b c"';
    const codec = createJsonCodec();
    const remote = newVault();
    const remoteBytes = await codec.encode(remote);
    const { adapter, requests } = fakeAdapter((request) => {
      switch (request.method) {
        case "GET":
          return new Response(new Uint8Array(remoteBytes), { headers: { ETag: etag, Date: new Date(FIXED_NOW).toUTCString() } });
        case "MKCOL":
          return new Response(null, { status: 405 });
        case "COPY":
          return new Response(null, { status: 201 });
        case "PROPFIND":
          return multistatus();
        case "PUT":
          return new Response(null, { status: 204, headers: { ETag: '"neu"' } });
        default:
          return new Response(null, { status: 500 });
      }
    });
    const local = structuredClone(remote);
    local.meta.databaseName = "geändert";

    const result = await syncVault(local, adapter, codec, { now: () => FIXED_NOW, merge: mergeVaults, maxAttempts: 1, maxClockSkewMs: 120_000, backupsToKeep: 3 });

    expect(result.written).toBe(true);
    const put = requests.find((request) => request.method === "PUT" && request.url === FILE_URL)!;
    expect(put.headers.get("If-Match")).toBe(etag);
    expect(put.headers.get("If-None-Match")).toBeNull();
    // Reihenfolge: Lesen, Sicherung (MKCOL, COPY, PROPFIND), erst dann Schreiben.
    expect(requests.map((request) => request.method)).toEqual(["GET", "MKCOL", "COPY", "PROPFIND", "PUT"]);
  });

  it("getetag aus PROPFIND: Entitäten aufgelöst, nur der XML-Einzug entfernt", () => {
    const xml = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/x</d:href><d:propstat><d:prop><d:getetag>
        &quot;ab cd&quot;
      </d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    expect(parseMultistatus(xml)[0]!.props.get("getetag")).toBe('"ab cd"');
  });
});

describe("Verdacht: feindliche PROPFIND-Antworten (DTD, Entitäten) werden verarbeitet (widerlegt)", () => {
  const body = '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/x</d:href></d:response></d:multistatus>';
  it.each([
    ["DOCTYPE klein geschrieben", `<!doctype d:multistatus>${body}`],
    ["DOCTYPE nach der XML-Deklaration", `<?xml version="1.0"?>\n<!DOCTYPE x SYSTEM "file:///etc/passwd">${body}`],
    ["Billion Laughs", `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "x"><!ENTITY b "&a;&a;&a;&a;">]>${body}`],
    ["ENTITY ohne DOCTYPE", `<!ENTITY a "x">${body}`],
    ["DOCTYPE in UTF-16", new TextDecoder().decode(new Uint8Array([0xff, 0xfe, ...[...`<!DOCTYPE x>${body}`].flatMap((c) => [c.charCodeAt(0), 0])]))],
  ])("%s -> Fehler", (_name, xml) => {
    expect(() => parseMultistatus(xml)).toThrow();
  });

  it("ein UTF-8-BOM vor gültigem XML stört nicht", () => {
    const text = new TextDecoder().decode(new Uint8Array([0xef, 0xbb, 0xbf, ...bytes(body)]));
    expect(parseMultistatus(text)).toHaveLength(1);
  });

  it("eine unbekannte Entität führt zu einem Fehler statt zu einem stillen Wert", () => {
    const xml = `<d:multistatus xmlns:d="DAV:"><d:response><d:href>/x</d:href><d:propstat><d:prop><d:getetag>&xxe;</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`;
    let etag: string | undefined;
    try {
      etag = parseMultistatus(xml)[0]!.props.get("getetag");
    } catch {
      return; // Fehler ist in Ordnung
    }
    // Ohne Fehler darf zumindest kein aufgelöster Fremdinhalt herauskommen.
    expect(etag === undefined || etag === "" || etag === "&xxe;").toBe(true);
  });
});

describe("Verdacht: Aufräumen löscht außerhalb des Sicherungsordners (widerlegt)", () => {
  it("prozentkodierte Punkt-Abschnitte, fremde Rechner, Unterordner und Ordner-Pfade werden nie gelöscht", async () => {
    const listing = [
      // %2e%2e = ".." -> zeigt auf den Ordner der Tresor-Datei
      fileResponse(`${FOLDER_PATH}%2e%2e/tresor.20000101-000000-000.kdbx`),
      fileResponse(`${FOLDER_PATH}%2E%2E/%2E%2E/tresor.20000101-000000-001.kdbx`),
      // Unterordner mit kodiertem "/"
      fileResponse(`${FOLDER_PATH}unter%2Ftresor.20000101-000000-002.kdbx`),
      // Ordner, der wie eine Sicherung heißt (href endet mit "/")
      fileResponse(`${FOLDER_PATH}tresor.20000101-000000-003.kdbx/`),
      // ganz andere Pfade
      fileResponse("/tresor.20000101-000000-004.kdbx"),
      fileResponse("//evil.example/tresor.20000101-000000-005.kdbx"),
    ];
    const { adapter, requests } = fakeAdapter((request) => {
      if (request.method === "PROPFIND") return multistatus(...listing);
      if (request.method === "MKCOL") return new Response(null, { status: 405 });
      return new Response(null, { status: request.method === "COPY" ? 201 : 204 });
    });
    await adapter.backup({ data: bytes("alt"), etag: '"1"' }, 1);
    expect(requests.filter((request) => request.method === "DELETE")).toEqual([]);
  });

  it("gelöscht wird immer auf dem eigenen Server, auch wenn der href einen anderen Rechner nennt", async () => {
    const { adapter, requests } = fakeAdapter((request) => {
      if (request.method === "PROPFIND") {
        return multistatus(
          fileResponse(`https://evil.example${FOLDER_PATH}tresor.20000101-000000-000.kdbx`),
          fileResponse(`http://evil.example${FOLDER_PATH}tresor.20000101-000000-001.kdbx`),
        );
      }
      if (request.method === "MKCOL") return new Response(null, { status: 405 });
      return new Response(null, { status: request.method === "COPY" ? 201 : 204 });
    });
    await adapter.backup({ data: bytes("alt"), etag: '"1"' }, 1);
    const deleted = requests.filter((request) => request.method === "DELETE").map((request) => new URL(request.url).origin);
    expect(deleted.length).toBeGreaterThan(0);
    expect(new Set(deleted)).toEqual(new Set(["https://cloud.example"]));
  });
});

describe("Verdacht: ein abgebrochener Upload gilt als geschrieben (widerlegt)", () => {
  it("bricht die Verbindung beim PUT ab, meldet write() einen Fehler statt eines Erfolgs", async () => {
    const { adapter } = fakeAdapter(() => {
      throw new TypeError("fetch failed", { cause: Object.assign(new Error("other side closed"), { code: "UND_ERR_SOCKET" }) });
    });
    const failure = adapter.write(bytes("neu"), { ifMatch: '"1"' });
    await expect(failure).rejects.toBeInstanceOf(StorageError);
    await expect(failure).rejects.toThrow(/UND_ERR_SOCKET/);
  });
});
