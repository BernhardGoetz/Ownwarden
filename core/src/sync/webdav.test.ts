/**
 * WebDavAdapter mit einer eingeschleusten fetch-Funktion (ohne Server): Adressprüfung,
 * Anmeldung, Fehlerbehandlung, ETag-Ausweg über PROPFIND, Sicherungskopien und Aufräumen.
 * Das Zusammenspiel mit einem echten Server prüft webdav.server.test.ts.
 */
import { describe, expect, it } from "vitest";
import { PreconditionFailedError, StorageAuthError, StorageError } from "../contracts";
import { backupVersionTag } from "./backup-names";
import { DEFAULT_WEBDAV_TIMEOUT_MS, MIN_UPLOAD_BYTES_PER_SECOND, WebDavAdapter, type WebDavAdapterOptions } from "./webdav";

const FILE_URL = "https://cloud.example/remote.php/webdav/Ownwarden/tresor.kdbx";
const PASSWORD = "Test-Pässwort-123";
const FIXED_NOW = Date.UTC(2026, 9, 15, 17, 15, 0, 42);

interface RecordedRequest {
  method: string;
  url: string;
  headers: Headers;
  body: string | Uint8Array | undefined;
  init: RequestInit;
}

type Handler = (request: RecordedRequest) => Response | Promise<Response>;

/** fetch-Ersatz: zeichnet Anfragen auf und beantwortet sie mit `handler`. */
function fakeFetch(handler: Handler) {
  const requests: RecordedRequest[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const body = init.body;
    const request: RecordedRequest = {
      method: init.method ?? "GET",
      url: String(input),
      headers: new Headers(init.headers),
      body: typeof body === "string" ? body : body instanceof Uint8Array ? body : undefined,
      init,
    };
    requests.push(request);
    return handler(request);
  }) as typeof fetch;
  return { fetchFn, requests };
}

function adapter(handler: Handler, overrides: Partial<WebDavAdapterOptions> = {}) {
  const fake = fakeFetch(handler);
  const instance = new WebDavAdapter({ fileUrl: FILE_URL, username: "jürgen", password: PASSWORD, fetch: fake.fetchFn, now: () => FIXED_NOW, ...overrides });
  return { adapter: instance, requests: fake.requests };
}

const bytes = (text: string) => new TextEncoder().encode(text);

function multistatus(...responses: string[]): Response {
  return new Response(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${responses.join("")}</d:multistatus>`, {
    status: 207,
    headers: { "Content-Type": "application/xml" },
  });
}

function davResponse(href: string, props: string): string {
  return `<d:response><d:href>${href}</d:href><d:propstat><d:prop>${props}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`;
}

/** Prüft, dass ein Fehler weder Passwort noch Authorization-Header enthält. */
function expectNoSecrets(error: unknown): void {
  const text = `${String(error)} ${(error as Error).stack ?? ""} ${JSON.stringify(error)}`;
  expect(text).not.toContain(PASSWORD);
  expect(text).not.toContain(btoa(String.fromCharCode(...new TextEncoder().encode(`jürgen:${PASSWORD}`))));
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("Es wurde kein Fehler geworfen.");
}

describe("WebDavAdapter: Adressen", () => {
  const make = (fileUrl: string, extra: Partial<WebDavAdapterOptions> = {}) => () =>
    new WebDavAdapter({ fileUrl, username: "u", password: "p", ...extra });

  it("erlaubt https:// und http:// nur für den eigenen Rechner", () => {
    expect(make("https://cloud.example/dav/t.kdbx")).not.toThrow();
    expect(make("http://localhost:8080/t.kdbx")).not.toThrow();
    expect(make("http://127.0.0.1:8080/t.kdbx")).not.toThrow();
    expect(make("http://[::1]:8080/t.kdbx")).not.toThrow();
    expect(make("http://cloud.example/dav/t.kdbx")).toThrow(/nur https/);
    expect(make("http://192.168.1.10/dav/t.kdbx")).toThrow(/nur https/);
    expect(make("ftp://cloud.example/t.kdbx")).toThrow(/nur https/);
  });

  it("lehnt Zugangsdaten in der Adresse, Ordner-Adressen, ? und # ab", () => {
    expect(make("https://u:p@cloud.example/t.kdbx")).toThrow(/Zugangsdaten/);
    expect(make("https://cloud.example/dav/")).toThrow(/Ordner/);
    expect(make("https://cloud.example/t.kdbx?x=1")).toThrow(/"\?"/);
    expect(make("https://cloud.example/t.kdbx#a")).toThrow(/"#"/);
    expect(make("kein url")).toThrow(/keine gültige Adresse/);
  });

  it("Sicherungsordner: Standard neben der Datei, eigener nur auf demselben Server", async () => {
    const { adapter: a, requests } = adapter(() => new Response(null, { status: 201 }), {
      backupFolderUrl: "https://cloud.example/remote.php/webdav/Sicherung",
    });
    // PROPFIND bekommt hier 201 statt 207: Die Kopie wird trotzdem angelegt; Aufräumen scheitert,
    // das ist seit 2026-10-16 nur ein Hinweis.
    const current = { data: bytes("x"), etag: '"1"' };
    expect((await a.backup(current)).warnings).toEqual([]);
    expect(requests.map((r) => r.method)).toContain("COPY");
    expect((await a.pruneBackups(current, 1)).warnings).toHaveLength(1);
    expect(requests[0]!.url).toBe("https://cloud.example/remote.php/webdav/Sicherung/");
    expect(make("https://cloud.example/t.kdbx", { backupFolderUrl: "https://other.example/b/" })).toThrow(/demselben Server/);
    expect(make("https://cloud.example/t.kdbx", { backupFolderUrl: "http://cloud.example/b/" })).toThrow(/nur https/);
  });

  it("describe() nennt die Adresse ohne Zugangsdaten", () => {
    const { adapter: a } = adapter(() => new Response());
    expect(a.describe()).toBe(`WebDAV ${FILE_URL}`);
  });
});

describe("WebDavAdapter: Anfragen und Fehler", () => {
  it("meldet sich per Basic-Auth mit UTF-8 an und setzt sichere fetch-Optionen", async () => {
    const { adapter: a, requests } = adapter(() => new Response(bytes("daten"), { headers: { ETag: '"e1"' } }));
    await a.read();
    const expected = `Basic ${Buffer.from(`jürgen:${PASSWORD}`, "utf8").toString("base64")}`;
    expect(requests[0]!.headers.get("Authorization")).toBe(expected);
    expect(requests[0]!.init).toMatchObject({ cache: "no-store", credentials: "omit", redirect: "manual" });
    expect(requests[0]!.init.signal).toBeInstanceOf(AbortSignal);
  });

  it("lehnt ':' im Benutzernamen ab (bei Basic-Auth nicht darstellbar)", () => {
    expect(() => new WebDavAdapter({ fileUrl: FILE_URL, username: "a:b", password: "p" })).toThrow(/":"/);
  });

  it("read: ETag unverändert (auch schwach), Date-Header als serverDate, 404 -> null", async () => {
    const { adapter: a } = adapter(() =>
      new Response(bytes("inhalt"), { headers: { ETag: 'W/"abc-123"', Date: "Thu, 15 Oct 2026 17:25:06 GMT" } }),
    );
    const file = await a.read();
    expect(file).toEqual({ data: bytes("inhalt"), etag: 'W/"abc-123"', serverDate: Date.UTC(2026, 9, 15, 17, 25, 6) });
    const { adapter: missing } = adapter(() => new Response("nicht da", { status: 404 }));
    expect(await missing.read()).toBeNull();
  });

  it("401/403 -> StorageAuthError, andere Codes -> StorageError mit Status; nie mit Passwort", async () => {
    for (const status of [401, 403]) {
      const { adapter: a } = adapter(() => new Response("nein", { status }));
      const error = await caught(a.read());
      expect(error).toBeInstanceOf(StorageAuthError);
      expectNoSecrets(error);
    }
    const { adapter: broken } = adapter(() => new Response("kaputt", { status: 500 }));
    const error = await caught(broken.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(error).toMatchObject({ status: 500 });
    expectNoSecrets(error);
  });

  it("Netzwerkfehler -> StorageError; Geheimnisse werden aus der Meldung entfernt", async () => {
    const { adapter: a } = adapter((request) => {
      throw new TypeError(`fetch failed (${request.headers.get("Authorization")} / ${PASSWORD})`);
    });
    const error = await caught(a.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/keine Antwort/);
    expectNoSecrets(error);
  });

  it("Zeitüberschreitung -> StorageError", async () => {
    const { adapter: a } = adapter(
      (request) =>
        new Promise<Response>((_resolve, reject) => {
          request.init.signal!.addEventListener("abort", () => reject(request.init.signal!.reason));
        }),
      { timeoutMs: 30 },
    );
    const error = await caught(a.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/Zeitüberschreitung/);
  });

  it("folgt keiner Weiterleitung, sondern meldet sie", async () => {
    const { adapter: a } = adapter(() => new Response(null, { status: 301, headers: { Location: "https://neu.example/t.kdbx" } }));
    const error = await caught(a.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/leitet .* weiter nach https:\/\/neu\.example\/t\.kdbx/);
  });

  it("write: If-Match bzw. If-None-Match, Content-Type, ETag aus ETag oder OC-ETag", async () => {
    const answers = [
      new Response(null, { status: 204, headers: { ETag: '"neu"', Date: "Thu, 15 Oct 2026 17:25:06 GMT" } }),
      new Response(null, { status: 201, headers: { "OC-ETag": '"oc"' } }),
      new Response(null, { status: 204 }),
    ];
    const { adapter: a, requests } = adapter(() => answers.shift()!);
    expect(await a.write(bytes("v2"), { ifMatch: '"alt"' })).toEqual({ etag: '"neu"', serverDate: Date.UTC(2026, 9, 15, 17, 25, 6) });
    expect(await a.write(bytes("v1"), { ifNoneMatch: "*" })).toEqual({ etag: '"oc"' });
    expect(await a.write(bytes("v3"), { ifMatch: '"x"' })).toEqual({ etag: null });
    expect(requests[0]!.method).toBe("PUT");
    expect(requests[0]!.headers.get("If-Match")).toBe('"alt"');
    expect(requests[0]!.headers.get("If-None-Match")).toBeNull();
    expect(requests[0]!.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(requests[0]!.body).toEqual(bytes("v2"));
    expect(requests[1]!.headers.get("If-None-Match")).toBe("*");
    expect(requests[1]!.headers.get("If-Match")).toBeNull();
  });

  it("write: 412 -> PreconditionFailedError; leerer If-Match wird gar nicht erst gesendet", async () => {
    const { adapter: a, requests } = adapter(() => new Response(null, { status: 412 }));
    await expect(a.write(bytes("x"), { ifMatch: '"alt"' })).rejects.toBeInstanceOf(PreconditionFailedError);
    await expect(a.write(bytes("x"), { ifMatch: "" })).rejects.toBeInstanceOf(TypeError);
    expect(requests).toHaveLength(1);
  });

  it("write: 409 (Ordner fehlt) mit Erklärung", async () => {
    const { adapter: a } = adapter(() => new Response(null, { status: 409 }));
    await expect(a.write(bytes("x"), { ifNoneMatch: "*" })).rejects.toThrow(/übergeordnete Ordner/);
  });
});

describe("WebDavAdapter: ETag über PROPFIND, wenn GET keinen nennt", () => {
  it("nimmt getetag, wenn er vor und nach dem Lesen gleich ist", async () => {
    const { adapter: a, requests } = adapter((request) => {
      if (request.method === "PROPFIND") return multistatus(davResponse("/remote.php/webdav/Ownwarden/tresor.kdbx", '<d:getetag>"p1"</d:getetag>'));
      return new Response(bytes("inhalt"));
    });
    const file = await a.read();
    expect(file).toMatchObject({ data: bytes("inhalt"), etag: '"p1"' });
    expect(requests.map((r) => r.method)).toEqual(["GET", "PROPFIND", "GET", "PROPFIND"]);
    expect(requests[1]!.headers.get("Depth")).toBe("0");
    expect(requests[2]!.headers.get("If-Match")).toBe('"p1"');
  });

  it("liest erneut, wenn die Datei zwischendurch geändert wurde", async () => {
    const etags = ['"p1"', '"p2"', '"p2"', '"p2"'];
    const { adapter: a } = adapter((request) => {
      if (request.method === "PROPFIND") return multistatus(davResponse("/x", `<d:getetag>${etags.shift()}</d:getetag>`));
      return new Response(bytes("inhalt"));
    });
    expect((await a.read())!.etag).toBe('"p2"');
  });

  it('etag "" wenn der Server gar keinen ETag kennt', async () => {
    const { adapter: a } = adapter((request) => {
      if (request.method === "PROPFIND") return multistatus(davResponse("/x", "<d:resourcetype/>"));
      return new Response(bytes("inhalt"));
    });
    expect(await a.read()).toMatchObject({ data: bytes("inhalt"), etag: "" });
  });

  it("gibt auf, wenn sich die Datei ständig ändert", async () => {
    let counter = 0;
    const { adapter: a } = adapter((request) => {
      if (request.method === "PROPFIND") return multistatus(davResponse("/x", `<d:getetag>"e${counter++}"</d:getetag>`));
      return new Response(bytes("inhalt"));
    });
    await expect(a.read()).rejects.toThrow(/mehrfach geändert/);
  });
});

describe("WebDavAdapter: Sicherungskopien", () => {
  const backupFolder = "https://cloud.example/remote.php/webdav/Ownwarden/ownwarden-backups/";
  const folderPath = "/remote.php/webdav/Ownwarden/ownwarden-backups/";
  /** Kennung der Fassung '"1"' im Namen (Review xc-1). */
  const tag = backupVersionTag('"1"');
  const expectedName = `tresor.20261015-171500-042.${tag}.kdbx`;
  const current = { data: bytes("alt"), etag: '"1"' };

  /** Ein kleiner Server: MKCOL, COPY/PUT und PROPFIND/DELETE nach Drehbuch. */
  function backupServer(options: { copyStatus?: number; listing?: string[]; mkcolStatus?: number } = {}) {
    return (request: RecordedRequest): Response => {
      switch (request.method) {
        case "MKCOL":
          return new Response(null, { status: options.mkcolStatus ?? 405 });
        case "COPY":
          return new Response(null, { status: options.copyStatus ?? 201 });
        case "PUT":
          return new Response(null, { status: 201 });
        case "PROPFIND":
          return multistatus(...(options.listing ?? []));
        case "DELETE":
          return new Response(null, { status: 204 });
        default:
          return new Response(null, { status: 500 });
      }
    };
  }

  // Seit Review xc-1 prüft backup() vorher per PROPFIND, ob die Fassung schon gesichert ist, und
  // räumt NICHT mehr auf (das macht pruneBackups nach erfolgreichem Schreiben).
  it("COPY mit absolutem Ziel und Overwrite: F, Name mit UTC-Zeit und Kennung der Fassung; kein Aufräumen", async () => {
    const { adapter: a, requests } = adapter(backupServer());
    expect(await a.backup(current)).toEqual({ warnings: [] });
    expect(requests.map((r) => r.method)).toEqual(["MKCOL", "PROPFIND", "COPY"]);
    expect(requests[0]!.url).toBe(backupFolder);
    expect(requests[1]!.url).toBe(backupFolder);
    expect(requests[1]!.headers.get("Depth")).toBe("1");
    expect(requests[2]!.url).toBe(FILE_URL);
    expect(requests[2]!.headers.get("Destination")).toBe(backupFolder + expectedName);
    expect(requests[2]!.headers.get("Overwrite")).toBe("F");
  });

  it("jede Fassung nur einmal: vorhandene vollständige Kopie mit gleicher Kennung -> keine neue (Review xc-1)", async () => {
    const existing = (name: string, length?: number) =>
      davResponse(`${folderPath}${name}`, `<d:resourcetype/>${length === undefined ? "" : `<d:getcontentlength>${length}</d:getcontentlength>`}`);
    const otherTag = backupVersionTag('"2"');
    const copiesFor = async (listing: string[]) => {
      const { adapter: a, requests } = adapter(backupServer({ listing }));
      await a.backup(current);
      return requests.filter((r) => r.method === "COPY").length;
    };
    // Schon gesichert (Größe passt bzw. der Server nennt keine): nichts anlegen.
    expect(await copiesFor([existing(`tresor.20261015-100000-000.${tag}.kdbx`, current.data.length)])).toBe(0);
    expect(await copiesFor([existing(`tresor.20261015-100000-000.${tag}.kdbx`)])).toBe(0);
    // Unvollständig (z. B. abgebrochener Upload), andere Fassung, alte Namen, andere Datei: neu anlegen.
    expect(await copiesFor([existing(`tresor.20261015-100000-000.${tag}.kdbx`, 1)])).toBe(1);
    expect(await copiesFor([existing(`tresor.20261015-100000-000.${otherTag}.kdbx`, 3)])).toBe(1);
    expect(await copiesFor([existing("tresor.20261015-100000-000.kdbx", 3)])).toBe(1);
    expect(await copiesFor([existing(`anderer.20261015-100000-000.${tag}.kdbx`, 3)])).toBe(1);
  });

  it("lässt sich der Ordner nicht auflisten, wird die Kopie trotzdem angelegt (Pflicht)", async () => {
    const { adapter: a, requests } = adapter((request) => (request.method === "PROPFIND" ? new Response(null, { status: 500 }) : backupServer()(request)));
    await a.backup(current);
    expect(requests.map((r) => r.method)).toEqual(["MKCOL", "PROPFIND", "COPY"]);
  });

  it("ohne COPY-Unterstützung (405/501): PUT der gelesenen Bytes mit If-None-Match", async () => {
    for (const copyStatus of [405, 501]) {
      const { adapter: a, requests } = adapter(backupServer({ copyStatus }));
      await a.backup({ data: bytes("alter Inhalt"), etag: '"1"' });
      const put = requests.find((r) => r.method === "PUT")!;
      expect(put.url).toBe(backupFolder + expectedName);
      expect(put.body).toEqual(bytes("alter Inhalt"));
      expect(put.headers.get("If-None-Match")).toBe("*");
    }
  });

  it("gleicher Name schon vorhanden (412): nächste Millisekunde", async () => {
    const statuses = [412, 201];
    const { adapter: a, requests } = adapter((request) => (request.method === "COPY" ? new Response(null, { status: statuses.shift()! }) : backupServer()(request)));
    await a.backup(current);
    const copies = requests.filter((r) => r.method === "COPY").map((r) => r.headers.get("Destination"));
    expect(copies).toEqual([backupFolder + expectedName, `${backupFolder}tresor.20261015-171500-043.${tag}.kdbx`]);
  });

  it("räumt auf: löscht nur die ältesten Sicherungen DIESER Datei im Sicherungsordner", async () => {
    const listing = [
      davResponse(folderPath, "<d:resourcetype><d:collection/></d:resourcetype>"),
      // die Sicherung der eben überschriebenen Fassung '"1"'
      davResponse(`${folderPath}${expectedName}`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.20261014-100000-000.kdbx`, "<d:resourcetype/>"),
      // absolute URL (manche Server) und prozentkodiert
      davResponse(`https://cloud.example${folderPath}tresor.20261013-100000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.20261012-100000-000.${backupVersionTag('"0"')}.kdbx`, "<d:resourcetype/>"),
      // fremde Dateien: nie löschen
      davResponse(`${folderPath}anderer.20200101-000000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${folderPath}notizen.txt`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.kaputt.kdbx`, "<d:resourcetype/>"),
      // außerhalb des Ordners bzw. Unterordner: nie löschen
      davResponse("/remote.php/webdav/Ownwarden/tresor.20000101-000000-000.kdbx", "<d:resourcetype/>"),
      davResponse(`${folderPath}unter/tresor.20000101-000000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.19990101-000000-000.kdbx/`, "<d:resourcetype><d:collection/></d:resourcetype>"),
    ];
    const { adapter: a, requests } = adapter(backupServer({ listing }));
    expect(await a.pruneBackups(current, 2)).toEqual({ warnings: [] });
    expect(requests.map((r) => r.method)).toEqual(["PROPFIND", "DELETE", "DELETE"]);
    const deleted = requests.filter((r) => r.method === "DELETE").map((r) => r.url);
    expect(deleted.sort()).toEqual([
      `https://cloud.example${folderPath}tresor.20261012-100000-000.${backupVersionTag('"0"')}.kdbx`,
      `https://cloud.example${folderPath}tresor.20261013-100000-000.kdbx`,
    ]);
  });

  it("findet Sicherungen auch bei Sonderzeichen im Dateinamen", async () => {
    const specialFolder = "/dav/ownwarden-backups/";
    const listing = [
      davResponse(`${specialFolder}Mein%20Tresor%20%28neu%29.20261015-171500-042.${tag}.kdbx`, "<d:resourcetype/>"),
      davResponse(`${specialFolder}Mein%20Tresor%20(neu).20261015-000000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${specialFolder}Mein%20Tresor%20%28neu%29.20261014-000000-000.kdbx`, "<d:resourcetype/>"),
    ];
    const special = adapter(backupServer(), { fileUrl: "https://cloud.example/dav/Mein Tresor (neu).kdbx" });
    await special.adapter.backup(current);
    expect(special.requests.find((r) => r.method === "COPY")!.headers.get("Destination")).toBe(
      `https://cloud.example/dav/ownwarden-backups/Mein%20Tresor%20(neu).20261015-171500-042.${tag}.kdbx`,
    );
    // keep 2 = die Sicherung der überschriebenen Fassung (prozentkodiert gelistet) + die neueste übrige.
    const { adapter: a, requests } = adapter(backupServer({ listing }), { fileUrl: "https://cloud.example/dav/Mein Tresor (neu).kdbx" });
    await a.pruneBackups(current, 2);
    expect(requests.filter((r) => r.method === "DELETE").map((r) => r.url)).toEqual([
      "https://cloud.example/dav/ownwarden-backups/Mein%20Tresor%20%28neu%29.20261014-000000-000.kdbx",
    ]);
  });

  it("MKCOL legt den Ordner an (201); Fehler beim Anlegen oder Kopieren brechen ab", async () => {
    const created = adapter(backupServer({ mkcolStatus: 201 }));
    await created.adapter.backup(current);
    expect(created.requests[0]!.method).toBe("MKCOL");

    await expect(adapter(backupServer({ mkcolStatus: 409 })).adapter.backup({ data: bytes("x"), etag: '"1"' })).rejects.toBeInstanceOf(StorageError);
    await expect(adapter(backupServer({ mkcolStatus: 401 })).adapter.backup({ data: bytes("x"), etag: '"1"' })).rejects.toBeInstanceOf(StorageAuthError);
    await expect(adapter(backupServer({ copyStatus: 507 })).adapter.backup({ data: bytes("x"), etag: '"1"' })).rejects.toThrow(/Speicherplatz/);
  });

  // Entscheidung des Eigentümers (2026-10-16): Aufräumen alter Kopien ist „best effort“.
  // Bis dahin brach auch ein Fehler beim Auflisten ab (Teil des vorherigen Tests).
  it("Aufräumen ist best effort: Fehler beim Auflisten oder Löschen alter Kopien werden zu Hinweisen", async () => {
    const badListing = adapter((request) => (request.method === "PROPFIND" ? new Response("<html/>", { status: 200 }) : backupServer()(request)));
    const listingResult = await badListing.adapter.pruneBackups({ data: bytes("x"), etag: '"1"' }, 1);
    expect(badListing.requests.map((r) => r.method)).toEqual(["PROPFIND"]);
    expect(listingResult.warnings).toHaveLength(1);
    expect(listingResult.warnings[0]).toMatch(/nicht aufgeräumt.*207/);

    const listing = [
      davResponse(`${folderPath}${expectedName}`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.20261014-100000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.20261013-100000-000.kdbx`, "<d:resourcetype/>"),
      davResponse(`${folderPath}tresor.20261012-100000-000.kdbx`, "<d:resourcetype/>"),
    ];
    const locked = `https://cloud.example${folderPath}tresor.20261013-100000-000.kdbx`;
    const { adapter: a, requests } = adapter((request) =>
      request.method === "DELETE" && request.url === locked ? new Response(null, { status: 423 }) : backupServer({ listing })(request),
    );
    const result = await a.pruneBackups(current, 2);
    // Beide alten Kopien wurden versucht; die gesperrte bleibt mit Hinweis, die andere ist weg.
    expect(requests.filter((r) => r.method === "DELETE").map((r) => r.url).sort()).toEqual([
      `https://cloud.example${folderPath}tresor.20261012-100000-000.kdbx`,
      locked,
    ]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("tresor.20261013-100000-000.kdbx");
    expect(result.warnings[0]).toContain("423");
    for (const warning of [...result.warnings, ...listingResult.warnings]) expect(warning).not.toContain(PASSWORD);
  });

  it("keep muss mindestens 1 sein", async () => {
    const { adapter: a, requests } = adapter(backupServer());
    await expect(a.pruneBackups({ data: bytes("x"), etag: '"1"' }, 0)).rejects.toBeInstanceOf(RangeError);
    expect(requests).toHaveLength(0);
  });

  // Review probe-2: Nennt der Server die Dateien unter einem anderen Pfad (umgeschriebene Adresse,
  // anderer DAV-Zugang), findet das Aufräumen nie etwas und löscht nie – das soll nicht still
  // bleiben. Erkennbar daran, dass die eben sichergestellte Sicherung in der Liste fehlt.
  it("fehlt die Sicherung der überschriebenen Fassung in der Ordnerliste, gibt es einen Hinweis", async () => {
    const listing = [
      davResponse(`/remote.php/dav/files/uid/Ownwarden/ownwarden-backups/${expectedName}`, "<d:resourcetype/>"),
      davResponse("/remote.php/dav/files/uid/Ownwarden/ownwarden-backups/tresor.20261014-100000-000.kdbx", "<d:resourcetype/>"),
    ];
    const { adapter: a, requests } = adapter(backupServer({ listing }));
    const result = await a.pruneBackups(current, 1);
    expect(requests.filter((r) => r.method === "DELETE")).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatch(/fehlt in der Liste des Sicherungsordners/);

    // Steht sie in der Liste, gibt es keinen Hinweis.
    const fine = adapter(backupServer({ listing: [davResponse(`${folderPath}${expectedName}`, "<d:resourcetype/>")] }));
    expect(await fine.adapter.pruneBackups(current, 1)).toEqual({ warnings: [] });
  });
});

// Review webdav-1/xc-7: Das Zeitlimit greift bei Stillstand, nicht für die ganze Übertragung,
// und der Standard bleibt unter dem 30-s-Limit des Service Workers.
describe("WebDavAdapter: Zeitlimit gegen Stillstand", () => {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  /** Antwort, deren Körper in `chunks` Stücken alle `everyMs` ms kommt (und beim Abbruch abbricht). */
  function slowBody(init: RequestInit, chunks: number, everyMs: number, stallAfter = Infinity): Response {
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        init.signal?.addEventListener("abort", () => controller.error(init.signal!.reason));
      },
      async pull(controller) {
        if (sent >= stallAfter) return new Promise<void>(() => {}); // kommt nie mehr etwas
        await sleep(everyMs);
        if (sent++ < chunks) controller.enqueue(new Uint8Array(1000).fill(sent));
        else controller.close();
      },
    });
    return new Response(stream, { headers: { ETag: '"e1"' } });
  }

  it("Standard unter 30 s (Service Worker der Erweiterung)", () => {
    expect(DEFAULT_WEBDAV_TIMEOUT_MS).toBeLessThan(30_000);
    expect(DEFAULT_WEBDAV_TIMEOUT_MS).toBeGreaterThanOrEqual(10_000);
  });

  it("langsamer, aber stetiger Download dauert länger als das Zeitlimit und klappt trotzdem", async () => {
    const { adapter: a } = adapter((request) => slowBody(request.init, 8, 25), { timeoutMs: 80 });
    const started = Date.now();
    const file = await a.read();
    expect(Date.now() - started).toBeGreaterThan(160);
    expect(file!.data).toHaveLength(8000);
  });

  it("Download bleibt stehen: StorageError mit Zeitüberschreitung", async () => {
    const { adapter: a } = adapter((request) => slowBody(request.init, 8, 10, 2), { timeoutMs: 80 });
    const error = await caught(a.read());
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/Zeitüberschreitung.*keine Daten/);
  });

  it("Upload: die Frist wächst mit der Größe des Inhalts (MIN_UPLOAD_BYTES_PER_SECOND)", async () => {
    // Der Server antwortet erst nach 300 ms (wie nach einem langsamen Upload).
    const lateAnswer = (request: RecordedRequest) =>
      new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => resolve(new Response(null, { status: 204, headers: { ETag: '"neu"' } })), 300);
        request.init.signal!.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(request.init.signal!.reason);
        });
      });
    const { adapter: a } = adapter(lateAnswer, { timeoutMs: 50 });
    // 16 KiB brauchen bei der Mindestrate 1 s: Frist 50 ms + 1000 ms.
    expect(await a.write(new Uint8Array(MIN_UPLOAD_BYTES_PER_SECOND), { ifMatch: '"alt"' })).toEqual({ etag: '"neu"' });
    const error = await caught(a.write(bytes("klein"), { ifMatch: '"alt"' }));
    expect(error).toBeInstanceOf(StorageError);
    expect(String(error)).toMatch(/PUT .*Zeitüberschreitung bei der Übertragung/);
    expect(String(error)).not.toMatch(/keine Antwort/);
  });
});
