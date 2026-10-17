/**
 * Gegenproben zu einzelnen Prüfungen des WebDAV-Servertests (Review probe-1/xc-2, probe-2,
 * probe-3/xc-9). Vor den SabreDAV-Testserver kommt dafür ein kleiner Vorschaltrechner (node:http)
 * bzw. eine fetch-Hülle, die ein bestimmtes Fehlverhalten eines Servers nachstellt.
 * Wird übersprungen, wenn PHP/Composer fehlen.
 */
import { mkdirSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { runWebDavProbe, type ProbeOptions, type ProbeReport } from "./webdav-probe";

/** Was der Vorschaltrechner mit dem großen PUT des Abbruch-Tests macht. */
type AbortMode = "early-411" | "early-201" | "commit-partial";

interface Proxy {
  url: string;
  /** Kopfzeilen jedes großen PUT (des Abbruch-Tests). */
  bigPuts: IncomingHttpHeaders[];
  close(): Promise<void>;
}

/** Leitet alles an `target` weiter; nur der große PUT des Abbruch-Tests wird nach `mode` behandelt. */
function startProxy(target: URL, mode: AbortMode): Promise<Proxy> {
  const bigPuts: IncomingHttpHeaders[] = [];
  const forward = (method: string, path: string, headers: IncomingHttpHeaders, body?: Buffer) =>
    httpRequest(new URL(path, target), { method, headers: { ...headers, host: target.host, ...(body ? { "content-length": String(body.length) } : {}) } });
  const server = createServer((req, res) => {
    if (req.method === "PUT" && Number(req.headers["content-length"] ?? 0) >= 100_000) {
      bigPuts.push(req.headers);
      if (mode === "early-411" || mode === "early-201") {
        res.writeHead(mode === "early-411" ? 411 : 201, { Connection: "close" });
        res.end();
        return;
      }
      // commit-partial: ein Server, der auch einen abgebrochenen Upload übernimmt (wie es
      // ungeschickte Server-Konfigurationen tun) – der Servertest muss das als ❌ melden.
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("close", () => {
        if (req.complete) return;
        const upstream = forward("PUT", req.url!, req.headers, Buffer.concat(chunks));
        upstream.on("response", (response) => response.resume());
        upstream.on("error", () => {});
        upstream.end(Buffer.concat(chunks));
      });
      return;
    }
    const upstream = forward(req.method!, req.url!, req.headers);
    upstream.on("response", (response) => {
      res.writeHead(response.statusCode!, response.headers);
      response.pipe(res);
    });
    upstream.on("error", () => res.destroy());
    req.pipe(upstream);
  });
  return new Promise((resolvePromise) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolvePromise({
        url: `http://127.0.0.1:${port}/`,
        bigPuts,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

describe.skipIf(!webDavTestServerAvailable())("WebDAV-Servertest: Gegenproben zu einzelnen Prüfungen", () => {
  let server: WebDavTestServer;
  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-probe-checks");
    mkdirSync(join(server.dataDir, "Test"));
  });
  afterAll(async () => {
    await server?.stop();
  });

  const probe = (overrides: Partial<ProbeOptions> = {}) =>
    runWebDavProbe({ folderUrl: new URL("Test/", server.baseUrl).href, username: server.username, password: server.password, ...overrides });
  const check = (report: ProbeReport, id: string) => report.checks.find((item) => item.id === id)!;

  describe("abgebrochener Upload wie beim echten Abgleich (Review probe-1/xc-2)", () => {
    const viaProxy = async (mode: AbortMode) => {
      const proxy = await startProxy(new URL(server.baseUrl), mode);
      try {
        const report = await probe({ folderUrl: new URL("Test/", proxy.url).href, abortTest: true });
        return { report, bigPuts: proxy.bigPuts };
      } finally {
        await proxy.close();
      }
    };

    it("der Upload kündigt per Content-Length die volle Größe an (nicht „chunked“), sendet aber nur einen Teil", async () => {
      const { report, bigPuts } = await viaProxy("early-411");
      expect(bigPuts).toHaveLength(1);
      expect(bigPuts[0]!["content-length"]).toBe(String(512 * 1024));
      expect(bigPuts[0]!["transfer-encoding"]).toBeUndefined();
      expect(report.checks.find((item) => item.id === "abort")).toBeDefined();
    });

    it("antwortet der Server vor dem Abbruch (z. B. 411), heißt das ⚠️ „nicht geprüft“, nie ✅", async () => {
      const { report } = await viaProxy("early-411");
      expect(check(report, "abort")).toMatchObject({ status: "warn" });
      expect(check(report, "abort").detail).toMatch(/^nicht geprüft: .*HTTP 411/);
      expect(report.safe).toBe(true);
    });

    it("nimmt der Server den unvollständigen Upload mit 2xx an, ist das ❌", async () => {
      const { report } = await viaProxy("early-201");
      expect(check(report, "abort")).toMatchObject({ status: "fail" });
      expect(check(report, "abort").detail).toContain("HTTP 201 angenommen");
      expect(report.safe).toBe(false);
    });

    it("übernimmt der Server die halbe Datei, ist das ❌", async () => {
      const { report } = await viaProxy("commit-partial");
      expect(check(report, "abort")).toMatchObject({ status: "fail" });
      expect(check(report, "abort").detail).toContain("anderen Inhalt oder ETag");
    });

    it("der echte Testserver verwirft den abgebrochenen Upload: ✅", async () => {
      const report = await probe({ abortTest: true });
      expect(check(report, "abort")).toMatchObject({ status: "ok" });
      expect(check(report, "abort").detail).toContain("256 von angekündigten 512 KiB");
    });
  });

  describe("neuer ETag in derselben Sekunde (Review probe-3/xc-9)", () => {
    it("liegen die beiden Schreibvorgänge nie in derselben Serversekunde, heißt das ⚠️ „nicht geprüft“, nicht ✅", async () => {
      // Antworten auf PUT tragen eine um 5 s spätere Serverzeit: Das zweite Schreiben endet so
      // nie in der Sekunde, in der das erste begann.
      const laterPutDate: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        if (init?.method !== "PUT") return response;
        const headers = new Headers(response.headers);
        headers.set("Date", new Date(Date.now() + 5000).toUTCString());
        const body = response.status === 204 || response.status === 201 ? null : await response.arrayBuffer();
        if (body === null) await response.body?.cancel();
        return new Response(body, { status: response.status, headers });
      };
      const report = await probe({ fetch: laterPutDate });
      expect(check(report, "same-second")).toMatchObject({ status: "warn" });
      expect(check(report, "same-second").detail).toMatch(/^nicht geprüft: In 5 Versuchen/);
    });

    it("ohne Date-Header: ⚠️ „nicht geprüft“", async () => {
      const withoutDate: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        const headers = new Headers(response.headers);
        headers.delete("Date");
        const body = [201, 204, 404].includes(response.status) || init?.method === "MKCOL" || init?.method === "DELETE" ? null : await response.arrayBuffer();
        if (body === null) await response.body?.cancel();
        return new Response(body, { status: response.status, headers });
      };
      const report = await probe({ fetch: withoutDate });
      expect(check(report, "same-second")).toMatchObject({ status: "warn" });
      expect(check(report, "same-second").detail).toContain("Ohne Date-Header");
    });

    it("gleicher ETag nach zwei Änderungen: ❌", async () => {
      // Jede PUT-Antwort und jedes GET nennen denselben ETag wie vor dem Schreiben – so sähe es
      // bei einem Server aus, der den ETag nur aus Größe + Sekunde bildet.
      let frozen: string | null = null;
      let puts = 0;
      const sameEtag: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        const method = init?.method ?? "GET";
        if (method === "PUT") puts += 1;
        // Ab dem 4. PUT (erstes Schreiben im Schritt „same-second“) bleibt es bei dessen ETag.
        if (puts < 4 || (method !== "GET" && method !== "PUT")) return response;
        const headers = new Headers(response.headers);
        frozen ??= headers.get("ETag");
        if (frozen !== null) {
          headers.set("ETag", frozen);
          headers.delete("OC-ETag");
        }
        const body = method === "GET" && response.status === 200 ? await response.arrayBuffer() : null;
        if (body === null) await response.body?.cancel();
        return new Response(body, { status: response.status, headers });
      };
      const report = await probe({ fetch: sameEtag });
      expect(check(report, "same-second")).toMatchObject({ status: "fail" });
      expect(check(report, "same-second").detail).toContain("Der ETag blieb gleich");
    });
  });

  describe("PROPFIND, MKCOL und Aufräumen so streng wie beim Abgleich (Review probe-2)", () => {
    it("nennt die Ordnerliste die Dateien unter einem anderen Pfad, ist das beim Auflisten und beim Aufräumen ⚠️ (nicht ✅)", async () => {
      const otherPrefix: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        if (init?.method !== "PROPFIND" || response.status !== 207) return response;
        const xml = (await response.text()).replace(/<d:href>\/Test\//g, "<d:href>/anderer-zugang/Test/");
        return new Response(xml, { status: 207, headers: response.headers });
      };
      const report = await probe({ fetch: otherPrefix });
      expect(check(report, "propfind")).toMatchObject({ status: "warn" });
      expect(check(report, "propfind").detail).toContain("anderen Pfad");
      expect(check(report, "backups")).toMatchObject({ status: "warn" });
      expect(check(report, "backups").detail).toContain("statt 1 Sicherung");
      expect(report.safe).toBe(true);
    });

    it("lehnt der Server MKCOL auf den schon vorhandenen Sicherungsordner ab, ist das ❌ (jedes Schreiben scheiterte)", async () => {
      let backupFolderMkcols = 0;
      const refusesSecondMkcol: typeof fetch = async (input, init) => {
        if (init?.method === "MKCOL" && String(input).endsWith("/ownwarden-backups/") && ++backupFolderMkcols > 1) {
          return new Response(null, { status: 500 });
        }
        return fetch(input, init);
      };
      const report = await probe({ fetch: refusesSecondMkcol });
      expect(backupFolderMkcols).toBe(2);
      expect(check(report, "backups")).toMatchObject({ status: "fail" });
      expect(check(report, "backups").detail).toContain("Sicherungsordners");
      expect(report.safe).toBe(false);
      expect(check(report, "cleanup")).toMatchObject({ status: "ok" });
    });
  });
});
