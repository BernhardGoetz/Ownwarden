/**
 * Review sync-cli-3 (Befund probe-1, Regressionstest): Der Servertest meldet „Abgebrochener
 * Upload lässt die alte Fassung unverändert“ als ✅, obwohl gar kein abgebrochener Upload beim
 * Server ankam.
 *
 * Der Abbruch-Test lädt als Stream hoch (Transfer-Encoding: chunked, ohne Content-Length) –
 * echte Uploads von WebDavAdapter.write haben immer eine Content-Length. Server oder
 * Vorschaltrechner, die chunked-Uploads sofort ablehnen (z. B. 411 Length Required), antworten
 * deshalb VOR dem Abbruch. webdav-probe.ts macht daraus „Server hat schon vor dem Abbruch
 * geantwortet (HTTP 411)“ und – weil sich die Datei natürlich nicht geändert hat – ✅.
 * README nennt diese Prüfung „die eigentliche Prüfung“ für den abgebrochenen Upload.
 *
 * Nachgestellt mit einer fetch-Hülle um den SabreDAV-Testserver, die einen Stream-PUT sofort mit
 * 411 beantwortet (so verhält sich undici auch bei einem echten Server: fetch liefert die
 * 411-Antwort nach wenigen Millisekunden, lange vor dem Abbruch).
 * Erwartet: Der Schritt „abort“ ist dann NICHT ✅ (sondern z. B. ⚠️ „nicht geprüft“).
 * (Benutzt eine Lösung für den Abbruch-Test gar kein fetch mehr, z. B. node:http mit
 * Content-Length, lässt sich die frühe Antwort so nicht einspielen; dann prüft der Test nichts.)
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runWebDavProbe } from "../../src/cli/webdav-probe";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";

describe.skipIf(!webDavTestServerAvailable())("Review sync-cli-3: Abbruch-Test des Servertests", () => {
  let server: WebDavTestServer;
  beforeAll(async () => {
    server = await startWebDavTestServer("review-sync-cli-3");
    mkdirSync(join(server.dataDir, "Test"));
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("Review sync-cli-3: lehnt der Server den Abbruch-Upload sofort ab (411), meldet der Servertest dafür kein ✅", async () => {
    let streamPutsAnsweredEarly = 0;
    const rejectsChunkedUploads: typeof fetch = async (input, init) => {
      if (init?.method === "PUT" && init.body instanceof ReadableStream) {
        streamPutsAnsweredEarly += 1;
        await init.body.cancel();
        return new Response(null, { status: 411, statusText: "Length Required" });
      }
      return fetch(input, init);
    };

    const report = await runWebDavProbe({
      folderUrl: new URL("Test/", server.baseUrl).href,
      username: server.username,
      password: server.password,
      abortTest: true,
      fetch: rejectsChunkedUploads,
    });
    const abort = report.checks.find((check) => check.id === "abort");
    expect(abort).toBeDefined();
    if (streamPutsAnsweredEarly === 0) return; // Abbruch-Test läuft nicht mehr über fetch (siehe oben)

    expect(abort!.status, abort!.detail).not.toBe("ok");
  });
});
