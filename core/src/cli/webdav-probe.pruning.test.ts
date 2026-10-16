/**
 * WebDAV-Servertest und „best effort“-Aufräumen (Entscheidung des Eigentümers, 2026-10-16):
 * Kann der Server keine Dateien löschen (z. B. Freigabe ohne Löschrecht) oder keinen Ordner
 * auflisten, bleiben nur alte Sicherungskopien liegen. Der Abgleich ist trotzdem sicher – der
 * Servertest meldet das deshalb als Hinweis (⚠️), nicht als Fehler (❌).
 * Wird übersprungen, wenn PHP/Composer fehlen.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { runWebDavProbe } from "./webdav-probe";

describe.skipIf(!webDavTestServerAvailable())("WebDAV-Servertest: Probleme beim Aufräumen sind nur Hinweise", () => {
  let server: WebDavTestServer;
  let folderUrl: string;
  beforeAll(async () => {
    server = await startWebDavTestServer("probe-pruning");
    mkdirSync(join(server.dataDir, "Ownwarden-Test"));
    folderUrl = new URL("Ownwarden-Test/", server.baseUrl).href;
  });
  afterAll(async () => {
    await server?.stop();
  });

  /** Wie der echte Server, nur DELETE auf Dateien (nicht auf den Testordner) mit `status` abgelehnt. */
  const refusingDeleteOfFiles =
    (status: number): typeof fetch =>
    async (input, init) =>
      init?.method === "DELETE" && !String(input).endsWith("/") ? new Response(null, { status }) : fetch(input, init);

  it.each([403, 423])("DELETE einer Datei -> HTTP %i: Hinweis, Server bleibt „sicher“", async (status) => {
    const report = await runWebDavProbe({ folderUrl, username: server.username, password: server.password, fetch: refusingDeleteOfFiles(status) });
    const check = report.checks.find((item) => item.id === "delete")!;
    expect(check.status).toBe("warn");
    expect(check.detail).toContain("nicht automatisch gelöscht");
    expect(report.safe).toBe(true);
  });

  it("PROPFIND liefert keine Liste: Hinweis, Server bleibt „sicher“", async () => {
    const noListing: typeof fetch = async (input, init) =>
      init?.method === "PROPFIND" ? new Response("<html/>", { status: 200 }) : fetch(input, init);
    const report = await runWebDavProbe({ folderUrl, username: server.username, password: server.password, fetch: noListing });
    expect(report.checks.find((item) => item.id === "propfind")!.status).toBe("warn");
    expect(report.safe).toBe(true);
  });
});
