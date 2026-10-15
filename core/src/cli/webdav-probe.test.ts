/**
 * Der WebDAV-Servertest (webdav-probe.ts) gegen den SabreDAV-Testserver: Ein guter Server
 * besteht alle Prüfungen; ein Server, der Bedingungen ignoriert, fällt durch. Zum Schluss
 * die Kommandozeile als eigener Prozess. Wird übersprungen, wenn PHP/Composer fehlen.
 */
import { spawn } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CORE_DIR } from "../../test/helpers/keepassxc";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { formatCheck, formatSummary, runWebDavProbe, type ProbeOptions, type ProbeReport } from "./webdav-probe";

describe.skipIf(!webDavTestServerAvailable())("WebDAV-Servertest gegen SabreDAV", () => {
  let server: WebDavTestServer;
  let folderUrl: string;

  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-probe");
    mkdirSync(join(server.dataDir, "Ownwarden-Test"));
    folderUrl = new URL("Ownwarden-Test", server.baseUrl).href; // ohne "/" am Ende: wird ergänzt
  });
  afterAll(async () => {
    await server?.stop();
  });

  const probe = (overrides: Partial<ProbeOptions> = {}) =>
    runWebDavProbe({ folderUrl, username: server.username, password: server.password, ...overrides });

  const statuses = (report: ProbeReport) => Object.fromEntries(report.checks.map((check) => [check.id, check.status]));

  /** Kein Testordner bleibt zurück. */
  const leftovers = () => readdirSync(join(server.dataDir, "Ownwarden-Test")).filter((name) => name.startsWith("ownwarden-probe-"));

  it("ein Nextcloud-artiger Server besteht alle Prüfungen (inkl. abgebrochenem Upload)", async () => {
    const lines: string[] = [];
    const report = await probe({ abortTest: true, onCheck: (check) => lines.push(formatCheck(check)) });

    expect(statuses(report)).toEqual({
      mkcol: "ok",
      create: "ok",
      "create-again": "ok",
      etag: "ok",
      update: "ok",
      "same-second": "ok",
      "stale-if-match": "ok",
      "if-match-missing": "ok",
      date: "ok",
      propfind: "ok",
      copy: "ok",
      delete: "ok",
      abort: "ok",
      cleanup: "ok",
    });
    expect(report.safe).toBe(true);
    expect(report.probeFolderUrl).toMatch(/\/Ownwarden-Test\/ownwarden-probe-[0-9a-f]{8}\/$/);
    expect(leftovers()).toEqual([]);
    const output = [...lines, formatSummary(report)].join("\n");
    expect(output).toContain("✅ Ergebnis: Ownwarden kann mit diesem Server sicher synchronisieren.");
    expect(output).not.toContain(server.password);
  });

  it("ohne --abort-test wird der Abbruch-Test übersprungen (mit Hinweis)", async () => {
    const report = await probe();
    expect(report.checks.find((check) => check.id === "abort")?.status).toBe("skip");
    expect(report.safe).toBe(true);
    expect(formatSummary(report)).toContain("--abort-test");
  });

  it("falsches Passwort: klare Meldung, Rest übersprungen", async () => {
    const report = await probe({ password: "falsch" });
    expect(report.safe).toBe(false);
    expect(report.checks[0]).toMatchObject({ id: "mkcol", status: "fail" });
    expect(report.checks[0]!.detail).toMatch(/Anmeldung abgelehnt \(HTTP 401\)/);
    expect(report.checks.slice(1, -1).every((check) => check.status === "skip")).toBe(true);
    expect(report.checks.at(-1)).toMatchObject({ id: "cleanup", status: "ok" });
  });

  it("ein Server, der If-Match/If-None-Match ignoriert, ist NICHT sicher – und wird trotzdem aufgeräumt", async () => {
    const ignoresConditions: typeof fetch = (input, init) => {
      const headers = new Headers(init?.headers);
      headers.delete("If-Match");
      headers.delete("If-None-Match");
      return fetch(input, { ...init, headers });
    };
    const report = await probe({ fetch: ignoresConditions });
    const status = statuses(report);
    expect(status["create-again"]).toBe("fail");
    expect(status["stale-if-match"]).toBe("fail");
    expect(status.update).toBe("ok");
    expect(report.safe).toBe(false);
    expect(formatSummary(report)).toContain("NICHT gewährleistet");
    expect(leftovers()).toEqual([]);
  });

  it("ohne ETag im GET: Warnung (PROPFIND-Ausweg), aber sicher", async () => {
    const withoutEtag: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if ((init?.method ?? "GET") !== "GET") return response;
      const headers = new Headers(response.headers);
      headers.delete("ETag");
      return new Response(response.status === 404 ? null : await response.arrayBuffer(), { status: response.status, headers });
    };
    const report = await probe({ fetch: withoutEtag });
    expect(statuses(report).etag).toBe("warn");
    expect(report.safe).toBe(true);
  });

  it("abweichende Geräteuhr: Warnung", async () => {
    const report = await probe({ maxClockSkewMs: 0, fetch: shiftedDate(-10 * 60_000) });
    expect(statuses(report).date).toBe("warn");
    expect(report.checks.find((check) => check.id === "date")!.detail).toMatch(/geht 60[01] s vor/); // Date-Header nur sekundengenau
  });

  it("fehlender Ordner -> MKCOL 409 mit Erklärung", async () => {
    const report = await probe({ folderUrl: new URL("gibt-es-nicht/", server.baseUrl).href });
    expect(report.checks[0]).toMatchObject({ id: "mkcol", status: "fail" });
    expect(report.checks[0]!.detail).toMatch(/409/);
  });

  it("lehnt http:// auf einen fremden Rechner ab", async () => {
    await expect(runWebDavProbe({ folderUrl: "http://example.com/dav/", username: "u", password: "p" })).rejects.toThrow(/nur https/);
  });

  it("Kommandozeile: Passwort aus der Umgebung, Exit-Code 0, Passwort nie in der Ausgabe", async () => {
    const result = await runCli(["--url", folderUrl, "--user", server.username], { OWNWARDEN_WEBDAV_PASSWORD: server.password });
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("✅ Testordner anlegen (MKCOL)");
    expect(result.stdout).toContain("✅ Ergebnis");
    expect(result.stdout + result.stderr).not.toContain(server.password);

    const wrong = await runCli(["--url", folderUrl, "--user", server.username], { OWNWARDEN_WEBDAV_PASSWORD: "falsch" });
    expect(wrong.code).toBe(1);
    expect(wrong.stdout).toContain("❌ Ergebnis");

    expect((await runCli([], {})).code).toBe(2);
    expect((await runCli(["--help"], {})).code).toBe(0);
  });
});

/** fetch, dessen Antworten einen um `offsetMs` verschobenen Date-Header tragen. */
function shiftedDate(offsetMs: number): typeof fetch {
  return async (input, init) => {
    const response = await fetch(input, init);
    const headers = new Headers(response.headers);
    headers.set("Date", new Date(Date.now() + offsetMs).toUTCString());
    const body = response.status === 204 || response.status === 404 || response.status === 201 ? null : await response.arrayBuffer();
    if (body === null) await response.body?.cancel();
    return new Response(body, { status: response.status, headers });
  };
}

/** Startet die Kommandozeile als eigenen Prozess (wie der Nutzer: tsx). */
function runCli(args: string[], env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(join(CORE_DIR, "node_modules", ".bin", "tsx"), ["src/cli/webdav-probe.ts", ...args], {
      cwd: CORE_DIR,
      env: { ...process.env, OWNWARDEN_WEBDAV_PASSWORD: undefined, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
  });
}
