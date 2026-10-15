/**
 * Kritische Prüfung des WebDAV-Servertests (webdav-probe.ts):
 *   - Die Kommandozeile gibt nie ein Passwort aus (auch nicht, wenn es versehentlich in der
 *     Adresse oder als loses Argument steht).
 *   - Der Testordner wird IMMER wieder gelöscht – auch wenn die Fortschrittsanzeige scheitert
 *     oder die Antwort auf MKCOL verloren geht (der Ordner aber angelegt wurde).
 *   - Alle Anfragen bleiben im eigenen Testordner.
 * Die Tests mit Server werden übersprungen, wenn PHP/Composer fehlen.
 */
import { spawn } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CORE_DIR } from "../../test/helpers/keepassxc";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { runWebDavProbe, type ProbeOptions } from "./webdav-probe";

describe("Kommandozeile: Passwort erscheint nie in der Ausgabe", () => {
  it("Zugangsdaten in --url werden abgelehnt, ohne die Adresse samt Passwort auszugeben", async () => {
    const result = await runCli(["--url", "https://bob:streng-geheim@cloud.example/dav/", "--user", "bob"], { OWNWARDEN_WEBDAV_PASSWORD: "x" });
    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain("streng-geheim");
    expect(result.stderr).toMatch(/Zugangsdaten/);
  });

  it("ein versehentlich als loses Argument angegebenes Passwort wird nicht wiederholt", async () => {
    const result = await runCli(["--url", "https://cloud.example/dav/", "--user", "bob", "streng-geheim"], { OWNWARDEN_WEBDAV_PASSWORD: "x" });
    expect(result.code).toBe(2);
    expect(result.stdout + result.stderr).not.toContain("streng-geheim");
  });

  it("ungültige Adresse (http:// auf fremden Rechner): Exit-Code 2, bevor ein Passwort abgefragt wird", async () => {
    const result = await runCli(["--url", "http://cloud.example/dav/", "--user", "bob"], {});
    expect(result.code).toBe(2);
    expect(result.stderr).toMatch(/nur https/);
  });
});

describe.skipIf(!webDavTestServerAvailable())("WebDAV-Servertest räumt immer auf", () => {
  let server: WebDavTestServer;
  let folderUrl: string;

  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-probe-adversarial");
    mkdirSync(join(server.dataDir, "Test"));
    folderUrl = new URL("Test/", server.baseUrl).href;
  });
  afterAll(async () => {
    await server?.stop();
  });

  const probe = (overrides: Partial<ProbeOptions> = {}) =>
    runWebDavProbe({ folderUrl, username: server.username, password: server.password, ...overrides });
  const probeFolders = () => readdirSync(join(server.dataDir, "Test")).filter((name) => name.startsWith("ownwarden-probe-"));
  /** Testordner, die seit `before` neu dazugekommen und nicht wieder gelöscht worden sind. */
  const leftoversSince = (before: string[]) => probeFolders().filter((name) => !before.includes(name));

  it("die Fortschrittsanzeige (onCheck) wirft: Fehler kommt beim Aufrufer an, der Testordner ist trotzdem weg", async () => {
    const before = probeFolders();
    let calls = 0;
    const failure = probe({
      onCheck: () => {
        if (++calls === 3) throw new Error("Ausgabe kaputt (z. B. EPIPE)");
      },
    });
    await expect(failure).rejects.toThrow(/Ausgabe kaputt/);
    expect(leftoversSince(before)).toEqual([]);
  });

  it("die Antwort auf MKCOL geht verloren, der Server hat den Ordner aber angelegt: er wird trotzdem gelöscht", async () => {
    const lostMkcolResponse: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if (init?.method === "MKCOL") {
        await response.body?.cancel();
        throw new TypeError("fetch failed", { cause: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) });
      }
      return response;
    };
    const before = probeFolders();
    const report = await probe({ fetch: lostMkcolResponse });
    expect(report.safe).toBe(false);
    expect(report.checks[0]).toMatchObject({ id: "mkcol", status: "fail" });
    expect(report.checks.at(-1)).toMatchObject({ id: "cleanup", status: "ok" });
    expect(leftoversSince(before)).toEqual([]);
  });

  it("MKCOL scheitert eindeutig (Anmeldung abgelehnt): kein Lösch-Versuch, keine irreführende Warnung", async () => {
    const methods: string[] = [];
    const recording: typeof fetch = async (input, init) => {
      methods.push(init?.method ?? "GET");
      return fetch(input, init);
    };
    const report = await probe({ password: "falsch", fetch: recording });
    expect(methods).toEqual(["MKCOL"]);
    expect(report.checks.at(-1)).toMatchObject({ id: "cleanup", status: "ok" });
  });

  it("eine Anfrage mittendrin bekommt keine Antwort: Rest übersprungen, Testordner trotzdem gelöscht", async () => {
    const noCopyAnswer: typeof fetch = async (input, init) => {
      if (init?.method === "COPY") throw new TypeError("fetch failed");
      return fetch(input, init);
    };
    const before = probeFolders();
    const report = await probe({ fetch: noCopyAnswer });
    expect(report.checks.find((check) => check.id === "copy")?.status).toBe("fail");
    expect(report.checks.at(-1)).toMatchObject({ id: "cleanup", status: "ok" });
    expect(leftoversSince(before)).toEqual([]);
  });

  it("alle Anfragen (inkl. COPY-Ziel) bleiben im eigenen Testordner", async () => {
    const urls: string[] = [];
    const recording: typeof fetch = async (input, init) => {
      urls.push(String(input));
      const destination = new Headers(init?.headers).get("Destination");
      if (destination !== null) urls.push(destination);
      return fetch(input, init);
    };
    const report = await probe({ fetch: recording, abortTest: true });
    expect(report.safe).toBe(true);
    for (const url of urls) expect(url.startsWith(report.probeFolderUrl), url).toBe(true);
  });
});

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
