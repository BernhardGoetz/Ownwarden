/**
 * Test-Hilfe: startet den WebDAV-Testserver aus tools/webdav-test-server (SabreDAV, verhält
 * sich beim Schreiben wie Nextcloud) mit dem eingebauten Webserver von PHP.
 *
 *   describe.skipIf(!webDavTestServerAvailable())("…", () => {
 *     let server: WebDavTestServer;
 *     beforeAll(async () => { server = await startWebDavTestServer("mein-test"); });
 *     afterAll(async () => { await server?.stop(); });
 *     it("…", async () => { const url = new URL("tresor.kdbx", server.baseUrl).href; … });
 *   });
 *
 * Ablauf von startWebDavTestServer:
 *   1. Fehlt tools/webdav-test-server/vendor, einmal "composer install" ausführen (mit einer
 *      Sperre, weil vitest Testdateien parallel startet).
 *   2. Datenordner unter core/test/.tmp/<name>-<zufall>/data anlegen.
 *   3. Einen freien Port suchen und "php -S 127.0.0.1:<port> server.php" starten, mit
 *      zufälligem Test-Passwort (keine echten Zugangsdaten).
 *   4. Warten, bis der Server antwortet.
 * stop() beendet PHP und löscht den Ordner.
 *
 * Nur für Tests: benutzt Node-APIs.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { CORE_DIR, TMP_ROOT, createTmpDir, removeTmpDir } from "./keepassxc";

/** Ordner des Testservers im Repo. */
export const WEBDAV_SERVER_DIR = resolve(CORE_DIR, "..", "tools", "webdav-test-server");

/** PHP-Erweiterungen, die SabreDAV braucht. */
const REQUIRED_PHP_EXTENSIONS = ["dom", "xmlreader", "xmlwriter", "simplexml", "mbstring", "ctype", "iconv"];

export interface WebDavTestServer {
  /** Wurzel des WebDAV-Baums, z. B. "http://127.0.0.1:41234/" (mit "/" am Ende). */
  baseUrl: string;
  username: string;
  /** Zufälliges Test-Passwort dieses Servers. */
  password: string;
  /** Ordner, in dem die Dateien des WebDAV-Baums liegen. */
  dataDir: string;
  /** Letzte Ausgaben des PHP-Servers (zur Fehlersuche). */
  log(): string;
  stop(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Verfügbarkeit
// ---------------------------------------------------------------------------

let available: boolean | undefined;

/** true, wenn PHP (mit den nötigen Erweiterungen) und SabreDAV bzw. Composer vorhanden sind. */
export function webDavTestServerAvailable(): boolean {
  if (available === undefined) {
    const check = `exit(count(array_filter(${JSON.stringify(REQUIRED_PHP_EXTENSIONS)}, fn($e) => !extension_loaded($e))) === 0 ? 0 : 1);`;
    const phpOk = commandSucceeds("php", ["-r", check]);
    const sabreOk = existsSync(join(WEBDAV_SERVER_DIR, "vendor", "autoload.php")) || commandSucceeds("composer", ["--version"]);
    available = phpOk && sabreOk;
  }
  return available;
}

function commandSucceeds(command: string, args: string[]): boolean {
  const result = spawnSync(command, args, { stdio: "ignore", timeout: 30_000 });
  return result.error === undefined && result.status === 0;
}

// ---------------------------------------------------------------------------
// composer install (einmalig)
// ---------------------------------------------------------------------------

const COMPOSER_LOCK_DIR = join(TMP_ROOT, "webdav-composer-install.lock");
/** Eine Sperre, die älter ist, gilt als verwaist (abgebrochener Testlauf). */
const STALE_LOCK_MS = 10 * 60 * 1000;

async function ensureSabreInstalled(): Promise<void> {
  const autoload = join(WEBDAV_SERVER_DIR, "vendor", "autoload.php");
  if (existsSync(autoload)) return;
  mkdirSync(TMP_ROOT, { recursive: true });
  // mkdir ist atomar: Nur ein Testprozess bekommt die Sperre, die anderen warten.
  for (;;) {
    try {
      mkdirSync(COMPOSER_LOCK_DIR);
      break;
    } catch {
      if (existsSync(autoload)) return;
      try {
        if (Date.now() - statSync(COMPOSER_LOCK_DIR).mtimeMs > STALE_LOCK_MS) rmSync(COMPOSER_LOCK_DIR, { recursive: true, force: true });
      } catch {
        // Sperre gerade verschwunden: einfach erneut versuchen
      }
      await sleep(200);
    }
  }
  try {
    if (existsSync(autoload)) return;
    const result = spawnSync("composer", ["install", "--no-interaction", "--no-progress"], {
      cwd: WEBDAV_SERVER_DIR,
      encoding: "utf8",
      timeout: 5 * 60 * 1000,
    });
    if (result.error !== undefined || result.status !== 0) {
      throw new Error(`composer install in ${WEBDAV_SERVER_DIR} fehlgeschlagen:\n${result.stderr ?? ""}${result.error?.message ?? ""}`);
    }
  } finally {
    rmSync(COMPOSER_LOCK_DIR, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Server starten und stoppen
// ---------------------------------------------------------------------------

/**
 * Startet einen eigenen Testserver (eigener Datenordner, eigenes Passwort).
 * @param name Kurzname für den Ordner unter core/test/.tmp/
 */
export async function startWebDavTestServer(name = "webdav"): Promise<WebDavTestServer> {
  await ensureSabreInstalled();
  const dir = createTmpDir(name);
  const dataDir = join(dir, "data");
  mkdirSync(dataDir);
  const username = "ownwarden-test";
  const password = `test-${randomBytes(9).toString("hex")}`;

  // Der Port kann zwischen Suche und Start belegt werden – dann mit einem anderen versuchen.
  let lastLog = "";
  for (let attempt = 0; attempt < 5; attempt++) {
    const port = await freePort();
    const baseUrl = `http://127.0.0.1:${port}/`;
    const child = spawn("php", ["-S", `127.0.0.1:${port}`, "server.php"], {
      cwd: WEBDAV_SERVER_DIR,
      env: { ...process.env, OWNWARDEN_WEBDAV_DATA_DIR: dataDir, OWNWARDEN_WEBDAV_USER: username, OWNWARDEN_WEBDAV_PASSWORD: password },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const log = new RingLog(200);
    // Ausgaben IMMER lesen: Ein volles Pipe-Puffer würde PHP anhalten.
    child.stdout?.on("data", (chunk: Buffer) => log.add(chunk.toString("utf8")));
    child.stderr?.on("data", (chunk: Buffer) => log.add(chunk.toString("utf8")));

    if (await waitUntilReady(baseUrl, child)) {
      return { baseUrl, username, password, dataDir, log: () => log.text(), stop: () => stopServer(child, dir) };
    }
    lastLog = log.text();
    await stopProcess(child);
  }
  removeTmpDir(dir);
  throw new Error(`WebDAV-Testserver startet nicht. Letzte Ausgabe:\n${lastLog}`);
}

/** Wartet, bis der Server auf Anfragen antwortet; false, wenn PHP vorher beendet wurde. */
async function waitUntilReady(baseUrl: string, child: ChildProcess): Promise<boolean> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) return false;
    try {
      const response = await fetch(baseUrl, { method: "OPTIONS", signal: AbortSignal.timeout(2000) });
      await response.body?.cancel();
      return true; // jede Antwort (auch 401) heißt: Server läuft
    } catch {
      await sleep(50);
    }
  }
  return false;
}

async function stopServer(child: ChildProcess, dir: string): Promise<void> {
  await stopProcess(child);
  removeTmpDir(dir);
}

async function stopProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolvePromise) => child.once("exit", () => resolvePromise()));
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 3000);
  await exited;
  clearTimeout(timer);
}

/** Ein freier TCP-Port auf 127.0.0.1 (vom Betriebssystem vergeben). */
function freePort(): Promise<number> {
  return new Promise((resolvePromise, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address !== null ? address.port : 0;
      server.close(() => resolvePromise(port));
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

/** Behält die letzten `max` Zeilen einer Ausgabe. */
class RingLog {
  private lines: string[] = [];
  constructor(private readonly max: number) {}
  add(text: string): void {
    this.lines.push(...text.split("\n").filter((line) => line !== ""));
    if (this.lines.length > this.max) this.lines.splice(0, this.lines.length - this.max);
  }
  text(): string {
    return this.lines.join("\n");
  }
}
