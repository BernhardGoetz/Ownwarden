/**
 * Kommandozeile des Prototyps (ownwarden-proto.ts): Befehle, Umgang mit Geheimnissen,
 * atomares Schreiben, Abgleich gegen den SabreDAV-Testserver und Start als echtes Programm.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CORE_DIR, createTmpDir, removeTmpDir } from "../../test/helpers/keepassxc";
import { TEST_KDF } from "../../test/helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { readKdbx } from "../kdbx/index";
import { findEntry } from "../merge/tree";
import type { Vault } from "../model";
import { writeFileAtomic } from "./atomic-file";
import { ENV, runCli, type CliIo } from "./ownwarden-proto";

const MASTER = "Proto-Master-äöü-7f3";
const ENTRY_PASSWORD = "Eintrag-Geheim-91x";

interface FakeIo {
  io: CliIo;
  out: string[];
  err: string[];
  questions: string[];
  /** Gesamte Ausgabe (stdout + stderr) – zum Prüfen, dass nie ein Geheimnis darin steht. */
  all(): string;
}

/** Ein-/Ausgabe für Tests: Umgebung, vorbereitete Antworten auf Abfragen, mitgeschriebene Ausgabe. */
function fakeIo(env: Record<string, string> = { [ENV.master]: MASTER }, answers: string[] = [], interactive = false): FakeIo {
  const out: string[] = [];
  const err: string[] = [];
  const questions: string[] = [];
  const io: CliIo = {
    env,
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    promptHidden: async (question) => {
      questions.push(question);
      return answers.shift() ?? "";
    },
    interactive,
    newVaultKdf: TEST_KDF,
  };
  return { io, out, err, questions, all: () => [...out, ...err].join("\n") };
}

async function cli(args: string[], fake: FakeIo = fakeIo()): Promise<{ code: number; fake: FakeIo }> {
  return { code: await runCli(args, fake.io), fake };
}

async function open(path: string): Promise<Vault> {
  return readKdbx(new Uint8Array(readFileSync(path)), { password: MASTER });
}

function titles(vault: Vault): string[] {
  const result: string[] = [];
  const walk = (group: Vault["root"]): void => {
    for (const entry of group.entries) result.push(entry.strings.get("Title")!.value);
    group.groups.forEach(walk);
  };
  walk(vault.root);
  return result;
}

describe("Kommandozeile des Prototyps", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("proto-cli");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });
  const file = (name: string) => join(dir, name);

  it("Hilfe nennt deutlich „nur für Testdaten“; ohne Befehl oder mit unbekanntem Befehl Exit 2", async () => {
    const help = await cli(["--help"]);
    expect(help.code).toBe(0);
    expect(help.fake.out.join("\n")).toContain("PROTOTYP – NUR FÜR TESTDATEN");
    expect((await cli([])).code).toBe(2);
    const unknown = await cli(["zaubern"]);
    expect(unknown.code).toBe(2);
    expect(unknown.fake.err.join("\n")).toContain("Unbekannter Befehl");
  });

  it("init legt eine lesbare Datei an und überschreibt nie eine vorhandene", async () => {
    const path = file("init.kdbx");
    const first = await cli(["init", path, "--name", "Testtresor"]);
    expect(first.code).toBe(0);
    const vault = await open(path);
    expect(vault.meta.databaseName).toBe("Testtresor");
    expect(vault.meta.recycleBinEnabled).toBe(true);

    const before = readFileSync(path);
    const again = await cli(["init", path]);
    expect(again.code).toBe(1);
    expect(again.fake.err.join("\n")).toContain("gibt es schon");
    expect(readFileSync(path).equals(before)).toBe(true);
  });

  it("init am Terminal: neues Master-Passwort zweimal; stimmen die Eingaben nicht überein, entsteht nichts", async () => {
    const path = file("init-tty.kdbx");
    const mismatch = await cli(["init", path], fakeIo({}, ["eins", "zwei"], true));
    expect(mismatch.code).toBe(1);
    expect(existsSync(path)).toBe(false);

    const ok = await cli(["init", path], fakeIo({}, [MASTER, MASTER], true));
    expect(ok.code).toBe(0);
    expect(ok.fake.questions).toHaveLength(2);
    expect((await open(path)).root.entries).toEqual([]);
  });

  it("add / ls / show: Passwörter erscheinen nur bei show --reveal", async () => {
    const path = file("geheim.kdbx");
    await cli(["init", path]);
    const add = await cli(
      ["add", path, "--title", "Mail", "--user", "alice", "--url", "https://mail.example", "--password"],
      fakeIo({ [ENV.master]: MASTER, [ENV.entryPassword]: ENTRY_PASSWORD }),
    );
    expect(add.code).toBe(0);

    const ls = await cli(["ls", path]);
    expect(ls.fake.out).toEqual(["Pfad\tBenutzername\tURL", "Mail\talice\thttps://mail.example"]);
    const show = await cli(["show", path, "Mail"]);
    expect(show.fake.out).toContain("Passwort: ****** (geschützt)");
    expect(show.fake.out).toContain("Benutzername: alice");
    const reveal = await cli(["show", path, "Mail", "--reveal"]);
    expect(reveal.fake.out).toContain(`Passwort: ${ENTRY_PASSWORD}`);

    for (const run of [add, ls, show]) {
      expect(run.fake.all()).not.toContain(ENTRY_PASSWORD);
      expect(run.fake.all()).not.toContain(MASTER);
    }
    expect(reveal.fake.all()).not.toContain(MASTER);
  });

  it("add ohne Umgebungsvariablen fragt Master- und Eintragspasswort verdeckt ab", async () => {
    const path = file("abfrage.kdbx");
    await cli(["init", path]);
    const add = await cli(["add", path, "--title", "Forum", "--password"], fakeIo({}, [MASTER, ENTRY_PASSWORD]));
    expect(add.code).toBe(0);
    expect(add.fake.questions).toEqual([`Master-Passwort für ${path}: `, "Passwort für den neuen Eintrag: "]);
    expect((await open(path)).root.entries[0]!.strings.get("Password")).toEqual({ value: ENTRY_PASSWORD, protected: true });
  });

  it("set: geschützte Werte nur über „-“ (Umgebung/Abfrage), nie von der Kommandozeile", async () => {
    const path = file("set.kdbx");
    await cli(["init", path]);
    await cli(["add", path, "--title", "Bank"]);

    expect((await cli(["set", path, "Bank", "user", "bob"])).code).toBe(0);
    const before = readFileSync(path);
    const inline = await cli(["set", path, "Bank", "Password", "von-der-kommandozeile"], fakeIo({}, [MASTER]));
    expect(inline.code).toBe(2);
    expect(inline.fake.questions).toEqual([]); // abgelehnt, bevor überhaupt etwas abgefragt wurde
    expect(inline.fake.all()).not.toContain("von-der-kommandozeile");
    expect(readFileSync(path).equals(before)).toBe(true);

    expect((await cli(["set", path, "Bank", "Password", "-"], fakeIo({ [ENV.master]: MASTER, [ENV.fieldValue]: "bank-pw" }))).code).toBe(0);
    expect((await cli(["set", path, "Bank", "PIN", "-", "--protect"], fakeIo({ [ENV.master]: MASTER }, ["4711"]))).code).toBe(0);
    const pinInline = await cli(["set", path, "Bank", "PIN", "1234"]); // PIN ist jetzt geschützt
    expect(pinInline.code).toBe(2);
    expect(pinInline.fake.all()).not.toContain("1234");

    const bank = (await open(path)).root.entries[0]!;
    expect(bank.strings.get("UserName")).toEqual({ value: "bob", protected: false });
    expect(bank.strings.get("Password")).toEqual({ value: "bank-pw", protected: true });
    expect(bank.strings.get("PIN")).toEqual({ value: "4711", protected: true });
  });

  it("attach hängt Binärdaten byte-genau an; rm verschiebt in den Papierkorb, dort endgültig", async () => {
    const path = file("anhang.kdbx");
    await cli(["init", path]);
    await cli(["add", path, "--title", "Mail"]);
    const scan = new Uint8Array(randomBytes(5000));
    writeFileSync(file("scan.bin"), scan);
    const attach = await cli(["attach", path, "Mail", file("scan.bin")]);
    expect(attach.fake.out).toEqual(["Anhang „scan.bin“ (5000 Byte) an „Mail“ gespeichert."]);
    const uuid = (await open(path)).root.entries[0]!.uuid;
    expect(Buffer.from(findEntry(await open(path), uuid)!.attachments[0]!.data).equals(Buffer.from(scan))).toBe(true);

    expect((await cli(["rm", path, "Mail"])).fake.out).toEqual(["„Mail“ in den Papierkorb verschoben."]);
    expect((await cli(["ls", path])).fake.out[1]).toMatch(/^Papierkorb\/Mail\t/);
    expect((await cli(["rm", path, "Papierkorb/Mail"])).fake.out).toEqual(["„Mail“ endgültig gelöscht."]);
    const vault = await open(path);
    expect(findEntry(vault, uuid)).toBeUndefined();
    expect(vault.deletedObjects.map((item) => item.uuid)).toEqual([uuid]);
  });

  it("Gruppen, mehrdeutige Titel und Pfade", async () => {
    const path = file("gruppen.kdbx");
    await cli(["init", path]);
    await cli(["add", path, "--title", "Login", "--group", "Arbeit/Intern"]);
    await cli(["add", path, "--title", "Login", "--group", "Privat"]);
    expect((await cli(["add", path, "--title", "Login", "--group", "Privat"])).code).toBe(1);

    const ambiguous = await cli(["show", path, "Login"]);
    expect(ambiguous.code).toBe(1);
    expect(ambiguous.fake.err.join("\n")).toContain("mehrdeutig (Arbeit/Intern/Login, Privat/Login)");
    expect((await cli(["show", path, "Privat/Login"])).code).toBe(0);
    expect(titles(await open(path))).toEqual(["Login", "Login"]);
  });

  it("falsches Master-Passwort: klare Meldung, Exit 1, Datei unverändert", async () => {
    const path = file("falsch.kdbx");
    await cli(["init", path]);
    const before = readFileSync(path);
    const wrong = await cli(["add", path, "--title", "X"], fakeIo({ [ENV.master]: "falsch" }));
    expect(wrong.code).toBe(1);
    expect(wrong.fake.err).toEqual(["Fehler: Falsches Master-Passwort (oder falsche Datei)."]);
    expect(readFileSync(path).equals(before)).toBe(true);
  });

  it("überzählige Argumente (oft ein versehentlich eingetipptes Passwort) werden nicht wiederholt", async () => {
    const path = file("argumente.kdbx");
    await cli(["init", path]);
    const extra = await cli(["ls", path, "MeinGeheimesPasswort"], fakeIo({}, [MASTER]));
    expect(extra.code).toBe(2);
    expect(extra.fake.all()).not.toContain("MeinGeheimesPasswort");
    expect(extra.fake.questions).toEqual([]);
  });

  it("sync lehnt Zugangsdaten in der Adresse ab, bevor etwas abgefragt oder ausgegeben wird", async () => {
    const run = await cli(["sync", file("x.kdbx"), "--url", "https://alice:pw-in-url-123@cloud.example/t.kdbx", "--user", "alice"], fakeIo({}, [MASTER, "x"]));
    expect(run.code).toBe(2);
    expect(run.fake.questions).toEqual([]);
    expect(run.fake.all()).not.toContain("pw-in-url-123");
    const folder = await cli(["sync", file("x.kdbx"), "--url", "https://cloud.example/ordner/", "--user", "alice"], fakeIo({}, [MASTER, "x"]));
    expect(folder.code).toBe(2);
    expect(folder.fake.questions).toEqual([]);
  });
});

describe("writeFileAtomic", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("atomic-file");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("schreibt und ersetzt; es bleibt keine temporäre Datei zurück; Rechte nur für den Besitzer", () => {
    const path = join(dir, "lokal.kdbx");
    writeFileAtomic(path, Uint8Array.from([1, 2, 3]));
    writeFileAtomic(path, Uint8Array.from([4, 5]));
    expect([...readFileSync(path)]).toEqual([4, 5]);
    expect(readdirSync(dir)).toEqual(["lokal.kdbx"]);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("scheitert das Umbenennen, bleibt das Ziel unverändert und die temporäre Datei wird entfernt", () => {
    const target = join(dir, "ordner-statt-datei");
    mkdirSync(target);
    writeFileSync(join(target, "inhalt.txt"), "bleibt");
    expect(() => writeFileAtomic(target, Uint8Array.from([9]))).toThrow();
    expect(readFileSync(join(target, "inhalt.txt"), "utf8")).toBe("bleibt");
    expect(readdirSync(dir).filter((name) => name.endsWith(".tmp"))).toEqual([]);
  });
});

describe.skipIf(!webDavTestServerAvailable())("Kommandozeile: sync gegen den SabreDAV-Testserver", () => {
  let server: WebDavTestServer;
  let dir: string;
  beforeAll(async () => {
    server = await startWebDavTestServer("proto-sync");
    dir = createTmpDir("proto-sync");
    mkdirSync(join(server.dataDir, "Ownwarden"));
  });
  afterAll(async () => {
    await server?.stop();
    if (dir) removeTmpDir(dir);
  });

  it("Vivaldi legt an und lädt hoch, Chrome holt die Datei, ändert, lädt hoch; Vivaldi übernimmt", async () => {
    const url = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const env = { [ENV.master]: MASTER, [ENV.webdav]: server.password };
    const sync = (path: string) => cli(["sync", path, "--url", url, "--user", server.username], fakeIo(env));
    const vivaldi = join(dir, "vivaldi.kdbx");
    const chrome = join(dir, "chrome.kdbx");

    await cli(["init", vivaldi]);
    await cli(["add", vivaldi, "--title", "Mail", "--user", "alice"]);
    const created = await sync(vivaldi);
    expect(created.code).toBe(0);
    expect(created.fake.out).toContain("Datei auf dem Server neu angelegt.");

    const fetched = await sync(chrome);
    expect(fetched.code).toBe(0);
    expect(fetched.fake.out.join("\n")).toContain("Server-Fassung");
    await cli(["set", chrome, "Mail", "UserName", "alice-chrome"]);
    const uploaded = await sync(chrome);
    expect(uploaded.fake.out).toContain("Zusammengeführt und hochgeladen.");

    const updated = await sync(vivaldi);
    expect(updated.code).toBe(0);
    expect(updated.fake.out).toContain("Server war schon aktuell – nichts hochgeladen.");
    expect((await cli(["ls", vivaldi])).fake.out[1]).toBe("Mail\talice-chrome\t");

    for (const run of [created, fetched, uploaded, updated]) {
      expect(run.fake.all()).not.toContain(server.password);
      expect(run.fake.all()).not.toContain(MASTER);
    }
  });

  it("falsches WebDAV-Passwort: Meldung ohne Passwort, lokale Datei unverändert", async () => {
    const url = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const path = join(dir, "falsches-webdav.kdbx");
    await cli(["init", path]);
    const before = readFileSync(path);
    const run = await cli(["sync", path, "--url", url, "--user", server.username], fakeIo({ [ENV.master]: MASTER, [ENV.webdav]: "falsches-webdav-pw" }));
    expect(run.code).toBe(1);
    expect(run.fake.err.join("\n")).toMatch(/Anmeldung .* abgelehnt/);
    expect(run.fake.all()).not.toContain("falsches-webdav-pw");
    expect(readFileSync(path).equals(before)).toBe(true);
  });
});

describe("Kommandozeile als echtes Programm (npm run proto / tsx)", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("proto-spawn");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  /** Startet ein Programm im Ordner core/ und liefert Exit-Code und Ausgaben. */
  function run(command: string, args: string[], stdin: string, env: Record<string, string> = {}) {
    return new Promise<{ code: number; stdout: string; stderr: string }>((resolvePromise, reject) => {
      const cleanEnv = { ...process.env, ...env };
      for (const name of Object.values(ENV)) if (!(name in env)) delete cleanEnv[name];
      const child = spawn(command, args, { cwd: CORE_DIR, env: cleanEnv, stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
      child.on("error", reject);
      child.on("close", (code) => resolvePromise({ code: code ?? -1, stdout, stderr }));
      child.stdin.end(stdin);
    });
  }

  it("npm run proto -- --help", async () => {
    const result = await run("npm", ["run", "--silent", "proto", "--", "--help"], "");
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("NUR FÜR TESTDATEN");
  });

  it("Passwörter über eine Pipe: mehrere Abfragen nacheinander (Master-, dann Eintragspasswort)", async () => {
    const path = join(dir, "pipe.kdbx");
    expect((await cli(["init", path])).code).toBe(0); // schnelle KDF (Test)
    const tsx = join(CORE_DIR, "node_modules", ".bin", "tsx");
    const add = await run(tsx, ["src/cli/ownwarden-proto.ts", "add", path, "--title", "Pipe", "--password"], `${MASTER}\n${ENTRY_PASSWORD}\n`);
    expect(add.code).toBe(0);
    expect(add.stdout).toContain("Eintrag „Pipe“ angelegt.");
    expect(add.stdout + add.stderr).not.toContain(ENTRY_PASSWORD);

    const show = await run(tsx, ["src/cli/ownwarden-proto.ts", "show", path, "Pipe", "--reveal"], "", { [ENV.master]: MASTER });
    expect(show.code).toBe(0);
    expect(show.stdout).toContain(`Passwort: ${ENTRY_PASSWORD}`);
  });
});
