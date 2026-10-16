/**
 * Kommandozeile des Prototyps: gezielte Gegenproben (Prüfung der Etappe „Zusammenführen,
 * CLI, Anleitung“). Jeder Test beschreibt eine Vermutung, wie die Kommandozeile ein
 * Geheimnis verraten könnte.
 *
 *   - Ein Passwort-Feld OHNE Schutz-Flag (z. B. aus KeePass mit abgeschaltetem Speicherschutz
 *     „ProtectPassword“) oder ein ungeschützter privater Passkey-Schlüssel darf bei `show`
 *     ohne --reveal trotzdem nicht im Klartext erscheinen.
 *   - Eine unbekannte Option (z. B. ein versehentlich eingetipptes Passwort, das mit „-“
 *     beginnt) darf in der Fehlermeldung nicht wiederholt werden.
 *   - Am echten Terminal (Pseudo-Terminal über `script`) erscheinen eingetippte Passwörter
 *     nicht auf dem Bildschirm (kein Echo).
 */
import { spawn, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CORE_DIR, createTmpDir, removeTmpDir } from "../../test/helpers/keepassxc";
import { TEST_KDF } from "../../test/helpers/kdbx-files";
import { readKdbx, writeKdbx } from "../kdbx/index";
import { createVaultClock } from "../merge/clock";
import { setField, setPasskey } from "../merge/vault-ops";
import { ENV, runCli, type CliIo } from "./ownwarden-proto";
import { main as probeMain } from "./webdav-probe";

const MASTER = "Proto-Gegenprobe-Master-4k2";

function fakeIo(env: Record<string, string> = { [ENV.master]: MASTER }) {
  const lines: string[] = [];
  const io: CliIo = {
    env,
    out: (line) => lines.push(line),
    err: (line) => lines.push(line),
    promptHidden: async () => "",
    interactive: false,
    newVaultKdf: TEST_KDF,
  };
  return { io, all: () => lines.join("\n") };
}

async function cli(args: string[], env?: Record<string, string>): Promise<{ code: number; output: string }> {
  const fake = fakeIo(env);
  const code = await runCli(args, fake.io);
  return { code, output: fake.all() };
}

describe("Kommandozeile: Gegenproben zum Umgang mit Geheimnissen", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("proto-adversarial");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("show ohne --reveal verdeckt auch ein Passwort ohne Schutz-Flag und einen ungeschützten privaten Passkey-Schlüssel", async () => {
    const path = join(dir, "ungeschuetzt.kdbx");
    expect((await cli(["init", path])).code).toBe(0);
    expect((await cli(["add", path, "--title", "Alt"])).code).toBe(0);

    // So sieht eine Datei aus, deren Programm Passwörter nicht schützt (KeePass mit
    // MemoryProtection/ProtectPassword = False) bzw. deren Passkey-Schlüssel ohne Schutz ist.
    const vault = await readKdbx(new Uint8Array(readFileSync(path)), { password: MASTER });
    const entry = vault.root.entries[0]!;
    const clock = createVaultClock(vault);
    setField(vault, entry.uuid, "Password", "klartext-pw-ohne-flag", { protected: false }, clock);
    setPasskey(
      vault,
      entry.uuid,
      {
        KPEX_PASSKEY_USERNAME: "alice",
        KPEX_PASSKEY_PRIVATE_KEY_PEM: { value: "-----BEGIN PRIVATE KEY-----\nTESTSCHLUESSEL\n-----END PRIVATE KEY-----", protected: false },
      },
      clock,
    );
    writeFileSync(path, await writeKdbx(vault, { password: MASTER }));
    const stored = (await readKdbx(new Uint8Array(readFileSync(path)), { password: MASTER })).root.entries[0]!;
    expect(stored.strings.get("Password")).toEqual({ value: "klartext-pw-ohne-flag", protected: false });

    const show = await cli(["show", path, "Alt"]);
    expect(show.code).toBe(0);
    expect(show.output).not.toContain("klartext-pw-ohne-flag");
    expect(show.output).not.toContain("TESTSCHLUESSEL");
    expect(show.output).toContain("Benutzername"); // sonst wäre die Probe sinnlos (leere Ausgabe)

    const reveal = await cli(["show", path, "Alt", "--reveal"]);
    expect(reveal.output).toContain("klartext-pw-ohne-flag");
    expect(reveal.output).toContain("TESTSCHLUESSEL");
  });

  it("eine unbekannte Option (oft ein versehentlich eingetipptes Passwort) wird nicht wiederholt", async () => {
    const path = join(dir, "option.kdbx");
    await cli(["init", path]);
    await cli(["add", path, "--title", "Mail"]);
    for (const args of [
      ["set", path, "Mail", "Password", "--Geheim-mit-Strichen-77"],
      ["ls", path, "--Geheim-mit-Strichen-77"],
    ]) {
      const run = await cli(args);
      expect(run.code).toBe(2);
      expect(run.output).not.toContain("Geheim-mit-Strichen-77");
      expect(run.output).toContain("--help");
    }
  });
});

describe("Kommandozeile: Gegenprobe Papierkorb", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("proto-adversarial-bin");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("add --group legt weder in den Papierkorb noch in eine Untergruppe davon an; die Datei bleibt unverändert", async () => {
    const path = join(dir, "papierkorb.kdbx");
    await cli(["init", path]);
    await cli(["add", path, "--title", "Alt"]);
    expect((await cli(["rm", path, "Alt"])).code).toBe(0); // legt den Papierkorb „Papierkorb“ an
    const before = readFileSync(path);
    for (const group of ["Papierkorb", "Papierkorb/Unterordner"]) {
      const run = await cli(["add", path, "--title", "Neu", "--group", group]);
      expect(run.code, group).toBe(1);
      expect(run.output, group).toContain("Papierkorb");
    }
    expect(readFileSync(path).equals(before)).toBe(true);
  });
});

describe("WebDAV-Servertest (Kommandozeile): Gegenprobe zu unbekannten Optionen", () => {
  it("eine unbekannte Option wird nicht wiederholt (Exit 2), es wird nichts abgefragt", async () => {
    const output: string[] = [];
    const log = vi.spyOn(console, "log").mockImplementation((text: unknown) => void output.push(String(text)));
    const error = vi.spyOn(console, "error").mockImplementation((text: unknown) => void output.push(String(text)));
    try {
      const code = await probeMain(["--url", "https://cloud.example/ordner/", "--user", "alice", "--Geheim-mit-Strichen-88"]);
      expect(code).toBe(2);
    } finally {
      log.mockRestore();
      error.mockRestore();
    }
    expect(output.join("\n")).not.toContain("Geheim-mit-Strichen-88");
    expect(output.join("\n")).toContain("Aufruf:");
  });
});

/** true, wenn `script` (util-linux) ein Pseudo-Terminal bereitstellen kann. */
function hasScript(): boolean {
  const result = spawnSync("script", ["-qfec", "true", "/dev/null"], { encoding: "utf8" });
  return result.error === undefined && result.status === 0;
}

describe.skipIf(process.platform === "win32" || !hasScript())("Kommandozeile am echten Terminal (Pseudo-Terminal)", () => {
  let dir: string;
  beforeAll(() => {
    dir = createTmpDir("proto-tty");
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  /**
   * Startet die Kommandozeile in einem Pseudo-Terminal (`script`) und tippt auf jede
   * Passwort-Abfrage die nächste Antwort. Ohne Rohmodus würde das Terminal jede Eingabe
   * sofort wieder ausgeben (Echo) – genau das prüft der Test.
   */
  function runInTerminal(args: string[], answers: string[]): Promise<{ code: number; screen: string }> {
    const tsx = join(CORE_DIR, "node_modules", ".bin", "tsx");
    const quoted = [tsx, "src/cli/ownwarden-proto.ts", ...args].map((part) => `'${part.replace(/'/g, "'\\''")}'`).join(" ");
    const env: NodeJS.ProcessEnv = { ...process.env, TERM: "dumb" };
    for (const name of Object.values(ENV)) delete env[name];
    return new Promise((resolvePromise, reject) => {
      const child = spawn("script", ["-qfec", quoted, "/dev/null"], { cwd: CORE_DIR, env, stdio: ["pipe", "pipe", "pipe"] });
      let screen = "";
      let typed = 0;
      const timer = setTimeout(() => child.kill(), 30_000);
      child.stdout.on("data", (chunk: Buffer) => {
        screen += chunk.toString("utf8");
        const prompts = (screen.match(/(Passwort[^:\n]*|wiederholen): /g) ?? []).length;
        // Kurz warten, bis der Rohmodus sicher eingeschaltet ist, dann tippen (mit Enter = \r).
        while (typed < prompts && typed < answers.length) {
          const answer = answers[typed++]!;
          setTimeout(() => child.stdin.write(`${answer}\r`), 150);
        }
      });
      child.stderr.on("data", (chunk: Buffer) => (screen += chunk.toString("utf8")));
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(timer);
        resolvePromise({ code: code ?? -1, screen });
      });
    });
  }

  it("Master- und Eintragspasswort werden verdeckt eingegeben (kein Echo), der Eintrag hat das Passwort", async () => {
    const path = join(dir, "terminal.kdbx");
    expect((await cli(["init", path])).code).toBe(0); // schnelle KDF (Test)
    const entryPassword = "Tippt-Niemand-Mit-91";
    const run = await runInTerminal(["add", path, "--title", "Terminal", "--password"], [MASTER, entryPassword]);

    expect(run.screen).toContain("Master-Passwort für");
    expect(run.screen).toContain("Passwort für den neuen Eintrag: ");
    expect(run.screen).toContain("Eintrag „Terminal“ angelegt.");
    expect(run.screen).not.toContain(MASTER);
    expect(run.screen).not.toContain(entryPassword);
    expect(run.code).toBe(0);
    const vault = await readKdbx(new Uint8Array(readFileSync(path)), { password: MASTER });
    expect(vault.root.entries[0]!.strings.get("Password")).toEqual({ value: entryPassword, protected: true });
  }, 40_000);
});
