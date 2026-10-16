/**
 * Die Befehle aus core/README.md funktionieren so, wie sie dort stehen.
 *
 * Der Test liest die bash-Blöcke der Abschnitte „Die Kommandozeile ausprobieren“ und
 * „WebDAV-Servertest“ direkt aus der README und führt jede Zeile der Reihe nach aus:
 *   - `npm run proto -- …`        über runCli (dieselbe Funktion wie das Programm),
 *   - `npm run webdav-probe -- …` über main() des Servertests,
 *   - `NAME=wert` setzt eine Variable, `cd core` wird übersprungen.
 * Ersetzt wird nur, was auf dem Rechner des Nutzers anders ist: die MagentaCLOUD-/Nextcloud-
 * Adresse und der Benutzername (-> SabreDAV-Testserver), Dateinamen (-> eigener Testordner)
 * und die verdeckten Passwort-Eingaben (-> Umgebungsvariablen). Ändert jemand die README,
 * prüft dieser Test die neuen Befehle mit.
 * Wird übersprungen, wenn PHP/SabreDAV fehlen.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CORE_DIR, createTmpDir, removeTmpDir } from "./helpers/keepassxc";
import { TEST_KDF } from "./helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "./helpers/webdav-server";
import { ENV, runCli, type CliIo } from "../src/cli/ownwarden-proto";
import { main as probeMain } from "../src/cli/webdav-probe";

const README = readFileSync(join(CORE_DIR, "README.md"), "utf8");
const MASTER = "Readme-Test-Master-5z";

/** Text eines Abschnitts (ab der Überschrift bis zur nächsten gleichrangigen). */
function section(heading: string): string {
  const start = README.indexOf(`\n## ${heading}`);
  if (start < 0) throw new Error(`Abschnitt „${heading}“ fehlt in der README`);
  const end = README.indexOf("\n## ", start + 1);
  return README.slice(start, end < 0 ? undefined : end);
}

/** Alle ```bash-Blöcke eines Abschnitts als Zeilen (ohne Kommentare, ohne Leerzeilen). */
function bashBlocks(text: string): string[][] {
  return [...text.matchAll(/```bash\n([\s\S]*?)```/g)].map((match) =>
    match[1]!
      .split("\n")
      .map((line) => stripComment(line).trim())
      .filter((line) => line !== ""),
  );
}

/** Entfernt einen Kommentar „ # …“ außerhalb von Anführungszeichen. */
function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const char = line[i]!;
    if (quote !== null) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "#" && (i === 0 || /\s/.test(line[i - 1]!))) {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Zerlegt eine Zeile wie die Shell in Wörter (Anführungszeichen, $VAR). */
function shellWords(line: string, vars: Record<string, string>): string[] {
  const words: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  for (const match of line.matchAll(pattern)) {
    const raw = match[1] ?? match[2] ?? match[3]!;
    words.push(match[2] !== undefined ? raw : raw.replace(/\$(\w+)/g, (_all, name: string) => vars[name] ?? ""));
  }
  return words;
}

describe.skipIf(!webDavTestServerAvailable())("README: jeder Befehl funktioniert wie beschrieben", () => {
  let server: WebDavTestServer;
  let dir: string;
  beforeAll(async () => {
    server = await startWebDavTestServer("readme");
    dir = createTmpDir("readme");
    mkdirSync(join(server.dataDir, "Ownwarden-Test"));
    writeFileSync(join(dir, "rechnung.pdf"), "%PDF-1.4 Testrechnung");
  });
  afterAll(async () => {
    await server?.stop();
    if (dir) removeTmpDir(dir);
  });

  /** Ersetzt Cloud-Adressen, Benutzernamen und Dateipfade durch die des Testaufbaus. */
  function localize(word: string): string {
    const cloud = /^https:\/\/(magentacloud\.de\/remote\.php\/webdav|cloud\.example\.de\/remote\.php\/dav\/files\/<benutzer>)\//;
    if (cloud.test(word)) return word.replace(cloud, server.baseUrl);
    if (word === "name@t-online.de" || word === "<benutzer>") return server.username;
    if (/\.(kdbx|pdf)$/.test(word) && !word.includes("/")) return join(dir, word);
    if (word.startsWith("./")) return join(dir, word.slice(2));
    return word;
  }

  /** Führt die Zeilen eines Blocks aus; liefert pro Befehl den Exit-Code und die Ausgabe. */
  async function runBlock(lines: string[]): Promise<{ line: string; code: number; output: string }[]> {
    const vars: Record<string, string> = {};
    const results: { line: string; code: number; output: string }[] = [];
    for (const line of lines) {
      const assignment = /^(\w+)=(\S+)$/.exec(line);
      if (assignment) {
        vars[assignment[1]!] = localize(assignment[2]!);
        continue;
      }
      const words = shellWords(line, vars);
      if (words.join(" ") === "cd core") continue;
      const [npm, run, script, separator, ...args] = words;
      expect([npm, run, separator], line).toEqual(["npm", "run", "--"]);
      const localArgs = args.map(localize);
      const output: string[] = [];
      let code: number;
      if (script === "proto") {
        const io: CliIo = {
          env: {
            [ENV.master]: MASTER,
            [ENV.webdav]: server.password,
            [ENV.entryPassword]: "Readme-Eintrag-pw",
            [ENV.fieldValue]: "Readme-Feldwert",
          },
          out: (text) => output.push(text),
          err: (text) => output.push(text),
          promptHidden: async () => {
            throw new Error("Abfrage trotz Umgebungsvariable");
          },
          interactive: false,
          newVaultKdf: TEST_KDF,
        };
        code = await runCli(localArgs, io);
      } else if (script === "webdav-probe") {
        vi.stubEnv("OWNWARDEN_WEBDAV_PASSWORD", server.password);
        const log = vi.spyOn(console, "log").mockImplementation((text: unknown) => void output.push(String(text)));
        const error = vi.spyOn(console, "error").mockImplementation((text: unknown) => void output.push(String(text)));
        try {
          code = await probeMain(localArgs);
        } finally {
          log.mockRestore();
          error.mockRestore();
          vi.unstubAllEnvs();
        }
      } else {
        throw new Error(`Unbekanntes Skript in der README: ${line}`);
      }
      results.push({ line, code, output: output.join("\n") });
    }
    return results;
  }

  it("Kommandozeile: beide Blöcke laufen der Reihe nach ohne Fehler durch", async () => {
    const blocks = bashBlocks(section("Die Kommandozeile ausprobieren"));
    expect(blocks.length).toBeGreaterThanOrEqual(2);
    for (const block of blocks) {
      for (const result of await runBlock(block)) {
        expect(result.code, `${result.line}\n${result.output}`).toBe(0);
        expect(result.output, result.line).not.toContain(MASTER);
        expect(result.output, result.line).not.toContain(server.password);
      }
    }
  });

  it("WebDAV-Servertest: die Aufrufe aus der Anleitung laufen und melden „sicher“ (Exit 0)", async () => {
    const blocks = bashBlocks(section("WebDAV-Servertest: MagentaCLOUD und Nextcloud prüfen"));
    expect(blocks.length).toBeGreaterThanOrEqual(2);
    for (const block of blocks) {
      for (const result of await runBlock(block)) {
        expect(result.code, `${result.line}\n${result.output}`).toBe(0);
        expect(result.output, result.line).not.toContain(server.password);
      }
    }
  });
});
