/**
 * Test-Hilfen für die Zusammenarbeit mit KeePassXC (Programm `keepassxc-cli`, getestet mit 2.7.6).
 *
 * KeePassXC ist die Referenz: Was Ownwarden schreibt, muss KeePassXC öffnen können, und
 * was KeePassXC schreibt, muss Ownwarden lesen können. Diese Datei kapselt die Aufrufe,
 * damit alle Tests sie gleich benutzen.
 *
 * Wichtig zu wissen:
 *   - `keepassxc-cli` liest Passwörter von der Standardeingabe, wenn diese kein Terminal ist
 *     (eine Zeile pro Abfrage). Passwörter stehen deshalb NIE in der Kommandozeile.
 *   - `keepassxc-cli db-create` legt in Version 2.7.6 eine KDBX-**3.1**-Datei mit AES-KDF an!
 *     KeePassXC schreibt KDBX 4 nur, wenn die Datenbank ein KDBX-4-Merkmal nutzt (z. B.
 *     CustomData an einer Gruppe) oder die KDF nicht AES-KDF ist. `createKpxcDb` legt die
 *     Datenbank deshalb über `keepassxc-cli import` aus einer kleinen XML-Vorlage an, deren
 *     Wurzelgruppe einen CustomData-Eintrag hat (für 4.1 zusätzlich ein Gruppen-Tag).
 *   - Die kürzeste erlaubte Entschlüsselungszeit (`-t`) ist 100 ms. KeePassXC-CLI wählt
 *     dann AES-KDF mit einigen Millionen Runden (abhängig vom Rechner).
 *   - Ist KeePassXC nicht installiert, sollen Tests sauber übersprungen werden:
 *       describe.skipIf(!hasKeepassxc())("…", () => { … })
 *     Mit OWNWARDEN_REQUIRE_TOOLS=1 (strenger Modus, siehe toolAvailable) ist das Fehlen dagegen
 *     ein Fehler.
 *   - Temporäre Dateien gehören nach core/test/.tmp/<eigener Unterordner> (siehe createTmpDir).
 */
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Name bzw. Pfad des Programms; über die Umgebungsvariable KEEPASSXC_CLI änderbar. */
export const KPXC_BIN = process.env.KEEPASSXC_CLI ?? "keepassxc-cli";

/** Ordner `core/` des Repos (für Pfade unabhängig vom aktuellen Arbeitsverzeichnis). */
export const CORE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Ordner für temporäre Testdateien (in .gitignore eingetragen). */
export const TMP_ROOT = join(CORE_DIR, "test", ".tmp");

// ---------------------------------------------------------------------------
// Grundfunktionen
// ---------------------------------------------------------------------------

/**
 * Strenger Modus (Review xc-8): Mit OWNWARDEN_REQUIRE_TOOLS=1 ist ein fehlendes Werkzeug
 * (keepassxc-cli; PHP/SabreDAV für den WebDAV-Testserver) ein FEHLER statt eines übersprungenen
 * Tests. Sonst gilt ein Lauf auf einem Rechner ohne diese Werkzeuge als grün, obwohl kein
 * einziger Interop-Test lief. Vor dem Umzug (PROJECT-CONTEXT) und in CI immer so laufen lassen.
 */
export const REQUIRE_TOOLS_ENV = "OWNWARDEN_REQUIRE_TOOLS";

/** Liefert `available`; im strengen Modus wirft es stattdessen, wenn das Werkzeug fehlt. */
export function toolAvailable(available: boolean, tool: string, env: NodeJS.ProcessEnv = process.env): boolean {
  if (!available && env[REQUIRE_TOOLS_ENV] === "1") {
    throw new Error(`${tool} fehlt, aber ${REQUIRE_TOOLS_ENV}=1 verlangt, dass alle Interop-Tests laufen (statt übersprungen zu werden).`);
  }
  return available;
}

let available: boolean | undefined;

/** true, wenn `keepassxc-cli` aufrufbar ist. Das Ergebnis wird zwischengespeichert. */
export function hasKeepassxc(): boolean {
  if (available === undefined) {
    const result = spawnSync(KPXC_BIN, ["--version"], { encoding: "utf8" });
    available = result.error === undefined && result.status === 0;
  }
  return toolAvailable(available, `KeePassXC (Programm „${KPXC_BIN}“)`);
}

/** Ergebnis eines Aufrufs von `keepassxc-cli`. */
export interface KpxcResult {
  /** Exit-Code (0 = Erfolg). */
  code: number;
  /** Standardausgabe als Text (UTF-8). */
  stdout: string;
  /** Standardausgabe als rohe Bytes (für Anhänge NICHT geeignet, siehe exportKpxcAttachment). */
  stdoutBytes: Uint8Array;
  /** Fehlerausgabe; enthält auch die Passwort-Abfragen („Enter password …“), nie die Passwörter. */
  stderr: string;
}

/**
 * Ruft `keepassxc-cli` mit den Argumenten auf und schreibt `stdin` in die Standardeingabe
 * (z. B. "passwort\n"). Wirft nur, wenn das Programm gar nicht startet; einen Exit-Code
 * ungleich 0 muss der Aufrufer selbst prüfen (oder `runKpxcOk` benutzen).
 */
export function runKpxc(args: string[], stdin = ""): Promise<KpxcResult> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(KPXC_BIN, args, { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      const stdoutBytes = new Uint8Array(Buffer.concat(out));
      resolvePromise({
        code: code ?? -1,
        stdout: Buffer.from(stdoutBytes).toString("utf8"),
        stdoutBytes,
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
    child.stdin.on("error", () => {
      // Das Programm hat die Eingabe evtl. schon geschlossen (z. B. bei einem Fehler) – egal.
    });
    child.stdin.end(stdin);
  });
}

/** Wie runKpxc, wirft aber einen Fehler mit der Fehlerausgabe, wenn der Exit-Code nicht 0 ist. */
export async function runKpxcOk(args: string[], stdin = ""): Promise<KpxcResult> {
  const result = await runKpxc(args, stdin);
  if (result.code !== 0) {
    // Nur den Befehlsnamen nennen, nicht alle Argumente (die enthalten Pfade, nie Passwörter).
    throw new Error(`keepassxc-cli ${args[0]} schlug fehl (Code ${result.code}): ${result.stderr.trim()}`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Zugangsdaten
// ---------------------------------------------------------------------------

/**
 * Zugang zu einer Datenbank: entweder nur ein Passwort (string) oder Passwort und/oder
 * Schlüsseldatei. Ohne Passwort wird `--no-password` übergeben.
 */
export type KpxcAuth = string | { password?: string; keyFile?: string };

/** Kommandozeilen-Optionen und Standardeingabe für das Entsperren einer Datenbank. */
function unlockArgs(auth: KpxcAuth): { args: string[]; stdin: string } {
  const { password, keyFile } = typeof auth === "string" ? { password: auth, keyFile: undefined } : auth;
  const args: string[] = [];
  if (keyFile !== undefined) args.push("-k", keyFile);
  if (password === undefined) {
    args.push("--no-password");
    return { args, stdin: "" };
  }
  return { args, stdin: `${password}\n` };
}

// ---------------------------------------------------------------------------
// Datenbanken anlegen
// ---------------------------------------------------------------------------

export interface CreateKpxcDbOptions {
  /** Ziel-Entschlüsselungszeit in ms (KeePassXC erlaubt 100..5000). Standard 100. */
  decryptionTimeMs?: number;
  /** KDBX-Version der neuen Datei. Standard "4.0". */
  version?: "4.0" | "4.1";
  /** Optional: Schlüsseldatei, die zusätzlich zum Passwort gilt. */
  keyFile?: string;
}

/**
 * Legt mit KeePassXC eine neue, leere KDBX-4-Datenbank an (AES-256, AES-KDF, GZip).
 * Die Wurzelgruppe heißt "Root" und trägt den CustomData-Eintrag "Ownwarden.Test" – der
 * zwingt KeePassXC zu KDBX 4 (siehe Kopfkommentar). Für "4.1" bekommt sie außerdem das
 * Tag "kdbx41".
 */
export async function createKpxcDb(path: string, password: string, options: CreateKpxcDbOptions = {}): Promise<void> {
  const uuid = randomBytes(16).toString("base64");
  const tags = options.version === "4.1" ? "<Tags>kdbx41</Tags>" : "";
  const xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<KeePassFile>
  <Meta><Generator>Ownwarden-Test</Generator></Meta>
  <Root>
    <Group>
      <UUID>${uuid}</UUID>
      <Name>Root</Name>${tags}
      <CustomData><Item><Key>Ownwarden.Test</Key><Value>kdbx4</Value></Item></CustomData>
    </Group>
    <DeletedObjects/>
  </Root>
</KeePassFile>
`;
  await importKpxcXml(xml, path, password, options);
}

/**
 * Legt mit `keepassxc-cli import` eine Datenbank aus XML-Text an (KeePass-XML wie bei
 * `export`). Praktisch, um gezielt Inhalte zu erzeugen, die KeePassXC dann selbst
 * verschlüsselt. Achtung: Ohne KDBX-4-Merkmal in der XML entsteht KDBX 3.1 (s. o.).
 */
export async function importKpxcXml(
  xml: string,
  dbPath: string,
  password: string,
  options: Omit<CreateKpxcDbOptions, "version"> = {},
): Promise<void> {
  const xmlPath = `${dbPath}.import.xml`;
  writeFileSync(xmlPath, xml, "utf8");
  try {
    const args = ["import", "-q", "-p", "-t", String(options.decryptionTimeMs ?? 100)];
    if (options.keyFile !== undefined) args.push("--set-key-file", options.keyFile);
    // -p fragt das neue Passwort zweimal ab (Eingabe und Wiederholung).
    await runKpxcOk([...args, xmlPath, dbPath], `${password}\n${password}\n`);
  } finally {
    rmSync(xmlPath, { force: true });
  }
}

// ---------------------------------------------------------------------------
// Datenbanken ändern
// ---------------------------------------------------------------------------

export interface KpxcEntryOptions {
  username?: string;
  url?: string;
  notes?: string;
  /** Passwort des neuen Eintrags (wird über die Standardeingabe übergeben). */
  password?: string;
}

/**
 * Legt mit KeePassXC einen Eintrag an. `entryPath` ist der Pfad in der Datenbank, z. B.
 * "Mein Eintrag" oder "Gruppe/Mein Eintrag" (die Gruppe muss existieren, siehe mkdirKpxc).
 * KeePassXC speichert die Datei danach neu (mit neuem Master-Seed).
 */
export async function addKpxcEntry(
  dbPath: string,
  auth: KpxcAuth,
  entryPath: string,
  entry: KpxcEntryOptions = {},
): Promise<void> {
  const unlock = unlockArgs(auth);
  const args = ["add", "-q", ...unlock.args];
  if (entry.username !== undefined) args.push("-u", entry.username);
  if (entry.url !== undefined) args.push("--url", entry.url);
  if (entry.notes !== undefined) args.push("--notes", entry.notes);
  let stdin = unlock.stdin;
  if (entry.password !== undefined) {
    args.push("-p");
    stdin += `${entry.password}\n`;
  }
  await runKpxcOk([...args, dbPath, entryPath], stdin);
}

/** Legt eine Gruppe an, z. B. "Banken" oder "Banken/Privat". */
export async function mkdirKpxc(dbPath: string, auth: KpxcAuth, groupPath: string): Promise<void> {
  const unlock = unlockArgs(auth);
  await runKpxcOk(["mkdir", "-q", ...unlock.args, dbPath, groupPath], unlock.stdin);
}

/** Hängt die Datei `filePath` unter dem Namen `attachmentName` an einen Eintrag an. */
export async function importKpxcAttachment(
  dbPath: string,
  auth: KpxcAuth,
  entryPath: string,
  attachmentName: string,
  filePath: string,
): Promise<void> {
  const unlock = unlockArgs(auth);
  await runKpxcOk(
    ["attachment-import", "-q", ...unlock.args, dbPath, entryPath, attachmentName, filePath],
    unlock.stdin,
  );
}

// ---------------------------------------------------------------------------
// Datenbanken lesen
// ---------------------------------------------------------------------------

/**
 * Exportiert die Datenbank als KeePass-XML (Klartext, geschützte Werte unverschlüsselt).
 * Hinweis: Bei KDBX 4 stehen Zeiten darin als Base64 (Sekunden seit Jahr 1), nicht als ISO-Text.
 */
export async function exportKpxcXml(dbPath: string, auth: KpxcAuth): Promise<string> {
  const unlock = unlockArgs(auth);
  return (await runKpxcOk(["export", "-q", ...unlock.args, "-f", "xml", dbPath], unlock.stdin)).stdout;
}

export interface ShowKpxcOptions {
  /** Geschützte Felder (Passwort) im Klartext zeigen. */
  showProtected?: boolean;
  /** Nur diese Attribute ausgeben (je eine Zeile, in dieser Reihenfolge). */
  attributes?: string[];
  /** Anhänge auflisten. */
  showAttachments?: boolean;
}

/** Zeigt einen Eintrag (`keepassxc-cli show`) und liefert die Textausgabe. */
export async function showKpxcEntry(
  dbPath: string,
  auth: KpxcAuth,
  entryPath: string,
  options: ShowKpxcOptions = {},
): Promise<string> {
  const unlock = unlockArgs(auth);
  const args = ["show", "-q", ...unlock.args];
  if (options.showProtected) args.push("-s");
  if (options.showAttachments) args.push("--show-attachments");
  for (const attribute of options.attributes ?? []) args.push("-a", attribute);
  return (await runKpxcOk([...args, dbPath, entryPath], unlock.stdin)).stdout;
}

/**
 * Liest einen Anhang eines Eintrags byte-genau. Achtung: `attachment-export --stdout` ist
 * NICHT binärsicher (KeePassXC 2.7.6 gibt den Inhalt als Text aus; aus 1000 Zufallsbytes
 * werden so 1874 Bytes). Deshalb exportieren wir in eine temporäre Datei neben der Datenbank.
 */
export async function exportKpxcAttachment(
  dbPath: string,
  auth: KpxcAuth,
  entryPath: string,
  attachmentName: string,
): Promise<Uint8Array> {
  const unlock = unlockArgs(auth);
  const outPath = `${dbPath}.export-${randomBytes(4).toString("hex")}.bin`;
  try {
    await runKpxcOk(["attachment-export", "-q", ...unlock.args, dbPath, entryPath, attachmentName, outPath], unlock.stdin);
    return new Uint8Array(readFileSync(outPath));
  } finally {
    rmSync(outPath, { force: true });
  }
}

/** Listet Einträge und Gruppen (`keepassxc-cli ls`); mit `recursive` als vollständige Pfade. */
export async function listKpxc(dbPath: string, auth: KpxcAuth, options: { recursive?: boolean } = {}): Promise<string[]> {
  const unlock = unlockArgs(auth);
  const args = ["ls", "-q", ...unlock.args, ...(options.recursive ? ["-R", "-f"] : []), dbPath];
  const { stdout } = await runKpxcOk(args, unlock.stdin);
  return stdout.split("\n").filter((line) => line.length > 0);
}

/**
 * Liefert die Angaben von `keepassxc-cli db-info` als Schlüssel-Wert-Paare,
 * z. B. { Cipher: "AES 256-bit", KDF: "AES (6666666 rounds)", … }.
 */
export async function kpxcDbInfo(dbPath: string, auth: KpxcAuth): Promise<Record<string, string>> {
  const unlock = unlockArgs(auth);
  const { stdout } = await runKpxcOk(["db-info", "-q", ...unlock.args, dbPath], unlock.stdin);
  const info: Record<string, string> = {};
  for (const line of stdout.split("\n")) {
    const colon = line.indexOf(":");
    if (colon > 0) info[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return info;
}

/** true, wenn KeePassXC die Datenbank mit diesen Zugangsdaten öffnen kann. */
export async function kpxcCanOpen(dbPath: string, auth: KpxcAuth): Promise<boolean> {
  const unlock = unlockArgs(auth);
  return (await runKpxc(["ls", "-q", ...unlock.args, dbPath], unlock.stdin)).code === 0;
}

// ---------------------------------------------------------------------------
// Temporäre Ordner
// ---------------------------------------------------------------------------

/** Legt einen eigenen, leeren Ordner unter core/test/.tmp an (Name + Zufallsendung). */
export function createTmpDir(name: string): string {
  const dir = join(TMP_ROOT, `${name}-${randomBytes(4).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * true nur für echte Unterordner von TMP_ROOT. Ein reiner Textvergleich (startsWith) würde
 * auch TMP_ROOT selbst und Geschwister wie „.tmp-fremd“ durchlassen.
 */
export function isInsideTmpRoot(dir: string): boolean {
  const rel = relative(TMP_ROOT, resolve(dir));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** Löscht einen mit createTmpDir angelegten Ordner samt Inhalt. */
export function removeTmpDir(dir: string): void {
  if (!isInsideTmpRoot(dir)) throw new Error(`Lösche nur Unterordner von ${TMP_ROOT}, nicht ${dir}.`);
  rmSync(dir, { recursive: true, force: true });
}
