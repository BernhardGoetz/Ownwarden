/**
 * Ownwarden-Prototyp: eine kleine Kommandozeile, um den Kern auszuprobieren.
 *
 *   ⚠️  PROTOTYP – NUR FÜR TESTDATEN. Keine echten Passwörter hineinschreiben!
 *
 * Aufruf (im Ordner core/):  npm run proto -- <Befehl> …   (Hilfe: npm run proto -- --help)
 *
 * Grundsätze:
 *   - Die lokale .kdbx-Datei ist der Zwischenspeicher dieses „Clients“ (wie später die Kopie
 *     in der Browser-Erweiterung). `sync` gleicht sie über WebDAV mit dem Server ab und
 *     schreibt das Ergebnis zurück.
 *   - Passwörter nie auf der Kommandozeile (Shell-Verlauf, Prozessliste): aus
 *     Umgebungsvariablen oder verdeckt abgefragt. Ausgegeben werden geschützte Werte nur bei
 *     `show --reveal`. Fehlermeldungen enthalten keine Passwörter.
 *   - Adressen mit Zugangsdaten (https://name:passwort@…) werden abgelehnt, bevor irgendetwas
 *     ausgegeben oder abgefragt wird.
 *   - Die lokale Datei wird atomar geschrieben (atomic-file.ts): Ein Absturz hinterlässt nie
 *     eine halbe Datei.
 *   - Geändert wird nur über die Funktionen aus vault-ops (über index.ts), damit die
 *     Feld-Zeitstempel stimmen.
 *
 * Aufbau: runCli() ist die eigentliche Kommandozeile (aus Tests mit eigener Ein-/Ausgabe
 * aufrufbar, siehe ownwarden-proto.test.ts); ganz unten startet sie, wenn die Datei direkt
 * ausgeführt wird.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs, type ParseArgsConfig } from "node:util";
import {
  ClockSkewError,
  createEntry,
  createGroup,
  createKdbxCodec,
  createNewVault,
  createVaultClock,
  DEFAULT_SYNC_SETTINGS,
  KdbxError,
  mergeVaults,
  NULL_UUID,
  readKdbx,
  recycleEntry,
  setAttachment,
  setField,
  STANDARD_FIELDS,
  syncVault,
  WebDavAdapter,
  writeKdbx,
  type Credentials,
  type Entry,
  type Group,
  type KdfParams,
  type ProtectedString,
  type SyncResult,
  type Vault,
} from "../index";
import { describeUrl, parseStorageUrl } from "../sync/http";
import { writeFileAtomic } from "./atomic-file";
import { createPrompter } from "./prompt";

// ---------------------------------------------------------------------------
// Ein- und Ausgabe (in Tests ersetzbar)
// ---------------------------------------------------------------------------

export interface CliIo {
  /** Umgebungsvariablen (Passwörter, siehe ENV). */
  env: Readonly<Record<string, string | undefined>>;
  /** Eine Zeile Ausgabe (stdout). */
  out(line: string): void;
  /** Eine Zeile Meldung (stderr). */
  err(line: string): void;
  /** Verdeckte Abfrage (Terminal: unsichtbar; Pipe: eine Zeile). */
  promptHidden(question: string): Promise<string>;
  /** true am Terminal: Ein neues Master-Passwort wird dann zweimal abgefragt. */
  interactive: boolean;
  /** Nur für Tests: eigene fetch-Funktion für WebDAV. */
  fetch?: typeof fetch;
  /** Nur für Tests: schnelle Schlüsselableitung für `init` (Standard: Argon2id 64 MiB). */
  newVaultKdf?: KdfParams;
  /** Nur für Tests: Uhr; Standard Date.now. */
  now?: () => number;
}

/** Namen der Umgebungsvariablen für Passwörter und geheime Werte. */
export const ENV = {
  master: "OWNWARDEN_MASTER_PASSWORD",
  webdav: "OWNWARDEN_WEBDAV_PASSWORD",
  entryPassword: "OWNWARDEN_ENTRY_PASSWORD",
  fieldValue: "OWNWARDEN_FIELD_VALUE",
} as const;

/** Bedienfehler (falsche Argumente): Exit-Code 2, mit Hinweis auf die Hilfe. */
class UsageError extends Error {}
/** Erwarteter Fehler mit verständlicher Meldung: Exit-Code 1. */
class CliError extends Error {}

export const USAGE = `Ownwarden-Prototyp – Kommandozeile

  ⚠️  PROTOTYP – NUR FÜR TESTDATEN. Keine echten Passwörter verwenden!

Aufruf (im Ordner core/):  npm run proto -- <Befehl> [Argumente]

Befehle:
  init   <datei> [--name <Name>]                    neue, leere Datenbank anlegen
  ls     <datei>                                     Einträge auflisten (ohne Passwörter)
  show   <datei> <eintrag> [--reveal]                Eintrag zeigen; geschützte Felder nur mit --reveal
  add    <datei> --title <Titel> [--user <Name>] [--url <URL>] [--group <Gruppe/Unter>] [--password]
                                                     Eintrag anlegen; --password fragt das Passwort ab
  set    <datei> <eintrag> <feld> <wert|-> [--protect]
                                                     Feld setzen; "-" = Wert verdeckt abfragen
                                                     (Pflicht für geschützte Felder wie Password)
  rm     <datei> <eintrag>                           in den Papierkorb (dort: endgültig löschen)
  attach <datei> <eintrag> <pfad> [--name <Name>]    Datei anhängen
  sync   <datei> --url <WebDAV-Adresse der .kdbx-Datei> --user <Benutzername>
                                                     mit dem Server abgleichen; fehlt die lokale
                                                     Datei, wird die Server-Fassung geholt

<eintrag> ist der Titel oder der Pfad "Gruppe/Titel".
Felder: Title, UserName, Password, URL, Notes oder ein eigener Name (Groß-/Kleinschreibung zählt).

Passwörter nie auf der Kommandozeile angeben. Sie kommen aus Umgebungsvariablen oder werden
verdeckt abgefragt:
  Master-Passwort der Datenbank   ${ENV.master}
  WebDAV-Passwort (sync)          ${ENV.webdav}   (App-/Gerätepasswort!)
  Passwort bei add --password     ${ENV.entryPassword}
  Wert bei set … -                ${ENV.fieldValue}

Beispiel MagentaCLOUD:
  npm run proto -- sync test.kdbx --url https://magentacloud.de/remote.php/webdav/Ownwarden-Test/test.kdbx --user name@t-online.de`;

/** Führt die Kommandozeile aus; liefert den Exit-Code (0 ok, 1 Fehler, 2 Bedienfehler). */
export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const [command, ...args] = argv;
  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    io.out(USAGE);
    return command === undefined ? 2 : 0;
  }
  const handler = COMMANDS[command];
  if (handler === undefined) {
    io.err(`Unbekannter Befehl "${command}".\n\n${USAGE}`);
    return 2;
  }
  try {
    await handler([...args], io);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      io.err(`${error.message}\n(Hilfe: npm run proto -- --help)`);
      return 2;
    }
    io.err(`Fehler: ${describeError(error)}`);
    return 1;
  }
}

/** Verständliche Meldung, ohne Stacktrace. Keine der Meldungen enthält Passwörter. */
function describeError(error: unknown): string {
  if (error instanceof KdbxError && error.code === "InvalidCredentials") {
    return "Falsches Master-Passwort (oder falsche Datei).";
  }
  if (error instanceof ClockSkewError) {
    return `${error.message} Bitte Datum, Uhrzeit und Zeitzone des Geräts prüfen. Es wurde nichts geschrieben.`;
  }
  return error instanceof Error ? error.message : String(error);
}

// ---------------------------------------------------------------------------
// Befehle
// ---------------------------------------------------------------------------

type Command = (args: string[], io: CliIo) => Promise<void>;

const COMMANDS: Record<string, Command> = {
  init: commandInit,
  ls: commandLs,
  show: commandShow,
  add: commandAdd,
  set: commandSet,
  rm: commandRm,
  attach: commandAttach,
  sync: commandSync,
};

async function commandInit(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse("init", args, { name: { type: "string" } }, ["datei"]);
  const file = positionals[0]!;
  if (existsSync(file)) throw new CliError(`${file} gibt es schon. init überschreibt nie eine Datei.`);
  const credentials = await masterCredentials(io, file, { isNew: true });
  const name = values.name ?? basename(file).replace(/\.kdbx$/i, "");
  const vault = createNewVault({ name, now: now(io), ...(io.newVaultKdf ? { kdf: io.newVaultKdf } : {}) });
  await saveVault(file, vault, credentials);
  io.out(`Neue Datenbank „${name}“ angelegt: ${file}`);
  io.out("Hinweis: Prototyp – nur für Testdaten.");
}

async function commandLs(args: string[], io: CliIo): Promise<void> {
  const { positionals } = parse("ls", args, {}, ["datei"]);
  const file = requireFile(positionals[0]!);
  const vault = await loadVault(file, await masterCredentials(io, file));
  const entries = entriesWithPaths(vault);
  if (entries.length === 0) {
    io.out("(keine Einträge)");
    return;
  }
  io.out("Pfad\tBenutzername\tURL");
  for (const { path, entry } of entries) {
    io.out([path, displayInline(entry.strings.get("UserName")), displayInline(entry.strings.get("URL"))].join("\t"));
  }
}

async function commandShow(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse("show", args, { reveal: { type: "boolean" } }, ["datei", "eintrag"]);
  const file = requireFile(positionals[0]!);
  const vault = await loadVault(file, await masterCredentials(io, file));
  const { entry, path } = findEntryByName(vault, positionals[1]!);
  const reveal = values.reveal === true;

  io.out(`Pfad: ${path}`);
  io.out(`UUID: ${entry.uuid}`);
  for (const [name, value] of orderedStrings(entry)) io.out(`${fieldLabel(name)}: ${displayValue(name, value, reveal)}`);
  io.out(`Tags: ${entry.tags.length > 0 ? entry.tags.join(", ") : "–"}`);
  const attachments = entry.attachments.map((item) => `${item.name} (${item.data.length} Byte)`);
  io.out(`Anhänge: ${attachments.length > 0 ? attachments.join(", ") : "–"}`);
  io.out(`Geändert: ${new Date(entry.times.lastModification).toISOString()}`);
  io.out(`Verlauf: ${entry.history.length} frühere Fassung(en)`);
  if (!reveal && [...entry.strings].some(([name, value]) => isSecretField(name, value) && value.value !== "")) {
    io.out("(Geschützte Werte sind verdeckt; „show --reveal“ zeigt sie im Klartext.)");
  }
}

async function commandAdd(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse(
    "add",
    args,
    {
      title: { type: "string" },
      user: { type: "string" },
      url: { type: "string" },
      group: { type: "string" },
      password: { type: "boolean" },
    },
    ["datei"],
  );
  if (values.title === undefined || values.title === "") throw new UsageError("add: --title <Titel> fehlt.");
  const file = requireFile(positionals[0]!);
  const credentials = await masterCredentials(io, file);
  const vault = await loadVault(file, credentials);
  const clock = createVaultClock(vault, () => now(io));

  const group = values.group === undefined ? vault.root : ensureGroupPath(vault, values.group, clock);
  if (group.entries.some((entry) => entry.strings.get("Title")?.value === values.title)) {
    throw new CliError(`In dieser Gruppe gibt es schon einen Eintrag „${values.title}“.`);
  }
  const fields: Record<string, string> = { Title: values.title };
  if (values.user !== undefined) fields.UserName = values.user;
  if (values.url !== undefined) fields.URL = values.url;
  if (values.password === true) fields.Password = await secretInput(io, ENV.entryPassword, "Passwort für den neuen Eintrag: ");
  createEntry(vault, group.uuid, fields, clock);
  await saveVault(file, vault, credentials);
  io.out(`Eintrag „${values.title}“ angelegt${group === vault.root ? "" : ` in ${groupPath(vault, group)}`}.`);
}

async function commandSet(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse("set", args, { protect: { type: "boolean" } }, ["datei", "eintrag", "feld", "wert"]);
  const [rawFile, query, rawField, rawValue] = positionals as [string, string, string, string];
  const file = requireFile(rawFile);
  const field = canonicalFieldName(rawField);
  // Offensichtliche Fälle schon vor der Passwort-Abfrage ablehnen, eigene geschützte Felder danach.
  rejectInlineSecret(field, rawValue, values.protect === true || isSecretField(field));
  const credentials = await masterCredentials(io, file);
  const vault = await loadVault(file, credentials);
  const { entry } = findEntryByName(vault, query);
  rejectInlineSecret(field, rawValue, isSecretField(field, entry.strings.get(field)));
  const value = rawValue === "-" ? await secretInput(io, ENV.fieldValue, `Wert für „${field}“: `) : rawValue;
  setField(vault, entry.uuid, field, value, values.protect === true ? { protected: true } : {}, createVaultClock(vault, () => now(io)));
  await saveVault(file, vault, credentials);
  io.out(`Feld „${field}“ von „${entryTitle(entry)}“ gesetzt.`);
}

/** Geschützte Werte nie von der Kommandozeile annehmen (Shell-Verlauf, Prozessliste). */
function rejectInlineSecret(field: string, rawValue: string, isProtected: boolean): void {
  if (rawValue === "-" || !isProtected) return;
  // Absichtlich ohne den Wert in der Meldung.
  throw new UsageError(
    `set: „${field}“ ist ein geschütztes Feld. Den Wert bitte nicht auf der Kommandozeile angeben (Shell-Verlauf!), ` +
      `sondern "-" schreiben: Er wird dann aus ${ENV.fieldValue} gelesen oder verdeckt abgefragt.`,
  );
}

async function commandRm(args: string[], io: CliIo): Promise<void> {
  const { positionals } = parse("rm", args, {}, ["datei", "eintrag"]);
  const file = requireFile(positionals[0]!);
  const credentials = await masterCredentials(io, file);
  const vault = await loadVault(file, credentials);
  const { entry } = findEntryByName(vault, positionals[1]!);
  const moved = recycleEntry(vault, entry.uuid, createVaultClock(vault, () => now(io)));
  await saveVault(file, vault, credentials);
  io.out(moved ? `„${entryTitle(entry)}“ in den Papierkorb verschoben.` : `„${entryTitle(entry)}“ endgültig gelöscht.`);
}

async function commandAttach(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse("attach", args, { name: { type: "string" } }, ["datei", "eintrag", "pfad"]);
  const file = requireFile(positionals[0]!);
  const source = positionals[2]!;
  if (!existsSync(source) || !statSync(source).isFile()) throw new CliError(`Anzuhängende Datei nicht gefunden: ${source}`);
  const name = values.name ?? basename(source);
  const credentials = await masterCredentials(io, file);
  const vault = await loadVault(file, credentials);
  const { entry } = findEntryByName(vault, positionals[1]!);
  const data = new Uint8Array(readFileSync(source));
  setAttachment(vault, entry.uuid, name, data, {}, createVaultClock(vault, () => now(io)));
  await saveVault(file, vault, credentials);
  io.out(`Anhang „${name}“ (${data.length} Byte) an „${entryTitle(entry)}“ gespeichert.`);
}

async function commandSync(args: string[], io: CliIo): Promise<void> {
  const { values, positionals } = parse("sync", args, { url: { type: "string" }, user: { type: "string" } }, ["datei"]);
  if (values.url === undefined || values.user === undefined) throw new UsageError("sync: --url und --user sind nötig.");
  // Adresse prüfen, BEVOR sie ausgegeben oder ein Passwort abgefragt wird: Eine Adresse mit
  // Zugangsdaten darf nie im Terminal oder in einem Log landen (die Meldung nennt sie nicht).
  let fileUrl: URL;
  try {
    fileUrl = parseStorageUrl(values.url, "WebDAV-Adresse");
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
  if (fileUrl.pathname.endsWith("/")) throw new UsageError("sync: --url muss auf die .kdbx-Datei zeigen, nicht auf einen Ordner.");
  const file = positionals[0]!;

  // Auch ohne lokale Datei ist es das Passwort einer BESTEHENDEN Datenbank (der auf dem Server).
  const credentials = await masterCredentials(io, file);
  const webDavPassword = await secretInput(io, ENV.webdav, `WebDAV-Passwort für ${values.user}: `);
  const adapter = new WebDavAdapter({
    fileUrl: fileUrl.href,
    username: values.user,
    password: webDavPassword,
    ...(io.fetch ? { fetch: io.fetch } : {}),
  });
  io.out(`Abgleich mit ${describeUrl(fileUrl)} …`);

  if (!existsSync(file)) {
    await downloadServerCopy(file, adapter, credentials, io);
    return;
  }
  const local = await loadVault(file, credentials);
  const codec = createKdbxCodec(credentials);
  const result = await syncVault(local, adapter, codec, { now: () => now(io), merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS });
  await saveVault(file, result.vault, credentials);
  for (const line of syncSummary(result)) io.out(line);
}

/** Lokale Datei fehlt: die Fassung vom Server holen (neuer Client, z. B. „Chrome“). */
async function downloadServerCopy(file: string, adapter: WebDavAdapter, credentials: Credentials, io: CliIo): Promise<void> {
  const remote = await adapter.read();
  if (remote === null) {
    throw new CliError(`Weder ${file} noch die Datei auf dem Server gibt es. Bitte zuerst mit „init“ anlegen und dann abgleichen.`);
  }
  const vault = await readKdbx(remote.data, credentials).catch((error: unknown) => {
    if (error instanceof KdbxError && error.code === "InvalidCredentials") {
      throw new CliError("Das Master-Passwort passt nicht zur Datei auf dem Server. Es wurde nichts gespeichert.");
    }
    throw error;
  });
  await saveVault(file, vault, credentials);
  io.out(`Lokale Datei fehlte: Server-Fassung nach ${file} geholt (${entriesWithPaths(vault).length} Einträge).`);
}

function syncSummary(result: SyncResult): string[] {
  const lines: string[] = [];
  if (result.created) lines.push("Datei auf dem Server neu angelegt.");
  else if (result.written) lines.push(`Zusammengeführt und hochgeladen${result.attempts > 1 ? ` (im ${result.attempts}. Versuch; ein anderes Gerät hatte gleichzeitig geschrieben)` : ""}.`);
  else lines.push("Server war schon aktuell – nichts hochgeladen.");
  const report = result.report;
  if (report !== undefined) {
    lines.push(
      `Vom Server: ${report.entriesAddedFromRemote} neu, ${report.entriesUpdated} geändert, ${report.entriesDeleted} gelöscht, ` +
        `${report.entriesResurrected} wiederhergestellt; Feld-Konflikte: ${report.fieldConflicts.length}; ` +
        `außerhalb von Ownwarden geändert: ${report.externalEdits.length}.`,
    );
    if (report.orphansRecovered > 0) lines.push(`${report.orphansRecovered} Einträge in die Gruppe „Wiederhergestellt (Ownwarden)“ gerettet.`);
  }
  for (const warning of result.warnings ?? []) lines.push(`⚠️  ${warning}`);
  lines.push("Lokale Datei aktualisiert.");
  return lines;
}

// ---------------------------------------------------------------------------
// Argumente
// ---------------------------------------------------------------------------

type Options = NonNullable<ParseArgsConfig["options"]>;

/** Argumente eines Befehls einlesen; genau so viele lose Argumente wie `names`. */
function parse<T extends Options>(command: string, args: string[], options: T, names: string[]) {
  let parsed;
  try {
    parsed = parseArgs({ args, options, allowPositionals: true, strict: true });
  } catch (error) {
    // Eine UNBEKANNTE Option nennt parseArgs wörtlich – das kann ein versehentlich
    // eingetipptes Passwort sein, das mit „-“ beginnt. Deshalb hier ohne den Text selbst.
    if ((error as { code?: unknown }).code === "ERR_PARSE_ARGS_UNKNOWN_OPTION") {
      throw new UsageError(
        `${command}: unbekannte Option (wird hier absichtlich nicht wiederholt). ` +
          `Ein Wert, der mit „-“ beginnt, gehört hinter „--“, z. B. … -- "-wert".`,
      );
    }
    // Übrige Fehler (z. B. „Option '--title <value>' argument missing“) nennen nur unsere
    // eigenen Optionsnamen, keine Werte.
    throw new UsageError(`${command}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (parsed.positionals.length !== names.length) {
    // Die Argumente selbst NICHT wiederholen: Ein überzähliges ist oft ein versehentlich
    // eingetipptes Passwort.
    throw new UsageError(`${command}: erwartet ${names.map((name) => `<${name}>`).join(" ")} (${parsed.positionals.length} lose Argumente angegeben).`);
  }
  return parsed;
}

/** Kurznamen für Standardfelder (sonst gilt der Name genau so, wie er geschrieben ist). */
const FIELD_ALIASES: Record<string, string> = {
  title: "Title",
  titel: "Title",
  user: "UserName",
  username: "UserName",
  benutzer: "UserName",
  benutzername: "UserName",
  password: "Password",
  passwort: "Password",
  url: "URL",
  notes: "Notes",
  notizen: "Notes",
};

function canonicalFieldName(name: string): string {
  if (name === "") throw new UsageError("set: Der Feldname ist leer.");
  return FIELD_ALIASES[name.toLowerCase()] ?? name;
}

// ---------------------------------------------------------------------------
// Passwörter und Dateien
// ---------------------------------------------------------------------------

function now(io: CliIo): number {
  return (io.now ?? Date.now)();
}

/** Master-Passwort aus der Umgebung oder verdeckt; ein NEUES am Terminal zweimal. */
async function masterCredentials(io: CliIo, file: string, options: { isNew?: boolean } = {}): Promise<Credentials> {
  const fromEnv = io.env[ENV.master];
  const password = fromEnv ?? (await io.promptHidden(`Master-Passwort für ${file}: `));
  if (password === "") throw new CliError(`Kein Master-Passwort angegeben (${ENV.master} oder Eingabe).`);
  if (options.isNew === true && fromEnv === undefined && io.interactive) {
    const again = await io.promptHidden("Master-Passwort wiederholen: ");
    if (again !== password) throw new CliError("Die beiden Eingaben stimmen nicht überein. Es wurde nichts gespeichert.");
  }
  return { password };
}

/** Geheimer Wert aus der Umgebung oder verdeckt abgefragt (nie leer). */
async function secretInput(io: CliIo, envName: string, question: string): Promise<string> {
  const value = io.env[envName] ?? (await io.promptHidden(question));
  if (value === "") throw new CliError(`Kein Wert angegeben (${envName} oder Eingabe).`);
  return value;
}

function requireFile(file: string): string {
  if (!existsSync(file)) throw new CliError(`Datei nicht gefunden: ${file} (neue Datenbank mit „init“ anlegen).`);
  return file;
}

async function loadVault(file: string, credentials: Credentials): Promise<Vault> {
  return readKdbx(new Uint8Array(readFileSync(file)), credentials);
}

/** Verschlüsseln und ATOMAR schreiben (siehe atomic-file.ts). */
async function saveVault(file: string, vault: Vault, credentials: Credentials): Promise<void> {
  writeFileAtomic(resolve(file), await writeKdbx(vault, credentials));
}

// ---------------------------------------------------------------------------
// Einträge finden und anzeigen
// ---------------------------------------------------------------------------

interface PlacedEntry {
  path: string;
  entry: Entry;
  group: Group;
}

/** Alle Einträge (ohne Verlauf) mit Pfad "Gruppe/Unter/Titel" (ohne Wurzelgruppe). */
function entriesWithPaths(vault: Vault): PlacedEntry[] {
  const result: PlacedEntry[] = [];
  const walk = (group: Group, prefix: string): void => {
    for (const entry of group.entries) result.push({ path: prefix + entryTitle(entry), entry, group });
    for (const child of group.groups) walk(child, `${prefix}${child.name}/`);
  };
  walk(vault.root, "");
  return result;
}

/** Eintrag nach Pfad (zuerst) oder Titel; bei mehreren Treffern eine klare Meldung. */
function findEntryByName(vault: Vault, query: string): PlacedEntry {
  const all = entriesWithPaths(vault);
  const byPath = all.filter((item) => item.path === query);
  if (byPath.length === 1) return byPath[0]!;
  const byTitle = all.filter((item) => entryTitle(item.entry) === query);
  if (byTitle.length === 1) return byTitle[0]!;
  const candidates = byPath.length > 1 ? byPath : byTitle;
  if (candidates.length === 0) throw new CliError(`Kein Eintrag „${query}“ gefunden („ls“ zeigt alle).`);
  throw new CliError(`„${query}“ ist mehrdeutig (${candidates.map((item) => item.path).join(", ")}). Bitte den Pfad angeben.`);
}

/**
 * Gruppe zum Pfad "A/B" unter der Wurzel; fehlende Gruppen werden angelegt. Führt der Pfad
 * in den Papierkorb oder in eine Gruppe darin, wird abgebrochen – BEVOR etwas angelegt wird
 * (alles im Papierkorb gilt als gelöscht, auch in Untergruppen).
 */
function ensureGroupPath(vault: Vault, path: string, clock: ReturnType<typeof createVaultClock>): Group {
  const names = path.split("/").filter((part) => part !== "");
  const isRecycleBin = (group: Group) => vault.meta.recycleBinUuid !== NULL_UUID && group.uuid === vault.meta.recycleBinUuid;
  let group = vault.root;
  for (const name of names) {
    const existing = group.groups.find((child) => child.name === name);
    if (existing !== undefined && isRecycleBin(existing)) throw new CliError("Neue Einträge nicht in den Papierkorb (oder eine Gruppe darin) legen.");
    group = existing ?? createGroup(vault, group.uuid, name, clock);
  }
  return group;
}

function groupPath(vault: Vault, target: Group): string {
  const search = (group: Group, prefix: string): string | undefined => {
    if (group === target) return prefix.replace(/\/$/, "");
    for (const child of group.groups) {
      const found = search(child, `${prefix}${child.name}/`);
      if (found !== undefined) return found;
    }
    return undefined;
  };
  return search(vault.root, "") ?? target.name;
}

function entryTitle(entry: Entry): string {
  return entry.strings.get("Title")?.value ?? "";
}

/** Standardfelder zuerst (in KeePass-Reihenfolge), dann eigene Felder wie gespeichert. */
function orderedStrings(entry: Entry): [string, ProtectedString][] {
  const standard = STANDARD_FIELDS.filter((name) => entry.strings.has(name)).map((name): [string, ProtectedString] => [name, entry.strings.get(name)!]);
  const custom = [...entry.strings].filter(([name]) => !(STANDARD_FIELDS as readonly string[]).includes(name));
  return [...standard, ...custom];
}

const LABELS: Record<string, string> = { Title: "Titel", UserName: "Benutzername", Password: "Passwort", URL: "URL", Notes: "Notizen" };

function fieldLabel(name: string): string {
  return LABELS[name] ?? `Feld ${name}`;
}

/** Platzhalter für geschützte Werte – immer gleich lang, verrät also nichts über den Wert. */
const HIDDEN = "******";

/**
 * Ist das Feld geheim (nur mit --reveal zeigen, nie von der Kommandozeile annehmen)?
 * Ja, wenn es geschützt ist – und IMMER beim Passwort und beim privaten Schlüssel eines
 * Passkeys, auch ohne Schutz-Flag: Manche Programme schützen sie nicht (z. B. KeePass mit
 * abgeschaltetem Speicherschutz „ProtectPassword“), geheim sind sie trotzdem.
 */
function isSecretField(name: string, value?: ProtectedString): boolean {
  return value?.protected === true || name === "Password" || /^KP(EX|XC)_PASSKEY_.*PRIVATE_KEY/.test(name);
}

/** Wert für show: geheim -> verdeckt (außer --reveal); mehrzeilig eingerückt. */
function displayValue(name: string, value: ProtectedString, reveal: boolean): string {
  if (isSecretField(name, value) && value.value !== "" && !reveal) return `${HIDDEN} (geschützt)`;
  return value.value.includes("\n") ? `\n  ${value.value.replace(/\r?\n/g, "\n  ")}` : value.value;
}

/** Wert für ls: eine Zeile; geschützte Werte immer verdeckt. */
function displayInline(value: ProtectedString | undefined): string {
  if (value === undefined || value.value === "") return "";
  return value.protected ? HIDDEN : value.value.replace(/\s+/g, " ");
}

// ---------------------------------------------------------------------------
// Start als Programm
// ---------------------------------------------------------------------------

/** true, wenn diese Datei direkt gestartet wurde (nicht importiert, z. B. aus einem Test). */
function isMainModule(): boolean {
  const script = process.argv[1];
  return script !== undefined && import.meta.url === pathToFileURL(resolve(script)).href;
}

if (isMainModule()) {
  const prompter = createPrompter();
  const io: CliIo = {
    env: process.env,
    out: (line) => process.stdout.write(`${line}\n`),
    err: (line) => process.stderr.write(`${line}\n`),
    promptHidden: (question) => prompter.hidden(question),
    interactive: prompter.interactive,
  };
  runCli(process.argv.slice(2), io).then(
    (code) => {
      prompter.close();
      process.exitCode = code;
    },
    (error: unknown) => {
      prompter.close();
      process.stderr.write(`Fehler: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
