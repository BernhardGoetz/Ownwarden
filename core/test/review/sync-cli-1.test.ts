/**
 * Review sync-cli-1 (Regressionstest): Eine nie hochgeladene lokale Änderung, die beim Abgleich
 * gegen eine NEUERE Löschung verliert, ist danach nirgends mehr zu finden.
 *
 * PROJECT-CONTEXT („Verlauf“): „Gewinnt eine Löschung, sind die Daten aus der Datei weg und nur
 * noch in Backups.“ Die Sicherungskopien auf dem Server enthalten aber nur frühere
 * SERVER-Fassungen, und `sync` ersetzt die lokale Datei ohne Kopie. Die Offline-Änderung von
 * Gerät A gab es nur in A's lokaler Datei – nach dem Abgleich ist sie weg.
 *
 * Ablauf (Kommandozeile gegen den SabreDAV-Testserver):
 *   1. A legt an und lädt hoch; B holt die Server-Fassung.
 *   2. A ändert offline das Passwort von „Mail“ (T+10 s).
 *   3. B löscht „Mail“ endgültig (T+20 s) und gleicht ab.
 *   4. A gleicht ab (T+30 s): Die neuere Löschung gewinnt (so gewollt).
 * Erwartet: A's geänderter Wert ist danach noch IRGENDWO wiederherstellbar – in A's lokaler
 * Datei (z. B. Verlauf/Wiederherstellungsgruppe), in einer lokalen Sicherungskopie neben ihr
 * oder in der Datei bzw. den Sicherungskopien auf dem Server.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ENV, runCli, type CliIo } from "../../src/cli/ownwarden-proto";
import { readKdbx } from "../../src/kdbx/index";
import type { Entry, Group, Vault } from "../../src/model";
import { TEST_KDF } from "../helpers/kdbx-files";
import { createTmpDir, removeTmpDir } from "../helpers/keepassxc";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";

const MASTER = "Review-sync-cli-1-Master";
const ORIGINAL = "Mail-Original-Testpasswort";
const OFFLINE_EDIT = "A-OFFLINE-EDIT-Testpasswort";

function io(env: Record<string, string>, now: number): CliIo {
  return {
    env,
    out: () => {},
    err: () => {},
    promptHidden: async () => "",
    interactive: false,
    newVaultKdf: TEST_KDF,
    now: () => now,
  };
}

/** Alle Dateien unterhalb von `dir` (rekursiv). */
function filesBelow(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const result: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) result.push(...filesBelow(path));
    else result.push(path);
  }
  return result;
}

/** Alle Werte aller Felder aller Einträge, auch im Verlauf. */
function allValues(vault: Vault): string[] {
  const values: string[] = [];
  const seeEntry = (entry: Entry): void => {
    for (const value of entry.strings.values()) values.push(value.value);
    entry.history.forEach(seeEntry);
  };
  const seeGroup = (group: Group): void => {
    group.entries.forEach(seeEntry);
    group.groups.forEach(seeGroup);
  };
  seeGroup(vault.root);
  return values;
}

/** true, wenn eine der Dateien (mit dem Master-Passwort lesbar) den Wert enthält. */
async function anyFileContains(paths: string[], needle: string): Promise<boolean> {
  for (const path of paths) {
    let vault: Vault;
    try {
      vault = await readKdbx(new Uint8Array(readFileSync(path)), { password: MASTER });
    } catch {
      continue; // keine (lesbare) KDBX-Datei
    }
    if (allValues(vault).includes(needle)) return true;
  }
  return false;
}

describe.skipIf(!webDavTestServerAvailable())("Review sync-cli-1: verlorene Offline-Änderung", () => {
  let server: WebDavTestServer;
  let dir: string;
  beforeAll(async () => {
    server = await startWebDavTestServer("review-sync-cli-1");
    dir = createTmpDir("review-sync-cli-1");
    mkdirSync(join(server.dataDir, "Ownwarden"));
  });
  afterAll(async () => {
    await server?.stop();
    if (dir) removeTmpDir(dir);
  });

  it("Review sync-cli-1: Offline-Änderung, die gegen eine neuere Löschung verliert, bleibt lokal oder in einer Sicherung erhalten", async () => {
    const url = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const dirA = join(dir, "geraet-a");
    const dirB = join(dir, "geraet-b");
    mkdirSync(dirA);
    mkdirSync(dirB);
    const fileA = join(dirA, "a.kdbx");
    const fileB = join(dirB, "b.kdbx");
    const env = { [ENV.master]: MASTER, [ENV.webdav]: server.password };
    // Nahe an der echten Zeit (Date-Header des Servers, erlaubt 2 Minuten), aber fest geordnet.
    const base = Date.now();
    const run = async (args: string[], at: number, extraEnv: Record<string, string> = {}) => {
      const code = await runCli(args, io({ ...env, ...extraEnv }, base + at));
      expect(code, args.join(" ")).toBe(0);
    };
    const sync = (file: string, at: number) => run(["sync", file, "--url", url, "--user", server.username], at);

    await run(["init", fileA], 0);
    await run(["add", fileA, "--title", "Mail", "--user", "alice", "--password"], 1000, { [ENV.entryPassword]: ORIGINAL });
    await sync(fileA, 2000);
    await sync(fileB, 3000); // B holt die Server-Fassung

    await run(["set", fileA, "Mail", "Password", "-"], 10_000, { [ENV.fieldValue]: OFFLINE_EDIT }); // A offline
    await run(["rm", fileB, "Mail"], 20_000); // B: in den Papierkorb …
    await run(["rm", fileB, "Papierkorb/Mail"], 21_000); // … und endgültig löschen
    await sync(fileB, 22_000);

    // Vorbedingung: A's Änderung ist vor dem Abgleich in A's lokaler Datei.
    expect(await anyFileContains([fileA], OFFLINE_EDIT)).toBe(true);

    await sync(fileA, 30_000);

    // Die neuere Löschung gewinnt (so gewollt): Der Eintrag ist aus A's Datei verschwunden.
    const merged = await readKdbx(new Uint8Array(readFileSync(fileA)), { password: MASTER });
    expect(allValues(merged)).not.toContain(ORIGINAL);

    // A's Offline-Änderung muss aber noch irgendwo wiederherstellbar sein.
    const candidates = [...filesBelow(dirA), ...filesBelow(server.dataDir)];
    // Gegenprobe, dass die Suche funktioniert: Die ALTE Server-Fassung (vor B's Löschung)
    // liegt in einer Sicherungskopie auf dem Server.
    expect(await anyFileContains(filesBelow(server.dataDir), ORIGINAL)).toBe(true);
    expect(await anyFileContains(candidates, OFFLINE_EDIT)).toBe(true);
  });
});
