/**
 * Ende-zu-Ende gegen den SabreDAV-Testserver: Aufräumen alter Sicherungskopien ist
 * „best effort“ (Entscheidung des Eigentümers, 2026-10-16).
 *
 *   - Eine ALTE Sicherung lässt sich nicht löschen (der Server antwortet 423 „gesperrt“):
 *     Der Abgleich schreibt trotzdem, legt die neue Sicherung an und meldet einen Hinweis.
 *   - Ist die Sperre weg, räumt der nächste Abgleich wieder auf (zurück auf backupsToKeep).
 * Die Sicherung der Fassung, die gleich überschrieben wird, bleibt Pflicht (geprüft in
 * src/sync/sync.warnings.test.ts und src/sync/sync.test.ts).
 * Wird übersprungen, wenn PHP/SabreDAV fehlen.
 */
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TEST_KDF } from "../helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";
import type { SyncOptions } from "../../src/contracts";
import { createNewVault, readKdbx } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import { createEntry, setField } from "../../src/merge/vault-ops";
import type { Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "../../src/sync/sync";
import { WebDavAdapter } from "../../src/sync/webdav";

const credentials = { password: "Backup-Test-äöü" };
const codec = createKdbxCodec(credentials);
const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS, backupsToKeep: 2 });

describe.skipIf(!webDavTestServerAvailable())("Ende-zu-Ende: eine alte Sicherung lässt sich nicht löschen", () => {
  let server: WebDavTestServer;
  beforeAll(async () => {
    server = await startWebDavTestServer("e2e-backups");
    mkdirSync(join(server.dataDir, "Ownwarden"));
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("Abgleich schreibt trotzdem, neue Sicherung ist da, Hinweis nennt die Datei; danach wird wieder aufgeräumt", async () => {
    const fileUrl = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const backupDir = join(server.dataDir, "Ownwarden", "ownwarden-backups");
    let lockedUrl: string | undefined;
    const deleteAttempts: string[] = [];
    // Wie ein Server, auf dem eine Datei gesperrt ist (WebDAV LOCK, Nextcloud-Dateisperre).
    const lockingFetch: typeof fetch = async (input, init) => {
      if (init?.method === "DELETE") deleteAttempts.push(String(input));
      if (init?.method === "DELETE" && String(input) === lockedUrl) return new Response(null, { status: 423 });
      return fetch(input, init);
    };
    const adapter = new WebDavAdapter({ fileUrl, username: server.username, password: server.password, fetch: lockingFetch });

    let vault: Vault = createNewVault({ name: "Sicherungen", now: Date.now(), kdf: TEST_KDF });
    const mail = createEntry(vault, vault.root.uuid, { Title: "Mail", Password: "v0" }, createVaultClock(vault)).uuid;
    vault = (await syncVault(vault, adapter, codec, options())).vault;
    for (const version of ["v1", "v2"]) {
      setField(vault, mail, "Password", version, {}, createVaultClock(vault));
      vault = (await syncVault(vault, adapter, codec, options())).vault;
    }
    const oldBackups = readdirSync(backupDir).sort();
    expect(oldBackups).toHaveLength(2);

    // Die älteste Sicherung wird „gesperrt“; sie wäre beim nächsten Abgleich dran.
    const oldest = oldBackups[0]!;
    lockedUrl = new URL(`Ownwarden/ownwarden-backups/${encodeURIComponent(oldest)}`, server.baseUrl).href;
    setField(vault, mail, "Password", "v3", {}, createVaultClock(vault));
    const result = await syncVault(vault, adapter, codec, options());

    expect(result.written).toBe(true);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain(oldest);
    expect(result.warnings![0]).toContain("423");
    expect(result.warnings![0]).not.toContain(server.password);
    expect(deleteAttempts).toEqual([lockedUrl]);
    const afterLocked = readdirSync(backupDir).sort();
    expect(afterLocked).toHaveLength(3); // gesperrte alte + vorige + NEUE Sicherung
    expect(afterLocked.slice(0, 2)).toEqual(oldBackups);
    // Die neue Sicherung ist die Fassung, die eben überschrieben wurde (v2).
    const newest = await readKdbx(new Uint8Array(readFileSync(join(backupDir, afterLocked[2]!))), credentials);
    expect(findEntry(newest, mail)!.strings.get("Password")?.value).toBe("v2");
    expect(findEntry(await codec.decode((await adapter.read())!.data), mail)!.strings.get("Password")?.value).toBe("v3");

    // Sperre aufgehoben: Der nächste schreibende Abgleich räumt wieder auf.
    lockedUrl = undefined;
    setField(result.vault, mail, "Password", "v4", {}, createVaultClock(result.vault));
    const cleaned = await syncVault(result.vault, adapter, codec, options());
    expect(cleaned).toMatchObject({ written: true });
    expect(cleaned.warnings).toBeUndefined();
    expect(readdirSync(backupDir)).toHaveLength(2);
  });
});
