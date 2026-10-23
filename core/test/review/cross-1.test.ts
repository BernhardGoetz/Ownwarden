/**
 * Review cross-1 (Regressionstest): Jeder gescheiterte Schreibversuch legt eine weitere
 * Sicherungskopie derselben, unveränderten Server-Fassung an und räumt dabei eine ältere,
 * VERSCHIEDENE Sicherung weg.
 *
 * WebDavAdapter.backup() sichert und ruft sofort pruneBackups(keep) auf – bevor syncVault weiß,
 * ob das bedingte PUT der Tresor-Datei gelingt. Scheitert das PUT dauerhaft (hier: 423, z. B. eine
 * hängende Nextcloud-Dateisperre; ebenso 5xx, Zeitlimit oder schwacher ETag mit 412 bei jedem
 * Versuch), bestehen die Sicherungen nach wenigen Abgleichen nur noch aus Kopien EINER Fassung.
 * README/PROJECT-CONTEXT versprechen „die letzten 20 behalten“, und Daten, die eine Löschung
 * verloren hat, gibt es nur noch in den Sicherungen.
 *
 * Ablauf (SabreDAV-Testserver, backupsToKeep = 3):
 *   1. v0 anlegen, dann v1, v2, v3 hochladen -> Sicherungen: v0, v1, v2 (drei verschiedene).
 *   2. Ab jetzt beantwortet der Server jedes PUT auf die Tresor-Datei mit 423 (gesperrt).
 *   3. Drei Abgleiche mit lokaler Änderung, alle scheitern (nichts wird geschrieben).
 * Erwartet: Gescheiterte Versuche vernichten keine älteren Sicherungen – im Sicherungsordner
 * liegen weiterhin mindestens backupsToKeep (3) verschiedene Fassungen.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { StorageError, type SyncOptions } from "../../src/contracts";
import { createNewVault } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { createEntry, setField } from "../../src/merge/vault-ops";
import type { Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "../../src/sync/sync";
import { WebDavAdapter } from "../../src/sync/webdav";
import { TEST_KDF } from "../helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";

const KEEP = 3;
const codec = createKdbxCodec({ password: "Review-cross-1-Testpasswort" });
const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS, backupsToKeep: KEEP });

/** Anzahl verschiedener Inhalte im Ordner (Kopien derselben Server-Fassung sind bytegleich). */
function distinctContents(dir: string): number {
  return new Set(readdirSync(dir).map((name) => createHash("sha256").update(readFileSync(join(dir, name))).digest("hex"))).size;
}

describe.skipIf(!webDavTestServerAvailable())("Review cross-1: gescheiterte Schreibversuche und Sicherungskopien", () => {
  let server: WebDavTestServer;
  beforeAll(async () => {
    server = await startWebDavTestServer("review-cross-1");
    mkdirSync(join(server.dataDir, "Ownwarden"));
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("Review cross-1: dauerhaft gesperrte Tresor-Datei (423) rotiert nicht alle älteren Sicherungen heraus", async () => {
    const fileUrl = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const backupDir = join(server.dataDir, "Ownwarden", "ownwarden-backups");
    let vaultLocked = false;
    // Wie ein Server mit hängender Dateisperre auf der Tresor-Datei: PUT darauf -> 423.
    const lockingFetch: typeof fetch = async (input, init) => {
      if (vaultLocked && init?.method === "PUT" && String(input) === fileUrl) return new Response(null, { status: 423 });
      return fetch(input, init);
    };
    const adapter = new WebDavAdapter({ fileUrl, username: server.username, password: server.password, fetch: lockingFetch });

    let vault: Vault = createNewVault({ name: "Review cross-1", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    const mail = createEntry(vault, vault.root.uuid, { Title: "Mail", Password: "v0" }, createVaultClock(vault)).uuid;
    vault = (await syncVault(vault, adapter, codec, options())).vault;
    for (const version of ["v1", "v2", "v3"]) {
      setField(vault, mail, "Password", version, {}, createVaultClock(vault));
      const result = await syncVault(vault, adapter, codec, options());
      expect(result.written).toBe(true);
      vault = result.vault;
    }
    expect(readdirSync(backupDir)).toHaveLength(KEEP);
    expect(distinctContents(backupDir)).toBe(KEEP); // v0, v1, v2
    const serverBefore = readFileSync(join(server.dataDir, "Ownwarden", "tresor.kdbx"));

    vaultLocked = true;
    for (let round = 1; round <= 3; round++) {
      setField(vault, mail, "Password", `offline-${round}`, {}, createVaultClock(vault));
      await expect(syncVault(vault, adapter, codec, options())).rejects.toBeInstanceOf(StorageError);
    }

    // Der Server hat nichts Neues bekommen ...
    expect(readFileSync(join(server.dataDir, "Ownwarden", "tresor.kdbx")).equals(serverBefore)).toBe(true);
    // ... und die älteren Wiederherstellungspunkte dürfen dadurch nicht verschwunden sein.
    expect(distinctContents(backupDir)).toBeGreaterThanOrEqual(KEEP);
  });
});
