/**
 * Kritische Prüfung gegen den SabreDAV-Testserver: Die wichtigste Zusage von syncVault ist
 * „jede Fassung, die überschrieben wird, liegt vorher als Sicherung im Sicherungsordner“.
 * Diese Tests prüfen sie in Lagen, die der Builder nicht abgedeckt hatte (abweichende
 * Geräteuhren beim Aufräumen, fremdes Schreiben zwischen Lesen und COPY).
 * Wird übersprungen, wenn PHP/Composer fehlen.
 */
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { entryByTitle, newVault, uuidFromName } from "../../test/helpers/vault-builder";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import type { SyncOptions } from "../contracts";
import type { Vault } from "../model";
import { createVaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setField } from "../merge/vault-ops";
import { syncVault } from "./sync";
import { createJsonCodec } from "./testing/json-codec";
import { WebDavAdapter } from "./webdav";

const MAIL = uuidFromName("mail");

describe.skipIf(!webDavTestServerAvailable())("syncVault gegen SabreDAV: jede überschriebene Fassung ist gesichert", () => {
  let server: WebDavTestServer;
  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-adversarial");
  });
  afterAll(async () => {
    await server?.stop();
    // Jede schreibende Anfrage aller Tests dieser Gruppe war bedingt.
    expect(unconditionalWrites).toEqual([]);
    expect(seen.PUT).toBeGreaterThan(0);
    expect(seen.COPY).toBeGreaterThan(0);
  });

  const codec = createJsonCodec();

  /** Verstöße gegen „nie unbedingt schreiben“, über alle Geräte und Tests gesammelt. */
  const unconditionalWrites: string[] = [];
  /** Wie viele PUT/COPY die Prüfung gesehen hat (damit sie nicht ins Leere prüft). */
  const seen = { PUT: 0, COPY: 0 };

  /** fetch, das jede schreibende Anfrage auf eine Bedingung prüft (PUT: If-Match/If-None-Match, COPY: Overwrite: F). */
  const checkingFetch =
    (inner: typeof fetch): typeof fetch =>
    (input, init) => {
      const headers = new Headers(init?.headers);
      const method = init?.method ?? "GET";
      if (method === "PUT" || method === "COPY") seen[method] += 1;
      if (method === "PUT" && !headers.has("If-Match") && headers.get("If-None-Match") !== "*") unconditionalWrites.push(`PUT ${String(input)}`);
      if (method === "COPY" && headers.get("Overwrite") !== "F") unconditionalWrites.push(`COPY ${String(input)}`);
      return inner(input, init);
    };

  /** Gerät mit Uhr-Versatz (für Sync-Zeit und Namen der Sicherungen). */
  function device(folder: string, offsetMs: number, fetchFn: typeof fetch = fetch) {
    const now = () => Date.now() + offsetMs;
    const adapter = new WebDavAdapter({
      fileUrl: new URL(`${folder}/tresor.kdbx`, server.baseUrl).href,
      username: server.username,
      password: server.password,
      now,
      fetch: checkingFetch(fetchFn),
    });
    const options = (backupsToKeep: number): SyncOptions => ({ now, merge: mergeVaults, maxAttempts: 4, maxClockSkewMs: 120_000, backupsToKeep });
    const edit = (vault: Vault, field: string, value: string) => setField(vault, MAIL, field, value, {}, createVaultClock(vault, now));
    return { adapter, options, edit };
  }

  const vaultFile = (folder: string) => readFileSync(join(server.dataDir, folder, "tresor.kdbx"));
  const backupContents = (folder: string) =>
    readdirSync(join(server.dataDir, folder, "ownwarden-backups")).map((name) => readFileSync(join(server.dataDir, folder, "ownwarden-backups", name)));
  const containsBytes = (list: Uint8Array[], wanted: Uint8Array) => list.some((item) => Buffer.compare(item, wanted) === 0);

  function initialVault(now: () => number): Vault {
    const vault = newVault();
    createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "bob", Password: "alt" }, createVaultClock(vault, now), { uuid: MAIL });
    return vault;
  }

  it("Uhr eines Geräts geht 60 s vor, keep = 1: die Fassung, die das andere Gerät überschreibt, bleibt gesichert", async () => {
    const folder = "skew";
    mkdirSync(join(server.dataDir, folder));
    const vivaldi = device(folder, 60_000); // Uhr 1 Minute vor (erlaubt sind 2)
    const chrome = device(folder, 0);

    let vaultA = (await syncVault(initialVault(Date.now), vivaldi.adapter, codec, vivaldi.options(1))).vault;
    vivaldi.edit(vaultA, "UserName", "alice");
    vaultA = (await syncVault(vaultA, vivaldi.adapter, codec, vivaldi.options(1))).vault; // Sicherung mit Zeit +60 s
    const overwrittenByChrome = vaultFile(folder);

    const vaultB = await codec.decode((await chrome.adapter.read())!.data);
    chrome.edit(vaultB, "Password", "neu");
    const result = await syncVault(vaultB, chrome.adapter, codec, chrome.options(1));

    expect(result.written).toBe(true);
    expect(containsBytes(backupContents(folder), overwrittenByChrome)).toBe(true);
    expect(backupContents(folder)).toHaveLength(1);
  });

  it("ein anderes Gerät schreibt zwischen Lesen und COPY: beide überschriebenen Fassungen sind gesichert, nichts geht verloren", async () => {
    const folder = "copy-race";
    mkdirSync(join(server.dataDir, folder));
    const vivaldi = device(folder, 0);
    let vaultA = (await syncVault(initialVault(Date.now), vivaldi.adapter, codec, vivaldi.options(10))).vault;
    const versionRead = vaultFile(folder);
    let versionWrittenBetween: Uint8Array | undefined;

    // Chrome-fetch: Unmittelbar vor Chromes ERSTEM COPY schreibt Vivaldi eine Änderung.
    let raced = false;
    const chromeFetch: typeof fetch = async (input, init) => {
      if (init?.method === "COPY" && !raced) {
        raced = true;
        vivaldi.edit(vaultA, "UserName", "alice");
        vaultA = (await syncVault(vaultA, vivaldi.adapter, codec, vivaldi.options(10))).vault;
        versionWrittenBetween = vaultFile(folder);
      }
      return fetch(input, init);
    };
    const chrome = device(folder, 0, chromeFetch);
    const vaultB = await codec.decode((await chrome.adapter.read())!.data);
    chrome.edit(vaultB, "Password", "neu");

    const result = await syncVault(vaultB, chrome.adapter, codec, chrome.options(10));

    expect(result).toMatchObject({ written: true, attempts: 2 });
    const backups = backupContents(folder);
    expect(containsBytes(backups, versionRead)).toBe(true); // von Vivaldi gesichert
    expect(containsBytes(backups, versionWrittenBetween!)).toBe(true); // von Chrome im 2. Versuch gesichert
    const final = await codec.decode(vaultFile(folder));
    expect(entryByTitle(final, "Mail").strings.get("UserName")?.value).toBe("alice");
    expect(entryByTitle(final, "Mail").strings.get("Password")?.value).toBe("neu");
  });
});
