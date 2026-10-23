/**
 * Ende-zu-Ende, Entscheidung des Eigentümers (2026-10-15): Datenbank-Einstellungen OHNE
 * Zeitstempel (Schlüsselableitung, Verlaufsgrenzen, Beschreibung …) nimmt Ownwarden aus der
 * Datei auf dem SERVER. Ein Gerät mit älterer Kopie darf eine Änderung aus KeePassXC nicht
 * still zurückdrehen.
 *
 *   1. Vivaldi legt die Datei an (Argon2id, Verlauf 10, keine Beschreibung) und behält seine Kopie.
 *   2. Am PC ändert KeePassXC die Datei: Verlauf höchstens 3, Beschreibung gesetzt, und
 *      KeePassXC schreibt sie mit seiner eigenen Schlüsselableitung (AES-KDF).
 *      keepassxc-cli kann diese Einstellungen nicht direkt ändern (nur die Oberfläche kann
 *      das); deshalb: export -> XML ändern -> import. Die Datei schreibt KeePassXC selbst.
 *   3. Vivaldi (alte Kopie) ändert viermal ein Passwort und gleicht ab.
 *   4. Die Datei behält KeePassXCs Werte; die Verlaufsgrenze 3 gilt schon beim Zusammenführen.
 *
 * Bereits vorhanden: src/sync/sync.test.ts („Einstellungen ohne Zeitstempel: die Fassung auf
 * dem Server gewinnt“, im Speicher). Neu hier: mit KeePassXC und echtem Server.
 * Wird übersprungen, wenn PHP/SabreDAV oder keepassxc-cli fehlen.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, exportKpxcXml, hasKeepassxc, importKpxcXml, kpxcDbInfo, removeTmpDir } from "../helpers/keepassxc";
import { TEST_KDF } from "../helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";
import type { SyncOptions } from "../../src/contracts";
import { createNewVault, readKdbx } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import { createEntry, setField } from "../../src/merge/vault-ops";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "../../src/sync/sync";
import { WebDavAdapter } from "../../src/sync/webdav";

const PASSWORD = "Einstellungen-äöü";
const credentials = { password: PASSWORD };
const codec = createKdbxCodec(credentials);
const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS });
const DESCRIPTION = "Von KeePassXC geändert";

describe.skipIf(!webDavTestServerAvailable() || !hasKeepassxc())("Ende-zu-Ende: Einstellungen aus KeePassXC bleiben", () => {
  let server: WebDavTestServer;
  let dir: string;
  beforeAll(async () => {
    server = await startWebDavTestServer("e2e-settings");
    dir = createTmpDir("e2e-settings");
    mkdirSync(join(server.dataDir, "Ownwarden"));
  });
  afterAll(async () => {
    await server?.stop();
    if (dir) removeTmpDir(dir);
  });

  it("ein Gerät mit älterer Kopie dreht Verlaufsgrenze, Beschreibung und Schlüsselableitung nicht zurück", async () => {
    const fileUrl = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    const adapter = new WebDavAdapter({ fileUrl, username: server.username, password: server.password });

    // 1. Vivaldi legt an.
    const initial = createNewVault({ name: "Einstellungen", now: Date.now(), kdf: TEST_KDF, allowWeakKdf: true });
    const mail = createEntry(initial, initial.root.uuid, { Title: "Mail", Password: "p0" }, createVaultClock(initial)).uuid;
    let vivaldi = (await syncVault(initial, adapter, codec, options())).vault;
    expect(vivaldi.meta.historyMaxItems).toBe(10);

    // 2. KeePassXC ändert die Einstellungen der Datei auf dem Server.
    const remote = (await adapter.read())!;
    const downloaded = join(dir, "vom-server.kdbx");
    writeFileSync(downloaded, remote.data);
    const xml = (await exportKpxcXml(downloaded, PASSWORD))
      .replace(/<HistoryMaxItems>\d+<\/HistoryMaxItems>/, "<HistoryMaxItems>3</HistoryMaxItems>")
      .replace(/<DatabaseDescription\/>|<DatabaseDescription>[^<]*<\/DatabaseDescription>/, "")
      .replace(/(<\/DatabaseName>)/, `$1<DatabaseDescription>${DESCRIPTION}</DatabaseDescription>`);
    expect(xml).toContain("<HistoryMaxItems>3</HistoryMaxItems>");
    const changed = join(dir, "von-keepassxc.kdbx");
    await importKpxcXml(xml, changed, PASSWORD);
    await adapter.write(new Uint8Array(readFileSync(changed)), { ifMatch: remote.etag });

    // 3. Vivaldi (alte Kopie mit Argon2id, Verlauf 10, ohne Beschreibung) ändert und gleicht ab.
    for (const password of ["p1", "p2", "p3", "p4"]) setField(vivaldi, mail, "Password", password, {}, createVaultClock(vivaldi));
    expect(findEntry(vivaldi, mail)!.history).toHaveLength(4);
    const result = await syncVault(vivaldi, adapter, codec, options());
    expect(result.written).toBe(true);
    vivaldi = result.vault;

    // 4. Die Datei behält KeePassXCs Einstellungen, enthält aber Vivaldis Änderung.
    const final = await readKdbx((await adapter.read())!.data, credentials);
    expect(final.meta.historyMaxItems).toBe(3);
    expect(final.meta.unknown).toContain(`<DatabaseDescription>${DESCRIPTION}</DatabaseDescription>`);
    expect(final.settings.kdf.type).toBe("aes");
    const entry = findEntry(final, mail)!;
    expect(entry.strings.get("Password")?.value).toBe("p4");
    expect(entry.history.length).toBeLessThanOrEqual(3);
    // Auch Vivaldis neue lokale Fassung hat die Server-Einstellungen übernommen.
    expect(vivaldi.meta.historyMaxItems).toBe(3);
    expect(vivaldi.settings.kdf.type).toBe("aes");

    const finalPath = join(dir, "final.kdbx");
    writeFileSync(finalPath, (await adapter.read())!.data);
    const info = await kpxcDbInfo(finalPath, PASSWORD);
    expect(info.Description).toBe(DESCRIPTION);
    expect(info.KDF).toMatch(/^AES/);
  });
});
