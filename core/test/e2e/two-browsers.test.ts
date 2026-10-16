/**
 * Ende-zu-Ende: zwei Browser-Clients („Vivaldi“ und „Chrome“) gleichen über einen echten
 * WebDAV-Server (SabreDAV-Testserver, verhält sich wie Nextcloud) ab – mit echtem KDBX-Codec,
 * echtem mergeVaults und am Ende KeePassXC als Prüfer.
 *
 *   1. Beide starten von derselben Datei.
 *      Vivaldi: ändert das Passwort von "Mail" und hängt eine Datei an.
 *      Chrome:  ändert den Benutzernamen von "Mail" und löscht "Forum".
 *   2. Erzwungenes Rennen: Chrome hat gelesen, zusammengeführt und gesichert – genau vor
 *      Chromes bedingtem Schreiben gleicht Vivaldi ab. Chromes PUT bekommt 412, Chrome liest
 *      neu, führt neu zusammen und schreibt.
 *   3. Die Datei auf dem Server enthält ALLE Änderungen; KeePassXC öffnet sie und sieht sie.
 *      Sicherungskopien liegen bereit und wurden aufgeräumt (backupsToKeep = 2).
 *   4. Ein drittes Gerät mit 10 Minuten falsch gehender Uhr: ClockSkewError, nichts geschrieben.
 *   5. Ein Upload bricht mitten im PUT ab: Die Datei auf dem Server bleibt lesbar (alte
 *      Fassung), der nächste Abgleich klappt.
 *
 * Bereits vorhandene, verwandte Tests: src/sync/webdav.server.test.ts (Rennen mit 412 bei
 * zwei Feldänderungen; abgebrochener Upload mit Rohbytes), src/sync/sync.adversarial.test.ts
 * (viele verschränkte Abgleiche im Speicher). Neu hier: Anhang + Löschung im Rennen, KeePassXC
 * prüft das Ergebnis, Aufräumen der Sicherungen, Uhr-Prüfung und Abbruch MIT echtem Server
 * und echtem Abgleich.
 *
 * Grenze: Der PHP-Testserver (php -S) puffert Uploads; ob ein ECHTER Server bei einem
 * abgebrochenen Upload die alte Datei behält, zeigt nur der WebDAV-Servertest mit --abort-test
 * gegen diesen Server (siehe README).
 * Wird übersprungen, wenn PHP/SabreDAV oder keepassxc-cli fehlen.
 */
import { randomBytes } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, exportKpxcAttachment, hasKeepassxc, listKpxc, removeTmpDir, showKpxcEntry } from "../helpers/keepassxc";
import { TEST_KDF } from "../helpers/kdbx-files";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../helpers/webdav-server";
import { ClockSkewError, StorageError, type SyncOptions } from "../../src/contracts";
import { createNewVault, readKdbx } from "../../src/kdbx/index";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import { createEntry, deleteEntry, setAttachment, setField } from "../../src/merge/vault-ops";
import type { Uuid, Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "../../src/sync/sync";
import { WebDavAdapter } from "../../src/sync/webdav";

const PASSWORD = "E2E-Tresor-äöü";
const credentials = { password: PASSWORD };
const codec = createKdbxCodec(credentials);
const RECHNUNG = new Uint8Array(randomBytes(4096));
/** Standardwerte, nur weniger Sicherungen – damit das Aufräumen wirklich etwas tut. */
const options = (now: () => number = () => Date.now()): SyncOptions => ({ now, merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS, backupsToKeep: 2 });

/** fetch, das „Methode Status“ jeder Antwort mitschreibt. */
function recordingFetch(log: string[], before?: (input: RequestInfo | URL, init?: RequestInit) => Promise<void>): typeof fetch {
  return async (input, init) => {
    await before?.(input, init);
    const response = await fetch(input, init);
    log.push(`${init?.method ?? "GET"} ${response.status}`);
    return response;
  };
}

describe.skipIf(!webDavTestServerAvailable() || !hasKeepassxc())("Ende-zu-Ende: Vivaldi und Chrome über WebDAV", () => {
  let server: WebDavTestServer;
  let dir: string;
  let fileUrl: string;
  let filePath: string;
  let backupDir: string;
  const uuids = {} as Record<"mail" | "forum" | "bleibt", Uuid>;
  let vivaldiVault: Vault;

  beforeAll(async () => {
    server = await startWebDavTestServer("e2e-browsers");
    dir = createTmpDir("e2e-browsers");
    mkdirSync(join(server.dataDir, "Ownwarden"));
    fileUrl = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    filePath = join(server.dataDir, "Ownwarden", "tresor.kdbx");
    backupDir = join(server.dataDir, "Ownwarden", "ownwarden-backups");
  });
  afterAll(async () => {
    await server?.stop();
    if (dir) removeTmpDir(dir);
  });

  const adapter = (fetchFn?: typeof fetch) => new WebDavAdapter({ fileUrl, username: server.username, password: server.password, ...(fetchFn ? { fetch: fetchFn } : {}) });

  it("Rennen mit 412: alle Änderungen beider Browser kommen an, KeePassXC sieht sie, Sicherungen aufgeräumt", async () => {
    // Ausgangslage: Vivaldi legt die Datei an, Chrome lädt sie herunter.
    const initial = createNewVault({ name: "E2E", now: Date.now(), kdf: TEST_KDF });
    const clock = createVaultClock(initial);
    uuids.mail = createEntry(initial, initial.root.uuid, { Title: "Mail", UserName: "alice", Password: "alt" }, clock).uuid;
    uuids.forum = createEntry(initial, initial.root.uuid, { Title: "Forum", UserName: "f", Password: "forum-pw" }, clock).uuid;
    uuids.bleibt = createEntry(initial, initial.root.uuid, { Title: "Bleibt" }, clock).uuid;
    const created = await syncVault(initial, adapter(), codec, options());
    expect(created.created).toBe(true);
    vivaldiVault = created.vault;
    const chromeVault = await codec.decode((await adapter().read())!.data);

    // Lokale Änderungen (offline, jede auf ihrer eigenen Kopie).
    const vivaldiClock = createVaultClock(vivaldiVault);
    setField(vivaldiVault, uuids.mail, "Password", "neu-vivaldi", {}, vivaldiClock);
    setAttachment(vivaldiVault, uuids.mail, "rechnung.pdf", RECHNUNG, {}, vivaldiClock);
    const chromeClock = createVaultClock(chromeVault);
    setField(chromeVault, uuids.mail, "UserName", "alice-chrome", {}, chromeClock);
    deleteEntry(chromeVault, uuids.forum, chromeClock);

    // Rennen erzwingen: Vor Chromes ERSTEM bedingten PUT der Tresor-Datei gleicht Vivaldi ab.
    const vivaldiLog: string[] = [];
    const chromeLog: string[] = [];
    let vivaldiPending = true;
    const chromeFetch = recordingFetch(chromeLog, async (input, init) => {
      const conditionalPut = init?.method === "PUT" && String(input) === fileUrl && new Headers(init.headers).has("If-Match");
      if (conditionalPut && vivaldiPending) {
        vivaldiPending = false;
        const vivaldiResult = await syncVault(vivaldiVault, adapter(recordingFetch(vivaldiLog)), codec, options());
        expect(vivaldiResult).toMatchObject({ written: true, attempts: 1 });
        vivaldiVault = vivaldiResult.vault;
      }
    });
    const chromeResult = await syncVault(chromeVault, adapter(chromeFetch), codec, options());

    expect(chromeResult).toMatchObject({ written: true, attempts: 2 });
    expect(chromeLog).toContain("PUT 412");
    expect(chromeResult.warnings).toBeUndefined();

    // Die Datei auf dem Server enthält alles …
    const final = await readKdbx(new Uint8Array(readFileSync(filePath)), credentials);
    const mail = findEntry(final, uuids.mail)!;
    expect(mail.strings.get("Password")?.value).toBe("neu-vivaldi");
    expect(mail.strings.get("UserName")?.value).toBe("alice-chrome");
    expect(Buffer.from(mail.attachments.find((a) => a.name === "rechnung.pdf")!.data).equals(Buffer.from(RECHNUNG))).toBe(true);
    expect(findEntry(final, uuids.forum)).toBeUndefined();
    expect(final.deletedObjects.map((item) => item.uuid)).toContain(uuids.forum);

    // … und KeePassXC sieht es genauso.
    const copy = join(dir, "final.kdbx");
    writeFileSync(copy, readFileSync(filePath));
    expect((await listKpxc(copy, PASSWORD)).sort()).toEqual(["Bleibt", "Mail"]);
    expect(await showKpxcEntry(copy, PASSWORD, "Mail", { showProtected: true, attributes: ["UserName", "Password"] })).toBe("alice-chrome\nneu-vivaldi\n");
    expect(Buffer.from(await exportKpxcAttachment(copy, PASSWORD, "Mail", "rechnung.pdf")).equals(Buffer.from(RECHNUNG))).toBe(true);

    // Sicherungen: drei angelegt (Chromes erster Versuch, Vivaldi, Chromes zweiter Versuch),
    // eine davon aufgeräumt (backupsToKeep = 2). Jede Sicherung ist eine lesbare Tresor-Datei,
    // und die zuletzt überschriebene Fassung (Vivaldis) ist dabei.
    const copies = [...chromeLog, ...vivaldiLog].filter((line) => line.startsWith("COPY 2")).length;
    const deletes = [...chromeLog, ...vivaldiLog].filter((line) => line.startsWith("DELETE 2")).length;
    expect({ copies, deletes }).toEqual({ copies: 3, deletes: 1 });
    const backups = readdirSync(backupDir);
    expect(backups).toHaveLength(2);
    const backupVaults = await Promise.all(backups.map((name) => readKdbx(new Uint8Array(readFileSync(join(backupDir, name))), credentials)));
    expect(backupVaults.some((vault) => findEntry(vault, uuids.mail)!.strings.get("Password")?.value === "neu-vivaldi")).toBe(true);

    // Danach übernimmt Vivaldi Chromes Änderungen, ohne zu schreiben (kein Ping-Pong).
    const again = await syncVault(vivaldiVault, adapter(), codec, options());
    expect(again.written).toBe(false);
    expect(findEntry(again.vault, uuids.mail)!.strings.get("UserName")?.value).toBe("alice-chrome");
    vivaldiVault = again.vault;
  });

  it("ein drittes Gerät mit 10 Minuten vorgehender Uhr: ClockSkewError, nur gelesen, nichts geschrieben", async () => {
    const before = readFileSync(filePath);
    const backupsBefore = readdirSync(backupDir).sort();
    const android = await readKdbx(new Uint8Array(before), credentials);
    setField(android, uuids.mail, "URL", "https://falsche-uhr.example", {}, createVaultClock(android));

    const log: string[] = [];
    const tenMinutesAhead = () => Date.now() + 10 * 60 * 1000;
    const error = await syncVault(android, adapter(recordingFetch(log)), codec, options(tenMinutesAhead)).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ClockSkewError);
    expect((error as ClockSkewError).skewMs).toBeGreaterThan(9 * 60 * 1000);
    expect(log).toEqual(["GET 200"]);
    expect(readFileSync(filePath).equals(before)).toBe(true);
    expect(readdirSync(backupDir).sort()).toEqual(backupsBefore);
  });

  it("Upload bricht mitten im PUT ab: Datei bleibt lesbar (alte Fassung), der nächste Abgleich klappt", async () => {
    const before = readFileSync(filePath);
    setField(vivaldiVault, uuids.mail, "Notes", "nach dem Abbruch", {}, createVaultClock(vivaldiVault));

    // fetch, das beim PUT der Tresor-Datei nur die erste Hälfte sendet und dann abbricht
    // (wie ein Verbindungsabbruch). Der Adapter meldet das als StorageError.
    let abortNextPut = true;
    const abortingFetch: typeof fetch = async (input, init) => {
      if (init?.method !== "PUT" || String(input) !== fileUrl || !abortNextPut) return fetch(input, init);
      abortNextPut = false;
      const body = init.body as Uint8Array;
      const firstHalf = body.slice(0, Math.floor(body.length / 2));
      const controller = new AbortController();
      const stream = new ReadableStream<Uint8Array>({
        start(streamController) {
          streamController.enqueue(firstHalf); // der Rest kommt nie
        },
      });
      setTimeout(() => controller.abort(), 300);
      return fetch(input, { ...init, body: stream, signal: controller.signal, duplex: "half" } as RequestInit);
    };

    await expect(syncVault(vivaldiVault, adapter(abortingFetch), codec, options())).rejects.toBeInstanceOf(StorageError);
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Alte Fassung, vollständig lesbar.
    expect(readFileSync(filePath).equals(before)).toBe(true);
    const stillReadable = await readKdbx(new Uint8Array(readFileSync(filePath)), credentials);
    expect(findEntry(stillReadable, uuids.mail)!.strings.get("Notes")?.value).toBe("");

    // Nächster Versuch: klappt, KeePassXC sieht die Änderung.
    const retry = await syncVault(vivaldiVault, adapter(), codec, options());
    expect(retry.written).toBe(true);
    const copy = join(dir, "nach-abbruch.kdbx");
    writeFileSync(copy, readFileSync(filePath));
    expect(await showKpxcEntry(copy, PASSWORD, "Mail", { attributes: ["Notes"] })).toBe("nach dem Abbruch\n");
  });
});
