/**
 * WebDavAdapter und syncVault gegen den SabreDAV-Testserver (tools/webdav-test-server), der
 * sich beim Schreiben wie Nextcloud verhält. Wird übersprungen, wenn PHP/Composer fehlen.
 */
import { connect } from "node:net";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startWebDavTestServer, webDavTestServerAvailable, type WebDavTestServer } from "../../test/helpers/webdav-server";
import { entryByTitle, newVault, uuidFromName } from "../../test/helpers/vault-builder";
import { PreconditionFailedError, StorageAuthError, type SyncOptions } from "../contracts";
import { createVaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setField } from "../merge/vault-ops";
import { basicAuthorization } from "./http";
import { createKdbxCodec } from "./kdbx-codec";
import { syncVault } from "./sync";
import { WebDavAdapter, type WebDavAdapterOptions } from "./webdav";

const bytes = (text: string) => new TextEncoder().encode(text);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe.skipIf(!webDavTestServerAvailable())("WebDavAdapter gegen den SabreDAV-Testserver", () => {
  let server: WebDavTestServer;

  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-adapter");
  });
  afterAll(async () => {
    await server?.stop();
  });

  const fileUrl = (name: string) => new URL(name, server.baseUrl).href;

  /** fetch, das Methode und Status jeder Antwort mitschreibt. */
  function recordingFetch() {
    const log: string[] = [];
    const fetchFn: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      log.push(`${init?.method ?? "GET"} ${response.status}`);
      return response;
    };
    return { log, fetchFn };
  }

  function adapterFor(name: string, extra: Partial<WebDavAdapterOptions> = {}): WebDavAdapter {
    return new WebDavAdapter({ fileUrl: fileUrl(name), username: server.username, password: server.password, ...extra });
  }

  it("legt mit If-None-Match: * an (201); ein zweites Anlegen scheitert mit 412", async () => {
    const { log, fetchFn } = recordingFetch();
    const adapter = adapterFor("create.kdbx", { fetch: fetchFn });

    const created = await adapter.write(bytes("erste Fassung"), { ifNoneMatch: "*" });
    await expect(adapter.write(bytes("zweite Fassung"), { ifNoneMatch: "*" })).rejects.toBeInstanceOf(PreconditionFailedError);

    expect(log).toEqual(["PUT 201", "PUT 412"]);
    expect(created.etag).toMatch(/^"[0-9a-f]+"$/); // stark, in Anführungszeichen
    const file = await adapter.read();
    expect(file?.data).toEqual(bytes("erste Fassung"));
    expect(file?.etag).toBe(created.etag);
  });

  it("GET liefert ETag und Date; fehlende Datei -> null", async () => {
    const adapter = adapterFor("read.kdbx");
    expect(await adapter.read()).toBeNull();
    await adapter.write(bytes("inhalt"), { ifNoneMatch: "*" });

    const file = await adapter.read();

    expect(file?.etag).toMatch(/^"/);
    expect(Math.abs(file!.serverDate! - Date.now())).toBeLessThan(60_000);
  });

  it("If-Match mit aktuellem ETag schreibt (neuer ETag), mit veraltetem nicht (412)", async () => {
    const adapter = adapterFor("update.kdbx");
    const v1 = await adapter.write(bytes("v1"), { ifNoneMatch: "*" });
    const v2 = await adapter.write(bytes("v2"), { ifMatch: v1.etag! });
    expect(v2.etag).not.toBeNull();
    expect(v2.etag).not.toBe(v1.etag);

    await expect(adapter.write(bytes("v3 mit altem ETag"), { ifMatch: v1.etag! })).rejects.toBeInstanceOf(PreconditionFailedError);

    expect(await adapter.read()).toMatchObject({ data: bytes("v2"), etag: v2.etag });
  });

  it("ETag ändert sich auch bei gleich großem Inhalt in derselben Sekunde", async () => {
    const adapter = adapterFor("same-second.kdbx");
    const a = await adapter.write(bytes("AAAA"), { ifNoneMatch: "*" });
    const b = await adapter.write(bytes("BBBB"), { ifMatch: a.etag! });
    const c = await adapter.write(bytes("BBBB"), { ifMatch: b.etag! });
    expect(new Set([a.etag, b.etag, c.etag]).size).toBe(3);
  });

  it("falsches Passwort -> StorageAuthError ohne Passwort in der Meldung", async () => {
    await adapterFor("auth.kdbx").write(bytes("x"), { ifNoneMatch: "*" });
    const wrong = new WebDavAdapter({ fileUrl: fileUrl("auth.kdbx"), username: server.username, password: "falsches-Passwort" });

    const failures = await Promise.allSettled([
      wrong.read(),
      wrong.write(bytes("y"), { ifNoneMatch: "*" }),
      wrong.backup({ data: bytes("x"), etag: '"1"' }, 3),
    ]);

    for (const failure of failures) {
      expect(failure.status).toBe("rejected");
      const reason = (failure as PromiseRejectedResult).reason;
      expect(reason).toBeInstanceOf(StorageAuthError);
      expect(String(reason)).not.toContain("falsches-Passwort");
    }
  });

  it("Schreiben in einen fehlenden Ordner -> StorageError 409", async () => {
    const adapter = adapterFor("fehlt/tresor.kdbx");
    await expect(adapter.write(bytes("x"), { ifNoneMatch: "*" })).rejects.toMatchObject({ name: "StorageError", status: 409 });
  });

  it("Sicherungskopien per COPY; Aufräumen behält die neuesten N, fremde Dateien bleiben", async () => {
    let time = Date.UTC(2026, 9, 15, 12, 0, 0, 0);
    const adapter = adapterFor("backup.kdbx", { now: () => (time += 1000) });
    const backupDir = join(server.dataDir, "ownwarden-backups");
    mkdirSync(backupDir);
    writeFileSync(join(backupDir, "anderer.20200101-000000-000.kdbx"), "fremd");
    writeFileSync(join(backupDir, "notizen.txt"), "fremd");

    await adapter.write(bytes("Fassung 0"), { ifNoneMatch: "*" });
    for (let version = 1; version <= 5; version++) {
      const current = (await adapter.read())!;
      await adapter.backup(current, 3);
      await adapter.write(bytes(`Fassung ${version}`), { ifMatch: current.etag });
    }

    const names = readdirSync(backupDir).sort();
    expect(names).toEqual([
      "anderer.20200101-000000-000.kdbx",
      "backup.20261015-120003-000.kdbx",
      "backup.20261015-120004-000.kdbx",
      "backup.20261015-120005-000.kdbx",
      "notizen.txt",
    ]);
    expect(readFileSync(join(backupDir, "backup.20261015-120005-000.kdbx"), "utf8")).toBe("Fassung 4");
    expect(readFileSync(join(backupDir, "backup.20261015-120003-000.kdbx"), "utf8")).toBe("Fassung 2");
  });

  it("ohne COPY-Unterstützung lädt backup() die gelesenen Bytes hoch", async () => {
    const noCopy: typeof fetch = async (input, init) =>
      init?.method === "COPY" ? new Response(null, { status: 501 }) : fetch(input, init);
    const adapter = adapterFor("nocopy.kdbx", { fetch: noCopy, now: () => Date.UTC(2026, 0, 2, 3, 4, 5, 6) });
    await adapter.write(bytes("Original"), { ifNoneMatch: "*" });

    await adapter.backup((await adapter.read())!, 2);

    expect(readFileSync(join(server.dataDir, "ownwarden-backups", "nocopy.20260102-030405-006.kdbx"), "utf8")).toBe("Original");
  });

  it("ohne ETag im GET holt read() ihn per PROPFIND (gleicher Wert)", async () => {
    const withoutEtag: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      if ((init?.method ?? "GET") !== "GET") return response;
      const headers = new Headers(response.headers);
      headers.delete("ETag");
      return new Response(await response.arrayBuffer(), { status: response.status, headers });
    };
    const plain = adapterFor("propfind.kdbx");
    const written = await plain.write(bytes("inhalt"), { ifNoneMatch: "*" });

    const file = await adapterFor("propfind.kdbx", { fetch: withoutEtag }).read();

    expect(file).toMatchObject({ data: bytes("inhalt"), etag: written.etag });
  });

  it("ein abgebrochener Upload (fetch mit Stream, AbortController) lässt die alte Fassung unverändert", async () => {
    const adapter = adapterFor("abort.kdbx");
    const original = bytes("alte, vollständige Fassung");
    const { etag } = await adapter.write(original, { ifNoneMatch: "*" });

    const controller = new AbortController();
    const body = new ReadableStream<Uint8Array>({
      start(stream) {
        stream.enqueue(new Uint8Array(64 * 1024).fill(0x41)); // erster Teil; der Rest kommt nie
      },
    });
    const upload = fetch(fileUrl("abort.kdbx"), {
      method: "PUT",
      body,
      headers: { Authorization: basicAuthorization(server.username, server.password), "If-Match": etag! },
      signal: controller.signal,
      duplex: "half", // Node verlangt das für Stream-Körper
    } as RequestInit);
    await sleep(200);
    controller.abort();
    await expect(upload).rejects.toThrow();
    await sleep(200);

    expect(await adapter.read()).toMatchObject({ data: original, etag });

    // Gegenprobe: Derselbe Stream-Upload, aber vollständig, kommt an (der Server kann also
    // Stream-Körper; der Abbruch oben war wirklich ein Abbruch).
    const complete = await fetch(fileUrl("abort.kdbx"), {
      method: "PUT",
      body: new ReadableStream<Uint8Array>({
        start(stream) {
          stream.enqueue(bytes("neue "));
          stream.enqueue(bytes("Fassung"));
          stream.close();
        },
      }),
      headers: { Authorization: basicAuthorization(server.username, server.password), "If-Match": etag! },
      duplex: "half",
    } as RequestInit);
    expect(complete.status).toBe(204);
    expect((await adapter.read())?.data).toEqual(bytes("neue Fassung"));
  });

  it("ein Upload, der vor Content-Length endet (Verbindung weg), lässt die alte Fassung unverändert", async () => {
    const adapter = adapterFor("truncated.kdbx");
    const original = bytes("alte Fassung");
    const { etag } = await adapter.write(original, { ifNoneMatch: "*" });
    const { port } = new URL(server.baseUrl);

    await new Promise<void>((resolve, reject) => {
      const socket = connect(Number(port), "127.0.0.1", () => {
        socket.write(
          "PUT /truncated.kdbx HTTP/1.1\r\n" +
            `Host: 127.0.0.1:${port}\r\n` +
            `Authorization: ${basicAuthorization(server.username, server.password)}\r\n` +
            `If-Match: ${etag}\r\n` +
            "Content-Type: application/octet-stream\r\n" +
            "Content-Length: 100000\r\n\r\n",
        );
        socket.write(new Uint8Array(1000).fill(0x42));
        setTimeout(() => {
          socket.destroy();
          resolve();
        }, 100);
      });
      socket.on("error", reject);
    });
    await sleep(200);

    expect(await adapter.read()).toMatchObject({ data: original, etag });
    expect(existsSync(join(server.dataDir, "truncated.kdbx"))).toBe(true);
  });
});

describe.skipIf(!webDavTestServerAvailable())("syncVault über WebDAV mit echten KDBX-Dateien", () => {
  let server: WebDavTestServer;

  beforeAll(async () => {
    server = await startWebDavTestServer("webdav-sync");
  });
  afterAll(async () => {
    await server?.stop();
  });

  it("zwei Geräte, verschränktes Schreiben (echte 412 vom Server): beide Änderungen bleiben, Backups liegen bereit", async () => {
    const codec = createKdbxCodec({ password: "Tresor-Testpasswort" });
    const fileUrl = new URL("Ownwarden/tresor.kdbx", server.baseUrl).href;
    mkdirSync(join(server.dataDir, "Ownwarden"));
    const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 5 });
    const mail = uuidFromName("mail");

    const vivaldi = new WebDavAdapter({ fileUrl, username: server.username, password: server.password });
    let triggerVivaldi: (() => Promise<void>) | undefined;
    // Chrome-fetch: Vor Chromes erstem bedingten Schreiben der Tresor-Datei schreibt Vivaldi.
    const chromeFetch: typeof fetch = async (input, init) => {
      const isConditionalPut = init?.method === "PUT" && String(input) === fileUrl && new Headers(init.headers).has("If-Match");
      if (isConditionalPut && triggerVivaldi !== undefined) {
        const run = triggerVivaldi;
        triggerVivaldi = undefined;
        await run();
      }
      return fetch(input, init);
    };
    const chrome = new WebDavAdapter({ fileUrl, username: server.username, password: server.password, fetch: chromeFetch });

    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail", UserName: "bob", Password: "alt" }, createVaultClock(initial), { uuid: mail });
    const created = await syncVault(initial, vivaldi, codec, options());
    expect(created.created).toBe(true);

    let vaultA = created.vault;
    const vaultB = await codec.decode((await chrome.read())!.data);
    setField(vaultA, mail, "UserName", "alice", {}, createVaultClock(vaultA));
    setField(vaultB, mail, "Password", "neu", {}, createVaultClock(vaultB));
    triggerVivaldi = async () => {
      vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
    };

    const resultB = await syncVault(vaultB, chrome, codec, options());

    expect(resultB).toMatchObject({ written: true, attempts: 2 });
    const final = await codec.decode((await vivaldi.read())!.data);
    expect(entryByTitle(final, "Mail").strings.get("UserName")?.value).toBe("alice");
    expect(entryByTitle(final, "Mail").strings.get("Password")?.value).toBe("neu");
    // Backups: vor Vivaldis Schreiben und vor Chromes erfolgreichem Schreiben (der erste Versuch
    // hatte ebenfalls schon gesichert, bevor er 412 bekam).
    const backups = readdirSync(join(server.dataDir, "Ownwarden", "ownwarden-backups"));
    expect(backups.length).toBe(3);
    for (const name of backups) expect(name).toMatch(/^tresor\.\d{8}-\d{6}-\d{3}\.kdbx$/);

    // Danach: Vivaldi übernimmt Chromes Stand ohne zu schreiben.
    const again = await syncVault(vaultA, vivaldi, codec, options());
    expect(again.written).toBe(false);
    expect(entryByTitle(again.vault, "Mail").strings.get("Password")?.value).toBe("neu");
  });

  it("http:// auf einen fremden Rechner wird abgelehnt (auch bei laufendem Server)", () => {
    expect(() => new WebDavAdapter({ fileUrl: "http://example.com/tresor.kdbx", username: "u", password: "p" })).toThrow(/nur https/);
    const loopback = new URL(server.baseUrl);
    expect(() => new WebDavAdapter({ fileUrl: `http://localhost:${loopback.port}/t.kdbx`, username: "u", password: "p" })).not.toThrow();
  });
});
