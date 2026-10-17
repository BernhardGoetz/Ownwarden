import { describe, expect, it } from "vitest";
import { PreconditionFailedError } from "../contracts";
import { InMemoryAdapter, InMemoryStorage } from "./memory-adapter";

const bytes = (text: string) => new TextEncoder().encode(text);

describe("InMemoryAdapter: verhält sich wie ein guter WebDAV-Server", () => {
  it("If-None-Match: * legt an und scheitert, wenn es die Datei schon gibt", async () => {
    const adapter = new InMemoryAdapter();
    expect(await adapter.read()).toBeNull();
    const { etag } = await adapter.write(bytes("a"), { ifNoneMatch: "*" });
    await expect(adapter.write(bytes("b"), { ifNoneMatch: "*" })).rejects.toBeInstanceOf(PreconditionFailedError);
    expect(await adapter.read()).toMatchObject({ data: bytes("a"), etag });
    expect(adapter.stats).toMatchObject({ writes: 1, rejectedWrites: 1 });
  });

  it("If-Match: nur mit aktuellem ETag; neuer ETag auch bei gleichem Inhalt; fehlende Datei -> 412", async () => {
    const adapter = new InMemoryAdapter();
    await expect(adapter.write(bytes("x"), { ifMatch: '"egal"' })).rejects.toBeInstanceOf(PreconditionFailedError);
    const first = await adapter.write(bytes("a"), { ifNoneMatch: "*" });
    const second = await adapter.write(bytes("a"), { ifMatch: first.etag! });
    expect(second.etag).not.toBe(first.etag);
    await expect(adapter.write(bytes("b"), { ifMatch: first.etag! })).rejects.toBeInstanceOf(PreconditionFailedError);
  });

  it("liefert Kopien: Änderungen an gelesenen oder geschriebenen Bytes ändern den Server nicht", async () => {
    const adapter = new InMemoryAdapter();
    const data = bytes("abc");
    await adapter.write(data, { ifNoneMatch: "*" });
    data[0] = 0x7a;
    const read = (await adapter.read())!;
    read.data[1] = 0x7a;
    expect((await adapter.read())!.data).toEqual(bytes("abc"));
  });

  it("mehrere Geräte teilen sich einen Server; beforeWrite spielt eine fremde Änderung ein", async () => {
    const storage = new InMemoryStorage();
    const vivaldi = new InMemoryAdapter({ storage, name: "Vivaldi" });
    const chrome = new InMemoryAdapter({ storage, name: "Chrome" });
    const { etag } = await vivaldi.write(bytes("v1"), { ifNoneMatch: "*" });
    chrome.beforeWrite = () => {
      storage.put(bytes("von Vivaldi"));
    };
    await expect(chrome.write(bytes("von Chrome"), { ifMatch: etag! })).rejects.toBeInstanceOf(PreconditionFailedError);
    expect(storage.current()!.data).toEqual(bytes("von Vivaldi"));
    expect(chrome.describe()).toContain("Chrome");
  });

  it("Date-Header (ganze Sekunden), abschaltbar; ETag zurückhalten", async () => {
    const storage = new InMemoryStorage({ serverClock: () => 1_700_000_000_999 });
    const adapter = new InMemoryAdapter({ storage });
    await adapter.write(bytes("a"), { ifNoneMatch: "*" });
    expect((await adapter.read())!.serverDate).toBe(1_700_000_000_000);
    storage.serverClock = null;
    storage.withholdEtag = true;
    const file = (await adapter.read())!;
    expect(file.serverDate).toBeUndefined();
    expect(file.etag).toBe("");
  });

  // Seit Review xc-1: backup() löscht nichts und sichert jede Fassung nur einmal; aufgeräumt
  // wird getrennt mit pruneBackups() (bisher behielt backup() selbst nur die neuesten `keep`).
  it("backup sichert jede Fassung einmal; pruneBackups behält die neuesten `keep`; nextBackupError schlägt einmal fehl", async () => {
    const adapter = new InMemoryAdapter();
    const texts = () => adapter.storage.backups.map((backup) => new TextDecoder().decode(backup.data));
    for (let i = 1; i <= 4; i++) await adapter.backup({ data: bytes(`v${i}`), etag: `"${i}"` });
    await adapter.backup({ data: bytes("v4"), etag: '"4"' }); // dieselbe Fassung noch einmal
    expect(texts()).toEqual(["v1", "v2", "v3", "v4"]);
    expect(adapter.stats.backups).toBe(4);

    await adapter.pruneBackups({ data: bytes("v4"), etag: '"4"' }, 2);
    expect(texts()).toEqual(["v3", "v4"]);
    // Die Sicherung der überschriebenen Fassung bleibt, auch wenn sie nicht die neueste ist.
    await adapter.backup({ data: bytes("v5"), etag: '"5"' });
    await adapter.pruneBackups({ data: bytes("v3"), etag: '"3"' }, 1);
    expect(texts()).toEqual(["v3"]);
    expect(adapter.stats.prunes).toBe(2);

    adapter.nextBackupError = new Error("kaputt");
    await expect(adapter.backup({ data: bytes("v6"), etag: '"6"' })).rejects.toThrow("kaputt");
    await adapter.backup({ data: bytes("v7"), etag: '"7"' });
    expect(adapter.stats.backups).toBe(6);
    await expect(adapter.pruneBackups({ data: bytes("x"), etag: '"x"' }, 0)).rejects.toBeInstanceOf(RangeError);
  });
});
