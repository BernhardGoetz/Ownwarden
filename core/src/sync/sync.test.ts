/**
 * Tests für syncVault mit dem InMemoryAdapter (realistische ETag-/412-Regeln) und dem
 * JSON-Codec. Zusammengeführt wird mit dem ECHTEN mergeVaults; ein Ersatz-Merge nur dort,
 * wo der Test das Verhalten des Merge steuern oder beobachten muss.
 */
import { describe, expect, it } from "vitest";
import { entryByTitle, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import {
  ClockSkewError,
  FutureTimestampsError,
  PreconditionFailedError,
  StorageAuthError,
  StorageError,
  type MergeVaults,
  type SyncOptions,
  type VaultCodec,
} from "../contracts";
import type { Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { createVaultClock, latestVaultTime } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setField } from "../merge/vault-ops";
import { restampFutureTimes } from "./future-times";
import { InMemoryAdapter, InMemoryStorage } from "./memory-adapter";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "./sync";
import { createJsonCodec } from "./testing/json-codec";

/** „Jetzt“ in diesen Tests: einen Tag nach T0. Server- und Geräteuhr stimmen überein. */
const NOW = T0 + 86_400_000;
const MAIL = uuidFromName("mail");

function options(overrides: Partial<SyncOptions> = {}): SyncOptions {
  return { now: () => NOW, merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 5, ...overrides };
}

function newServer(): InMemoryStorage {
  return new InMemoryStorage({ serverClock: () => NOW });
}

/** Ausgangs-Datenbank: ein Eintrag "Mail", angelegt mit der Bearbeitungs-API (Feld-Zeitstempel korrekt). */
function baseVault(): Vault {
  const vault = newVault();
  createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "bob", Password: "alt" }, createVaultClock(vault, () => T0), { uuid: MAIL });
  return vault;
}

/** Ändert ein Feld wie ein Gerät, dessen Uhr bei NOW steht. */
function edit(vault: Vault, field: string, value: string): void {
  setField(vault, MAIL, field, value, {}, createVaultClock(vault, () => NOW));
}

async function serverVault(server: InMemoryStorage, codec: VaultCodec): Promise<Vault> {
  const file = server.current();
  if (file === null) throw new Error("Keine Datei auf dem Server");
  return codec.decode(file.data);
}

const field = (vault: Vault, name: string) => entryByTitle(vault, "Mail").strings.get(name)?.value;

describe("syncVault: erstes Hochladen und Abgleich ohne Änderung", () => {
  it("legt die Datei mit If-None-Match an, wenn es noch keine gibt", async () => {
    const server = newServer();
    const adapter = new InMemoryAdapter({ storage: server });
    const codec = createJsonCodec();
    const local = baseVault();

    const result = await syncVault(local, adapter, codec, options());

    expect(result).toMatchObject({ created: true, written: true, attempts: 1, etag: server.current()!.etag });
    expect(result.vault).toBe(local);
    expect(result.report).toBeUndefined();
    expect(await serverVault(server, codec)).toEqual(local);
    expect(server.backups).toHaveLength(0); // es gab nichts zu sichern
  });

  it("schreibt nicht, wenn sich nichts geändert hat (kein Backup, gleicher ETag)", async () => {
    const server = newServer();
    const adapter = new InMemoryAdapter({ storage: server });
    const codec = createJsonCodec();
    const first = await syncVault(baseVault(), adapter, codec, options());
    const encodes = codec.encodes;

    const second = await syncVault(first.vault, adapter, codec, options());

    expect(second).toMatchObject({ created: false, written: false, attempts: 1, etag: first.etag });
    expect(codec.encodes).toBe(encodes);
    expect(adapter.stats.writes).toBe(1);
    expect(server.backups).toHaveLength(0);
    expect(second.report).toBeDefined();
  });

  it("lokale Änderung: Backup der Server-Fassung, dann Schreiben mit If-Match", async () => {
    const server = newServer();
    const adapter = new InMemoryAdapter({ storage: server });
    const codec = createJsonCodec();
    const first = await syncVault(baseVault(), adapter, codec, options());
    const before = server.current()!;
    const local = cloneVault(first.vault);
    edit(local, "Password", "neu");

    const result = await syncVault(local, adapter, codec, options());

    expect(result).toMatchObject({ created: false, written: true, attempts: 1 });
    expect(result.etag).toBe(server.current()!.etag);
    expect(result.etag).not.toBe(before.etag);
    expect(field(await serverVault(server, codec), "Password")).toBe("neu");
    expect(server.backups).toHaveLength(1);
    expect(server.backups[0]!.data).toEqual(before.data);
  });

  it("übernimmt Änderungen vom Server, ohne zu schreiben", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const vivaldi = new InMemoryAdapter({ storage: server, name: "Vivaldi" });
    const chrome = new InMemoryAdapter({ storage: server, name: "Chrome" });
    const base = (await syncVault(baseVault(), vivaldi, codec, options())).vault;
    const changed = cloneVault(base);
    edit(changed, "UserName", "alice");
    await syncVault(changed, vivaldi, codec, options());

    const result = await syncVault(cloneVault(base), chrome, codec, options());

    expect(result.written).toBe(false);
    expect(field(result.vault, "UserName")).toBe("alice");
    expect(chrome.stats.writes).toBe(0);
  });
});

describe("syncVault: gleichzeitiges Schreiben (412)", () => {
  it("zwei Geräte verschränkt: 412 -> neu lesen, neu zusammenführen, beide Änderungen bleiben", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const vivaldi = new InMemoryAdapter({ storage: server, name: "Vivaldi" });
    const chrome = new InMemoryAdapter({ storage: server, name: "Chrome" });
    const base = (await syncVault(baseVault(), vivaldi, codec, options())).vault;
    let vaultA = cloneVault(base);
    const vaultB = cloneVault(base);
    edit(vaultA, "UserName", "alice");
    edit(vaultB, "Password", "neu");

    // Chrome hat gelesen und zusammengeführt; genau vor seinem Schreiben schreibt Vivaldi.
    let interleaved = 0;
    chrome.beforeWrite = async () => {
      if (interleaved++ > 0) return;
      vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
    };
    const result = await syncVault(vaultB, chrome, codec, options());

    expect(result).toMatchObject({ written: true, attempts: 2 });
    expect(chrome.stats.rejectedWrites).toBe(1);
    const final = await serverVault(server, codec);
    expect(field(final, "UserName")).toBe("alice");
    expect(field(final, "Password")).toBe("neu");
    expect(result.etag).toBe(server.current()!.etag);

    // Vivaldi gleicht danach erneut ab: bekommt Chromes Änderung und muss nichts schreiben.
    const again = await syncVault(vaultA, vivaldi, codec, options());
    expect(again.written).toBe(false);
    expect(field(again.vault, "Password")).toBe("neu");

    // Und Chrome ebenso (kein „Ping-Pong“).
    expect((await syncVault(result.vault, chrome, codec, options())).written).toBe(false);
  });

  it("zwei Geräte legen die Datei gleichzeitig an: der zweite führt zusammen statt zu überschreiben", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const other = newVault();
    other.root.uuid = baseVault().root.uuid;
    createEntry(other, other.root.uuid, { Title: "Bank" }, createVaultClock(other, () => NOW), { uuid: uuidFromName("bank") });
    const local = baseVault();
    local.root.uuid = other.root.uuid;

    let created = false;
    adapter.beforeWrite = async () => {
      if (created) return;
      created = true;
      server.put(await codec.encode(other));
    };
    const result = await syncVault(local, adapter, codec, options());

    expect(result).toMatchObject({ created: false, written: true, attempts: 2 });
    const final = await serverVault(server, codec);
    expect(entryByTitle(final, "Mail")).toBeDefined();
    expect(entryByTitle(final, "Bank")).toBeDefined();
  });

  it("gibt nach maxAttempts mit PreconditionFailedError (deutsche Meldung) auf", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const foreign = await codec.encode(base);
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    // Vor JEDEM Schreiben kommt ein anderes Gerät zuvor.
    adapter.beforeWrite = () => {
      server.put(foreign);
    };

    const failure = syncVault(local, adapter, codec, options({ maxAttempts: 3 }));

    await expect(failure).rejects.toBeInstanceOf(PreconditionFailedError);
    await expect(failure).rejects.toThrow(/3 Versuche/);
    expect(adapter.stats.rejectedWrites).toBe(3);
    expect(adapter.stats.reads).toBe(4); // 1x Anlegen + 3 Versuche
    expect(field(await serverVault(server, codec), "Password")).toBe("alt");
  });

  it("andere Schreibfehler werden nicht wiederholt", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    adapter.beforeWrite = () => {
      throw new StorageError("Fehler auf dem Server", 500);
    };

    await expect(syncVault(local, adapter, codec, options())).rejects.toMatchObject({ name: "StorageError", status: 500 });
    expect(adapter.stats.reads).toBe(2);
  });
});

describe("syncVault: Schutz vor Datenverlust", () => {
  it("bricht bei abweichender Geräteuhr VOR dem Schreiben ab (ClockSkewError)", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    server.serverClock = () => NOW + 5 * 60_000; // Server 5 Minuten weiter: Geräteuhr geht nach

    const failure = syncVault(local, adapter, codec, options());

    await expect(failure).rejects.toBeInstanceOf(ClockSkewError);
    await expect(failure).rejects.toMatchObject({ skewMs: -300_000 });
    expect(adapter.stats.backups).toBe(0);
    expect(codec.decodes).toBe(0);
    expect(field(await serverVault(server, codec), "Password")).toBe("alt");
  });

  it("toleriert Abweichungen bis maxClockSkewMs und Server ohne Date-Header", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;

    server.serverClock = () => NOW - 119_000;
    expect((await syncVault(base, adapter, codec, options())).written).toBe(false);
    server.serverClock = null;
    expect((await syncVault(base, adapter, codec, options())).written).toBe(false);
  });

  it("schreibt nicht, wenn der Server keinen ETag liefert", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const before = server.current()!;
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    server.withholdEtag = true;

    const failure = syncVault(local, adapter, codec, options());

    await expect(failure).rejects.toBeInstanceOf(StorageError);
    await expect(failure).rejects.toThrow(/ETag/);
    expect(server.current()!.etag).toBe(before.etag);
    expect(adapter.stats.backups).toBe(0);
  });

  it("schreibt nicht, wenn die Sicherungskopie scheitert", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const before = server.current()!;
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    const cause = new StorageError("Speicher voll", 507);
    adapter.nextBackupError = cause;

    const failure = syncVault(local, adapter, codec, options());

    await expect(failure).rejects.toMatchObject({ name: "StorageError", status: 507, cause });
    await expect(failure).rejects.toThrow(/Sicherungskopie.*nichts geändert/s);
    expect(server.current()!.etag).toBe(before.etag);
    expect(adapter.stats.writes).toBe(1); // nur das erste Anlegen
  });

  it("reicht eine abgelehnte Anmeldung beim Backup als StorageAuthError weiter", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const local = cloneVault(base);
    edit(local, "Password", "neu");
    adapter.nextBackupError = new StorageAuthError();

    await expect(syncVault(local, adapter, codec, options())).rejects.toBeInstanceOf(StorageAuthError);
    expect(adapter.stats.writes).toBe(1);
  });

  it("schreibt nicht, wenn die Server-Datei sich nicht entschlüsseln lässt", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    await syncVault(baseVault(), adapter, codec, options());
    const broken: VaultCodec = {
      encode: (vault) => codec.encode(vault),
      decode: async () => {
        throw new Error("falsches Passwort");
      },
    };

    await expect(syncVault(baseVault(), adapter, broken, options())).rejects.toThrow("falsches Passwort");
    expect(adapter.stats.writes).toBe(1);
    expect(adapter.stats.backups).toBe(0);
  });

  // Review merge-2/sync-2, Entscheidung des Eigentümers (2026-10-17): Zeitstempel aus der Zukunft
  // in der LOKALEN Fassung (offline mit vorgehender Uhr bearbeitet, Uhr danach gestellt).
  it("lokale Zeitstempel nach Serverzeit + maxClockSkewMs: FutureTimestampsError, nichts gesichert oder geschrieben", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const before = server.current()!;
    const local = cloneVault(base);
    setField(local, MAIL, "Password", "falsche Uhr", {}, createVaultClock(local, () => NOW + 3 * 60_000));

    const failure = syncVault(local, adapter, codec, options());

    await expect(failure).rejects.toBeInstanceOf(FutureTimestampsError);
    await expect(failure).rejects.toMatchObject({ latestTime: NOW + 3 * 60_000, limit: NOW + 120_000 });
    await expect(failure).rejects.toThrow(/Zukunft.*nichts geschrieben/s);
    expect(server.current()!.etag).toBe(before.etag);
    expect(adapter.stats).toMatchObject({ writes: 1, backups: 0 });

    // Bis maxClockSkewMs ist es erlaubt (z. B. ein anderes Gerät mit etwas vorgehender Uhr).
    const almost = cloneVault(base);
    setField(almost, MAIL, "Password", "knapp", {}, createVaultClock(almost, () => NOW + 120_000));
    expect((await syncVault(almost, adapter, codec, options())).written).toBe(true);
  });

  it("nach der Reparatur (restampFutureTimes) klappt der Abgleich; die Änderung gilt als jetzt gemacht", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    const local = cloneVault(base);
    setField(local, MAIL, "Password", "falsche Uhr", {}, createVaultClock(local, () => NOW + 86_400_000));
    await expect(syncVault(local, adapter, codec, options())).rejects.toBeInstanceOf(FutureTimestampsError);

    const { vault: repaired } = restampFutureTimes(local, NOW + 120_000, NOW);
    const result = await syncVault(repaired, adapter, codec, options());

    expect(result.written).toBe(true);
    const final = await serverVault(server, codec);
    expect(field(final, "Password")).toBe("falsche Uhr");
    expect(latestVaultTime(final)).toBe(NOW);
  });

  it("erstes Hochladen: Grenze ist die Gerätezeit + maxClockSkewMs; ohne Date-Header ebenso", async () => {
    const codec = createJsonCodec();
    const future = baseVault();
    setField(future, MAIL, "Password", "falsche Uhr", {}, createVaultClock(future, () => NOW + 86_400_000));

    const empty = new InMemoryAdapter({ storage: newServer() });
    await expect(syncVault(future, empty, codec, options())).rejects.toBeInstanceOf(FutureTimestampsError);
    expect(empty.storage.current()).toBeNull();
    expect(codec.encodes).toBe(0);

    const noDate = new InMemoryStorage({ serverClock: null });
    const adapter = new InMemoryAdapter({ storage: noDate });
    await syncVault(baseVault(), adapter, codec, options());
    const before = noDate.current()!.etag;
    await expect(syncVault(future, adapter, codec, options())).rejects.toBeInstanceOf(FutureTimestampsError);
    expect(noDate.current()!.etag).toBe(before);
  });

  it("stammen die Zeiten aus der Zukunft schon vom Server (z. B. KeePassXC mit falscher Uhr), sperrt das die Geräte nicht dauerhaft", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    // Ein anderes Programm hat mit Uhr einen Tag vor geschrieben (ohne Ownwarden-Prüfung).
    const polluted = cloneVault(base);
    setField(polluted, MAIL, "UserName", "von KeePassXC", {}, createVaultClock(polluted, () => NOW + 86_400_000));
    server.put(await codec.encode(polluted));

    // Erster Abgleich übernimmt die Zeiten; danach enthält auch die lokale Fassung sie ...
    const first = await syncVault(base, adapter, codec, options());
    expect(latestVaultTime(first.vault)).toBeGreaterThan(NOW + 120_000);
    // ... und eine neue lokale Änderung (VaultClock stempelt knapp danach) wird trotzdem abgeglichen.
    const local = cloneVault(first.vault);
    setField(local, MAIL, "Password", "neu", {}, createVaultClock(local, () => NOW));
    const second = await syncVault(local, adapter, codec, options());
    expect(second.written).toBe(true);
    expect(field(await serverVault(server, codec), "Password")).toBe("neu");
    // Weiter in die Zukunft als die Datei auf dem Server (plus maxClockSkewMs) geht es aber nicht.
    const further = cloneVault(second.vault);
    setField(further, MAIL, "Notes", "noch weiter", {}, createVaultClock(further, () => NOW + 2 * 86_400_000));
    await expect(syncVault(further, adapter, codec, options())).rejects.toBeInstanceOf(FutureTimestampsError);
  });

  it("prüft die Optionen", async () => {
    const adapter = new InMemoryAdapter({ storage: newServer() });
    const codec = createJsonCodec();
    await expect(syncVault(baseVault(), adapter, codec, options({ maxAttempts: 0 }))).rejects.toBeInstanceOf(RangeError);
    await expect(syncVault(baseVault(), adapter, codec, options({ backupsToKeep: 0 }))).rejects.toBeInstanceOf(RangeError);
    await expect(syncVault(baseVault(), adapter, codec, options({ maxClockSkewMs: Number.NaN }))).rejects.toBeInstanceOf(RangeError);
    expect(adapter.stats.reads).toBe(0);
  });
});

describe("syncVault: Zusammenspiel mit dem Merge", () => {
  it("übergibt local, die Server-Fassung und options.now() an merge", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    await syncVault(baseVault(), adapter, codec, options());
    const calls: { local: Vault; remote: Vault; now: number }[] = [];
    const recordingMerge: MergeVaults = (local, remote, mergeOptions) => {
      calls.push({ local, remote, now: mergeOptions.now });
      return mergeVaults(local, remote, mergeOptions);
    };
    const local = baseVault();
    edit(local, "Notes", "lokal");

    await syncVault(local, adapter, codec, options({ merge: recordingMerge, now: () => NOW + 42 }));

    expect(calls).toHaveLength(1);
    expect(calls[0]!.now).toBe(NOW + 42);
    expect(field(calls[0]!.local, "Notes")).toBe("lokal");
    expect(field(calls[0]!.remote, "Notes")).toBe("");
  });

  it("Einstellungen ohne Zeitstempel: die Fassung auf dem Server gewinnt", async () => {
    const server = newServer();
    const codec = createJsonCodec();
    const adapter = new InMemoryAdapter({ storage: server });
    const base = (await syncVault(baseVault(), adapter, codec, options())).vault;
    // Auf dem Server (z. B. mit KeePassXC) geändert: Verschlüsselung, Verlaufsgrenze, Beschreibung.
    const remote = cloneVault(base);
    remote.settings.cipher = "chacha20";
    remote.meta.historyMaxItems = 3;
    remote.meta.unknown = ["<DatabaseDescription>vom Server</DatabaseDescription>"];
    remote.rootUnknown = ["<Unbekannt/>"];
    server.put(await codec.encode(remote));
    const local = cloneVault(base);
    edit(local, "Password", "neu");

    const result = await syncVault(local, adapter, codec, options());

    const final = await serverVault(server, codec);
    expect(final.settings.cipher).toBe("chacha20");
    expect(final.meta.historyMaxItems).toBe(3);
    expect(final.meta.unknown).toEqual(["<DatabaseDescription>vom Server</DatabaseDescription>"]);
    expect(final.rootUnknown).toEqual(["<Unbekannt/>"]);
    expect(field(final, "Password")).toBe("neu");
    expect(result.vault.settings.cipher).toBe("chacha20");
    // local selbst bleibt unverändert
    expect(local.settings.cipher).toBe("aes256");
    expect(local.meta.historyMaxItems).toBe(10);
  });

  it("liefert sinnvolle Standardwerte", () => {
    expect(DEFAULT_SYNC_SETTINGS.maxAttempts).toBeGreaterThanOrEqual(3);
    expect(DEFAULT_SYNC_SETTINGS.backupsToKeep).toBeGreaterThanOrEqual(1);
    expect(DEFAULT_SYNC_SETTINGS.maxClockSkewMs).toBeGreaterThanOrEqual(60_000);
  });
});
