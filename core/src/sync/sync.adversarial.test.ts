/**
 * Kritische Prüfung von syncVault: Invarianten unter vielen verschränkten Abgleichen mehrerer
 * Geräte und Grenzfälle in der 412-Schleife (Uhr, ETag, Sicherung im WIEDERHOLTEN Versuch).
 *
 * Invarianten, die bei JEDEM Schreibversuch gelten müssen:
 *   1. Bedingtes Schreiben: "If-Match" genau mit dem ETag des letzten Lesens (unverändert),
 *      "If-None-Match: *" nur, wenn das letzte Lesen „keine Datei“ ergab.
 *   2. Vor jedem "If-Match"-Schreiben eine Sicherung GENAU der gelesenen Fassung (gleicher
 *      ETag, gleiche Bytes), nach dem letzten Lesen.
 *   3. Keine Änderung geht verloren: Am Ende hat jedes Feld den Wert der zeitlich letzten
 *      Änderung, auf allen Geräten und auf dem Server; danach schreibt keiner mehr (kein Ping-Pong).
 */
import { isDeepStrictEqual } from "node:util";
import { describe, expect, it } from "vitest";
import { entryByTitle, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import {
  ClockSkewError,
  StorageError,
  type RemoteFile,
  type StorageAdapter,
  type SyncOptions,
  type WriteCondition,
} from "../contracts";
import type { Millis, Uuid, Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { createVaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setField } from "../merge/vault-ops";
import { InMemoryAdapter, InMemoryStorage } from "./memory-adapter";
import { syncVault } from "./sync";
import { createJsonCodec } from "./testing/json-codec";
import { WebDavAdapter } from "./webdav";

const MAIL = uuidFromName("mail");
const codec = createJsonCodec();

/** Kleiner, reproduzierbarer Zufallsgenerator (nur für den Testablauf, nicht sicherheitsrelevant). */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Adapter, der jeden Aufruf prüft (Invarianten 1 und 2) und Verstöße sammelt, statt zu werfen
 * (ein Wurf mitten im Abgleich würde den Fehler verschleiern).
 */
class CheckingAdapter implements StorageAdapter {
  readonly violations: string[] = [];
  private lastRead: RemoteFile | null | undefined;
  private backupsSinceRead: RemoteFile[] = [];

  constructor(readonly inner: InMemoryAdapter) {}

  describe(): string {
    return this.inner.describe();
  }

  async read(): Promise<RemoteFile | null> {
    const file = await this.inner.read();
    this.lastRead = file === null ? null : { ...file, data: file.data.slice() };
    this.backupsSinceRead = [];
    return file;
  }

  async backup(current: RemoteFile, keep: number): Promise<void> {
    await this.inner.backup(current, keep);
    this.backupsSinceRead.push({ ...current, data: current.data.slice() });
  }

  async write(data: Uint8Array, condition: WriteCondition): Promise<{ etag: string | null; serverDate?: Millis }> {
    const read = this.lastRead;
    if ("ifMatch" in condition) {
      if (read === undefined || read === null) this.violations.push("If-Match ohne vorheriges Lesen einer Datei");
      else if (condition.ifMatch !== read.etag) this.violations.push(`If-Match ${condition.ifMatch} statt gelesenem ETag ${read.etag}`);
      else if (!this.backupsSinceRead.some((b) => b.etag === read.etag && isDeepStrictEqual(b.data, read.data))) {
        this.violations.push(`Schreiben ohne Sicherung der gelesenen Fassung ${read.etag}`);
      }
    } else if (read !== null) {
      this.violations.push('"If-None-Match: *" obwohl zuletzt eine Datei gelesen wurde');
    }
    // Nach einem Schreibversuch muss neu gelesen werden, bevor erneut geschrieben wird.
    this.lastRead = undefined;
    return this.inner.write(data, condition);
  }
}

describe("syncVault: Invarianten bei vielen verschränkten Abgleichen (3 Geräte, zufällige Reihenfolge)", () => {
  it.each([1, 2, 3, 4, 5])("Durchlauf mit Startwert %i: bedingt, gesichert, nichts verloren, danach Ruhe", async (seed) => {
    const random = seededRandom(seed);
    let time = T0;
    const tick = () => (time += 1000);
    const storage = new InMemoryStorage({ serverClock: () => time });
    const fields = ["UserName", "Password", "Notes", "URL"];
    /** Neueste Änderung pro Feld (zeitlich), so muss es am Ende überall stehen. */
    const latest = new Map<string, { value: string; at: number }>();
    const createdTitles: string[] = [];

    const devices = ["Vivaldi", "Chrome", "Android"].map((name) => ({
      name,
      adapter: new CheckingAdapter(new InMemoryAdapter({ storage, name })),
      vault: undefined as Vault | undefined,
    }));
    const options = (): SyncOptions => ({ now: () => time, merge: mergeVaults, maxAttempts: 5, maxClockSkewMs: 120_000, backupsToKeep: 1000 });

    // Gerät 0 legt an; die anderen starten mit der Datei vom Server.
    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail", UserName: "bob" }, createVaultClock(initial, tick), { uuid: MAIL });
    devices[0]!.vault = (await syncVault(initial, devices[0]!.adapter, codec, options())).vault;
    for (const device of devices.slice(1)) device.vault = await codec.decode(storage.current()!.data);

    let step = 0;
    let created = 0;
    const editRandomly = (device: (typeof devices)[number]) => {
      const vault = device.vault!;
      if (random() < 0.15) {
        const title = `Neu-${device.name}-${created++}`;
        createEntry(vault, vault.root.uuid, { Title: title }, createVaultClock(vault, tick), { uuid: uuidFromName(title) as Uuid });
        createdTitles.push(title);
        return;
      }
      const field = fields[Math.floor(random() * fields.length)]!;
      const value = `${device.name}-${step}`;
      const clock = createVaultClock(vault, tick);
      setField(vault, MAIL, field, value, {}, clock);
      latest.set(field, { value, at: time });
    };
    const sync = async (device: (typeof devices)[number]) => {
      device.vault = (await syncVault(device.vault!, device.adapter, codec, options())).vault;
    };

    for (step = 0; step < 40; step++) {
      const device = devices[Math.floor(random() * devices.length)]!;
      editRandomly(device);
      if (random() < 0.5) editRandomly(device);
      if (random() < 0.4) {
        // Ein anderes Gerät ändert und schreibt genau zwischen Lesen und Schreiben dieses Geräts.
        const other = devices.filter((candidate) => candidate !== device)[Math.floor(random() * 2)]!;
        device.adapter.inner.beforeWrite = async () => {
          device.adapter.inner.beforeWrite = undefined;
          editRandomly(other);
          await sync(other);
        };
      }
      await sync(device);
      device.adapter.inner.beforeWrite = undefined;
    }

    // Alle gleichen zweimal ab: danach muss überall derselbe Stand sein ...
    for (let round = 0; round < 2; round++) for (const device of devices) await sync(device);
    // ... und eine weitere Runde schreibt nichts mehr.
    const writesBefore = devices.reduce((sum, device) => sum + device.adapter.inner.stats.writes, 0);
    for (const device of devices) await sync(device);
    expect(devices.reduce((sum, device) => sum + device.adapter.inner.stats.writes, 0)).toBe(writesBefore);

    const server = await codec.decode(storage.current()!.data);
    for (const vault of [server, ...devices.map((device) => device.vault!)]) {
      for (const [field, { value }] of latest) expect(entryByTitle(vault, "Mail").strings.get(field)?.value, field).toBe(value);
      for (const title of createdTitles) expect(entryByTitle(vault, title), title).toBeDefined();
    }
    for (const device of devices) expect(device.adapter.violations, device.name).toEqual([]);
    // Jede überschriebene Fassung liegt als Sicherung vor (keep = 1000: nichts aufgeräumt):
    // Jedes erfolgreiche Schreiben außer dem ersten Anlegen hat genau eine Fassung ersetzt.
    const totalWrites = devices.reduce((sum, device) => sum + device.adapter.inner.stats.writes, 0);
    expect(new Set(storage.backups.map((backup) => backup.etag)).size).toBe(totalWrites - 1);
    // Der Durchlauf hat die 412-Schleife wirklich durchlaufen.
    expect(devices.reduce((sum, device) => sum + device.adapter.inner.stats.rejectedWrites, 0)).toBeGreaterThan(0);
  });
});

describe("syncVault: Grenzfälle im wiederholten Versuch nach 412", () => {
  const NOW = T0 + 86_400_000;

  async function setup() {
    const storage = new InMemoryStorage({ serverClock: () => NOW });
    const adapter = new InMemoryAdapter({ storage });
    const options = (overrides: Partial<SyncOptions> = {}): SyncOptions => ({
      now: () => NOW,
      merge: mergeVaults,
      maxAttempts: 3,
      maxClockSkewMs: 120_000,
      backupsToKeep: 10,
      ...overrides,
    });
    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail", Password: "alt" }, createVaultClock(initial, () => T0), { uuid: MAIL });
    const base = (await syncVault(initial, adapter, codec, options())).vault;
    const local = cloneVault(base);
    setField(local, MAIL, "Password", "neu", {}, createVaultClock(local, () => NOW));
    const foreign = cloneVault(base);
    setField(foreign, MAIL, "Notes", "fremd", {}, createVaultClock(foreign, () => NOW));
    return { storage, adapter, options, local, foreignBytes: await codec.encode(foreign) };
  }

  it("Geräteuhr weicht erst beim zweiten Lesen ab: ClockSkewError, keine zweite Sicherung, kein Schreiben", async () => {
    const { storage, adapter, options, local, foreignBytes } = await setup();
    adapter.beforeWrite = () => {
      adapter.beforeWrite = undefined;
      storage.put(foreignBytes);
      storage.serverClock = () => NOW + 10 * 60_000;
    };
    const failure = syncVault(local, adapter, codec, options());
    await expect(failure).rejects.toBeInstanceOf(ClockSkewError);
    expect(adapter.stats).toMatchObject({ writes: 1, rejectedWrites: 1, backups: 1 });
    expect(storage.current()!.data).toEqual(foreignBytes);
  });

  it("ETag fehlt erst beim zweiten Lesen: StorageError, kein Schreiben", async () => {
    const { storage, adapter, options, local, foreignBytes } = await setup();
    adapter.beforeWrite = () => {
      adapter.beforeWrite = undefined;
      storage.put(foreignBytes);
      storage.withholdEtag = true;
    };
    await expect(syncVault(local, adapter, codec, options())).rejects.toBeInstanceOf(StorageError);
    expect(adapter.stats).toMatchObject({ writes: 1, rejectedWrites: 1, backups: 1 });
    expect(storage.current()!.data).toEqual(foreignBytes);
  });

  it("Sicherung scheitert erst im zweiten Versuch: kein Schreiben", async () => {
    const { storage, adapter, options, local, foreignBytes } = await setup();
    adapter.beforeWrite = () => {
      adapter.beforeWrite = undefined;
      storage.put(foreignBytes);
      adapter.nextBackupError = new StorageError("Speicher voll", 507);
    };
    await expect(syncVault(local, adapter, codec, options())).rejects.toMatchObject({ name: "StorageError", status: 507 });
    expect(adapter.stats).toMatchObject({ writes: 1, rejectedWrites: 1 });
    expect(storage.current()!.data).toEqual(foreignBytes);
  });

  it("syncVault verändert `local` nicht, auch nicht über 412-Wiederholungen hinweg", async () => {
    const { storage, adapter, options, local, foreignBytes } = await setup();
    const snapshot = cloneVault(local);
    adapter.beforeWrite = () => {
      adapter.beforeWrite = undefined;
      storage.put(foreignBytes);
    };
    const result = await syncVault(local, adapter, codec, options());
    expect(result).toMatchObject({ written: true, attempts: 2 });
    expect(isDeepStrictEqual(local, snapshot)).toBe(true);
    const final = await codec.decode(storage.current()!.data);
    expect(entryByTitle(final, "Mail").strings.get("Notes")?.value).toBe("fremd");
    expect(entryByTitle(final, "Mail").strings.get("Password")?.value).toBe("neu");
  });

  it("Geräteuhr geht vor: skewMs positiv", async () => {
    const { adapter, options, local } = await setup();
    await expect(syncVault(local, adapter, codec, options({ now: () => NOW + 5 * 60_000 }))).rejects.toMatchObject({ skewMs: 5 * 60_000 });
  });
});

describe("syncVault mit WebDavAdapter: Uhrprüfung vor JEDER schreibenden Anfrage", () => {
  it("abweichender Date-Header beim GET: nur das GET, kein MKCOL/COPY/PUT/DELETE", async () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const remote = newVault();
    const remoteBytes = await codec.encode(remote);
    const methods: string[] = [];
    const fetchFn: typeof fetch = async (_input, init) => {
      methods.push(init?.method ?? "GET");
      return new Response(new Uint8Array(remoteBytes), { headers: { ETag: '"1"', Date: new Date(now + 3 * 60_000).toUTCString() } });
    };
    const adapter = new WebDavAdapter({ fileUrl: "https://cloud.example/dav/t.kdbx", username: "u", password: "p", fetch: fetchFn });
    const local = cloneVault(remote);
    local.meta.databaseName = "geändert";

    await expect(
      syncVault(local, adapter, codec, { now: () => now, merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 3 }),
    ).rejects.toBeInstanceOf(ClockSkewError);
    expect(methods).toEqual(["GET"]);
  });
});
