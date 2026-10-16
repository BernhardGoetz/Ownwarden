/**
 * syncVault: Aufräumen alter Sicherungskopien ist „best effort“ (Entscheidung des
 * Eigentümers, 2026-10-16). Die Sicherung der Fassung, die gleich überschrieben wird, bleibt
 * Pflicht; Hinweise des Adapters (z. B. „alte Kopie ließ sich nicht löschen“) landen in
 * result.warnings und halten den Abgleich nicht auf.
 * Gegen einen echten Server: test/e2e/backup-pruning.test.ts.
 */
import { describe, expect, it } from "vitest";
import { newVault, uuidFromName } from "../../test/helpers/vault-builder";
import type { BackupResult, RemoteFile, StorageAdapter, SyncOptions, WriteCondition } from "../contracts";
import type { Vault } from "../model";
import { createVaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setField } from "../merge/vault-ops";
import { createKdbxCodec } from "./kdbx-codec";
import { InMemoryAdapter, InMemoryStorage, type InMemoryAdapterOptions } from "./memory-adapter";
import { syncVault } from "./sync";

// newVault() benutzt eine schnelle Schlüsselableitung (nur für Tests).
const codec = createKdbxCodec({ password: "Warnungen-Test" });

const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 2 });
const MAIL = uuidFromName("mail");

/**
 * Speicher wie InMemoryAdapter, dessen backup() zusätzlich Hinweise liefert (so wie
 * WebDavAdapter, wenn sich eine alte Kopie nicht löschen lässt, z. B. HTTP 423).
 */
class WarningAdapter implements StorageAdapter {
  readonly inner: InMemoryAdapter;
  warningsPerBackup: string[] = [];
  constructor(options: InMemoryAdapterOptions = {}) {
    this.inner = new InMemoryAdapter(options);
  }
  get storage(): InMemoryStorage {
    return this.inner.storage;
  }
  describe(): string {
    return this.inner.describe();
  }
  read(): Promise<RemoteFile | null> {
    return this.inner.read();
  }
  write(data: Uint8Array, condition: WriteCondition) {
    return this.inner.write(data, condition);
  }
  async backup(current: RemoteFile, keep: number): Promise<BackupResult> {
    await this.inner.backup(current, keep);
    return { warnings: [...this.warningsPerBackup] };
  }
}

function initialVault(): Vault {
  const vault = newVault();
  createEntry(vault, vault.root.uuid, { Title: "Mail", Password: "alt" }, createVaultClock(vault), { uuid: MAIL });
  return vault;
}

describe("syncVault: Hinweise beim Aufräumen der Sicherungskopien", () => {
  it("eine alte Kopie lässt sich nicht löschen: trotzdem gesichert und geschrieben, Hinweis im Ergebnis", async () => {
    const storage = new InMemoryStorage();
    const adapter = new WarningAdapter({ storage });
    const created = await syncVault(initialVault(), adapter, codec, options());
    expect(created.warnings).toBeUndefined(); // Anlegen braucht keine Sicherung

    adapter.warningsPerBackup = ['Alte Sicherungskopie "tresor.alt.kdbx" ließ sich nicht löschen (HTTP 423).'];
    setField(created.vault, MAIL, "Password", "neu", {}, createVaultClock(created.vault));
    const result = await syncVault(created.vault, adapter, codec, options());

    expect(result.written).toBe(true);
    expect(result.warnings).toEqual(adapter.warningsPerBackup);
    expect(storage.backups).toHaveLength(1);
    expect((await codec.decode(storage.current()!.data)).root.entries[0]!.strings.get("Password")?.value).toBe("neu");
  });

  it("Hinweise aus einem Versuch, der danach 412 bekam, gehen nicht verloren (doppelte nur einmal)", async () => {
    const storage = new InMemoryStorage();
    const vivaldi = new WarningAdapter({ storage, name: "Vivaldi" });
    const chrome = new InMemoryAdapter({ storage, name: "Chrome" });
    const created = await syncVault(initialVault(), vivaldi, codec, options());
    const chromeVault = await codec.decode(storage.current()!.data);

    vivaldi.warningsPerBackup = ["Hinweis A"];
    let raced = false;
    vivaldi.inner.beforeWrite = async () => {
      if (raced) return;
      raced = true;
      setField(chromeVault, MAIL, "UserName", "chrome", {}, createVaultClock(chromeVault));
      await syncVault(chromeVault, chrome, codec, options());
    };
    setField(created.vault, MAIL, "Password", "vivaldi", {}, createVaultClock(created.vault));
    const result = await syncVault(created.vault, vivaldi, codec, options());

    expect(result).toMatchObject({ written: true, attempts: 2, warnings: ["Hinweis A"] });
  });

  it("ohne Hinweise gibt es kein Feld warnings (bisherige Aufrufer sehen keinen Unterschied)", async () => {
    const adapter = new InMemoryAdapter();
    const created = await syncVault(initialVault(), adapter, codec, options());
    setField(created.vault, MAIL, "Password", "neu", {}, createVaultClock(created.vault));
    const result = await syncVault(created.vault, adapter, codec, options());
    expect(result.written).toBe(true);
    expect("warnings" in result).toBe(false);
  });

  it("scheitert die Sicherung selbst, wird weiterhin NICHT geschrieben", async () => {
    const adapter = new WarningAdapter();
    const created = await syncVault(initialVault(), adapter, codec, options());
    const before = adapter.storage.current()!.etag;
    adapter.inner.nextBackupError = new Error("COPY abgelehnt");
    setField(created.vault, MAIL, "Password", "neu", {}, createVaultClock(created.vault));
    await expect(syncVault(created.vault, adapter, codec, options())).rejects.toThrow(/Sicherungskopie/);
    expect(adapter.storage.current()!.etag).toBe(before);
  });
});
