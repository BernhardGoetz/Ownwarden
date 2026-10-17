/**
 * syncVault mit ECHTEN KDBX-Dateien (createKdbxCodec) und dem echten mergeVaults.
 *
 * Wichtigster Punkt: Im Speicher stehen Zeiten in Millisekunden, in der Datei nur ganze
 * Sekunden. Ein Abgleich ohne inhaltliche Änderung darf trotzdem NICHT schreiben – sonst
 * entstünde bei jedem Abgleich eine neue Fassung samt Sicherungskopie, und zwei Geräte
 * schrieben sich gegenseitig endlos ihre Fassung zurück.
 */
import { describe, expect, it } from "vitest";
import { entryByTitle, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import type { SyncOptions } from "../contracts";
import type { Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { createVaultClock, type VaultClock } from "../merge/clock";
import { mergeVaults } from "../merge/merge";
import { createEntry, setAttachment, setField } from "../merge/vault-ops";
import { createKdbxCodec } from "./kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "./memory-adapter";
import { syncVault } from "./sync";

const codec = createKdbxCodec({ password: "Sync-Test-äöü" });

/** Gerät mit eigener Uhr, die in „krummen“ Millisekunden läuft (wie im echten Leben). */
function device(name: string, storage: InMemoryStorage, start: number) {
  let time = start;
  const timeSource = () => (time += 1234);
  return {
    adapter: new InMemoryAdapter({ storage, name }),
    clock: (vault: Vault): VaultClock => createVaultClock(vault, timeSource),
    options: (): SyncOptions => ({ now: () => time, merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 3 }),
  };
}

function storageAt(start: number): InMemoryStorage {
  return new InMemoryStorage({ serverClock: () => start + 10_000 });
}

describe("syncVault mit KDBX-Dateien", () => {
  it("schreibt nach dem Hochladen nicht erneut, obwohl die Zeiten im Speicher Millisekunden haben", async () => {
    const start = T0 + 123;
    const storage = storageAt(start);
    const vivaldi = device("Vivaldi", storage, start);
    const local = newVault();
    createEntry(local, local.root.uuid, { Title: "Mail", Password: "geheim" }, vivaldi.clock(local), { uuid: uuidFromName("mail") });
    expect(entryByTitle(local, "Mail").times.creation % 1000).not.toBe(0);

    const created = await syncVault(local, vivaldi.adapter, codec, vivaldi.options());
    expect(created.created).toBe(true);

    const again = await syncVault(created.vault, vivaldi.adapter, codec, vivaldi.options());
    expect(again.written).toBe(false);

    // Ändern -> schreiben; danach wieder Ruhe.
    const edited = cloneVault(again.vault);
    setField(edited, uuidFromName("mail"), "Password", "neu", {}, vivaldi.clock(edited));
    setAttachment(edited, uuidFromName("mail"), "notiz.txt", new TextEncoder().encode("Anhang"), {}, vivaldi.clock(edited));
    const written = await syncVault(edited, vivaldi.adapter, codec, vivaldi.options());
    expect(written.written).toBe(true);
    const quiet = await syncVault(written.vault, vivaldi.adapter, codec, vivaldi.options());
    expect(quiet.written).toBe(false);
    expect(vivaldi.adapter.stats.writes).toBe(2);
    expect(storage.backups).toHaveLength(1);
  });

  it("zwei Geräte ändern verschiedene Felder gleichzeitig: beide Änderungen kommen an, danach kein Ping-Pong", async () => {
    const start = T0 + 777;
    const storage = storageAt(start);
    const vivaldi = device("Vivaldi", storage, start);
    const chrome = device("Chrome", storage, start + 50);
    const mail = uuidFromName("mail");
    const bank = uuidFromName("bank");

    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail", UserName: "bob", Password: "alt" }, vivaldi.clock(initial), { uuid: mail });
    let vaultA = (await syncVault(initial, vivaldi.adapter, codec, vivaldi.options())).vault;
    // Chrome startet mit der Datei vom Server (wie nach dem Einrichten).
    let vaultB = await codec.decode(storage.current()!.data);

    setField(vaultA, mail, "UserName", "alice", {}, vivaldi.clock(vaultA));
    setField(vaultB, mail, "Password", "neu", {}, chrome.clock(vaultB));
    createEntry(vaultB, vaultB.root.uuid, { Title: "Bank" }, chrome.clock(vaultB), { uuid: bank });

    // Vivaldi schreibt genau zwischen Chromes Lesen und Schreiben.
    let interleaved = false;
    chrome.adapter.beforeWrite = async () => {
      if (interleaved) return;
      interleaved = true;
      vaultA = (await syncVault(vaultA, vivaldi.adapter, codec, vivaldi.options())).vault;
    };
    const resultB = await syncVault(vaultB, chrome.adapter, codec, chrome.options());
    expect(resultB.attempts).toBe(2);
    vaultB = resultB.vault;

    const final = await codec.decode(storage.current()!.data);
    expect(entryByTitle(final, "Mail").strings.get("UserName")?.value).toBe("alice");
    expect(entryByTitle(final, "Mail").strings.get("Password")?.value).toBe("neu");
    expect(entryByTitle(final, "Bank")).toBeDefined();

    // Beide Geräte gleichen noch zweimal ab: Vivaldi übernimmt Chromes Stand, danach schreibt keiner mehr.
    const writesBefore = vivaldi.adapter.stats.writes + chrome.adapter.stats.writes;
    for (let round = 0; round < 2; round++) {
      vaultA = (await syncVault(vaultA, vivaldi.adapter, codec, vivaldi.options())).vault;
      vaultB = (await syncVault(vaultB, chrome.adapter, codec, chrome.options())).vault;
    }
    expect(vivaldi.adapter.stats.writes + chrome.adapter.stats.writes).toBe(writesBefore);
    expect(entryByTitle(vaultA, "Bank")).toBeDefined();
    expect(entryByTitle(vaultA, "Mail").strings.get("Password")?.value).toBe("neu");
  });

  it("eine andere Reihenfolge der Einträge auf einem Gerät löst kein Schreiben aus", async () => {
    const start = T0 + 5;
    const storage = storageAt(start);
    const vivaldi = device("Vivaldi", storage, start);
    const local = newVault();
    for (const title of ["A", "B", "C"]) {
      createEntry(local, local.root.uuid, { Title: title }, vivaldi.clock(local), { uuid: uuidFromName(title) });
    }
    await syncVault(local, vivaldi.adapter, codec, vivaldi.options());
    const reordered = cloneVault(local);
    reordered.root.entries.reverse();

    const result = await syncVault(reordered, vivaldi.adapter, codec, vivaldi.options());

    expect(result.written).toBe(false);
  });

  // Review xc-4: Eine Fassung im Speicher trägt Zeiten an CustomData-Einträgen (z. B. aus einer
  // 4.1-Datei gelesen), die Datei auf dem Server ist KDBX 4.0 (z. B. ältere Sicherung
  // zurückgespielt). 4.0 kann diese Zeiten nicht speichern; bisher schrieb deshalb JEDER Abgleich
  // neu (samt Sicherungskopie), solange das Gerät result.vault weiterverwendete.
  it("Zeiten an CustomData-Einträgen, die KDBX 4.0 nicht speichern kann, lösen nicht bei jedem Abgleich ein Schreiben aus", async () => {
    const start = T0 + 42;
    const storage = storageAt(start);
    const vivaldi = device("Vivaldi", storage, start);
    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail" }, vivaldi.clock(initial), { uuid: uuidFromName("mail") });
    await syncVault(initial, vivaldi.adapter, codec, vivaldi.options());
    expect((await codec.decode(storage.current()!.data)).settings.versionMinor).toBe(0);

    let local = await codec.decode(storage.current()!.data);
    local.meta.customData.set("KPXC_DECRYPTION_TIME_PREFERENCE", { value: "1000", lastModified: start });
    entryByTitle(local, "Mail").customData.set("Farbe", { value: "rot", lastModified: start });
    local.root.customData.set("Sortierung", { value: "a", lastModified: start });
    const first = await syncVault(local, vivaldi.adapter, codec, vivaldi.options());
    expect(first.written).toBe(true); // neue Schlüssel: einmal schreiben ist richtig
    expect(first.vault.meta.customData.get("KPXC_DECRYPTION_TIME_PREFERENCE")?.lastModified).toBe(start);
    local = first.vault;

    for (let round = 0; round < 3; round++) {
      const result = await syncVault(local, vivaldi.adapter, codec, vivaldi.options());
      expect(result.written).toBe(false);
      local = result.vault;
    }
    expect(vivaldi.adapter.stats.writes).toBe(2);
    expect(storage.backups).toHaveLength(1);
  });
});
