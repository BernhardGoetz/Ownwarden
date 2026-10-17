/**
 * Review merge-1 (Regressionstest): Doppelte Verlaufsfassungen, die sich nur in Rohdaten
 * unterscheiden, die der Rohdaten-Fingerabdruck nicht sieht (hier: das Standard-<AutoType>,
 * das KeePassXC 2.7.6 beim Speichern auch in jeden VERLAUFSEINTRAG schreibt).
 *
 * mergeHistory behält dann die Fassung von local (Gleichstand der Fingerabdrücke). Folge:
 *   - merge(a, b) und merge(b, a) haben verschiedene Verläufe (spec/README.md §5: „Inhaltlich
 *     hängt das Ergebnis nicht davon ab, welche Seite local ist“), und
 *   - zwei Geräte laden nach einem einzigen Speichern in KeePassXC bei JEDEM Abgleich ihre
 *     eigene Fassung hoch (je mit Sicherungskopie) – entgegen core/README.md „kein Ping-Pong“.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { SyncOptions } from "../../src/contracts";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { createEntry, setField } from "../../src/merge/vault-ops";
import type { Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "../../src/sync/memory-adapter";
import { syncVault } from "../../src/sync/sync";
import { createTmpDir, hasKeepassxc, removeTmpDir, runKpxcOk } from "../helpers/keepassxc";
import { entryByTitle, newEntry, newGroup, newVault, secret, T0, uuidFromName } from "../helpers/vault-builder";

/** Das Standard-AutoType, das KeePassXC 2.7.6 beim Speichern ergänzt (auch im Verlauf). */
const DEFAULT_AUTO_TYPE =
  "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>";

/** Eintrag „Mail“ mit einem Verlaufseintrag, dessen unbekannte Elemente `historyUnknown` sind. */
function vaultWithHistoryUnknown(historyUnknown: string[]): Vault {
  const uuid = uuidFromName("mail");
  const old = newEntry({ uuid, at: T0, fields: { Title: "Mail", Password: secret("alt") }, unknown: historyUnknown });
  const entry = newEntry({ uuid, at: T0 + 5000, fields: { Title: "Mail", Password: secret("neu") }, history: [old] });
  return newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root", entries: [entry] }) });
}

describe("Review merge-1: doppelte Verlaufsfassungen mit unsichtbarem Rohdaten-Unterschied", () => {
  it("merge(a, b) und merge(b, a) behalten dieselbe Verlaufsfassung", () => {
    const withoutAutoType = vaultWithHistoryUnknown([]);
    const withAutoType = vaultWithHistoryUnknown([DEFAULT_AUTO_TYPE]);
    const now = T0 + 100_000;
    const ab = mergeVaults(withoutAutoType, withAutoType, { now }).vault;
    const ba = mergeVaults(withAutoType, withoutAutoType, { now }).vault;
    expect(entryByTitle(ab, "Mail").history.map((item) => item.unknown)).toEqual(
      entryByTitle(ba, "Mail").history.map((item) => item.unknown),
    );
  });

  describe.skipIf(!hasKeepassxc())("mit KeePassXC 2.7.6", () => {
    const PASSWORD = "Review-merge-1";
    const codec = createKdbxCodec({ password: PASSWORD });
    const options = (): SyncOptions => ({ now: () => Date.now(), merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 20 });
    let dir: string;
    beforeAll(() => {
      dir = createTmpDir("review-merge-1");
    });
    afterAll(() => {
      if (dir) removeTmpDir(dir);
    });

    it("nach einmal Speichern in KeePassXC schreiben zwei Geräte nicht bei jedem Abgleich", async () => {
      const storage = new InMemoryStorage();
      const vivaldi = new InMemoryAdapter({ storage, name: "Vivaldi" });
      const chrome = new InMemoryAdapter({ storage, name: "Chrome" });

      // Vivaldi legt „Mail“ an und ändert das Passwort (-> ein Verlaufseintrag ohne AutoType).
      const vault = newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root" }) });
      const clock = createVaultClock(vault);
      const mail = createEntry(vault, vault.root.uuid, { Title: "Mail", UserName: "alice", Password: "pw-1" }, clock, {
        uuid: uuidFromName("mail"),
      });
      createEntry(vault, vault.root.uuid, { Title: "Dummy" }, clock, { uuid: uuidFromName("dummy") });
      setField(vault, mail.uuid, "Password", "pw-2", {}, clock);
      await syncVault(vault, vivaldi, codec, options());
      // Lokale Kopie von Vivaldi so, wie sie nach einem Neustart aus der Datei käme (Zeiten in s).
      let vaultA = await codec.decode(storage.current()!.data);

      // KeePassXC öffnet die Server-Datei, ändert einen ANDEREN Eintrag und speichert.
      const path = join(dir, "server.kdbx");
      writeFileSync(path, storage.current()!.data);
      await runKpxcOk(["edit", "-q", "-u", "geändert", path, "Dummy"], `${PASSWORD}\n`);
      storage.put(new Uint8Array(readFileSync(path)));
      expect(entryByTitle(await codec.decode(storage.current()!.data), "Mail").history[0]!.unknown).toEqual([DEFAULT_AUTO_TYPE]);

      // Chrome holt die Server-Fassung.
      let vaultB = await codec.decode(storage.current()!.data);

      // Einschwingen: höchstens ein paar Schreibvorgänge (KeePassXC-Änderung übernehmen).
      for (let round = 0; round < 3; round++) {
        vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
        vaultB = (await syncVault(vaultB, chrome, codec, options())).vault;
      }
      // Danach darf niemand mehr schreiben.
      const writesBefore = vivaldi.stats.writes + chrome.stats.writes;
      for (let round = 0; round < 2; round++) {
        vaultA = (await syncVault(vaultA, vivaldi, codec, options())).vault;
        vaultB = (await syncVault(vaultB, chrome, codec, options())).vault;
      }
      expect(vivaldi.stats.writes + chrome.stats.writes - writesBefore).toBe(0);
    });
  });
});
