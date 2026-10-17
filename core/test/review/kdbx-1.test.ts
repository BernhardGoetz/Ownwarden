/**
 * Review kdbx-1 (Regressionstest): doppelte Eintrags-UUIDs in EINER Datei.
 *
 * In der KeePass-Welt kommen solche Dateien vor (KeePass 2.x bietet dafür eigens „doppelte
 * UUIDs reparieren“ an). Der XML-Leser nimmt sie ohne Prüfung an; mergeVaults legt die beiden
 * Einträge dann still zu EINEM zusammen, und syncVault lädt das Ergebnis hoch. Die
 * unterlegene Fassung landet nur im Verlauf des anderen Eintrags – ist der Verlauf voll
 * (HistoryMaxItems), ist sie samt Passwort ganz aus der Datei verschwunden. Der Bericht
 * meldet dabei 0 gelöschte Einträge.
 *
 * Erwartet (eine der vom Review vorgeschlagenen Lösungen):
 *   - Lesen oder Abgleich bricht mit KdbxError ab, und auf dem Server ändert sich nichts, ODER
 *   - beide Einträge bleiben als eigene Einträge erhalten (z. B. neue UUID für das Duplikat).
 */
import { describe, expect, it } from "vitest";
import { KdbxError } from "../../src/contracts";
import { readKdbx, writeKdbx } from "../../src/kdbx/index";
import { mergeVaults } from "../../src/merge/merge";
import type { Vault } from "../../src/model";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "../../src/sync/memory-adapter";
import { syncVault } from "../../src/sync/sync";
import { allEntries, newEntry, newGroup, newVault, secret, T0, uuidFromName } from "../helpers/vault-builder";

const credentials = { password: "Review-kdbx-1" };
const NOW = T0 + 100_000;

/** Wurzel mit „Bank“, Untergruppe mit „Mail“ – beide mit DERSELBEN UUID. „Mail“ hat einen vollen Verlauf. */
function vaultWithDuplicateEntryUuid(): Vault {
  const dup = uuidFromName("doppelt");
  const bank = newEntry({ uuid: dup, at: T0, fields: { Title: "Bank", UserName: "bob", Password: secret("bank-test-pw") } });
  const mailHistory = Array.from({ length: 10 }, (_, i) =>
    newEntry({ uuid: dup, at: T0 + 10_000 + i * 1000, fields: { Title: "Mail", UserName: `alice${i}` } }),
  );
  const mail = newEntry({
    uuid: dup,
    at: T0 + 50_000,
    fields: { Title: "Mail", UserName: "alice", Password: secret("mail-test-pw") },
    history: mailHistory,
  });
  const sub = newGroup({ uuid: uuidFromName("sub"), name: "Sub", at: T0, entries: [mail] });
  return newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root", at: T0, entries: [bank], groups: [sub] }) });
}

describe("Review kdbx-1: doppelte Eintrags-UUID", () => {
  it("Review kdbx-1: Abgleich einer Datei mit doppelter Eintrags-UUID verliert keinen Eintrag (oder bricht ohne Schreiben ab)", async () => {
    const fileBytes = await writeKdbx(vaultWithDuplicateEntryUuid(), credentials);
    const storage = new InMemoryStorage({ serverClock: () => NOW });
    const etagBefore = storage.put(fileBytes);

    let local: Vault;
    try {
      local = await readKdbx(fileBytes, credentials);
    } catch (error) {
      // Lösung „ablehnen“: klarer Fehler beim Lesen ist in Ordnung.
      expect(error).toBeInstanceOf(KdbxError);
      return;
    }

    try {
      await syncVault(local, new InMemoryAdapter({ storage }), createKdbxCodec(credentials), {
        now: () => NOW,
        merge: mergeVaults,
        maxAttempts: 3,
        maxClockSkewMs: 120_000,
        backupsToKeep: 20,
      });
    } catch (error) {
      // Lösung „ablehnen“ beim Abgleich: dann darf nichts geschrieben worden sein.
      expect(error).toBeInstanceOf(Error);
      expect(storage.current()!.etag).toBe(etagBefore);
      return;
    }

    const server = await readKdbx(storage.current()!.data, credentials);
    const current = allEntries(server);
    expect(current.map((e) => e.strings.get("Title")?.value).sort()).toEqual(["Bank", "Mail"]);
    const bank = current.find((e) => e.strings.get("Title")?.value === "Bank")!;
    expect(bank.strings.get("Password")?.value).toBe("bank-test-pw");
  });
});
