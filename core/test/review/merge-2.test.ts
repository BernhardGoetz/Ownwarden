/**
 * Review merge-2 (Regressionstest): Eine Änderung, die ein Gerät mit falsch gehender Uhr
 * (ein Jahr vor) offline gemacht hat, wird nach dem Stellen der Uhr ohne Rückfrage
 * hochgeladen. Die Uhrprüfung in syncVault vergleicht nur die Gerätezeit BEIM ABGLEICH mit
 * dem Date-Header, nicht die Zeitstempel in der lokalen Datenbank.
 *
 * core/README.md („Bekannte Grenzen“): „Weicht sie mehr als 2 Minuten von der Serverzeit ab,
 * verweigert Ownwarden den Abgleich (statt mit falschen Zeitstempeln zu schreiben).“
 *
 * Erwartet: Entweder lehnt der Abgleich ab (und der Server bleibt unverändert), oder auf dem
 * Server landen keine Zeitstempel jenseits von Serverzeit + maxClockSkewMs. Und eine spätere
 * endgültige Löschung (z. B. in KeePassXC, mit richtiger Uhr) darf nicht an den Zeitstempeln
 * aus der Zukunft scheitern.
 */
import { describe, expect, it } from "vitest";
import type { SyncOptions } from "../../src/contracts";
import { createVaultClock, latestVaultTime } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import { createEntry, setField } from "../../src/merge/vault-ops";
import { createKdbxCodec } from "../../src/sync/kdbx-codec";
import { InMemoryAdapter, InMemoryStorage } from "../../src/sync/memory-adapter";
import { DEFAULT_SYNC_SETTINGS, syncVault } from "../../src/sync/sync";
import { newGroup, newVault, uuidFromName } from "../helpers/vault-builder";

const codec = createKdbxCodec({ password: "Review-merge-2" });
/** Die richtige Zeit (Server und KeePassXC). */
const REAL = Date.UTC(2026, 9, 17, 12, 0, 0);
const DAY = 24 * 60 * 60 * 1000;
const YEAR = 365 * DAY;

describe("Review merge-2: offline mit falsch gehender Uhr gestempelte Änderung", () => {
  it("wird nach dem Stellen der Uhr nicht mit Zeitstempeln aus der Zukunft hochgeladen", async () => {
    const storage = new InMemoryStorage({ serverClock: () => REAL });
    const phone = new InMemoryAdapter({ storage, name: "Handy" });

    // Ausgangslage auf dem Server: „Mail“, vor einem Tag mit richtiger Uhr angelegt.
    const base = newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root" }) });
    const mail = createEntry(base, base.root.uuid, { Title: "Mail", Password: "alt" }, createVaultClock(base, () => REAL - DAY), {
      uuid: uuidFromName("mail"),
    });
    storage.put(await codec.encode(base));

    // Handy: offline, Uhr ein Jahr vor -> Passwort geändert.
    const local = await codec.decode(storage.current()!.data);
    setField(local, mail.uuid, "Password", "neu", {}, createVaultClock(local, () => REAL + YEAR));
    const before = storage.current()!;

    // Uhr gestellt (z. B. per Netzwerkzeit), dann Abgleich.
    const options: SyncOptions = { now: () => REAL, merge: mergeVaults, ...DEFAULT_SYNC_SETTINGS };
    let result;
    try {
      result = await syncVault(local, phone, codec, options);
    } catch {
      // Ablehnen ist eine zulässige Lösung – dann darf aber nichts geschrieben worden sein.
      expect(storage.current()!.etag).toBe(before.etag);
      return;
    }

    const server = await codec.decode(storage.current()!.data);
    expect(latestVaultTime(server)).toBeLessThanOrEqual(REAL + DEFAULT_SYNC_SETTINGS.maxClockSkewMs);

    // Folge, falls doch: KeePassXC löscht „Mail“ 10 Minuten später endgültig (richtige Uhr).
    server.root.entries = server.root.entries.filter((entry) => entry.uuid !== mail.uuid);
    server.deletedObjects.push({ uuid: mail.uuid, deletionTime: REAL + 10 * 60 * 1000 });
    const next = mergeVaults(result.vault, server, { now: REAL + 11 * 60 * 1000 }).vault;
    expect(findEntry(next, mail.uuid)).toBeUndefined();
  });
});
