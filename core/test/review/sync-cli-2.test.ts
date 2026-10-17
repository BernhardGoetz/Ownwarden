/**
 * Review sync-cli-2 (Regressionstest): Zeitstempel, die mit einer falsch gehenden Geräteuhr
 * entstanden sind, werden still hochgeladen und schlagen echte neuere Änderungen.
 *
 * README „Bekannte Grenzen“: „Weicht [die Geräteuhr] mehr als 2 Minuten von der Serverzeit ab,
 * verweigert Ownwarden den Abgleich (statt mit falschen Zeitstempeln zu schreiben).“
 * syncVault prüft aber nur die Uhr IM MOMENT des Abgleichs. Die Feld-Zeitstempel entstehen
 * früher, beim Bearbeiten – ohne jede Prüfung.
 *
 * Ablauf:
 *   1. A lädt hoch, B holt die Datei.
 *   2. A ändert offline das Passwort, während A's Uhr einen Tag vorgeht.
 *   3. Eine Stunde später (echte Zeit) ändert B dasselbe Feld mit richtiger Uhr und gleicht ab.
 *   4. A's Uhr wird gestellt (z. B. Netzwerkzeit), dann gleicht A ab.
 * Erwartet: Der Abgleich lädt A's in der Zukunft datierte Änderung nicht still hoch – er bricht
 * ab, warnt (result.warnings), oder B's tatsächlich neuere Änderung bleibt gültig.
 */
import { describe, expect, it } from "vitest";
import type { SyncResult } from "../../src/contracts";
import type { Vault } from "../../src/model";
import { cloneVault } from "../../src/merge/clone";
import { createVaultClock } from "../../src/merge/clock";
import { mergeVaults } from "../../src/merge/merge";
import { createEntry, setField } from "../../src/merge/vault-ops";
import { InMemoryAdapter, InMemoryStorage } from "../../src/sync/memory-adapter";
import { syncVault } from "../../src/sync/sync";
import { createJsonCodec } from "../../src/sync/testing/json-codec";
import { entryByTitle, newVault, T0, uuidFromName } from "../helpers/vault-builder";

const MAIL = uuidFromName("review-sync-cli-2-mail");
const DAY = 86_400_000;
const HOUR = 3_600_000;
/** Echte Zeit beim ersten Hochladen. */
const REAL = T0 + DAY;

describe("Review sync-cli-2: Feld-Zeitstempel aus einer falsch gehenden Uhr", () => {
  it("Review sync-cli-2: eine offline mit vorgehender Uhr gemachte Änderung schlägt nicht still eine echt neuere", async () => {
    let realTime = REAL;
    const server = new InMemoryStorage({ serverClock: () => realTime });
    const codec = createJsonCodec();
    const options = (now: number) => ({ now: () => now, merge: mergeVaults, maxAttempts: 3, maxClockSkewMs: 120_000, backupsToKeep: 10 });

    // 1. A legt an und lädt hoch; B holt die Datei.
    const initial = newVault();
    createEntry(initial, initial.root.uuid, { Title: "Mail", Password: "alt" }, createVaultClock(initial, () => REAL - HOUR), { uuid: MAIL });
    const deviceA = new InMemoryAdapter({ storage: server, name: "A" });
    const deviceB = new InMemoryAdapter({ storage: server, name: "B" });
    let localA: Vault = (await syncVault(initial, deviceA, codec, options(REAL))).vault;
    let localB: Vault = await codec.decode(server.current()!.data);
    localA = cloneVault(localA);

    // 2. A offline, Uhr geht einen Tag vor (echte Zeit: REAL + 1 min).
    realTime = REAL + 60_000;
    setField(localA, MAIL, "Password", "A-alt-mit-falscher-Uhr", {}, createVaultClock(localA, () => realTime + DAY));

    // 3. Eine Stunde später (echte Zeit) ändert B mit richtiger Uhr und gleicht ab.
    realTime = REAL + HOUR;
    setField(localB, MAIL, "Password", "B-wirklich-neuer", {}, createVaultClock(localB, () => realTime));
    localB = (await syncVault(localB, deviceB, codec, options(realTime))).vault;
    expect(entryByTitle(await codec.decode(server.current()!.data), "Mail").strings.get("Password")?.value).toBe("B-wirklich-neuer");

    // 4. A's Uhr ist wieder richtig; A gleicht ab.
    realTime = REAL + 2 * HOUR;
    let result: SyncResult | undefined;
    try {
      result = await syncVault(localA, deviceA, codec, options(realTime));
    } catch {
      // Abbruch ist eine zulässige Lösung – dann darf sich auf dem Server nichts geändert haben.
    }
    const serverPassword = entryByTitle(await codec.decode(server.current()!.data), "Mail").strings.get("Password")?.value;
    const warned = (result?.warnings ?? []).length > 0;

    // Fehlerfall: A's in der Zukunft datierte Änderung gewinnt still (kein Abbruch, kein Hinweis).
    expect(serverPassword === "B-wirklich-neuer" || warned, `Server-Passwort: ${serverPassword}, Hinweise: ${String(warned)}`).toBe(true);
  });
});
