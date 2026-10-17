/**
 * Review merge-3 (Regressionstest): Eintrag OHNE Ownwarden.FieldTimes (z. B. in KeePassXC
 * angelegt). KeePassXC entfernt ein Feld, leert die Tags und schaltet den Ablauf ab – ohne
 * Verlaufseintrag (z. B. HistoryMaxItems = 0, Eintrag über HistoryMaxSize oder Verlauf
 * gelöscht). Ein Gerät mit der älteren Fassung bringt beim Abgleich alles zurück, weil ein
 * fehlendes Feld ohne Verlauf keine Zeit hat (−∞) und „vorhanden“ der älteren Seite gewinnt.
 *
 * spec/README.md §10 beschreibt nur: Solche Einträge „gelten als komplett zur
 * lastModification geändert“ – dann müsste die neuere Fassung auch mit ihren Entfernungen
 * gewinnen.
 */
import { describe, expect, it } from "vitest";
import { mergeVaults } from "../../src/merge/merge";
import { findEntry } from "../../src/merge/tree";
import type { Entry, Vault } from "../../src/model";
import { newEntry, newGroup, newTimes, newVault, plain, uuidFromName } from "../helpers/vault-builder";

const OLD = 1_700_000_000_000;
const NEW = 1_700_000_500_000;
const uuid = uuidFromName("e1");

function vaultWith(entry: Entry): Vault {
  return newVault({ root: newGroup({ uuid: uuidFromName("root"), name: "Root", entries: [entry] }) });
}

describe("Review merge-3: Entfernung ohne Verlauf in einem Eintrag ohne FieldTimes", () => {
  it("die neuere Fassung (Feld, Tags, Ablauf entfernt) gewinnt gegen eine ältere Kopie – in beiden Richtungen", () => {
    const stale = newEntry({
      uuid,
      at: OLD,
      fields: { Title: "Konto", PIN: plain("1234") },
      tags: ["alt"],
      times: newTimes(OLD, { expires: true, expiry: OLD + 1_000_000_000 }),
    });
    const server = newEntry({ uuid, at: NEW, times: newTimes(OLD, { lastModification: NEW }), fields: { Title: "Konto" } });

    for (const [local, remote] of [
      [stale, server],
      [server, stale],
    ] as const) {
      const merged = findEntry(mergeVaults(vaultWith(local), vaultWith(remote), { now: NEW + 100_000 }).vault, uuid)!;
      expect(merged.strings.has("PIN")).toBe(false);
      expect(merged.tags).toEqual([]);
      expect(merged.times.expires).toBe(false);
    }
  });
});
