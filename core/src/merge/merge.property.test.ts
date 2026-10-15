/**
 * Eigenschafts-Tests für mergeVaults mit zufälligen, reproduzierbaren Szenarien
 * (testing/random-vaults.ts). Für jeden Seed gilt:
 *   - Symmetrie:        merge(a, b) und merge(b, a) haben denselben Inhalt
 *   - Idempotenz:       merge(m, m) = m
 *   - Stabilität:       merge(m, b) = m und merge(m, a) = m  (m = merge(a, b))
 *   - keine Doppelten:  jede UUID höchstens einmal; nichts zugleich vorhanden und gelöscht
 *   - kein stiller Verlust: jeder Eintrag aus a oder b ist im Ergebnis oder hat einen
 *                       Lösch-Vermerk
 *   - reine Funktion:   a und b bleiben unverändert
 *   - speicherbar:      Das Ergebnis übersteht XML schreiben + lesen.
 * Schlägt ein Seed fehl, lässt er sich einzeln nachstellen: randomScenario(seed).
 */
import { describe, expect, it } from "vitest";
import { identityStream } from "../../test/fixtures/xml/fixtures";
import { parseVaultXml, serializeVaultXml } from "../kdbx/xml";
import type { Entry, Group, KdbxTimes, Vault } from "../model";
import { cloneVault } from "./clone";
import { mergeVaults } from "./merge";
import { entryUuids, presentUuids, randomScenario, semanticView } from "./testing/random-vaults";

const SEEDS = Array.from({ length: 300 }, (_, i) => i + 1);

describe("mergeVaults – Eigenschaften (zufällige Szenarien)", () => {
  it.each(SEEDS)("Seed %i", (seed) => {
    const { a, b, now } = randomScenario(seed);
    const aBefore = cloneVault(a);
    const bBefore = cloneVault(b);

    const ab = mergeVaults(a, b, { now }).vault;
    const ba = mergeVaults(b, a, { now }).vault;
    expect(semanticView(ba), "Symmetrie").toEqual(semanticView(ab));
    expect(a, "a unverändert").toEqual(aBefore);
    expect(b, "b unverändert").toEqual(bBefore);

    expect(semanticView(mergeVaults(ab, ab, { now }).vault), "Idempotenz").toEqual(semanticView(ab));
    expect(semanticView(mergeVaults(ab, b, { now }).vault), "merge(m, b)").toEqual(semanticView(ab));
    expect(semanticView(mergeVaults(ab, a, { now }).vault), "merge(m, a)").toEqual(semanticView(ab));
    expect(semanticView(mergeVaults(b, ab, { now }).vault), "merge(b, m)").toEqual(semanticView(ab));

    const present = presentUuids(ab);
    expect(new Set(present).size, "keine doppelten UUIDs").toBe(present.length);
    const presentSet = new Set(present);
    expect(ab.deletedObjects.filter((d) => presentSet.has(d.uuid)), "vorhanden und gelöscht").toEqual([]);
    const deleted = new Set(ab.deletedObjects.map((d) => d.uuid));
    for (const uuid of [...entryUuids(a), ...entryUuids(b)]) {
      expect(presentSet.has(uuid) || deleted.has(uuid), `Eintrag ${uuid} still verloren`).toBe(true);
    }

    // KDBX speichert Zeiten nur sekundengenau; Feld-Zeitstempel (in FieldTimes) bleiben genau.
    const { xml, binaries } = serializeVaultXml(ab, identityStream());
    const reread = parseVaultXml(xml, binaries, identityStream(), ab.settings);
    expect(semanticView(reread), "XML-Rundlauf").toEqual(semanticView(withSecondTimes(ab)));
  });
});

/** Kopie mit allen KDBX-Zeiten auf ganze Sekunden abgerundet (wie nach dem Speichern). */
function withSecondTimes(vault: Vault): Vault {
  const copy = cloneVault(vault);
  const second = (t: number) => Math.floor(t / 1000) * 1000;
  const times = (t: KdbxTimes): KdbxTimes => ({
    ...t,
    creation: second(t.creation),
    lastModification: second(t.lastModification),
    lastAccess: second(t.lastAccess),
    expiry: second(t.expiry),
    locationChanged: second(t.locationChanged),
  });
  const entry = (e: Entry): void => {
    e.times = times(e.times);
    e.history.forEach(entry);
  };
  const group = (g: Group): void => {
    g.times = times(g.times);
    g.entries.forEach(entry);
    g.groups.forEach(group);
  };
  group(copy.root);
  copy.deletedObjects = copy.deletedObjects.map((d) => ({ ...d, deletionTime: second(d.deletionTime) }));
  copy.meta.databaseNameChanged = second(copy.meta.databaseNameChanged);
  copy.meta.recycleBinChanged = second(copy.meta.recycleBinChanged);
  return copy;
}
