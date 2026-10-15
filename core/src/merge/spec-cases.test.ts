/**
 * Läufer für die sprachneutralen Merge-Testfälle in spec/merge-cases/*.json (Format:
 * spec/README.md). Jeder Fall läuft in BEIDE Richtungen (local/remote vertauscht) und muss
 * jedes Mal dasselbe Ergebnis liefern. Zusätzlich je Richtung:
 *   - die Eingaben bleiben unverändert (reine Funktion),
 *   - keine UUID ist zugleich vorhanden und gelöscht,
 *   - erneutes Zusammenführen ändert nichts: merge(m, m), merge(m, remote), merge(m, local).
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Vault } from "../model";
import { cloneVault } from "./clone";
import { mergeVaults } from "./merge";
import {
  buildSpecVault,
  describeActual,
  describeExpected,
  describeReport,
  expectedReportFor,
  SPEC_DEFAULT_NOW,
  SpecNames,
  type SpecCase,
} from "./testing/spec-fixture";

const SPEC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "spec", "merge-cases");

function loadCases(): [string, SpecCase][] {
  return readdirSync(SPEC_DIR)
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => [file, JSON.parse(readFileSync(join(SPEC_DIR, file), "utf8")) as SpecCase]);
}

/** Alle UUIDs von Einträgen und Gruppen (ohne Verlauf). */
function presentUuids(vault: Vault): string[] {
  const result: string[] = [];
  const walk = (group: Vault["root"]): void => {
    result.push(group.uuid, ...group.entries.map((e) => e.uuid));
    group.groups.forEach(walk);
  };
  walk(vault.root);
  return result;
}

const cases = loadCases();

describe("spec/merge-cases", () => {
  it("es gibt Testfälle mit eindeutigen Namen", () => {
    expect(cases.length).toBeGreaterThanOrEqual(20);
    const names = cases.map(([, testCase]) => testCase.name);
    expect(new Set(names).size).toBe(names.length);
    for (const [file, testCase] of cases) expect(file).toBe(`${testCase.name}.json`);
  });

  describe.each(cases)("%s", (_file, testCase) => {
    const now = testCase.now ?? SPEC_DEFAULT_NOW;
    const names = new SpecNames();
    names.learn(testCase);
    const expected = describeExpected(testCase.expected);

    it.each([
      ["local -> remote", false],
      ["vertauscht", true],
    ])("%s", (_direction, swapped) => {
      const local = buildSpecVault(swapped ? testCase.remote : testCase.local);
      const remote = buildSpecVault(swapped ? testCase.local : testCase.remote);
      const localBefore = cloneVault(local);
      const remoteBefore = cloneVault(remote);

      const { vault, report } = mergeVaults(local, remote, { now });
      expect(describeActual(vault, testCase.expected, names)).toEqual(expected);

      const expectedReport = expectedReportFor(testCase, swapped);
      if (expectedReport !== undefined) expect(describeReport(report, expectedReport, names)).toEqual(expectedReport);

      expect(local).toEqual(localBefore);
      expect(remote).toEqual(remoteBefore);
      const present = new Set(presentUuids(vault));
      expect(vault.deletedObjects.filter((d) => present.has(d.uuid))).toEqual([]);
      expect(present.size).toBe(presentUuids(vault).length); // keine doppelten UUIDs

      for (const other of [vault, remote, local]) {
        const again = mergeVaults(vault, other, { now });
        expect(describeActual(again.vault, testCase.expected, names)).toEqual(expected);
      }
    });
  });
});
