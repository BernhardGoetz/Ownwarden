/**
 * restampFutureTimes (Review merge-2/sync-2, Entscheidung des Eigentümers 2026-10-17): repariert
 * Zeitstempel aus der Zukunft, ohne Werte zu ändern; die Feld-Zeitstempel bleiben gültig, und
 * der Merge behandelt die Änderungen danach als „jetzt“ gemacht.
 */
import { describe, expect, it } from "vitest";
import { entryByTitle, newVault, T0, uuidFromName } from "../../test/helpers/vault-builder";
import { FIELD_TIMES_KEY } from "../contracts";
import * as api from "../index";
import type { Vault } from "../model";
import { cloneVault } from "../merge/clone";
import { createVaultClock, latestVaultTime } from "../merge/clock";
import { effectiveFieldTimes, readFieldTimes } from "../merge/field-times";
import { mergeVaults } from "../merge/merge";
import { createEntry, createGroup, deleteEntry, setField } from "../merge/vault-ops";
import { restampFutureTimes } from "./future-times";

const NOW = T0 + 86_400_000;
const LIMIT = NOW + 120_000;
const YEAR = 365 * 86_400_000;
const MAIL = uuidFromName("mail");
const BANK = uuidFromName("bank");

/** Mail und Bank mit richtiger Uhr angelegt; danach auf einem Gerät mit Uhr ein Jahr vor bearbeitet. */
function scenario(): { base: Vault; future: Vault } {
  const base = newVault();
  const clock = createVaultClock(base, () => NOW - 3_600_000);
  createEntry(base, base.root.uuid, { Title: "Mail", Password: "alt" }, clock, { uuid: MAIL });
  createEntry(base, base.root.uuid, { Title: "Bank", Password: "b" }, clock, { uuid: BANK });
  const future = cloneVault(base);
  const wrong = createVaultClock(future, () => NOW + YEAR);
  setField(future, MAIL, "Password", "neu", {}, wrong);
  setField(future, MAIL, "Password", "noch neuer", {}, wrong); // eine Fassung mit falscher Zeit im Verlauf
  createGroup(future, future.root.uuid, "Neu", wrong);
  deleteEntry(future, BANK, wrong);
  future.meta.databaseName = "Umbenannt";
  future.meta.databaseNameChanged = NOW + YEAR;
  future.meta.customData.set("Meta", { value: "x", lastModified: NOW + YEAR });
  return { base, future };
}

describe("restampFutureTimes", () => {
  it("setzt jede Zeit nach limit auf now, ändert keinen Wert und verändert die Eingabe nicht", () => {
    const { future } = scenario();
    const snapshot = cloneVault(future);
    expect(latestVaultTime(future)).toBeGreaterThan(LIMIT);

    const { vault, restamped } = restampFutureTimes(future, LIMIT, NOW + 0.7);

    expect(future).toEqual(snapshot);
    expect(restamped).toBeGreaterThan(0);
    expect(latestVaultTime(vault)).toBe(NOW);
    const mail = entryByTitle(vault, "Mail");
    expect(mail.strings.get("Password")?.value).toBe("noch neuer");
    expect(mail.times.lastModification).toBe(NOW);
    expect(mail.history.at(-1)!.times.lastModification).toBe(NOW);
    expect(vault.root.groups[0]!.times.lastModification).toBe(NOW);
    expect(vault.deletedObjects.find((item) => item.uuid === BANK)!.deletionTime).toBe(NOW);
    expect(vault.meta.databaseName).toBe("Umbenannt");
    expect(vault.meta.databaseNameChanged).toBe(NOW);
    expect(vault.meta.customData.get("Meta")).toEqual({ value: "x", lastModified: NOW });
    // Zeiten, die nicht in der Zukunft lagen, bleiben; ebenso das Ablaufdatum.
    expect(mail.times.creation).toBe(NOW - 3_600_000);
  });

  it("Feld-Zeitstempel bleiben gültig: Fingerabdrücke passen, kein „extern geändert“", () => {
    const { vault } = restampFutureTimes(scenario().future, LIMIT, NOW);
    const mail = entryByTitle(vault, "Mail");
    const stored = readFieldTimes(mail)!;
    expect(stored.sealedAt).toBe(NOW);
    expect(stored.fields.get("s:Password")!.t).toBe(NOW);
    const effective = effectiveFieldTimes(mail, vault.root.uuid);
    expect(effective.sealed).toBe(true);
    expect(effective.externallyEdited).toBe(false);
    expect(effective.times.get("s:Password")).toEqual({ t: NOW, present: true });
  });

  it("danach gelten die Änderungen als jetzt gemacht: eine spätere echte Änderung bzw. Löschung gewinnt", () => {
    const { base, future } = scenario();
    const { vault: repaired } = restampFutureTimes(future, LIMIT, NOW);
    // Ein anderes Gerät mit richtiger Uhr ändert 10 Minuten später dasselbe Feld.
    const other = cloneVault(base);
    setField(other, MAIL, "Password", "wirklich neuer", {}, createVaultClock(other, () => NOW + 600_000));
    const merged = mergeVaults(repaired, other, { now: NOW + 660_000 }).vault;
    expect(entryByTitle(merged, "Mail").strings.get("Password")?.value).toBe("wirklich neuer");
    // Auch Fassungen, die jetzt dieselbe Zeit tragen, bleiben im Verlauf (verschiedener Inhalt).
    const passwords = entryByTitle(merged, "Mail").history.map((version) => version.strings.get("Password")?.value);
    expect(passwords).toEqual(expect.arrayContaining(["alt", "neu", "noch neuer"]));
    // Ohne Reparatur hätte die Änderung mit der falschen Uhr gewonnen.
    expect(entryByTitle(mergeVaults(future, other, { now: NOW + 660_000 }).vault, "Mail").strings.get("Password")?.value).toBe("noch neuer");
  });

  it("nichts in der Zukunft: unveränderte Kopie, restamped 0", () => {
    const { base } = scenario();
    const { vault, restamped } = restampFutureTimes(base, LIMIT, NOW);
    expect(restamped).toBe(0);
    expect(vault).toEqual(base);
    expect(vault).not.toBe(base);
  });

  it("auch ungültige FieldTimes werden toleriert (wie latestVaultTime), Ablaufdatum bleibt", () => {
    const vault = newVault();
    createEntry(vault, vault.root.uuid, { Title: "Mail" }, createVaultClock(vault, () => NOW), { uuid: MAIL });
    const entry = entryByTitle(vault, "Mail");
    entry.times.expires = true;
    entry.times.expiry = NOW + 10 * YEAR;
    entry.customData.set(FIELD_TIMES_KEY, { value: `{"v":99,"w":${NOW + YEAR},"f":{"s:Title":{"t":${NOW + YEAR}},"x":null}}` });
    const { vault: repaired } = restampFutureTimes(vault, LIMIT, NOW);
    const fixed = entryByTitle(repaired, "Mail");
    expect(fixed.customData.get(FIELD_TIMES_KEY)!.value).toBe(`{"v":99,"w":${NOW},"f":{"s:Title":{"t":${NOW}},"x":null}}`);
    expect(fixed.times.expiry).toBe(NOW + 10 * YEAR);
    expect(latestVaultTime(repaired)).toBeLessThanOrEqual(LIMIT);
    // Kaputtes JSON bleibt, wie es ist.
    entry.customData.set(FIELD_TIMES_KEY, { value: "{kaputt" });
    expect(entryByTitle(restampFutureTimes(vault, LIMIT, NOW).vault, "Mail").customData.get(FIELD_TIMES_KEY)!.value).toBe("{kaputt");
  });

  it("lehnt now nach limit und ungültige Zeiten ab", () => {
    const { base } = scenario();
    expect(() => restampFutureTimes(base, NOW, NOW + 1)).toThrow(RangeError);
    expect(() => restampFutureTimes(base, Number.NaN, NOW)).toThrow(RangeError);
    expect(() => restampFutureTimes(base, Infinity, Number.NaN)).toThrow(RangeError);
  });

  it("ist über die öffentliche Schnittstelle (index.ts) erreichbar, samt FutureTimestampsError", () => {
    expect(api.restampFutureTimes).toBe(restampFutureTimes);
    const error = new api.FutureTimestampsError(NOW + YEAR, LIMIT);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("FutureTimestampsError");
    expect(error.message).toMatch(/Zeitstempel aus der Zukunft.*nichts geschrieben.*reparieren/s);
  });
});
