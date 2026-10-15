/**
 * Tests für Ownwarden.FieldTimes (field-times.ts): Format, wirksame Zeitstempel nach den
 * Regeln aus spec/README.md, Verfeinerung über den Verlauf, Versiegeln.
 */
import { describe, expect, it } from "vitest";
import { newEntry, T0 } from "../../test/helpers/vault-builder";
import { FIELD_TIMES_KEY } from "../contracts";
import type { Entry } from "../model";
import { encodeParts, fingerprint } from "./encoding";
import { effectiveFieldTimes, formatFieldTimes, readFieldTimes, sealFieldTimes, type FieldTime } from "./field-times";

const P = "UEFSRU5UUEFSRU5UUEFSRQ=="; // Elterngruppe

/** Eintrag, den „Ownwarden“ zum Zeitpunkt T0+1000 mit diesen Feldzeiten versiegelt hat. */
function sealed(fields: Record<string, string>, times: Record<string, number>, at = T0 + 1000): Entry {
  const entry = newEntry({ at, fields });
  sealFieldTimes(entry, new Map(Object.entries(times).map(([k, t]) => [k, { t, present: entry.strings.has(k.slice(2)) || k === "parent" }])), P);
  return entry;
}

const asObject = (times: Map<string, FieldTime>) => Object.fromEntries(times);

describe("Ownwarden.FieldTimes lesen und schreiben", () => {
  it("schreibt kompaktes JSON mit sortierten Schlüsseln", () => {
    const text = formatFieldTimes({
      sealedAt: 5,
      fields: new Map([
        ["s:URL", { t: 3, deleted: true }],
        ["parent", { t: 2, deleted: false, hash: "h2" }],
        ["s:Password", { t: 1, deleted: false, hash: "h1" }],
      ]),
    });
    expect(text).toBe('{"v":1,"w":5,"f":{"parent":{"t":2,"h":"h2"},"s:Password":{"t":1,"h":"h1"},"s:URL":{"t":3,"d":1}}}');
    const entry = newEntry({ customData: new Map([[FIELD_TIMES_KEY, { value: text }]]) });
    expect(readFieldTimes(entry)).toEqual({
      sealedAt: 5,
      fields: new Map([
        ["parent", { t: 2, deleted: false, hash: "h2" }],
        ["s:Password", { t: 1, deleted: false, hash: "h1" }],
        ["s:URL", { t: 3, deleted: true }],
      ]),
    });
  });

  it.each([
    ["kein JSON", "{"],
    ["alte Form ohne Version", '{"s:Password":1770000000000}'],
    ["andere Version", '{"v":2,"w":1,"f":{}}'],
    ["w fehlt", '{"v":1,"f":{}}'],
    ["f ist Liste", '{"v":1,"w":1,"f":[]}'],
    ["t ist Text", '{"v":1,"w":1,"f":{"s:A":{"t":"1","h":"x"}}}'],
    ["weder h noch d", '{"v":1,"w":1,"f":{"s:A":{"t":1}}}'],
    ["null", "null"],
  ])("ungültig (%s) -> wie keine FieldTimes", (_name, value) => {
    expect(readFieldTimes(newEntry({ customData: new Map([[FIELD_TIMES_KEY, { value }]]) }))).toBeUndefined();
  });

  it("überspringt unbekannte Schlüssel und __proto__ ohne Schaden", () => {
    const value = '{"v":1,"w":1,"f":{"__proto__":{"t":1,"h":"x"},"s:KPEX_PASSKEY_X":{"t":1,"h":"x"},"cd:_LAST_MODIFIED":{"t":1,"h":"x"},"s:A":{"t":1,"d":1},"s:":{"t":1,"d":1}}}';
    const stored = readFieldTimes(newEntry({ customData: new Map([[FIELD_TIMES_KEY, { value }]]) }));
    expect([...stored!.fields.keys()]).toEqual(["s:A", "s:"]);
    expect(({} as Record<string, unknown>).t).toBeUndefined();
  });
});

describe("wirksame Feld-Zeitstempel", () => {
  it("ohne FieldTimes: lastModification für alle Felder, locationChanged für parent", () => {
    const entry = newEntry({ at: T0, fields: { Title: "T", Password: "p" }, times: { ...newEntry().times, lastModification: T0 + 7000, locationChanged: T0 + 3000 } });
    const effective = effectiveFieldTimes(entry, P);
    expect(effective.sealed).toBe(false);
    expect(effective.externallyEdited).toBe(false);
    expect(asObject(effective.times)).toEqual({
      "s:Title": { t: T0 + 7000, present: true },
      "s:Password": { t: T0 + 7000, present: true },
      parent: { t: T0 + 3000, present: true },
    });
  });

  it("mit passenden Fingerabdrücken: Zeiten aus FieldTimes, auch Lösch-Marker", () => {
    const entry = sealed({ Title: "T", Password: "p" }, { "s:Title": T0 + 10, "s:Password": T0 + 20, parent: T0 + 5, "s:URL": T0 + 30 });
    const effective = effectiveFieldTimes(entry, P);
    expect(effective.sealed).toBe(true);
    expect(effective.externallyEdited).toBe(false);
    expect(asObject(effective.times)).toEqual({
      "s:Title": { t: T0 + 10, present: true },
      "s:Password": { t: T0 + 20, present: true },
      parent: { t: T0 + 5, present: true },
      "s:URL": { t: T0 + 30, present: false },
    });
  });

  it("erkennt Änderungen anderer Programme am Fingerabdruck", () => {
    const entry = sealed({ Title: "T", Password: "p", Notes: "n" }, { "s:Title": T0 + 10, "s:Password": T0 + 2000, "s:Notes": T0 + 10, parent: T0 + 5, "s:URL": T0 + 30 });
    // „KeePassXC“ ändert Titel und Passwort, entfernt Notes, legt URL und ein eigenes Feld an.
    entry.strings.set("Title", { value: "T2", protected: false });
    entry.strings.set("Password", { value: "p2", protected: true });
    entry.strings.set("Notes", { value: "", protected: false });
    entry.strings.set("URL", { value: "https://x", protected: false });
    entry.strings.set("Neu", { value: "x", protected: false });
    entry.times.lastModification = T0 + 1000; // KeePassXC-Zeit (Sekunden), älter als FieldTimes-t von Password
    const effective = effectiveFieldTimes(entry, P);
    expect(asObject(effective.times)).toEqual({
      "s:Title": { t: T0 + 1000, present: true }, // max(lastModification, 10+1)
      "s:Password": { t: T0 + 2001, present: true }, // max(lastModification, 2000+1)
      "s:URL": { t: T0 + 1000, present: true }, // war entfernt (Marker bei 30) -> max(1000, 31)
      "s:Neu": { t: T0 + 1000, present: true }, // unbekannt -> lastModification
      parent: { t: T0 + 5, present: true },
      "s:Notes": { t: T0 + 1000, present: false }, // extern entfernt
    });
    expect(effective.externalFields.sort()).toEqual(["s:Neu", "s:Notes", "s:Password", "s:Title", "s:URL"]);
    expect(effective.externallyEdited).toBe(true);
  });

  it("externe Verschiebung zählt mit locationChanged", () => {
    const entry = sealed({ Title: "T" }, { "s:Title": T0, parent: T0 });
    entry.times.locationChanged = T0 + 9000;
    expect(effectiveFieldTimes(entry, "QU5ERVJFQU5ERVJFQU5ERQ==").times.get("parent")).toEqual({ t: T0 + 9000, present: true });
  });

  it("neuere lastModification ohne erkennbare Feldänderung: nur als extern markiert", () => {
    const entry = sealed({ Title: "T" }, { "s:Title": T0 }, T0 + 1000);
    entry.times.lastModification = T0 + 5000;
    const effective = effectiveFieldTimes(entry, P);
    expect(effective.externallyEdited).toBe(true);
    expect(effective.externalFields).toEqual([]);
    expect(effective.times.get("s:Title")).toEqual({ t: T0, present: true });
  });

  it("ohne FieldTimes, mit Verlauf: Felder bekommen die Zeit der Fassung, in der ihr Wert entstand", () => {
    const v0 = newEntry({ at: T0, fields: { Title: "T", UserName: "u0", Password: "p", Weg: "x" } });
    const v1 = newEntry({ at: T0 + 1000, fields: { Title: "T", UserName: "u1", Password: "p", Weg: "x" } });
    const current = newEntry({
      uuid: v0.uuid,
      at: T0 + 2000,
      fields: { Title: "T", UserName: "u1", Password: "p2", Neu: "n" },
      history: [v0, v1],
    });
    expect(asObject(effectiveFieldTimes(current).times)).toEqual({
      "s:Title": { t: T0, present: true }, // seit der ältesten Fassung gleich
      "s:UserName": { t: T0 + 1000, present: true }, // in v1 geändert
      "s:Password": { t: T0 + 2000, present: true }, // jetzt geändert
      "s:Neu": { t: T0 + 2000, present: true },
      "s:Weg": { t: T0 + 2000, present: false }, // jetzt entfernt
    });
  });

  it("Versiegeln schreibt frische Fingerabdrücke und w = lastModification", () => {
    const entry = newEntry({ at: T0 + 500, fields: { Title: "T" } });
    sealFieldTimes(entry, new Map([["s:Title", { t: T0 + 1, present: true }], ["s:Alt", { t: T0 + 2, present: true }]]), P);
    const parsed = JSON.parse(entry.customData.get(FIELD_TIMES_KEY)!.value);
    expect(parsed).toEqual({
      v: 1,
      w: T0 + 500,
      f: {
        parent: { t: T0 + 500, h: fingerprint(encodeParts(["parent", P])) },
        "s:Alt": { t: T0 + 2, d: 1 }, // gibt es nicht (mehr) -> Lösch-Marker
        "s:Title": { t: T0 + 1, h: fingerprint(encodeParts(["s", "T", "0"])) },
      },
    });
  });
});
