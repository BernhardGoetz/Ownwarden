/**
 * Tests für das Feld-Modell (fields.ts) und die Byte-Kodierung (encoding.ts).
 * Schwerpunkt: Die kanonischen Werte dürfen sich durch die Umformungen von KeePassXC beim
 * Speichern NICHT ändern – sonst sähe jedes Laden+Speichern in KeePassXC wie eine Änderung aus.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { attachment, newEntry, plain, secret, T0 } from "../../test/helpers/vault-builder";
import { FIELD_TIMES_KEY } from "../contracts";
import type { Entry } from "../model";
import { base64Url, compareBytes, compareText, encodeParts, fingerprint } from "./encoding";
import { copyField, entryFields, fieldKind, isPasskeyAttribute, materializeStandardFields, significantUnknown } from "./fields";
import { buildSpecEntry, specUuid, type SpecEntry } from "./testing/spec-fixture";

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const DEFAULT_AUTO_TYPE = "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>";

/** Kanonische Werte aller Felder als Hex (für Vergleiche). */
function canonicalMap(entry: Entry, parent?: string): Record<string, string> {
  return Object.fromEntries([...entryFields(entry, parent)].map(([key, value]) => [key, hex(value.canonical)]));
}

describe("encoding", () => {
  it("kodiert Teile längenpräfixiert (uint32 Big Endian), Texte als UTF-8, Listen verschachtelt", () => {
    expect(hex(encodeParts(["ab", Uint8Array.of(0xff), "ä"]))).toBe("000000026162" + "00000001ff" + "00000002c3a4");
    expect(hex(encodeParts([["x"], ""]))).toBe("00000005" + "0000000178" + "00000000");
  });

  it("vergleicht Bytes lexikografisch (Präfix ist kleiner) und Texte nach UTF-8", () => {
    expect(compareBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBeLessThan(0);
    expect(compareBytes(Uint8Array.of(1), Uint8Array.of(1, 0))).toBeLessThan(0);
    expect(compareBytes(Uint8Array.of(2), Uint8Array.of(1, 9))).toBeGreaterThan(0);
    // UTF-16 würde U+FF5E (Vollbreite) hinter U+1F600 (Surrogat D83D) sortieren, UTF-8 davor.
    expect(compareText("～", "\u{1f600}")).toBeLessThan(0);
  });

  it("Fingerabdruck = Base64url der ersten 12 Byte von SHA-256", () => {
    const canonical = encodeParts(["s", "geheim", "1"]);
    const expected = createHash("sha256").update(canonical).digest().subarray(0, 12).toString("base64url");
    expect(fingerprint(canonical)).toBe(expected);
    expect(fingerprint(canonical)).toHaveLength(16);
    expect(base64Url(Uint8Array.of(0xfb, 0xff))).toBe("-_8");
  });
});

describe("Feld-Modell", () => {
  it("zerlegt einen Eintrag in Felder (Passkey als eine Einheit, ohne FieldTimes/_LAST_MODIFIED)", () => {
    const entry = newEntry({
      fields: {
        Title: "Mail",
        UserName: "",
        KPEX_PASSKEY_USERNAME: "alice",
        Password: "pw",
        KPEX_PASSKEY_PRIVATE_KEY_PEM: secret("PEM"),
        Eigenes: "",
      },
      attachments: [attachment("a.txt", "A")],
      customData: new Map([
        [FIELD_TIMES_KEY, { value: "{}" }],
        ["_LAST_MODIFIED", { value: "x" }],
        ["Typ", { value: "login" }],
      ]),
      tags: ["b", "a"],
      iconId: 5,
      times: { ...newEntry().times, expires: true, expiry: T0 + 1234 },
      foregroundColor: "#ff0000",
      overrideUrl: "cmd://x",
      unknown: ["<Fremd/>"],
    });
    expect([...entryFields(entry, "PARENT").keys()]).toEqual([
      "s:Title",
      "passkey",
      "s:Password",
      "s:Eigenes", // leeres EIGENES Feld ist vorhanden, leeres Standardfeld nicht
      "a:a.txt",
      "cd:Typ",
      "tags",
      "icon",
      "colors",
      "overrideUrl",
      "expiry",
      "misc",
      "parent",
    ]);
    // Ohne Elterngruppe (Verlaufseintrag) gibt es kein Feld "parent".
    expect(entryFields(entry).has("parent")).toBe(false);
  });

  it("Standardwerte zählen als „nicht vorhanden“", () => {
    const entry = newEntry({ fields: { Title: "", Notes: "" }, times: { ...newEntry().times, expires: false, expiry: T0 } });
    expect([...entryFields(entry).keys()]).toEqual([]);
  });

  it("ist unempfindlich gegen die Umformungen von KeePassXC beim Speichern", () => {
    const ownwarden = newEntry({
      fields: { Title: "T", Notes: "a\r\nb\rc", Password: secret("﻿geheim") },
      attachments: [attachment("b.bin", "B", false), attachment("a.bin", "A", false)],
      tags: ["Zeta", "alpha", "Mitte"],
      iconId: 12,
      customIconUuid: "AQEBAQEBAQEBAQEBAQEBAQ==",
      times: { ...newEntry().times, expires: true, expiry: T0 + 999 },
      customData: new Map([
        ["x", { value: "1\r\n2", lastModified: T0 }],
        ["y", { value: "2" }],
      ]),
      unknown: [],
    });
    const keepassxc = newEntry({
      uuid: ownwarden.uuid,
      fields: { Title: "T", UserName: "", Password: secret("geheim"), URL: "", Notes: "a\nb\nc" },
      attachments: [attachment("a.bin", "A", true), attachment("b.bin", "B", true)],
      tags: ["Mitte", "Zeta", "alpha"],
      iconId: 0,
      customIconUuid: "AQEBAQEBAQEBAQEBAQEBAQ==",
      times: { ...newEntry().times, expires: true, expiry: T0 },
      customData: new Map([
        ["y", { value: "2" }],
        ["x", { value: "1\n2" }],
        ["_LAST_MODIFIED", { value: "Thu Oct 15 11:11:11 2026 GMT" }],
      ]),
      qualityCheck: true,
      unknown: [DEFAULT_AUTO_TYPE],
    });
    expect(canonicalMap(keepassxc, "P")).toEqual(canonicalMap(ownwarden, "P"));
  });

  it("unterscheidet echte Änderungen", () => {
    const base = newEntry({ fields: { Title: "T", Password: "pw" } });
    const variants: Partial<Entry>[] = [
      { strings: new Map([["Title", plain("T")], ["Password", plain("pw")]]) }, // Schutz-Flag geändert
      { strings: new Map([["Title", plain("T ")], ["Password", secret("pw")]]) },
      { iconId: 3 },
      { qualityCheck: false },
      { previousParentGroup: "AgICAgICAgICAgICAgICAg==" },
      { unknown: ["<AutoType><Enabled>False</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>"] },
      { backgroundColor: "#000000" },
    ];
    for (const variant of variants) {
      expect(canonicalMap({ ...base, ...variant })).not.toEqual(canonicalMap(base));
    }
  });

  it("erkennt Passkey-Attribute und Feldarten", () => {
    expect(isPasskeyAttribute("KPEX_PASSKEY_CREDENTIAL_ID")).toBe(true);
    expect(isPasskeyAttribute("KPXC_PASSKEY_USERNAME")).toBe(true);
    expect(isPasskeyAttribute("KPEX_PASSKEYS")).toBe(false);
    expect(fieldKind("s:Title")).toEqual({ kind: "string", name: "Title" });
    expect(fieldKind("cd:a:b")).toEqual({ kind: "customData", name: "a:b" });
    expect(fieldKind("a:x")).toEqual({ kind: "attachment", name: "x" });
    expect(fieldKind("passkey")).toEqual({ kind: "passkey" });
    expect(fieldKind("bogus")).toEqual({ kind: "unknown" });
    expect(significantUnknown([DEFAULT_AUTO_TYPE, "<X/>"])).toEqual(["<X/>"]);
  });

  it("copyField überträgt Rohwerte und entfernt fehlende Felder", () => {
    const source = newEntry({
      fields: { Title: "Neu", KPEX_PASSKEY_USERNAME: "u", KPEX_PASSKEY_RELYING_PARTY: "rp" },
      attachments: [attachment("a", "x")],
      customData: new Map([["k", { value: "v" }]]),
      tags: ["t"],
      customIconUuid: "AQEBAQEBAQEBAQEBAQEBAQ==",
      qualityCheck: false,
      times: { ...newEntry().times, expires: true, expiry: T0 + 5 },
    });
    const target = newEntry({ fields: { Title: "Alt", Weg: "x", KPEX_PASSKEY_USERNAME: "alt", KPEX_PASSKEY_FLAG_BE: "1" } });
    for (const key of ["s:Title", "s:Weg", "passkey", "a:a", "cd:k", "tags", "icon", "misc", "expiry"]) copyField(target, source, key);
    expect(Object.fromEntries([...target.strings].map(([k, v]) => [k, v.value]))).toEqual({
      Title: "Neu",
      KPEX_PASSKEY_USERNAME: "u",
      KPEX_PASSKEY_RELYING_PARTY: "rp",
    });
    expect(target.attachments.map((a) => a.name)).toEqual(["a"]);
    expect(target.attachments[0]!.data).toBe(source.attachments[0]!.data); // geteilt, nicht kopiert
    expect(target.customData.get("k")).toEqual({ value: "v" });
    expect(target.tags).toEqual(["t"]);
    expect(target.customIconUuid).toBe(source.customIconUuid);
    expect(target.qualityCheck).toBe(false);
    expect(target.times.expires).toBe(true);
    expect(target.times.expiry).toBe(T0 + 5);
    materializeStandardFields(target);
    expect([...target.strings.keys()].slice(0, 5)).toEqual(["Title", "UserName", "Password", "URL", "Notes"]);
    expect(target.strings.get("Password")).toEqual({ value: "", protected: true });
  });
});

describe("Prüfwerte aus spec/field-vectors.json (gemeinsam mit Kotlin)", () => {
  interface Vector {
    name: string;
    entry: SpecEntry;
    fields: Record<string, { canonical: string; fingerprint: string }>;
    fieldTimesJson?: string;
  }
  const file = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "spec", "field-vectors.json");
  const { vectors } = JSON.parse(readFileSync(file, "utf8")) as { vectors: Vector[] };

  it("enthält Prüfwerte für alle Feldarten", () => {
    const keys = new Set(vectors.flatMap((v) => Object.keys(v.fields).map((k) => k.replace(/:.*/, ":"))));
    expect([...keys].sort()).toEqual(["a:", "cd:", "colors", "expiry", "icon", "misc", "overrideUrl", "parent", "passkey", "s:", "tags"]);
  });

  it.each(vectors.map((v) => [v.name, v] as const))("%s", (_name, vector) => {
    const parent = specUuid(vector.entry.parent ?? "root");
    const entry = buildSpecEntry(vector.entry, parent);
    const actual = Object.fromEntries(
      [...entryFields(entry, parent)].map(([key, value]) => [key, { canonical: hex(value.canonical), fingerprint: fingerprint(value.canonical) }]),
    );
    expect(actual).toEqual(vector.fields);
    for (const { canonical, fingerprint: fp } of Object.values(vector.fields)) {
      expect(createHash("sha256").update(Buffer.from(canonical, "hex")).digest().subarray(0, 12).toString("base64url")).toBe(fp);
    }
    if (vector.fieldTimesJson !== undefined) expect(entry.customData.get(FIELD_TIMES_KEY)?.value).toBe(vector.fieldTimesJson);
  });
});
