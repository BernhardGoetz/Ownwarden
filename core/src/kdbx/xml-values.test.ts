import { describe, expect, it } from "vitest";
import { KdbxError } from "../contracts";
import {
  decodeBase64,
  decodeBool,
  decodeInteger,
  decodeTime,
  decodeUtf8Strict,
  decodeUuid,
  encodeBase64,
  encodeBool,
  encodeInteger,
  encodeTime,
  encodeUuid,
  formatTags,
  isTrueAttribute,
  parseTags,
} from "./xml-values";

const corrupt = expect.objectContaining({ name: "KdbxError", code: "Corrupt" });

/** Erwartete KDBX-Zeit: int64 LE Sekunden seit 0001-01-01 als Base64 (unabhängig berechnet). */
function kdbxTime(seconds: bigint): string {
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64LE(seconds);
  return buffer.toString("base64");
}

describe("Zeiten", () => {
  it("kodiert den Unix-Nullpunkt als 62135596800 Sekunden seit Jahr 1", () => {
    expect(encodeTime(0)).toBe(kdbxTime(62_135_596_800n));
    expect(decodeTime(kdbxTime(62_135_596_800n), "t")).toBe(0);
  });

  it("liest und schreibt die Grenzen Jahr 1 und Jahr 9999", () => {
    const year1 = Date.parse("0001-01-01T00:00:00Z");
    const year9999 = Date.parse("9999-12-31T23:59:59Z");
    expect(encodeTime(year1)).toBe("AAAAAAAAAAA=");
    expect(decodeTime("AAAAAAAAAAA=", "t")).toBe(year1);
    expect(decodeTime(encodeTime(year9999), "t")).toBe(year9999);
  });

  it("stimmt mit einer echten KeePassXC-Zeit überein", () => {
    // Aus einer von KeePassXC 2.7.6 geschriebenen KDBX-4.1-Datei (Eintrag geändert um 06:53:59 UTC).
    expect(decodeTime("h29i4g4AAAA=", "t")).toBe(Date.parse("2026-10-15T06:53:59Z"));
    expect(encodeTime(Date.parse("2026-10-15T06:53:59Z"))).toBe("h29i4g4AAAA=");
  });

  it("rundet Millisekunden beim Schreiben ab (auch vor 1970)", () => {
    const t = Date.parse("2026-10-15T10:00:00Z");
    expect(decodeTime(encodeTime(t + 999), "t")).toBe(t);
    expect(decodeTime(encodeTime(-1), "t")).toBe(-1000);
  });

  it("liest ISO-8601-Text (KDBX-3-Stil), auch mit Zeitzone und Bruchteilen", () => {
    expect(decodeTime("2026-10-14T16:37:20Z", "t")).toBe(Date.parse("2026-10-14T16:37:20Z"));
    expect(decodeTime(" 2026-03-01T14:00:00+02:00 ", "t")).toBe(Date.parse("2026-03-01T12:00:00Z"));
    expect(decodeTime("2026-03-01T10:00:00-0130", "t")).toBe(Date.parse("2026-03-01T11:30:00Z"));
    expect(decodeTime("2026-01-02T03:04:05.987Z", "t")).toBe(Date.parse("2026-01-02T03:04:05Z"));
    expect(decodeTime("0050-06-01T00:00:00", "t")).toBe(Date.parse("0050-06-01T00:00:00Z"));
  });

  it("lehnt ungültige Zeiten ab", () => {
    expect(() => decodeTime("2026-02-30T00:00:00Z", "t")).toThrow(corrupt);
    expect(() => decodeTime("2026-01-01T24:00:00Z", "t")).toThrow(corrupt);
    expect(() => decodeTime("kein Base64!", "t")).toThrow(corrupt);
    expect(() => decodeTime("AAAA", "t")).toThrow(/3 statt 8 Byte/);
    expect(() => decodeTime(kdbxTime(-1n), "t")).toThrow(/außerhalb/);
    expect(() => decodeTime(kdbxTime(315_537_897_600n), "t")).toThrow(/außerhalb/);
  });

  it("wirft beim Schreiben unmöglicher Zeiten einen RangeError", () => {
    expect(() => encodeTime(Number.NaN)).toThrow(RangeError);
    expect(() => encodeTime(Date.parse("9999-12-31T23:59:59Z") + 1000)).toThrow(RangeError);
  });
});

describe("Wahrheitswerte und Zahlen", () => {
  it("liest True/False ohne Rücksicht auf Groß-/Kleinschreibung", () => {
    expect(decodeBool("True", "b")).toBe(true);
    expect(decodeBool(" TRUE ", "b")).toBe(true);
    expect(decodeBool("false", "b")).toBe(false);
    expect(() => decodeBool("ja", "b")).toThrow(corrupt);
    expect(encodeBool(true)).toBe("True");
    expect(encodeBool(false)).toBe("False");
  });

  it("erkennt Protected-Attributwerte wie KeePassXC", () => {
    expect(isTrueAttribute("True")).toBe(true);
    expect(isTrueAttribute("true")).toBe(true);
    expect(isTrueAttribute("1")).toBe(true);
    expect(isTrueAttribute("False")).toBe(false);
    expect(isTrueAttribute(undefined)).toBe(false);
  });

  it("liest ganze Zahlen und lehnt anderes ab", () => {
    expect(decodeInteger("42", "n")).toBe(42);
    expect(decodeInteger(" -1 ", "n")).toBe(-1);
    expect(decodeInteger("+7", "n")).toBe(7);
    for (const bad of ["", "1.5", "0x10", "abc", "1e3", "99999999999999999"]) {
      expect(() => decodeInteger(bad, "n")).toThrow(corrupt);
    }
    expect(encodeInteger(-1, "n")).toBe("-1");
    expect(() => encodeInteger(1.5, "n")).toThrow(RangeError);
  });
});

describe("Base64, UTF-8 und UUIDs", () => {
  it("kodiert und dekodiert Base64 (auch große Daten)", () => {
    const big = Uint8Array.from({ length: 200_000 }, (_, i) => (i * 7) % 256);
    const text = encodeBase64(big);
    expect(text).toBe(Buffer.from(big).toString("base64"));
    expect(Buffer.from(decodeBase64(text, "b")).equals(Buffer.from(big))).toBe(true);
    expect(decodeBase64(" QU\nJD ", "b")).toEqual(new TextEncoder().encode("ABC"));
    expect(() => decodeBase64("ab$c", "b")).toThrow(corrupt);
    expect(() => decodeBase64("abcde", "b")).toThrow(corrupt);
  });

  it("dekodiert UTF-8 streng (ungültige Bytes sind ein Fehler, BOM wird entfernt)", () => {
    expect(decodeUtf8Strict(Uint8Array.from([0xef, 0xbb, 0xbf, 0x41]), "u")).toBe("A");
    expect(() => decodeUtf8Strict(Uint8Array.from([0xff, 0xfe]), "u")).toThrow(corrupt);
  });

  it("prüft UUIDs auf 16 Byte und vereinheitlicht die Schreibweise", () => {
    expect(decodeUuid(" AAAAAAAAAAAAAAAAAAAAAA ", "u")).toBe("AAAAAAAAAAAAAAAAAAAAAA==");
    expect(() => decodeUuid("AAAA", "u")).toThrow(/3 statt 16 Byte/);
    expect(encodeUuid("AQEBAQEBAQEBAQEBAQEBAQ==", "u")).toBe("AQEBAQEBAQEBAQEBAQEBAQ==");
    expect(() => encodeUuid("AAAA", "u")).toThrow(RangeError);
    expect(() => encodeUuid("%%%", "u")).toThrow(RangeError);
  });

  it("wirft bei Fehlern immer KdbxError", () => {
    expect(() => decodeUuid("%%%", "u")).toThrow(KdbxError);
  });
});

describe("Tags", () => {
  it("trennt an Komma und Semikolon, entfernt Leerraum, Leeres und Doppeltes", () => {
    expect(parseTags(" Bank , Privat;Bank;; ")).toEqual(["Bank", "Privat"]);
    expect(parseTags("")).toEqual([]);
    expect(parseTags("Ein Tag mit Leerzeichen")).toEqual(["Ein Tag mit Leerzeichen"]);
  });

  it("schreibt mit Semikolon wie KeePass", () => {
    expect(formatTags(["a", "b c"])).toBe("a;b c");
    expect(formatTags([])).toBe("");
  });
});
