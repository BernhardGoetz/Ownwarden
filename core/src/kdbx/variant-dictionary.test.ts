import { describe, expect, it } from "vitest";
import { ByteWriter, toHex, utf8Encode } from "./bytes";
import {
  getBytes,
  getInteger,
  parseVariantDictionary,
  serializeVariantDictionary,
  type VariantDictionary,
} from "./variant-dictionary";

/** Baut ein VariantDictionary von Hand (unabhängig vom Serializer). */
function rawDict(version: number, items: { type: number; name: string; value: Uint8Array }[], end = true) {
  const w = new ByteWriter().writeU16(version);
  for (const item of items) {
    const name = utf8Encode(item.name);
    w.writeU8(item.type).writeU32(name.length).writeBytes(name).writeU32(item.value.length).writeBytes(item.value);
  }
  if (end) w.writeU8(0);
  return w.toBytes();
}

const corrupt = expect.objectContaining({ code: "Corrupt" });

describe("VariantDictionary", () => {
  it("überträgt alle Typen verlustfrei und in Reihenfolge", () => {
    const dict: VariantDictionary = new Map([
      ["u32", { type: "uint32", value: 0xffffffff }],
      ["u64", { type: "uint64", value: 0xffff_ffff_ffff_ffffn }],
      ["bool", { type: "bool", value: true }],
      ["i32", { type: "int32", value: -5 }],
      ["i64", { type: "int64", value: -(2n ** 63n) }],
      ["text", { type: "string", value: "Grüße" }],
      ["bytes", { type: "bytes", value: Uint8Array.of(1, 2, 3) }],
      ["leer", { type: "bytes", value: new Uint8Array(0) }],
    ]);
    const parsed = parseVariantDictionary(serializeVariantDictionary(dict));
    expect([...parsed.keys()]).toEqual([...dict.keys()]);
    expect(parsed).toEqual(dict);
  });

  it("schreibt genau das Format von KeePassXC", () => {
    const bytes = serializeVariantDictionary(new Map([["R", { type: "uint64", value: 1000n }]]));
    // Version 0x0100, Typ 0x05, Namenslänge 1, "R", Wertlänge 8, 1000 LE, Ende 0x00
    expect(toHex(bytes)).toBe("0001" + "05" + "01000000" + "52" + "08000000" + "e803000000000000" + "00");
  });

  it("akzeptiert eine höhere Nebenversion, lehnt eine höhere Hauptversion ab", () => {
    expect(parseVariantDictionary(rawDict(0x01ff, [])).size).toBe(0);
    expect(() => parseVariantDictionary(rawDict(0x0200, []))).toThrow(corrupt);
  });

  it("erkennt abgeschnittene und fehlerhafte Daten", () => {
    const good = rawDict(0x0100, [{ type: 0x04, name: "P", value: Uint8Array.of(2, 0, 0, 0) }]);
    for (let cut = 0; cut < good.length; cut++) {
      expect(() => parseVariantDictionary(good.subarray(0, cut)), `abgeschnitten bei ${cut}`).toThrow(corrupt);
    }
    // falsche Wertlängen für Zahlen und Bool
    expect(() => parseVariantDictionary(rawDict(0x0100, [{ type: 0x04, name: "P", value: new Uint8Array(8) }]))).toThrow(corrupt);
    expect(() => parseVariantDictionary(rawDict(0x0100, [{ type: 0x05, name: "M", value: new Uint8Array(4) }]))).toThrow(corrupt);
    expect(() => parseVariantDictionary(rawDict(0x0100, [{ type: 0x08, name: "B", value: new Uint8Array(2) }]))).toThrow(corrupt);
    // unbekannter Typ
    expect(() => parseVariantDictionary(rawDict(0x0100, [{ type: 0x11, name: "D", value: new Uint8Array(8) }]))).toThrow(corrupt);
    // Länge größer als die Daten
    const lying = rawDict(0x0100, [{ type: 0x42, name: "S", value: Uint8Array.of(1) }]);
    lying[2 + 1 + 4 + 1] = 0xff; // Wertlänge auf 255 setzen
    expect(() => parseVariantDictionary(lying)).toThrow(corrupt);
  });

  it("bei doppelten Namen gewinnt der letzte (wie KeePassXC)", () => {
    const dict = parseVariantDictionary(
      rawDict(0x0100, [
        { type: 0x04, name: "P", value: Uint8Array.of(1, 0, 0, 0) },
        { type: 0x04, name: "P", value: Uint8Array.of(2, 0, 0, 0) },
      ]),
    );
    expect(dict.get("P")).toEqual({ type: "uint32", value: 2 });
  });

  it("getInteger nimmt jeden Ganzzahltyp, getBytes nur Byte-Arrays", () => {
    const dict = parseVariantDictionary(
      serializeVariantDictionary(
        new Map([
          ["a", { type: "uint32", value: 7 }],
          ["b", { type: "int64", value: 8n }],
          ["s", { type: "string", value: "x" }],
          ["y", { type: "bytes", value: Uint8Array.of(5) }],
        ]),
      ),
    );
    expect(getInteger(dict, "a")).toBe(7n);
    expect(getInteger(dict, "b")).toBe(8n);
    expect(getInteger(dict, "fehlt")).toBeUndefined();
    expect(() => getInteger(dict, "s")).toThrow(corrupt);
    expect([...getBytes(dict, "y")!]).toEqual([5]);
    expect(() => getBytes(dict, "a")).toThrow(corrupt);
  });
});
