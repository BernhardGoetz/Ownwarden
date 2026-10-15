import { describe, expect, it } from "vitest";
import { KdbxError } from "../contracts";
import {
  ByteReader,
  ByteWriter,
  asBufferSource,
  bytesEqual,
  bytesToUuid,
  concatBytes,
  toHex,
  u32le,
  u64le,
  utf8Decode,
  utf8Encode,
  uuidToBytes,
} from "./bytes";
import { CIPHER_UUID, KDBX_SIGNATURE_1, KDBX_SIGNATURE_2 } from "./constants";

function expectCorrupt(fn: () => unknown): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(KdbxError);
    expect((error as KdbxError).code).toBe("Corrupt");
    return;
  }
  throw new Error("Es wurde kein Fehler geworfen.");
}

describe("ByteWriter/ByteReader", () => {
  it("schreibt und liest alle Ganzzahltypen Little Endian", () => {
    const bytes = new ByteWriter()
      .writeU8(0xab)
      .writeU16(0x1234)
      .writeU32(0xdeadbeef)
      .writeI32(-2)
      .writeU64(0x0102030405060708n)
      .writeI64(-3n)
      .writeBytes(Uint8Array.of(9, 9))
      .toBytes();
    expect(toHex(bytes.subarray(0, 7))).toBe("ab3412efbeadde");

    const reader = new ByteReader(bytes, "Test");
    expect(reader.readU8()).toBe(0xab);
    expect(reader.readU16()).toBe(0x1234);
    expect(reader.readU32()).toBe(0xdeadbeef);
    expect(reader.readI32()).toBe(-2);
    expect(reader.readU64()).toBe(0x0102030405060708n);
    expect(reader.readI64()).toBe(-3n);
    expect(reader.remaining).toBe(2);
    expect([...reader.readRest()]).toEqual([9, 9]);
    expect(reader.remaining).toBe(0);
  });

  it("wirft Corrupt statt über das Pufferende zu lesen", () => {
    const reader = new ByteReader(Uint8Array.of(1, 2, 3), "Test");
    expectCorrupt(() => reader.readU32());
    expect(reader.offset).toBe(0); // fehlgeschlagener Lesezugriff verschiebt nichts
    expectCorrupt(() => reader.readBytes(4));
    expectCorrupt(() => reader.readView(-1));
    expectCorrupt(() => reader.readBytes(1.5));
    reader.readBytes(3);
    expectCorrupt(() => reader.readU8());
  });

  it("readBytes kopiert, readView nicht", () => {
    const data = Uint8Array.of(1, 2, 3, 4);
    const copy = new ByteReader(data, "Test").readBytes(2);
    const view = new ByteReader(data, "Test").readView(2);
    data[0] = 99;
    expect(copy[0]).toBe(1);
    expect(view[0]).toBe(99);
  });

  it("liest korrekt aus Teilansichten (byteOffset != 0)", () => {
    const backing = Uint8Array.of(0xff, 0x01, 0x00, 0x00, 0x00);
    expect(new ByteReader(backing.subarray(1), "Test").readU32()).toBe(1);
  });

  it("lehnt Werte außerhalb des Wertebereichs ab statt sie abzuschneiden", () => {
    const w = new ByteWriter();
    expect(() => w.writeU8(256)).toThrow(RangeError);
    expect(() => w.writeU16(-1)).toThrow(RangeError);
    expect(() => w.writeU32(2 ** 32)).toThrow(RangeError);
    expect(() => w.writeI32(2 ** 31)).toThrow(RangeError);
    expect(() => w.writeU64(-1n)).toThrow(RangeError);
    expect(() => w.writeI64(2n ** 63n)).toThrow(RangeError);
    expect(() => u32le(1.5)).toThrow(RangeError);
    expect(() => u64le(2n ** 64n)).toThrow(RangeError);
    expect(w.byteLength).toBe(0);
  });
});

describe("Hilfsfunktionen", () => {
  it("concatBytes und bytesEqual", () => {
    expect([...concatBytes(Uint8Array.of(1), new Uint8Array(0), Uint8Array.of(2, 3))]).toEqual([1, 2, 3]);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1))).toBe(false);
  });

  it("UTF-8 hin und zurück", () => {
    expect(utf8Decode(utf8Encode("Grüße 🔑"))).toBe("Grüße 🔑");
  });

  it("asBufferSource liefert dieselben Bytes", () => {
    const view = Uint8Array.of(0, 1, 2, 3).subarray(1, 3);
    expect([...asBufferSource(view)]).toEqual([1, 2]);
  });
});

describe("Konstanten gegen echte KeePassXC-Bytes", () => {
  it("Signaturen ergeben die Bytes am Anfang jeder KDBX-Datei", () => {
    const start = new ByteWriter().writeU32(KDBX_SIGNATURE_1).writeU32(KDBX_SIGNATURE_2).toBytes();
    expect(toHex(start)).toBe("03d9a29a67fb4bb5");
  });

  it("UUIDs stehen in der Datei in Schreibreihenfolge (RFC 4122)", () => {
    // So steht AES-256 im Header einer von KeePassXC 2.7.6 erzeugten Datei.
    const fromFile = Uint8Array.from([
      0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
    ]);
    expect(bytesToUuid(fromFile)).toBe(CIPHER_UUID.aes256);
    expect([...uuidToBytes(CIPHER_UUID.aes256)]).toEqual([...fromFile]);
    expect(() => uuidToBytes("kein-uuid")).toThrow();
  });
});
