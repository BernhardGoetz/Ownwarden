import { describe, expect, it } from "vitest";
import { ByteWriter, toHex, uuidToBytes } from "./bytes";
import { CIPHER_UUID, HeaderFieldId, MAX_OUTER_HEADER_BYTES } from "./constants";
import { decryptContainer } from "./container";
import { outerHeaderLength, parseOuterHeader, serializeOuterHeader, type OuterHeader } from "./header";
import { serializeKdfParameters } from "./kdf";
import { serializeVariantDictionary } from "./variant-dictionary";

const code = (c: string) => expect.objectContaining({ code: c });

function sampleHeader(overrides: Partial<OuterHeader> = {}): OuterHeader {
  return {
    versionMinor: 0,
    cipher: "aes256",
    compression: true,
    masterSeed: new Uint8Array(32).fill(1),
    encryptionIv: new Uint8Array(16).fill(2),
    kdf: { type: "aes", seed: new Uint8Array(32).fill(3), rounds: 1000 },
    ...overrides,
  };
}

/** Baut einen Header von Hand aus (ID, Daten)-Paaren – auch fehlerhafte. */
function rawHeader(fields: [number, Uint8Array][], version = 0x00040000): Uint8Array {
  const w = new ByteWriter().writeU32(0x9aa2d903).writeU32(0xb54bfb67).writeU32(version);
  for (const [id, data] of fields) w.writeU8(id).writeU32(data.length).writeBytes(data);
  return w.toBytes();
}

const u32 = (v: number) => new ByteWriter().writeU32(v).toBytes();
const END: [number, Uint8Array] = [HeaderFieldId.EndOfHeader, Uint8Array.of(13, 10, 13, 10)];

function validFields(): [number, Uint8Array][] {
  return [
    [HeaderFieldId.CipherId, uuidToBytes(CIPHER_UUID.aes256)],
    [HeaderFieldId.CompressionFlags, u32(1)],
    [HeaderFieldId.MasterSeed, new Uint8Array(32)],
    [HeaderFieldId.EncryptionIv, new Uint8Array(16)],
    [HeaderFieldId.KdfParameters, serializeKdfParameters({ type: "aes", seed: new Uint8Array(32), rounds: 1 })],
  ];
}

describe("Äußerer Header", () => {
  it("Rundreise; headerBytes reicht genau bis EndOfHeader", () => {
    const header = sampleHeader({ publicCustomData: serializeVariantDictionary(new Map([["x", { type: "string", value: "y" }]])) });
    const bytes = serializeOuterHeader(header);
    const file = new Uint8Array([...bytes, 0xaa, 0xbb]); // danach folgt in der Datei der Rest
    const parsed = parseOuterHeader(file);
    expect(parsed.header).toEqual(header);
    expect(parsed.headerBytes).toEqual(bytes);
  });

  it("schreibt Felder in KeePassXC-Reihenfolge mit \\r\\n\\r\\n am Ende", () => {
    const bytes = serializeOuterHeader(sampleHeader({ versionMinor: 1, cipher: "chacha20", encryptionIv: new Uint8Array(12) }));
    expect(toHex(bytes.subarray(0, 12))).toBe("03d9a29a67fb4bb5" + "01000400");
    const ids: number[] = [];
    let pos = 12;
    for (;;) {
      const id = bytes[pos]!;
      const len = new DataView(bytes.buffer, bytes.byteOffset + pos + 1, 4).getUint32(0, true);
      ids.push(id);
      pos += 5 + len;
      if (id === 0) break;
    }
    expect(ids).toEqual([2, 3, 4, 7, 11, 0]);
    expect(toHex(bytes.subarray(-4))).toBe("0d0a0d0a");
    expect(pos).toBe(bytes.length);
  });

  it("erkennt Nicht-KDBX-Dateien", () => {
    expect(() => parseOuterHeader(new Uint8Array(0))).toThrow(code("BadSignature"));
    expect(() => parseOuterHeader(new Uint8Array(100))).toThrow(code("BadSignature"));
    // KeePass-1.x-Signatur (KDB)
    const kdb = new ByteWriter().writeU32(0x9aa2d903).writeU32(0xb54bfb65).writeU32(0).toBytes();
    expect(() => parseOuterHeader(kdb)).toThrow(code("BadSignature"));
  });

  it("lehnt andere Versionen als 4.0 und 4.1 ab", () => {
    for (const version of [0x00030001, 0x00040002, 0x00050000, 0x00020000]) {
      expect(() => parseOuterHeader(rawHeader([...validFields(), END], version)), version.toString(16)).toThrow(
        code("UnsupportedVersion"),
      );
    }
    expect(parseOuterHeader(rawHeader([...validFields(), END], 0x00040001)).header.versionMinor).toBe(1);
  });

  it("lehnt Twofish, AES-128 und unbekannte Verfahren ab", () => {
    for (const uuid of [CIPHER_UUID.twofish, CIPHER_UUID.aes128, "00112233-4455-6677-8899-aabbccddeeff"]) {
      const fields = validFields();
      fields[0] = [HeaderFieldId.CipherId, uuidToBytes(uuid)];
      expect(() => parseOuterHeader(rawHeader([...fields, END]))).toThrow(code("UnsupportedCipher"));
    }
  });

  it("erkennt abgeschnittene Header an jeder Stelle", () => {
    const good = rawHeader([...validFields(), END]);
    expect(parseOuterHeader(good).headerBytes.length).toBe(good.length);
    for (let cut = 12; cut < good.length; cut++) {
      expect(() => parseOuterHeader(good.subarray(0, cut)), `abgeschnitten bei ${cut}`).toThrow(code("Corrupt"));
    }
  });

  it("erkennt fehlende Pflichtfelder und falsche Längen", () => {
    const without = (id: number) => rawHeader([...validFields().filter(([f]) => f !== id), END]);
    expect(() => parseOuterHeader(without(HeaderFieldId.CipherId))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(without(HeaderFieldId.MasterSeed))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(without(HeaderFieldId.EncryptionIv))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(without(HeaderFieldId.KdfParameters))).toThrow(code("Corrupt"));

    const withField = (id: number, data: Uint8Array) =>
      rawHeader([...validFields().map(([f, d]) => [f, f === id ? data : d] as [number, Uint8Array]), END]);
    expect(() => parseOuterHeader(withField(HeaderFieldId.MasterSeed, new Uint8Array(16)))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(withField(HeaderFieldId.EncryptionIv, new Uint8Array(12)))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(withField(HeaderFieldId.CipherId, new Uint8Array(15)))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(withField(HeaderFieldId.CompressionFlags, u32(2)))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(withField(HeaderFieldId.CompressionFlags, new Uint8Array(1)))).toThrow(code("Corrupt"));
    expect(() => parseOuterHeader(withField(HeaderFieldId.KdfParameters, Uint8Array.of(0, 1)))).toThrow(code("Corrupt"));
  });

  it("lehnt KDBX-3-Felder ab und ignoriert unbekannte Felder", () => {
    expect(() => parseOuterHeader(rawHeader([...validFields(), [HeaderFieldId.TransformRounds, new Uint8Array(8)], END]))).toThrow(
      code("Corrupt"),
    );
    const withUnknown = rawHeader([[HeaderFieldId.Comment, Uint8Array.of(1, 2)], [99, new Uint8Array(3)], ...validFields(), END]);
    expect(parseOuterHeader(withUnknown).header.cipher).toBe("aes256");
  });

  it("fehlt CompressionFlags, gilt GZip (wie KeePassXC)", () => {
    const fields = validFields().filter(([f]) => f !== HeaderFieldId.CompressionFlags);
    expect(parseOuterHeader(rawHeader([...fields, END])).header.compression).toBe(true);
  });

  it("prüft PublicCustomData beim Lesen und Schreiben", () => {
    expect(() => parseOuterHeader(rawHeader([...validFields(), [HeaderFieldId.PublicCustomData, Uint8Array.of(0, 1, 9)], END]))).toThrow(
      code("Corrupt"),
    );
    expect(() => serializeOuterHeader(sampleHeader({ publicCustomData: Uint8Array.of(1, 2, 3) }))).toThrow(code("Corrupt"));
  });

  it("Namen aus Feld 11 und 12 gelangen nicht roh in die Fehlermeldung (Sicherheitsaudit leak-1)", () => {
    // Nachbau des Angriffs aus dem Audit: Terminal leeren, Phishing-Text, HTML, Rest verbergen
    const evil = "\u001b[2J\u001b[H\nMagentaCLOUD: Bitte Master-Passwort bestätigen\n<img src=x onerror=alert(1)>\u001b[8m";
    const name = new TextEncoder().encode(evil);
    const dict = new ByteWriter().writeU16(0x0100).writeU8(0x04).writeU32(name.length).writeBytes(name).writeU32(3).writeBytes(new Uint8Array(3)).writeU8(0).toBytes();
    for (const id of [HeaderFieldId.KdfParameters, HeaderFieldId.PublicCustomData]) {
      const fields = validFields().filter(([f]) => f !== id);
      let message = "";
      try {
        parseOuterHeader(rawHeader([...fields, [id, dict], END]));
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/^VariantDictionary: Eintrag 0/);
      expect(message).not.toMatch(/[\u0000-\u001f]/);
    }
  });

  it("lehnt einen äußeren Header über 64 KiB ab, ohne ihn zu Ende zu lesen (Sicherheitsaudit dos-1, Nachprüfung)", () => {
    expect(MAX_OUTER_HEADER_BYTES).toBe(64 * 1024);
    const base = rawHeader([...validFields(), END]).length;
    const withCustomData = (headerLength: number) => {
      // Ein Eintrag "S" mit Byte-Array: 13 Byte Verwaltung plus Wert
      const dictLength = headerLength - base - 5;
      const dict = serializeVariantDictionary(new Map([["S", { type: "bytes", value: new Uint8Array(dictLength - 13) }]]));
      return rawHeader([...validFields(), [HeaderFieldId.PublicCustomData, dict], END]);
    };
    const atLimit = withCustomData(MAX_OUTER_HEADER_BYTES);
    expect(atLimit.length).toBe(MAX_OUTER_HEADER_BYTES);
    expect(outerHeaderLength(atLimit)).toBe(MAX_OUTER_HEADER_BYTES);
    expect(parseOuterHeader(atLimit).header.publicCustomData).toHaveLength(MAX_OUTER_HEADER_BYTES - base - 5);
    const overLimit = withCustomData(MAX_OUTER_HEADER_BYTES + 1);
    for (const read of [outerHeaderLength, parseOuterHeader]) {
      expect(() => read(overLimit)).toThrow(code("Corrupt"));
      expect(() => read(overLimit)).toThrow("Äußerer Header: unplausibel lang (mehr als 64 KiB; echte Dateien haben wenige hundert Byte).");
    }
    // Millionen leerer Kommentarfelder (15 MiB): Abbruch nach 64 KiB statt alle Felder zu lesen
    const start = rawHeader(validFields());
    const end = rawHeader([END]).subarray(12);
    const manyFields = new Uint8Array(start.length + 3_000_000 * 5 + end.length);
    manyFields.set(start);
    for (let i = start.length; i < manyFields.length - end.length; i += 5) manyFields[i] = HeaderFieldId.Comment;
    manyFields.set(end, manyFields.length - end.length);
    for (const read of [outerHeaderLength, parseOuterHeader]) {
      expect(() => read(manyFields)).toThrow(/unplausibel lang/);
    }
  });

  it("decryptContainer prüft die Header-Länge vor der Header-SHA-256 (Sicherheitsaudit dos-1, Nachprüfung)", async () => {
    // Nachbau aus der Nachprüfung: öffentliche Zusatzdaten mit Millionen winziger Einträge
    // (1 MiB, ~75 000 Einträge; im Angriff bis 257 MiB, über WebDAV stark komprimiert).
    const dict = new ByteWriter().writeU16(0x0100);
    for (let i = 0; dict.byteLength < 1024 * 1024; i++) {
      const name = i.toString(36);
      dict.writeU8(0x42).writeU32(name.length).writeBytes(new TextEncoder().encode(name)).writeU32(0);
    }
    const header = rawHeader([...validFields(), [HeaderFieldId.PublicCustomData, dict.writeU8(0).toBytes()], END]);
    const file = new Uint8Array(header.length + 64); // SHA-256 und HMAC: Nullen
    file.set(header);
    await expect(decryptContainer(file, { password: "egal" })).rejects.toThrow(code("Corrupt"));
    await expect(decryptContainer(file, { password: "egal" })).rejects.toThrow(/unplausibel lang/);
  });

  it("schreibt keinen äußeren Header, den das Lesen ablehnt (Sicherheitsaudit dos-1, Nachprüfung)", () => {
    const customData = (valueLength: number) =>
      serializeVariantDictionary(new Map([["S", { type: "bytes", value: new Uint8Array(valueLength) }]]));
    expect(() => serializeOuterHeader(sampleHeader({ publicCustomData: customData(MAX_OUTER_HEADER_BYTES - 300) }))).not.toThrow();
    // Das VariantDictionary allein passt, der ganze Header aber nicht mehr
    expect(() => serializeOuterHeader(sampleHeader({ publicCustomData: customData(MAX_OUTER_HEADER_BYTES - 100) }))).toThrow(RangeError);
    expect(() => serializeOuterHeader(sampleHeader({ publicCustomData: customData(MAX_OUTER_HEADER_BYTES - 100) }))).toThrow(/64 KiB/);
  });

  it("schreibt nur unterstützte Einstellungen", () => {
    expect(() => serializeOuterHeader(sampleHeader({ cipher: "twofish" as never }))).toThrow(code("UnsupportedCipher"));
    expect(() => serializeOuterHeader(sampleHeader({ versionMinor: 2 as never }))).toThrow(code("UnsupportedVersion"));
    expect(() => serializeOuterHeader(sampleHeader({ encryptionIv: new Uint8Array(12) }))).toThrow(RangeError);
    expect(() => serializeOuterHeader(sampleHeader({ masterSeed: new Uint8Array(31) }))).toThrow(RangeError);
  });
});
