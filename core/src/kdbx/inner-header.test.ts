import { describe, expect, it } from "vitest";
import { ByteWriter, toHex, utf8Decode, utf8Encode } from "./bytes";
import { MAX_INNER_BINARIES } from "./constants";
import { innerHeaderLength, parseInnerHeader, serializeInnerHeader, type InnerHeader } from "./inner-header";

const code = (c: string) => expect.objectContaining({ code: c });
const KEY = new Uint8Array(64).fill(9);

function raw(fields: [number, Uint8Array][], rest = ""): Uint8Array {
  const w = new ByteWriter();
  for (const [id, data] of fields) w.writeU8(id).writeU32(data.length).writeBytes(data);
  return new Uint8Array([...w.toBytes(), ...utf8Encode(rest)]);
}
const u32 = (v: number) => new ByteWriter().writeU32(v).toBytes();

describe("Innerer Header", () => {
  it("Rundreise mit Anhängen in Pool-Reihenfolge; Rest = XML", () => {
    const header: InnerHeader = {
      innerStreamId: "chacha20",
      innerStreamKey: KEY,
      binaries: [
        { data: utf8Encode("erster"), protected: true },
        { data: new Uint8Array(0), protected: false },
        { data: Uint8Array.of(0, 255), protected: false },
      ],
    };
    const bytes = new Uint8Array([...serializeInnerHeader(header), ...utf8Encode("<KeePassFile/>")]);
    const parsed = parseInnerHeader(bytes);
    expect(parsed.header).toEqual(header);
    expect(utf8Decode(parsed.xml)).toBe("<KeePassFile/>");
  });

  it("schreibt das Format von KeePassXC", () => {
    const bytes = serializeInnerHeader({
      innerStreamId: "salsa20",
      innerStreamKey: Uint8Array.of(0xaa),
      binaries: [{ data: Uint8Array.of(0x42), protected: true }],
    });
    expect(toHex(bytes)).toBe(
      "01" + "04000000" + "02000000" + // Strom-Nr. 2 = Salsa20
        "02" + "01000000" + "aa" + // Schlüssel
        "03" + "02000000" + "01" + "42" + // Anhang: Flag 0x01 + Daten
        "00" + "00000000", // Ende
    );
  });

  it("liest Salsa20 und ChaCha20, lehnt andere Ströme ab", () => {
    expect(parseInnerHeader(raw([[1, u32(2)], [2, KEY], [0, new Uint8Array(0)]])).header.innerStreamId).toBe("salsa20");
    expect(parseInnerHeader(raw([[1, u32(3)], [2, KEY], [0, new Uint8Array(0)]])).header.innerStreamId).toBe("chacha20");
    for (const id of [0, 1, 4]) {
      expect(() => parseInnerHeader(raw([[1, u32(id)], [2, KEY], [0, new Uint8Array(0)]]))).toThrow(
        code("UnsupportedInnerStream"),
      );
    }
  });

  it("erkennt fehlende und kaputte Felder", () => {
    const end: [number, Uint8Array] = [0, new Uint8Array(0)];
    expect(() => parseInnerHeader(raw([[2, KEY], end]))).toThrow(code("Corrupt")); // Strom-Nr. fehlt
    expect(() => parseInnerHeader(raw([[1, u32(3)], end]))).toThrow(code("Corrupt")); // Schlüssel fehlt
    expect(() => parseInnerHeader(raw([[1, u32(3)], [2, new Uint8Array(0)], end]))).toThrow(code("Corrupt"));
    expect(() => parseInnerHeader(raw([[1, Uint8Array.of(3)], [2, KEY], end]))).toThrow(code("Corrupt"));
    expect(() => parseInnerHeader(raw([[1, u32(3)], [2, KEY], [3, new Uint8Array(0)], end]))).toThrow(code("Corrupt"));
    // Ende fehlt bzw. Länge größer als die Daten
    expect(() => parseInnerHeader(raw([[1, u32(3)], [2, KEY]]))).toThrow(code("Corrupt"));
    const lying = raw([[1, u32(3)], [2, KEY], end]);
    lying[1] = 0xff;
    expect(() => parseInnerHeader(lying)).toThrow(code("Corrupt"));
  });

  it("überspringt unbekannte Felder (wie KeePassXC)", () => {
    const parsed = parseInnerHeader(raw([[1, u32(3)], [7, Uint8Array.of(1, 2)], [2, KEY], [0, new Uint8Array(0)]], "x"));
    expect(parsed.header.innerStreamKey).toEqual(KEY);
    expect(utf8Decode(parsed.xml)).toBe("x");
  });

  it("höchstens 100 000 Anhänge, beim Lesen und beim Schreiben (Sicherheitsaudit crypto-4)", () => {
    // Ein leerer Anhang kostet in der Datei 6 Byte, im Speicher über 200 Byte.
    expect(MAX_INNER_BINARIES).toBe(100_000);
    const fields = (count: number): Uint8Array => {
      const w = new ByteWriter().writeU8(1).writeU32(4).writeU32(3).writeU8(2).writeU32(KEY.length).writeBytes(KEY);
      for (let i = 0; i < count; i++) w.writeU8(3).writeU32(1).writeU8(0);
      return w.writeU8(0).writeU32(0).toBytes();
    };
    expect(parseInnerHeader(fields(MAX_INNER_BINARIES)).header.binaries).toHaveLength(MAX_INNER_BINARIES);
    expect(() => parseInnerHeader(fields(MAX_INNER_BINARIES + 1))).toThrow(code("Corrupt"));
    expect(() => parseInnerHeader(fields(MAX_INNER_BINARIES + 1))).toThrow(/mehr als 100000 Anhänge/);

    const shared = { data: new Uint8Array(0), protected: false };
    const header = (count: number): InnerHeader => ({
      innerStreamId: "chacha20",
      innerStreamKey: KEY,
      binaries: Array.from({ length: count }, () => shared),
    });
    expect(serializeInnerHeader(header(MAX_INNER_BINARIES))).toEqual(fields(MAX_INNER_BINARIES));
    expect(() => serializeInnerHeader(header(MAX_INNER_BINARIES + 1))).toThrow(RangeError);
  });

  it("innerHeaderLength rechnet die Länge aus, ohne zu serialisieren", () => {
    const header: InnerHeader = {
      innerStreamId: "salsa20",
      innerStreamKey: KEY,
      binaries: [
        { data: utf8Encode("erster"), protected: true },
        { data: new Uint8Array(0), protected: false },
      ],
    };
    expect(innerHeaderLength(header)).toBe(serializeInnerHeader(header).length);
    expect(innerHeaderLength({ ...header, binaries: [] })).toBe(serializeInnerHeader({ ...header, binaries: [] }).length);
  });

  it("Anhänge sind Kopien, nicht Sichten auf den Klartext", () => {
    const bytes = raw([[1, u32(3)], [2, KEY], [3, Uint8Array.of(1, 5)], [0, new Uint8Array(0)]]);
    const { header } = parseInnerHeader(bytes);
    bytes.fill(0);
    expect([...header.binaries[0]!.data]).toEqual([5]);
    expect(header.binaries[0]!.protected).toBe(true);
  });
});
