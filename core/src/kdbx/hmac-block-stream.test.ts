import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ByteWriter, u64le } from "./bytes";
import { HEADER_HMAC_BLOCK_INDEX, blockHmacKey, readHmacBlockStream, writeHmacBlockStream } from "./hmac-block-stream";

const corrupt = expect.objectContaining({ code: "Corrupt" });
const BASE_KEY = Uint8Array.from({ length: 64 }, (_, i) => i * 3);
const DATA = Uint8Array.from({ length: 2500 }, (_, i) => (i * 7) & 0xff);

/** Positionen der Blöcke in einem Strom (zum gezielten Manipulieren). */
function blockOffsets(stream: Uint8Array): { start: number; size: number }[] {
  const blocks: { start: number; size: number }[] = [];
  let pos = 0;
  while (pos < stream.length) {
    const size = new DataView(stream.buffer, stream.byteOffset + pos + 32, 4).getInt32(0, true);
    blocks.push({ start: pos, size });
    pos += 36 + size;
  }
  return blocks;
}

describe("HMAC-Blockstrom", () => {
  it("Blockschlüssel = SHA-512(uint64 LE Index || Basisschlüssel)", async () => {
    for (const index of [0n, 1n, HEADER_HMAC_BLOCK_INDEX]) {
      const expected = createHash("sha512").update(u64le(index)).update(BASE_KEY).digest();
      expect(await blockHmacKey(index, BASE_KEY)).toEqual(new Uint8Array(expected));
    }
  });

  it("schreibt das Format wie KeePassXC (unabhängig nachgerechnet)", async () => {
    const stream = await writeHmacBlockStream(DATA, BASE_KEY, 1000);
    const blocks = blockOffsets(stream);
    expect(blocks.map((b) => b.size)).toEqual([1000, 1000, 500, 0]);

    // HMAC des ersten Blocks mit Node-Krypto nachrechnen
    const key = createHash("sha512").update(u64le(0n)).update(BASE_KEY).digest();
    const size = new ByteWriter().writeI32(1000).toBytes();
    const hmac = createHmac("sha256", key).update(u64le(0n)).update(size).update(DATA.subarray(0, 1000)).digest();
    expect(stream.subarray(0, 32)).toEqual(new Uint8Array(hmac));
  });

  it.each([1, 7, 1000, 2500, 4096])("Rundreise mit Blockgröße %i", async (blockSize) => {
    const stream = await writeHmacBlockStream(DATA, BASE_KEY, blockSize);
    expect(await readHmacBlockStream(stream, BASE_KEY)).toEqual(DATA);
  });

  it("leere Daten: nur der Endblock", async () => {
    const stream = await writeHmacBlockStream(new Uint8Array(0), BASE_KEY);
    expect(stream.length).toBe(36);
    expect(await readHmacBlockStream(stream, BASE_KEY)).toEqual(new Uint8Array(0));
  });

  it("erkennt jedes veränderte Byte", async () => {
    const stream = await writeHmacBlockStream(DATA.subarray(0, 100), BASE_KEY, 40);
    for (let i = 0; i < stream.length; i++) {
      const tampered = stream.slice();
      tampered[i]! ^= 0x01;
      await expect(readHmacBlockStream(tampered, BASE_KEY), `Byte ${i}`).rejects.toThrow(corrupt);
    }
  });

  it("erkennt vertauschte Blöcke", async () => {
    const stream = await writeHmacBlockStream(DATA.subarray(0, 80), BASE_KEY, 40);
    const [first, second] = blockOffsets(stream);
    const swapped = new Uint8Array(stream.length);
    swapped.set(stream.subarray(second!.start, second!.start + 76), 0);
    swapped.set(stream.subarray(first!.start, first!.start + 76), 76);
    swapped.set(stream.subarray(152), 152);
    await expect(readHmacBlockStream(swapped, BASE_KEY)).rejects.toThrow(corrupt);
  });

  it("erkennt abgeschnittene Ströme (auch genau an einer Blockgrenze)", async () => {
    const stream = await writeHmacBlockStream(DATA.subarray(0, 80), BASE_KEY, 40);
    await expect(readHmacBlockStream(stream.subarray(0, 76), BASE_KEY)).rejects.toThrow(corrupt); // Endblock fehlt
    await expect(readHmacBlockStream(stream.subarray(0, 100), BASE_KEY)).rejects.toThrow(corrupt);
    await expect(readHmacBlockStream(new Uint8Array(0), BASE_KEY)).rejects.toThrow(corrupt);
  });

  it("erkennt negative oder zu große Blockgrößen", async () => {
    const stream = await writeHmacBlockStream(DATA.subarray(0, 10), BASE_KEY);
    const negative = stream.slice();
    new DataView(negative.buffer).setInt32(32, -1, true);
    await expect(readHmacBlockStream(negative, BASE_KEY)).rejects.toThrow(corrupt);
    const huge = stream.slice();
    new DataView(huge.buffer).setInt32(32, 0x7fffffff, true);
    await expect(readHmacBlockStream(huge, BASE_KEY)).rejects.toThrow(corrupt);
  });

  it("falscher Schlüssel -> Corrupt", async () => {
    const stream = await writeHmacBlockStream(DATA, BASE_KEY);
    await expect(readHmacBlockStream(stream, new Uint8Array(64))).rejects.toThrow(corrupt);
  });

  it("Bytes nach dem Endblock werden ignoriert (wie KeePassXC)", async () => {
    const stream = await writeHmacBlockStream(DATA, BASE_KEY);
    const padded = new Uint8Array([...stream, 1, 2, 3]);
    expect(await readHmacBlockStream(padded, BASE_KEY)).toEqual(DATA);
  });
});
