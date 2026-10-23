/**
 * HMAC-Blockstrom von KDBX 4: Der verschlüsselte Inhalt wird in Blöcke zerlegt, und jeder
 * Block bekommt eine eigene Prüfsumme (HMAC-SHA-256). So fällt jede Veränderung,
 * Vertauschung oder Kürzung der Datei auf, BEVOR irgendetwas entschlüsselt wird.
 *
 * Aufbau, wiederholt bis zu einem Block der Größe 0:
 *   32 Byte  HMAC-SHA-256( uint64 LE Blocknummer || int32 LE Größe || Daten )
 *    4 Byte  int32 LE Größe
 *    n Byte  Daten
 *
 * Der HMAC-Schlüssel ist für jeden Block ein anderer:
 *   Blockschlüssel(i) = SHA-512( uint64 LE i || HMAC-Basisschlüssel )
 * Weil die Blocknummer im Schlüssel UND im HMAC steckt, lassen sich Blöcke nicht vertauschen.
 * Der Header benutzt den Blockschlüssel mit der Nummer 2^64-1.
 *
 * Abgeglichen mit KeePassXC 2.7.6: src/streams/HmacBlockStream.cpp.
 */
import { KdbxError } from "../contracts";
import { ByteReader, ByteWriter, bytesEqual, concatByteArrays, corrupt, u64le, wipe } from "./bytes";
import { HMAC_BLOCK_SIZE, MAX_PAYLOAD_BYTES } from "./constants";
import { hmacSha256, sha512 } from "./crypto";

/** Blocknummer, mit der der Header-HMAC berechnet wird (UINT64_MAX). */
export const HEADER_HMAC_BLOCK_INDEX = 0xffff_ffff_ffff_ffffn;

/** HMAC-Schlüssel für Block `index`. */
export async function blockHmacKey(index: bigint, hmacBaseKey: Uint8Array): Promise<Uint8Array> {
  return sha512(u64le(index), hmacBaseKey);
}

/** HMAC eines Blocks; `sizeBytes` ist die int32-LE-Größenangabe genau wie in der Datei. */
async function blockHmac(index: bigint, sizeBytes: Uint8Array, data: Uint8Array, hmacBaseKey: Uint8Array) {
  const key = await blockHmacKey(index, hmacBaseKey);
  try {
    return await hmacSha256(key, u64le(index), sizeBytes, data);
  } finally {
    wipe(key); // Blockschlüssel nach Gebrauch löschen (Sicherheitsaudit crypto-5)
  }
}

/**
 * Liest den Blockstrom, prüft jeden Block-HMAC und liefert die Daten aller Blöcke
 * aneinandergehängt (= der verschlüsselte Inhalt). Wirft KdbxError("Corrupt"), wenn ein
 * HMAC nicht passt, eine Größe ungültig ist oder der abschließende leere Block fehlt
 * (abgeschnittene Datei). Bytes nach dem Endblock werden – wie bei KeePassXC – ignoriert.
 * Mehr als `maxBytes` Inhalt: KdbxError("TooLarge"), die Blöcke bis dahin sind ja echt.
 */
export async function readHmacBlockStream(
  stream: Uint8Array,
  hmacBaseKey: Uint8Array,
  maxBytes = MAX_PAYLOAD_BYTES,
): Promise<Uint8Array> {
  const reader = new ByteReader(stream, "HMAC-Blockstrom");
  const blocks: Uint8Array[] = [];
  let total = 0;

  for (let index = 0n; ; index++) {
    if (reader.remaining === 0) corrupt("HMAC-Blockstrom: Der abschließende Block fehlt (Datei abgeschnitten?).");
    const storedHmac = reader.readView(32, `HMAC von Block ${index}`);
    const sizeBytes = reader.readView(4, `Größe von Block ${index}`);
    const size = new DataView(sizeBytes.buffer, sizeBytes.byteOffset, 4).getInt32(0, true);
    if (size < 0) corrupt(`HMAC-Blockstrom: Block ${index} hat eine negative Größe.`);
    const data = reader.readView(size, `Daten von Block ${index}`);

    const expected = await blockHmac(index, sizeBytes, data, hmacBaseKey);
    if (!bytesEqual(expected, storedHmac)) {
      corrupt(`HMAC-Blockstrom: Block ${index} ist beschädigt (HMAC passt nicht).`);
    }
    if (size === 0) break;

    total += size;
    if (total > maxBytes) {
      throw new KdbxError("TooLarge", `HMAC-Blockstrom: Inhalt zu groß für Ownwarden (mehr als ${sizeText(maxBytes)}).`);
    }
    blocks.push(data);
  }
  return concatByteArrays(blocks);
}

/** Größe für Meldungen: "256 MiB" oder "1000 Byte". */
function sizeText(bytes: number): string {
  return bytes % (1024 * 1024) === 0 ? `${bytes / (1024 * 1024)} MiB` : `${bytes} Byte`;
}

/**
 * Schreibt `data` als HMAC-Blockstrom: Blöcke zu `blockSize` Byte (Standard 1 MiB wie
 * KeePassXC), danach ein leerer Endblock.
 */
export async function writeHmacBlockStream(
  data: Uint8Array,
  hmacBaseKey: Uint8Array,
  blockSize = HMAC_BLOCK_SIZE,
): Promise<Uint8Array> {
  if (!Number.isInteger(blockSize) || blockSize <= 0) throw new RangeError(`Ungültige Blockgröße ${blockSize}.`);
  const writer = new ByteWriter();
  let index = 0n;
  for (let offset = 0; offset < data.length; offset += blockSize, index++) {
    await writeBlock(writer, index, data.subarray(offset, offset + blockSize), hmacBaseKey);
  }
  await writeBlock(writer, index, new Uint8Array(0), hmacBaseKey);
  return writer.toBytes();
}

async function writeBlock(writer: ByteWriter, index: bigint, block: Uint8Array, hmacBaseKey: Uint8Array) {
  const sizeBytes = new ByteWriter().writeI32(block.length).toBytes();
  writer.writeBytes(await blockHmac(index, sizeBytes, block, hmacBaseKey));
  writer.writeBytes(sizeBytes);
  writer.writeBytes(block);
}
