/**
 * Innerer Zufallsstrom: schützt einzelne Werte (Passwörter usw.) INNERHALB der XML-Datenbank.
 *
 * Alle geschützten Werte einer Datei werden in Dokumentreihenfolge nacheinander mit EINEM
 * fortlaufenden Schlüsselstrom per XOR verschlüsselt. Deshalb ist `process` zustandsbehaftet:
 * Der zweite Aufruf setzt den Schlüsselstrom dort fort, wo der erste aufgehört hat – er
 * beginnt NICHT von vorn. Ver- und Entschlüsseln ist dieselbe Operation.
 *
 * Varianten (abgeglichen mit KeePassXC 2.7.6: src/format/KeePass2RandomStream.cpp):
 *   ChaCha20 (Nr. 3, Standard in KDBX 4): h = SHA-512(Schlüssel);
 *            ChaCha20-Schlüssel = h[0..32), Nonce = h[32..44), Blockzähler ab 0.
 *   Salsa20  (Nr. 2, KDBX 3 und ältere KeePass-Versionen): Schlüssel = SHA-256(Schlüssel),
 *            fester 8-Byte-Nonce E8 30 09 4B 97 20 5D 2A.
 *
 * Bewusst SYNCHRON (XML-Parser rufen `process` mitten im Parsen auf). Deshalb hier die
 * synchronen Hashes von @noble/hashes statt WebCrypto.
 */
import { chacha20 } from "@noble/ciphers/chacha.js";
import { salsa20 } from "@noble/ciphers/salsa.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { KdbxError, type CreateInnerStream, type InnerStreamCipher, type InnerStreamId } from "../contracts";
import { SALSA20_INNER_STREAM_NONCE } from "./constants";
import { randomBytes } from "./crypto";

/** Länge eines neuen Schlüssels für den inneren Strom (wie KeePassXC). */
const INNER_STREAM_KEY_LENGTH = 64;
/** ChaCha20 und Salsa20 erzeugen den Schlüsselstrom in Blöcken zu 64 Byte. */
const STREAM_BLOCK_SIZE = 64;

/** Erzeugt `blocks` Blöcke Schlüsselstrom, beginnend bei Blocknummer `counter`. */
type KeystreamGenerator = (blocks: number, counter: number) => Uint8Array;

/**
 * Hält den Zustand des Stroms: die Nummer des nächsten Blocks und die noch nicht
 * verbrauchten Bytes des zuletzt erzeugten Blocks.
 */
class XorKeystream implements InnerStreamCipher {
  private nextBlock = 0;
  private leftover: Uint8Array = new Uint8Array(0);

  constructor(private readonly generate: KeystreamGenerator) {}

  process(data: Uint8Array): Uint8Array {
    const keystream = this.take(data.length);
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ keystream[i]!;
    return out;
  }

  /** Liefert die nächsten `length` Bytes des Schlüsselstroms. */
  private take(length: number): Uint8Array {
    const result = new Uint8Array(length);
    const fromLeftover = Math.min(length, this.leftover.length);
    result.set(this.leftover.subarray(0, fromLeftover));
    this.leftover = this.leftover.subarray(fromLeftover);

    const missing = length - fromLeftover;
    if (missing > 0) {
      const blocks = Math.ceil(missing / STREAM_BLOCK_SIZE);
      const fresh = this.generate(blocks, this.nextBlock);
      this.nextBlock += blocks;
      result.set(fresh.subarray(0, missing), fromLeftover);
      this.leftover = fresh.subarray(missing);
    }
    return result;
  }
}

/** Erzeugt den inneren Zufallsstrom für die Kennung aus dem inneren Header. */
export const createInnerStream: CreateInnerStream = (id: InnerStreamId, key: Uint8Array): InnerStreamCipher => {
  if (id === "chacha20") {
    const hash = sha512(key);
    const streamKey = hash.slice(0, 32);
    const nonce = hash.slice(32, 44);
    hash.fill(0);
    // Schlüsselstrom = Verschlüsselung von Nullbytes.
    return new XorKeystream((blocks, counter) =>
      chacha20(streamKey, nonce, new Uint8Array(blocks * STREAM_BLOCK_SIZE), undefined, counter),
    );
  }
  if (id === "salsa20") {
    const streamKey = sha256(key);
    return new XorKeystream((blocks, counter) =>
      salsa20(streamKey, SALSA20_INNER_STREAM_NONCE, new Uint8Array(blocks * STREAM_BLOCK_SIZE), undefined, counter),
    );
  }
  throw new KdbxError("UnsupportedInnerStream", `Innerer Zufallsstrom "${String(id)}" wird nicht unterstützt.`);
};

/** Neuer zufälliger Schlüssel für den inneren Strom (64 Byte), für jedes Speichern neu. */
export function newInnerStreamKey(): Uint8Array {
  return randomBytes(INNER_STREAM_KEY_LENGTH);
}
