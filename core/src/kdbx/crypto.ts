/**
 * Dünne Hüllen um die Krypto-Bausteine, die der KDBX-Container braucht.
 *
 * Grundsatz: KEINE selbst gebaute Kryptografie. Alles hier ruft nur fertige Bausteine auf:
 *   - WebCrypto (`globalThis.crypto`): Zufall, SHA-256/512, HMAC-SHA-256, AES-256-CBC.
 *     WebCrypto ist im Browser, im Service Worker der Erweiterung und in Node vorhanden.
 *   - @noble/ciphers: ChaCha20, weil WebCrypto kein ChaCha20 kennt.
 *
 * Alle Funktionen sind asynchron, weil WebCrypto asynchron ist. Für den inneren
 * Zufallsstrom (muss synchron sein) gibt es eigene Hashes in inner-stream.ts.
 */
import { chacha20 } from "@noble/ciphers/chacha.js";
import { KdbxError } from "../contracts";
import { asBufferSource, concatBytes, wipe } from "./bytes";

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

/** getRandomValues liefert pro Aufruf höchstens 65536 Byte. */
const MAX_RANDOM_CHUNK = 65536;

/** Kryptografisch sichere Zufallsbytes (nie Math.random!). */
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_RANDOM_CHUNK) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(length, offset + MAX_RANDOM_CHUNK)));
  }
  return out;
}

/** SHA-256 über die aneinandergehängten Teile. */
export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  return digest("SHA-256", parts);
}

/** SHA-512 über die aneinandergehängten Teile. */
export async function sha512(...parts: Uint8Array[]): Promise<Uint8Array> {
  return digest("SHA-512", parts);
}

/**
 * Hash über mehrere Teile. Die dafür angelegte Kopie wird danach überschrieben: Die Teile sind
 * oft Schlüssel (Master-Seed || transformierter Schlüssel, Blocknummer || HMAC-Basisschlüssel),
 * und die Aufrufer können nur ihre eigenen Puffer löschen (Sicherheitsaudit crypto-5).
 */
async function digest(algorithm: "SHA-256" | "SHA-512", parts: Uint8Array[]): Promise<Uint8Array> {
  if (parts.length === 1) return new Uint8Array(await subtle().digest(algorithm, asBufferSource(parts[0]!)));
  const data = concatBytes(...parts);
  try {
    return new Uint8Array(await subtle().digest(algorithm, asBufferSource(data)));
  } finally {
    wipe(data);
  }
}

/** HMAC-SHA-256 mit beliebig langem Schlüssel (KDBX nutzt 64-Byte-Schlüssel). */
export async function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey(
    "raw",
    asBufferSource(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = parts.length === 1 ? parts[0]! : concatBytes(...parts);
  return new Uint8Array(await subtle().sign("HMAC", cryptoKey, asBufferSource(data)));
}

/** Importiert einen 32-Byte-Schlüssel für AES-256-CBC (zum Mehrfachgebrauch). */
export async function importAesCbcKey(key: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  if (key.length !== 32) throw new RangeError(`AES-256 braucht 32 Byte Schlüssel, nicht ${key.length}.`);
  return subtle().importKey("raw", asBufferSource(key), { name: "AES-CBC" }, false, [usage]);
}

/**
 * AES-256-CBC verschlüsseln. WebCrypto hängt immer PKCS#7-Padding an – genau das, was
 * KDBX verlangt (die Ausgabe ist also 1 bis 16 Byte länger als die Eingabe).
 */
export async function aesCbcEncrypt(key: Uint8Array | CryptoKey, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = key instanceof Uint8Array ? await importAesCbcKey(key, "encrypt") : key;
  const result = await subtle().encrypt({ name: "AES-CBC", iv: asBufferSource(iv) }, cryptoKey, asBufferSource(data));
  return new Uint8Array(result);
}

/**
 * AES-256-CBC entschlüsseln und PKCS#7-Padding entfernen. Ein falsches Padding oder eine
 * Länge, die kein Vielfaches von 16 ist, bedeutet eine beschädigte Datei. (Ein falsches
 * Passwort wird schon vorher am Header-HMAC erkannt.)
 */
export async function aesCbcDecrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await importAesCbcKey(key, "decrypt");
  try {
    const result = await subtle().decrypt({ name: "AES-CBC", iv: asBufferSource(iv) }, cryptoKey, asBufferSource(data));
    return new Uint8Array(result);
  } catch {
    throw new KdbxError("Corrupt", "AES-Entschlüsselung fehlgeschlagen (Länge oder Padding ungültig).");
  }
}

/**
 * ChaCha20 nach RFC 8439 (12-Byte-Nonce, 32-Bit-Blockzähler ab 0) – so verschlüsseln
 * KeePass und KeePassXC den Inhalt. Ver- und Entschlüsseln ist dieselbe XOR-Operation.
 */
export function chacha20Xor(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
  return chacha20(key, nonce, data);
}
