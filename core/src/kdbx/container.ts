/**
 * Die äußere Hülle einer KDBX-4-Datei: Header, Prüfsummen, Verschlüsselung, Kompression.
 *
 * Datei-Aufbau:
 *   [äußerer Header]                      header.ts
 *   [SHA-256 des Headers, 32 Byte]        erkennt Beschädigung
 *   [HMAC-SHA-256 des Headers, 32 Byte]   erkennt falsches Passwort (und Manipulation)
 *   [HMAC-Blockstrom]                     hmac-block-stream.ts, enthält den Chiffretext:
 *      AES-256-CBC oder ChaCha20 von
 *        GZip (optional) von
 *          [innerer Header][XML]          inner-header.ts
 *
 * Entschlüsseln prüft in dieser Reihenfolge: Signatur/Version, Header-SHA-256 (billig, vor
 * der teuren KDF), Header-HMAC (falsches Passwort?), alle Block-HMACs – erst danach wird
 * entschlüsselt. Ein Fehler bricht mit KdbxError ab; Teilergebnisse gibt es nie.
 *
 * Abgeglichen mit KeePassXC 2.7.6: src/format/Kdbx4Reader.cpp, Kdbx4Writer.cpp.
 */
import {
  KdbxError,
  type DecryptContainer,
  type DecryptedPayload,
  type EncryptContainer,
} from "../contracts";
import type { Credentials, KdbxSettings } from "../model";
import { ByteReader, bytesEqual, concatBytes, wipe } from "./bytes";
import { gunzip, gzip } from "./compression";
import { ENCRYPTION_IV_LENGTH, MASTER_SEED_LENGTH, MAX_PAYLOAD_BYTES, MAX_XML_BYTES } from "./constants";
import { aesCbcDecrypt, aesCbcEncrypt, chacha20Xor, hmacSha256, randomBytes, sha256 } from "./crypto";
import { outerHeaderLength, parseOuterHeader, serializeOuterHeader, type OuterHeader, type SupportedCipher } from "./header";
import {
  HEADER_HMAC_BLOCK_INDEX,
  blockHmacKey,
  readHmacBlockStream,
  writeHmacBlockStream,
} from "./hmac-block-stream";
import { innerHeaderLength, parseInnerHeader, serializeInnerHeader } from "./inner-header";
import { transformKey, validateKdfParams, withFreshKdfSalt } from "./kdf";
import { compositeKey, deriveMasterKeys, type MasterKeys } from "./keys";

export { defaultKdbxSettings } from "./settings";

// ---------------------------------------------------------------------------
// Entschlüsseln
// ---------------------------------------------------------------------------

export const decryptContainer: DecryptContainer = async (file, credentials) => {
  // Erst die Header-SHA-256 prüfen, dann die Felder bewerten (siehe outerHeaderLength).
  const headerBytes = file.subarray(0, outerHeaderLength(file));

  // Direkt hinter dem Header: SHA-256 und HMAC des Headers.
  const afterHeader = new ByteReader(file.subarray(headerBytes.length), "Header-Prüfsummen");
  const storedHash = afterHeader.readView(32, "Header-SHA-256");
  const storedHmac = afterHeader.readView(32, "Header-HMAC");
  if (!bytesEqual(await sha256(headerBytes), storedHash)) {
    throw new KdbxError("Corrupt", "Der Header ist beschädigt (SHA-256 passt nicht).");
  }
  const { header } = parseOuterHeader(file);

  const keys = await deriveKeys(credentials, header);
  try {
    const expectedHmac = await headerHmac(headerBytes, keys.hmacBaseKey);
    if (!bytesEqual(expectedHmac, storedHmac)) {
      throw new KdbxError("InvalidCredentials", "Falsches Passwort oder falsche Schlüsseldatei (Header-HMAC passt nicht).");
    }

    const ciphertext = await readHmacBlockStream(afterHeader.readRest(), keys.hmacBaseKey);
    let plaintext = await decryptPayload(header.cipher, keys.encryptionKey, header.encryptionIv, ciphertext);
    if (header.compression) {
      const packed = plaintext;
      try {
        plaintext = await gunzip(packed);
      } finally {
        wipe(packed);
      }
    }

    try {
      const { header: inner, xml } = parseInnerHeader(plaintext);
      // Stromschlüssel und Anhänge sind Kopien: den inneren Header im Klartext löschen. Die XML
      // bleibt als Sicht auf den Klartext stehen; readKdbx löscht sie nach dem Einlesen.
      wipe(plaintext.subarray(0, plaintext.length - xml.length));
      return {
        settings: settingsFromHeader(header),
        innerStreamId: inner.innerStreamId,
        innerStreamKey: inner.innerStreamKey,
        binaries: inner.binaries,
        xml,
      };
    } catch (error) {
      wipe(plaintext);
      throw error;
    }
  } finally {
    wipe(keys.encryptionKey, keys.hmacBaseKey);
  }
};

async function decryptPayload(
  cipher: SupportedCipher,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (cipher === "chacha20") return chacha20Xor(key, iv, ciphertext);
  return aesCbcDecrypt(key, iv, ciphertext);
}

/** Die Einstellungen, die beim Speichern erhalten bleiben sollen. */
function settingsFromHeader(header: OuterHeader): KdbxSettings {
  const settings: KdbxSettings = {
    versionMinor: header.versionMinor,
    cipher: header.cipher,
    compression: header.compression,
    kdf: header.kdf,
  };
  if (header.publicCustomData !== undefined) settings.publicCustomData = header.publicCustomData;
  return settings;
}

// ---------------------------------------------------------------------------
// Verschlüsseln
// ---------------------------------------------------------------------------

export const encryptContainer: EncryptContainer = async (payload: DecryptedPayload, credentials: Credentials) => {
  const header = freshHeader(payload.settings);
  const headerBytes = serializeOuterHeader(header);
  const inner = { innerStreamId: payload.innerStreamId, innerStreamKey: payload.innerStreamKey, binaries: payload.binaries };
  checkPayloadSize(innerHeaderLength(inner), payload.xml.length);

  // Klartext (und gepackter Klartext) sind eigene Kopien: nach dem Verschlüsseln löschen.
  const innerHeader = serializeInnerHeader(inner);
  let plaintext = concatBytes(innerHeader, payload.xml);
  wipe(innerHeader);
  try {
    if (header.compression) {
      const unpacked = plaintext;
      plaintext = await gzip(unpacked);
      wipe(unpacked);
    }
    checkCiphertextSize(header.cipher, plaintext.length);

    const keys = await deriveKeys(credentials, header);
    try {
      const ciphertext = await encryptPayload(header.cipher, keys.encryptionKey, header.encryptionIv, plaintext);
      const blocks = await writeHmacBlockStream(ciphertext, keys.hmacBaseKey);
      return concatBytes(headerBytes, await sha256(headerBytes), await headerHmac(headerBytes, keys.hmacBaseKey), blocks);
    } finally {
      wipe(keys.encryptionKey, keys.hmacBaseKey);
    }
  } finally {
    wipe(plaintext);
  }
};

const MIB = 1024 * 1024;

/**
 * Nie eine Datei schreiben, die Ownwarden selbst nicht mehr öffnen würde (Sicherheitsaudit
 * crypto-3): Beim Lesen gelten MAX_XML_BYTES für die XML und MAX_PAYLOAD_BYTES für den
 * (entpackten) Inhalt. Geprüft wird VOR dem Zusammensetzen und vor der teuren KDF.
 */
function checkPayloadSize(innerHeaderBytes: number, xmlBytes: number): void {
  if (xmlBytes > MAX_XML_BYTES) {
    throw new RangeError(
      `Die XML-Datenbank ist zu groß zum Speichern: ${mebibytes(xmlBytes)} MiB, höchstens ${MAX_XML_BYTES / MIB} MiB ` +
        "sind erlaubt (sonst ließe sich die Datei nicht mehr öffnen). Bitte Verlauf, Papierkorb oder alte Einträge aufräumen.",
    );
  }
  const total = innerHeaderBytes + xmlBytes;
  if (total > MAX_PAYLOAD_BYTES) {
    throw new RangeError(
      `Der Tresor ist zu groß zum Speichern: ${mebibytes(total)} MiB mit Anhängen, höchstens ${MAX_PAYLOAD_BYTES / MIB} MiB ` +
        "sind erlaubt (sonst ließe sich die Datei nicht mehr öffnen). Bitte große Anhänge entfernen.",
    );
  }
}

/** Der HMAC-Blockstrom (= Chiffretext) darf beim Lesen ebenfalls höchstens MAX_PAYLOAD_BYTES groß sein. */
function checkCiphertextSize(cipher: SupportedCipher, plaintextBytes: number): void {
  // AES-CBC hängt 1 bis 16 Byte PKCS#7-Padding an, ChaCha20 ändert die Länge nicht.
  const ciphertextBytes = cipher === "aes256" ? plaintextBytes - (plaintextBytes % 16) + 16 : plaintextBytes;
  if (ciphertextBytes > MAX_PAYLOAD_BYTES) {
    throw new RangeError(
      `Der Tresor ist zu groß zum Speichern: ${mebibytes(ciphertextBytes)} MiB verschlüsselt, höchstens ` +
        `${MAX_PAYLOAD_BYTES / MIB} MiB sind erlaubt (sonst ließe sich die Datei nicht mehr öffnen). Bitte große Anhänge entfernen.`,
    );
  }
}

/** Byte -> „12,3“ (MiB, eine Nachkommastelle, deutsches Komma) für Meldungen. */
function mebibytes(bytes: number): string {
  return (bytes / MIB).toFixed(1).replace(".", ",");
}

/**
 * Baut den Header für eine neue Fassung der Datei: Einstellungen übernehmen, aber Master-Seed,
 * IV und KDF-Salt/-Seed IMMER neu auswürfeln. Ein wiederverwendeter IV mit demselben
 * Schlüssel würde bei ChaCha20 den Klartext preisgeben.
 */
function freshHeader(settings: KdbxSettings): OuterHeader {
  if (settings.cipher !== "aes256" && settings.cipher !== "chacha20") {
    throw new KdbxError("UnsupportedCipher", `Verschlüsselung "${settings.cipher}" kann nicht geschrieben werden.`);
  }
  validateKdfParams(settings.kdf);
  const header: OuterHeader = {
    versionMinor: settings.versionMinor,
    cipher: settings.cipher,
    compression: settings.compression,
    masterSeed: randomBytes(MASTER_SEED_LENGTH),
    encryptionIv: randomBytes(ENCRYPTION_IV_LENGTH[settings.cipher]),
    kdf: withFreshKdfSalt(settings.kdf),
  };
  if (settings.publicCustomData !== undefined) header.publicCustomData = settings.publicCustomData;
  return header;
}

async function encryptPayload(
  cipher: SupportedCipher,
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (cipher === "chacha20") return chacha20Xor(key, iv, plaintext);
  return aesCbcEncrypt(key, iv, plaintext);
}

// ---------------------------------------------------------------------------
// Gemeinsam
// ---------------------------------------------------------------------------

/** Zugangsdaten -> zusammengesetzter Schlüssel -> KDF -> Verschlüsselungs- und HMAC-Schlüssel. */
async function deriveKeys(credentials: Credentials, header: OuterHeader): Promise<MasterKeys> {
  const composite = await compositeKey(credentials);
  const transformed = await transformKey(composite, header.kdf);
  try {
    return await deriveMasterKeys(header.masterSeed, transformed);
  } finally {
    wipe(composite, transformed);
  }
}

/** HMAC über die Header-Bytes mit dem Blockschlüssel für die Nummer 2^64-1. */
async function headerHmac(headerBytes: Uint8Array, hmacBaseKey: Uint8Array): Promise<Uint8Array> {
  const key = await blockHmacKey(HEADER_HMAC_BLOCK_INDEX, hmacBaseKey);
  const result = await hmacSha256(key, headerBytes);
  wipe(key);
  return result;
}
