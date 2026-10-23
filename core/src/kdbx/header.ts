/**
 * Äußerer Header einer KDBX-4-Datei (unverschlüsselt, aber durch SHA-256 und HMAC geschützt).
 *
 * Aufbau:
 *   uint32 LE  Signatur 1 (0x9AA2D903)
 *   uint32 LE  Signatur 2 (0xB54BFB67)
 *   uint32 LE  Version (obere 16 Bit Haupt-, untere 16 Bit Nebenversion)
 *   Felder, wiederholt: 1 Byte ID, uint32 LE Länge, Daten – bis zum Feld 0 (EndOfHeader).
 *
 * Direkt danach folgen in der Datei SHA-256 und HMAC-SHA-256 über alle Header-Bytes
 * (das prüft container.ts).
 *
 * Abgeglichen mit KeePassXC 2.7.6: KdbxReader.cpp, Kdbx4Reader::readHeaderField,
 * Kdbx4Writer::writeDatabase.
 */
import { KdbxError } from "../contracts";
import type { CipherId, KdfParams } from "../model";
import { ByteReader, ByteWriter, bytesToUuid, corrupt, uuidToBytes } from "./bytes";
import {
  CIPHER_UUID,
  ENCRYPTION_IV_LENGTH,
  END_OF_HEADER_DATA,
  HeaderFieldId,
  KDBX_MAJOR_VERSION,
  KDBX_SIGNATURE_1,
  KDBX_SIGNATURE_2,
  KDBX_SUPPORTED_MINOR_VERSIONS,
  LEGACY_HEADER_FIELDS,
  MASTER_SEED_LENGTH,
  MAX_OUTER_HEADER_BYTES,
} from "./constants";
import { parseKdfParameters, serializeKdfParameters } from "./kdf";
import { parseVariantDictionary } from "./variant-dictionary";

/** Die äußere Verschlüsselungen, die Ownwarden kann. */
export type SupportedCipher = Exclude<CipherId, "twofish">;

export interface OuterHeader {
  versionMinor: 0 | 1;
  cipher: SupportedCipher;
  compression: boolean;
  masterSeed: Uint8Array;
  encryptionIv: Uint8Array;
  kdf: KdfParams;
  /** Rohes VariantDictionary aus Feld 12, unverändert. */
  publicCustomData?: Uint8Array;
}

export interface ParsedOuterHeader {
  header: OuterHeader;
  /** Alle Header-Bytes vom Dateianfang bis einschließlich EndOfHeader (Sicht auf die Datei). */
  headerBytes: Uint8Array;
}

const CONTEXT = "Äußerer Header";

/** Liest Signatur, Version und alle Header-Felder; prüft Pflichtfelder und Längen. */
export function parseOuterHeader(file: Uint8Array): ParsedOuterHeader {
  const reader = new ByteReader(file, CONTEXT);
  const versionMinor = readSignatureAndVersion(file, reader);

  // Wie in KeePassXC: Fehlt das Feld CompressionFlags, gilt GZip.
  let compression = true;
  let cipher: SupportedCipher | undefined;
  let masterSeed: Uint8Array | undefined;
  let encryptionIv: Uint8Array | undefined;
  let kdf: KdfParams | undefined;
  let publicCustomData: Uint8Array | undefined;

  for (;;) {
    const fieldId = reader.readU8("Feld-ID");
    const length = reader.readU32(`Länge von Feld ${fieldId}`);
    requireHeaderLimit(reader.offset + length);
    const data = reader.readBytes(length, `Daten von Feld ${fieldId}`);
    if (fieldId === HeaderFieldId.EndOfHeader) break;
    if (LEGACY_HEADER_FIELDS.has(fieldId)) corrupt(`${CONTEXT}: KDBX-3-Feld ${fieldId} in einer KDBX-4-Datei.`);

    switch (fieldId) {
      case HeaderFieldId.CipherId:
        cipher = decodeCipher(data);
        break;
      case HeaderFieldId.CompressionFlags:
        compression = decodeCompression(data);
        break;
      case HeaderFieldId.MasterSeed:
        if (data.length !== MASTER_SEED_LENGTH) corrupt(`${CONTEXT}: Master-Seed hat ${data.length} statt 32 Byte.`);
        masterSeed = data;
        break;
      case HeaderFieldId.EncryptionIv:
        encryptionIv = data;
        break;
      case HeaderFieldId.KdfParameters:
        kdf = parseKdfParameters(data);
        break;
      case HeaderFieldId.PublicCustomData:
        parseVariantDictionary(data); // nur prüfen; weitergereicht wird das Original
        publicCustomData = data;
        break;
      default:
        // Unbekannte Felder (auch "Comment") ignoriert KeePassXC ebenfalls.
        break;
    }
  }

  if (cipher === undefined) corrupt(`${CONTEXT}: Verschlüsselungsverfahren fehlt.`);
  if (masterSeed === undefined) corrupt(`${CONTEXT}: Master-Seed fehlt.`);
  if (kdf === undefined) corrupt(`${CONTEXT}: KDF-Parameter fehlen.`);
  if (encryptionIv === undefined) corrupt(`${CONTEXT}: IV fehlt.`);
  if (encryptionIv.length !== ENCRYPTION_IV_LENGTH[cipher]) {
    corrupt(`${CONTEXT}: IV hat ${encryptionIv.length} statt ${ENCRYPTION_IV_LENGTH[cipher]} Byte.`);
  }

  const header: OuterHeader = { versionMinor, cipher, compression, masterSeed, encryptionIv, kdf };
  if (publicCustomData !== undefined) header.publicCustomData = publicCustomData;
  return { header, headerBytes: file.subarray(0, reader.offset) };
}

/**
 * Länge des äußeren Headers (bis einschließlich EndOfHeader), OHNE die Felder auszuwerten.
 * decryptContainer prüft damit die Header-SHA-256, bevor parseOuterHeader die KDF-Parameter
 * bewertet: Ein zufällig beschädigter Header soll „beschädigt“ heißen und nicht zum Ändern der
 * KDF-Einstellungen raten (Sicherheitsaudit crypto-1).
 *
 * Einen Header über MAX_OUTER_HEADER_BYTES lehnt es ab, sobald das feststeht, also auch vor der
 * SHA-256 (Sicherheitsaudit dos-1, Nachprüfung).
 */
export function outerHeaderLength(file: Uint8Array): number {
  const reader = new ByteReader(file, CONTEXT);
  readSignatureAndVersion(file, reader);
  for (;;) {
    const fieldId = reader.readU8("Feld-ID");
    const length = reader.readU32(`Länge von Feld ${fieldId}`);
    requireHeaderLimit(reader.offset + length);
    reader.readView(length, `Daten von Feld ${fieldId}`);
    if (fieldId === HeaderFieldId.EndOfHeader) return reader.offset;
  }
}

/**
 * Bricht ab, wenn der Header bis `end` (Ende des nächsten Felds) länger als MAX_OUTER_HEADER_BYTES
 * würde – vor dem Lesen des Felds. Corrupt statt TooLarge: Der Header ist hier noch ungeprüft,
 * und echte Dateien haben wenige hundert Byte; wahrscheinlich ist die Datei beschädigt oder
 * manipuliert.
 */
function requireHeaderLimit(end: number): void {
  if (end > MAX_OUTER_HEADER_BYTES) {
    corrupt(`${CONTEXT}: unplausibel lang (mehr als ${MAX_OUTER_HEADER_BYTES / 1024} KiB; echte Dateien haben wenige hundert Byte).`);
  }
}

/** Prüft die Signaturen und liefert die Nebenversion (0 oder 1). */
function readSignatureAndVersion(file: Uint8Array, reader: ByteReader): 0 | 1 {
  if (file.length < 8) throw new KdbxError("BadSignature", "Die Datei ist zu kurz für eine KDBX-Datei.");
  const signature1 = reader.readU32();
  const signature2 = reader.readU32();
  if (signature1 !== KDBX_SIGNATURE_1 || signature2 !== KDBX_SIGNATURE_2) {
    throw new KdbxError("BadSignature", "Keine KeePass-2-Datei (KDBX-Signatur fehlt).");
  }

  const version = reader.readU32("Version");
  const major = version >>> 16;
  const minor = version & 0xffff;
  if (major !== KDBX_MAJOR_VERSION || !KDBX_SUPPORTED_MINOR_VERSIONS.includes(minor)) {
    const hint =
      major < KDBX_MAJOR_VERSION
        ? " Bitte die Datei in KeePassXC öffnen und im Format KDBX 4 speichern" +
          " (Datenbank-Einstellungen → Sicherheit → Verschlüsselung)."
        : "";
    throw new KdbxError("UnsupportedVersion", `KDBX-Version ${major}.${minor} wird nicht unterstützt.${hint}`);
  }
  return minor as 0 | 1;
}

function decodeCipher(data: Uint8Array): SupportedCipher {
  if (data.length !== 16) corrupt(`${CONTEXT}: Verschlüsselungs-UUID hat ${data.length} statt 16 Byte.`);
  const uuid = bytesToUuid(data);
  if (uuid === CIPHER_UUID.aes256) return "aes256";
  if (uuid === CIPHER_UUID.chacha20) return "chacha20";
  const name = uuid === CIPHER_UUID.twofish ? "Twofish" : uuid === CIPHER_UUID.aes128 ? "AES-128" : uuid;
  throw new KdbxError(
    "UnsupportedCipher",
    `Verschlüsselung ${name} wird nicht unterstützt. Bitte in KeePassXC auf AES-256 oder ChaCha20 umstellen.`,
  );
}

function decodeCompression(data: Uint8Array): boolean {
  if (data.length !== 4) corrupt(`${CONTEXT}: Kompressionsfeld hat ${data.length} statt 4 Byte.`);
  const flags = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);
  if (flags > 1) corrupt(`${CONTEXT}: Unbekanntes Kompressionsverfahren ${flags}.`);
  return flags === 1;
}

/**
 * Schreibt den äußeren Header in der Reihenfolge von KeePassXC: CipherID, CompressionFlags,
 * MasterSeed, EncryptionIV, KdfParameters, (PublicCustomData), EndOfHeader = "\r\n\r\n".
 */
export function serializeOuterHeader(header: OuterHeader): Uint8Array {
  if (header.cipher !== "aes256" && header.cipher !== "chacha20") {
    throw new KdbxError("UnsupportedCipher", `Verschlüsselung "${String(header.cipher)}" kann nicht geschrieben werden.`);
  }
  if (!KDBX_SUPPORTED_MINOR_VERSIONS.includes(header.versionMinor)) {
    throw new KdbxError("UnsupportedVersion", `KDBX 4.${header.versionMinor} kann nicht geschrieben werden.`);
  }
  if (header.masterSeed.length !== MASTER_SEED_LENGTH) throw new RangeError("Master-Seed muss 32 Byte lang sein.");
  if (header.encryptionIv.length !== ENCRYPTION_IV_LENGTH[header.cipher]) {
    throw new RangeError(`IV muss für ${header.cipher} ${ENCRYPTION_IV_LENGTH[header.cipher]} Byte lang sein.`);
  }

  const writer = new ByteWriter();
  writer.writeU32(KDBX_SIGNATURE_1).writeU32(KDBX_SIGNATURE_2);
  writer.writeU32(((KDBX_MAJOR_VERSION << 16) | header.versionMinor) >>> 0);

  const field = (id: number, data: Uint8Array) => writer.writeU8(id).writeU32(data.length).writeBytes(data);
  field(HeaderFieldId.CipherId, uuidToBytes(CIPHER_UUID[header.cipher]));
  field(HeaderFieldId.CompressionFlags, new ByteWriter().writeU32(header.compression ? 1 : 0).toBytes());
  field(HeaderFieldId.MasterSeed, header.masterSeed);
  field(HeaderFieldId.EncryptionIv, header.encryptionIv);
  field(HeaderFieldId.KdfParameters, serializeKdfParameters(header.kdf));
  if (header.publicCustomData !== undefined && header.publicCustomData.length > 0) {
    parseVariantDictionary(header.publicCustomData); // nie ungültige Daten schreiben
    field(HeaderFieldId.PublicCustomData, header.publicCustomData);
  }
  field(HeaderFieldId.EndOfHeader, END_OF_HEADER_DATA);
  // Nie einen Header schreiben, den das Lesen ablehnt (siehe requireHeaderLimit).
  if (writer.byteLength > MAX_OUTER_HEADER_BYTES) {
    throw new RangeError(
      `Äußerer Header: ${writer.byteLength} Byte, höchstens ${MAX_OUTER_HEADER_BYTES / 1024} KiB sind erlaubt ` +
        "(zu große öffentliche Zusatzdaten).",
    );
  }
  return writer.toBytes();
}
