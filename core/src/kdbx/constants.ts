/**
 * Feste Kennungen des KDBX-4-Formats (Signaturen, Header-Feld-IDs, UUIDs).
 *
 * Alle Werte wurden mit dem Quellcode von KeePassXC 2.7.6 abgeglichen
 * (src/format/KeePass2.h, KeePass2.cpp). UUIDs stehen hier in der üblichen
 * Schreibweise; in der Datei stehen sie als 16 Byte in genau dieser Reihenfolge
 * (RFC 4122, „big endian“ wie gelesen).
 */

/** Erste Signatur (uint32 LE) am Dateianfang: Bytes 03 D9 A2 9A. */
export const KDBX_SIGNATURE_1 = 0x9aa2d903;
/** Zweite Signatur (uint32 LE): kennzeichnet KeePass 2.x (Bytes 67 FB 4B B5). */
export const KDBX_SIGNATURE_2 = 0xb54bfb67;
/** Hauptversion, die Ownwarden versteht (obere 16 Bit des Versionsfelds). */
export const KDBX_MAJOR_VERSION = 4;

/** IDs der Felder im äußeren Header (1 Byte ID + uint32 LE Länge + Daten). */
export const HeaderFieldId = {
  EndOfHeader: 0,
  Comment: 1,
  CipherId: 2,
  CompressionFlags: 3,
  MasterSeed: 4,
  /** KDBX 3: in KDBX 4 verboten. */
  TransformSeed: 5,
  /** KDBX 3: in KDBX 4 verboten. */
  TransformRounds: 6,
  EncryptionIv: 7,
  /** KDBX 3: in KDBX 4 verboten. */
  ProtectedStreamKey: 8,
  /** KDBX 3: in KDBX 4 verboten. */
  StreamStartBytes: 9,
  /** KDBX 3: in KDBX 4 verboten. */
  InnerRandomStreamId: 10,
  KdfParameters: 11,
  PublicCustomData: 12,
} as const;

/** Header-Felder aus KDBX 3, die in einer KDBX-4-Datei nicht vorkommen dürfen (wie KeePassXC). */
export const LEGACY_HEADER_FIELDS: ReadonlySet<number> = new Set([
  HeaderFieldId.TransformSeed,
  HeaderFieldId.TransformRounds,
  HeaderFieldId.ProtectedStreamKey,
  HeaderFieldId.StreamStartBytes,
  HeaderFieldId.InnerRandomStreamId,
]);

/** Inhalt des End-Felds im äußeren Header; KeePassXC und KeePass schreiben "\r\n\r\n". */
export const END_OF_HEADER_DATA = new Uint8Array([0x0d, 0x0a, 0x0d, 0x0a]);

/** IDs der Felder im inneren Header (am Anfang des entschlüsselten Inhalts). */
export const InnerHeaderFieldId = {
  End: 0,
  InnerRandomStreamId: 1,
  InnerRandomStreamKey: 2,
  Binary: 3,
} as const;

/** Nummern der inneren Zufallsströme im inneren Header (Feld 1, uint32 LE). */
export const InnerStreamNumber = {
  /** Uralte KeePass-Variante, wird nicht unterstützt. */
  ArcFourVariant: 1,
  Salsa20: 2,
  ChaCha20: 3,
} as const;

/** Bit im Flag-Byte eines Anhangs im inneren Header: „geschützt“ (nur Speicherschutz, keine Verschlüsselung). */
export const BINARY_FLAG_PROTECTED = 0x01;

/** UUIDs der äußeren Verschlüsselung (Header-Feld 2). */
export const CIPHER_UUID = {
  aes256: "31c1f2e6-bf71-4350-be58-05216afc5aff",
  chacha20: "d6038a2b-8b6f-4cb5-a524-339a31dbb59a",
  twofish: "ad68f29f-576f-4bb9-a36a-d47af965346c",
  /** Nur KeePassXC kennt AES-128; Ownwarden lehnt es ab. */
  aes128: "61ab05a1-9464-41c3-8d74-3a563df8dd35",
} as const;

/** UUIDs der Schlüsselableitung (Eintrag "$UUID" in den KDF-Parametern). */
export const KDF_UUID = {
  argon2d: "ef636ddf-8c29-444b-91f7-a9a403e30a0c",
  argon2id: "9e298b19-56db-4773-b23d-fc3ec6f0a1e6",
  /**
   * AES-KDF, ursprüngliche KeePass-UUID. KeePassXC schreibt beim Speichern IMMER diese
   * UUID („for compatibility with other applications“), auch in KDBX-4-Dateien.
   */
  aesKdbx3: "c9d9f39a-628a-4460-bf74-0d08c18a4fea",
  /** AES-KDF, KeePassXC-interne KDBX-4-UUID. Wird nur gelesen, nie geschrieben. */
  aesKdbx4: "7c02bb82-79a7-4ac0-927d-114a00648238",
} as const;

/** Fester 8-Byte-Nonce des Salsa20-Zufallsstroms (KeePass2::INNER_STREAM_SALSA20_IV). */
export const SALSA20_INNER_STREAM_NONCE = new Uint8Array([0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a]);

/** Größe eines Blocks im HMAC-Blockstrom beim Schreiben (wie KeePassXC: 1 MiB). */
export const HMAC_BLOCK_SIZE = 1024 * 1024;

/**
 * Obergrenze für den entschlüsselten (und entpackten) Inhalt. Schützt vor „Zip-Bomben“ und
 * Speicherüberlauf im Service Worker. 512 MiB reichen auch für Datenbanken mit Anhängen.
 */
export const MAX_PAYLOAD_BYTES = 512 * 1024 * 1024;
