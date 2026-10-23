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
/**
 * Hauptversion, die Ownwarden versteht (obere 16 Bit des Versionsfelds).
 * Das Versionsfeld ist ein uint32 LE: untere 16 Bit = Nebenversion, obere 16 Bit = Hauptversion.
 * In der Datei stehen also z. B. für KDBX 4.1 die Bytes 01 00 04 00.
 */
export const KDBX_MAJOR_VERSION = 4;
/** Nebenversionen von KDBX 4, die Ownwarden liest und schreibt (4.0 und 4.1). */
export const KDBX_SUPPORTED_MINOR_VERSIONS: readonly number[] = [0, 1];

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

/** Länge des Initialisierungsvektors (Header-Feld 7) je äußerer Verschlüsselung. */
export const ENCRYPTION_IV_LENGTH = {
  aes256: 16,
  chacha20: 12,
} as const;

/** Länge des Master-Seeds (Header-Feld 4); KeePassXC verlangt genau 32 Byte. */
export const MASTER_SEED_LENGTH = 32;

/**
 * Version des VariantDictionary (uint16 LE). Nur das obere Byte ist „kritisch“: Ein Leser
 * muss Dateien mit höherer Hauptversion ablehnen, eine höhere Nebenversion aber akzeptieren
 * (so machen es KeePass und KeePassXC).
 */
export const VARIANT_DICTIONARY_VERSION = 0x0100;
export const VARIANT_DICTIONARY_CRITICAL_MASK = 0xff00;

/** Schlüssel in den KDF-Parametern (VariantDictionary aus Header-Feld 11). */
export const KdfParamKey = {
  Uuid: "$UUID",
  /** Argon2: Salt; AES-KDF: Seed (beide "S"). */
  Salt: "S",
  /** Argon2: Parallelität (UInt32). */
  Parallelism: "P",
  /** Argon2: Speicher in BYTE (UInt64), nicht in KiB. */
  Memory: "M",
  /** Argon2: Iterationen (UInt64). */
  Iterations: "I",
  /** Argon2: Version (UInt32), 0x13 = Argon2 v1.3. */
  Version: "V",
  /** Argon2: geheimer Schlüssel – nutzt weder KeePass noch KeePassXC. */
  Secret: "K",
  /** Argon2: „associated data“ – nutzt weder KeePass noch KeePassXC. */
  AssocData: "A",
  /** AES-KDF: Anzahl Runden (UInt64). */
  Rounds: "R",
} as const;

/** Argon2-Version 1.3; die einzige, die die verwendete Bibliothek (hash-wasm) rechnet. */
export const ARGON2_VERSION_13 = 0x13;

/**
 * Grenzen für KDF-Parameter. Die KDF-Parameter stehen im Header und werden benutzt, BEVOR
 * die Header-Prüfsumme (HMAC) geprüft werden kann – eine manipulierte Datei könnte also
 * absurde Werte verlangen. Die Grenzen entsprechen denen von KeePassXC (Kdf.cpp,
 * Argon2Kdf.cpp), plus einer Speicher- und einer Aufwandsgrenze für Argon2 im Browser.
 */
export const KDF_LIMITS = {
  /** Salt/Seed-Länge in Byte (KeePassXC: KDF_MIN_SEED_SIZE..KDF_MAX_SEED_SIZE). */
  minSaltLength: 8,
  maxSaltLength: 32,
  /** Runden/Iterationen: 1 .. INT_MAX-1 (KeePassXC speichert sie als int). */
  maxRounds: 0x7fffffff - 1,
  /** Argon2-Parallelität: 1 .. 2^24-1. */
  maxParallelism: 0xffffff,
  /** Argon2-Speicher: mindestens 8 KiB (Argon2 verlangt außerdem 8 KiB je Spur). */
  minMemoryBytes: 8 * 1024,
  /**
   * Höchstens 2 GiB: WebAssembly im Browser kann ohnehin kaum mehr reservieren, und eine
   * manipulierte Datei soll den Service Worker nicht mit Speicheranforderungen lahmlegen.
   */
  maxMemoryBytes: 2 * 1024 * 1024 * 1024,
  /**
   * Argon2-Arbeitsaufwand: höchstens 2^25 „KiB × Iterationen“ (Speicher in KiB mal Anzahl
   * Durchläufe; die Rechenzeit wächst mit diesem Produkt, die Parallelität ändert daran in
   * hash-wasm nichts, weil es nur einen Thread nutzt).
   *
   * Warum nötig: Die Einzelgrenzen oben lassen z. B. 2^31 Iterationen zu. hash-wasm würde
   * damit Stunden bis Jahre rechnen und blockiert dabei den GANZEN Thread (der Service
   * Worker friert ein, kein Timeout greift). Ein manipulierter Header kann so etwas
   * verlangen, weil der Header-HMAC erst NACH der KDF geprüft werden kann.
   *
   * Warum dieser Wert: hash-wasm schafft (Node 22, gemessen 2026-10) etwa 450–700 KiB×It
   * pro ms; 2^25 sind also rund eine Minute – so lange wie die schlimmste erlaubte AES-KDF
   * (INT_MAX-1 Runden, ~85 s, blockiert aber nicht). Erlaubt bleiben z. B. 64 MiB × 512
   * Iterationen, 1 GiB × 32, 1 MiB × 32768. Ownwardens Standard (64 MiB × 3) nutzt weniger
   * als 1 % davon.
   *
   * Achtung bei Einstellungen, die in KeePassXC geändert wurden: KeePassXC misst die gewählte
   * Entschlüsselungszeit MIT allen Threads (Parallelität = Anzahl der Threads des PCs),
   * hash-wasm rechnet alle Spuren nacheinander auf EINEM Thread. Was in KeePassXC N Sekunden
   * dauert, dauert hier also bis zu „Parallelität × N“ Sekunden, und auf einem PC mit vielen
   * Threads kann schon „5 s“ bei 64 MiB mehr als 512 Iterationen ergeben – dann lehnt
   * readKdbx die Datei mit UnsupportedKdf ab (siehe core/README.md, „Bekannte Grenzen“).
   * Gemessen 2026-10 auf einer VM mit 4 vCPUs, Argon2id mit 64 MiB: libargon2 von KeePassXC
   * 48,5 ms je Iteration bei P=1 und 19,2 ms bei P=4 (also „5 s“ ≈ 260 Iterationen),
   * hash-wasm 75 ms (512 Iterationen ≈ 38 s).
   */
  maxArgon2WorkKiBIterations: 2 ** 25,
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

/**
 * Obergrenze für das XML-Dokument (UTF-8-Byte), bevor es dem XML-Parser übergeben wird
 * (Sicherheitsaudit dos-4). Anhänge stehen nicht im XML, sondern im inneren Header; 16 MiB XML
 * entsprechen Zehntausenden Einträgen. Der DOM-Parser braucht ein Vielfaches davon an
 * Arbeitsspeicher, auf dem Handy und im Service Worker ist das die engere Grenze.
 */
export const MAX_XML_BYTES = 16 * 1024 * 1024;
