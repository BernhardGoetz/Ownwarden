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

/**
 * Obergrenze für den äußeren Header (Sicherheitsaudit dos-1, Nachprüfung). Er wird gelesen,
 * BEVOR irgendein Schlüssel geprüft ist. Ohne Grenze reichte eine heruntergeladene Datei bis zur
 * Obergrenze von read() (257 MiB, über WebDAV komprimiert nur wenige MiB) mit Millionen winziger
 * Felder bzw. VariantDictionary-Einträge für Gigabytes an Speicher (gemessen: 64 MiB Header,
 * über 1,5 GB) und viele Sekunden Rechenzeit. KeePassXC 2.7.6 und Ownwarden schreiben 200–260
 * Byte (gemessen: 207 bzw. 253); 64 KiB lassen auch für öffentliche Zusatzdaten (Feld 12) viel Platz.
 */
export const MAX_OUTER_HEADER_BYTES = 64 * 1024;

/**
 * Höchstzahl der Einträge eines VariantDictionary (KDF-Parameter, öffentliche Zusatzdaten). Ein
 * Eintrag belegt in der Datei ab 10 Byte, im Speicher ein Vielfaches davon. Die KDF-Parameter
 * haben höchstens 8 Einträge; 1000 lassen Plugins (Feld 12) reichlich Platz.
 */
export const MAX_VARIANT_DICTIONARY_ENTRIES = 1000;

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
 * Argon2Kdf.cpp), plus engeren Grenzen für Speicher, Parallelität und Aufwand von Argon2 im Browser.
 */
export const KDF_LIMITS = {
  /** Salt/Seed-Länge in Byte (KeePassXC: KDF_MIN_SEED_SIZE..KDF_MAX_SEED_SIZE). */
  minSaltLength: 8,
  maxSaltLength: 32,
  /** Runden/Iterationen: 1 .. INT_MAX-1 (KeePassXC speichert sie als int). */
  maxRounds: 0x7fffffff - 1,
  /**
   * Argon2-Parallelität: höchstens 256 Spuren (Argon2 selbst erlaubt 2^24-1). KeePassXC setzt
   * die Anzahl der Threads des PCs ein, KeePass 2 und Ownwarden 2 – 256 reicht großzügig.
   * Warum begrenzt (Sicherheitsaudit crypto-1): hash-wasm rechnet je Spur zusätzlich zwei
   * Hashes in JavaScript (gemessen 0,1–0,2 ms), ohne den Thread freizugeben. Mit 262 000 Spuren
   * (vorher erlaubt) dauerte die schlimmste Einstellung 100 s statt 60 s; 256 Spuren kosten
   * höchstens etwa 50 ms.
   */
  maxParallelism: 256,
  /** Argon2-Speicher: mindestens 8 KiB (Argon2 verlangt außerdem 8 KiB je Spur). */
  minMemoryBytes: 8 * 1024,
  /**
   * Höchstens 1 GiB (Sicherheitsaudit crypto-6): hash-wasm 4.12 scheitert ab knapp 2 GiB
   * („Invalid typed array length“, erst NACH dem Reservieren), Browser und Handys oft schon
   * deutlich früher. 1 GiB ließ sich gemessen reservieren (Node 22, 2026-10) und liegt weit über
   * üblichen Einstellungen (KeePassXC-Standard 64 MiB). Eine manipulierte Datei soll den Service
   * Worker außerdem nicht mit Speicheranforderungen lahmlegen.
   */
  maxMemoryBytes: 1024 * 1024 * 1024,
  /**
   * Argon2-Arbeitsaufwand: höchstens 2^25 „KiB × Iterationen“ (Speicher in KiB mal Anzahl
   * Durchläufe; die Rechenzeit wächst mit diesem Produkt. hash-wasm nutzt nur einen Thread,
   * die Spuren laufen also nacheinander; ihre Vorarbeit begrenzt maxParallelism).
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

/**
 * Mindeststärke der Schlüsselableitung (Sicherheitsaudit crypto-2). Darunter wird das Erraten
 * des Master-Passworts zu billig. createNewVault lehnt schwächere Werte ab; beim Lesen und
 * Zurückschreiben bestehender Dateien gilt die Grenze NICHT (sonst wäre der eigene Tresor
 * gesperrt) – dort kann der Aufrufer mit kdfBelowFloor/kdfWeakerThan (kdf.ts) warnen.
 */
export const KDF_FLOOR = {
  /**
   * Argon2: die gleichwertigen Mindest-Einstellungen aus dem OWASP Password Storage Cheat Sheet
   * (Argon2id, Parallelität 1): 46 MiB × 1, 19 MiB × 2, 12 MiB × 3, 9 MiB × 4, 7 MiB × 5
   * Iterationen. Es genügt, eine Zeile zu erreichen (mindestens so viel Speicher UND so viele
   * Iterationen). Für Argon2d gilt dasselbe.
   */
  argon2: [
    { memoryKiB: 46 * 1024, iterations: 1 },
    { memoryKiB: 19 * 1024, iterations: 2 },
    { memoryKiB: 12 * 1024, iterations: 3 },
    { memoryKiB: 9 * 1024, iterations: 4 },
    { memoryKiB: 7 * 1024, iterations: 5 },
  ],
  /**
   * AES-KDF: 6 Millionen Runden. OWASP nennt für AES-KDF keinen Wert; Maßstab ist die
   * OWASP-Vorgabe für PBKDF2-HMAC-SHA256 (600 000 Iterationen ≈ 1,2 Mio. SHA-256-Blöcke je
   * Rateversuch). AES-KDF rechnet je Runde zwei AES-Blöcke, und ein AES-Block ist (AES-NI,
   * Grafikkarten) grob 10-mal billiger als ein SHA-256-Block: 2 × 6 Mio. AES ≈ 1,2 Mio. SHA-256.
   * AES-KDF bleibt dabei nicht speicherhart, also schwächer als Argon2. Zum Vergleich:
   * KeePassXC wählt für „1 s“ auf der Test-VM rund 64 Mio. Runden; Ownwarden braucht für
   * 6 Mio. Runden etwa 0,25 s.
   */
  aesRounds: 6_000_000,
} as const;

/** Fester 8-Byte-Nonce des Salsa20-Zufallsstroms (KeePass2::INNER_STREAM_SALSA20_IV). */
export const SALSA20_INNER_STREAM_NONCE = new Uint8Array([0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a]);

/** Größe eines Blocks im HMAC-Blockstrom beim Schreiben (wie KeePassXC: 1 MiB). */
export const HMAC_BLOCK_SIZE = 1024 * 1024;

/**
 * Obergrenze für den entschlüsselten (und entpackten) Inhalt: innerer Header mit allen Anhängen
 * plus XML. Schützt vor „Zip-Bomben“ und Speicherüberlauf im Service Worker und auf dem Handy
 * (Sicherheitsaudit dos-4: vorher 512 MiB; beim Lesen liegt der Inhalt mehrfach im Speicher).
 * 256 MiB reichen auch für Datenbanken mit Anhängen. Gilt beim Lesen UND beim Schreiben
 * (encryptContainer), damit Ownwarden nie eine Datei schreibt, die es selbst nicht mehr öffnet.
 */
export const MAX_PAYLOAD_BYTES = 256 * 1024 * 1024;

/**
 * Höchstzahl der Anhänge im inneren Header (Sicherheitsaudit crypto-4). Ein leerer Anhang
 * kostet in der Datei 6 Byte, im Speicher über 200 Byte: Ohne Grenze reichte eine kleine,
 * stark komprimierte Datei für Gigabytes an Objekten. Gleiche Anhänge legt der Writer nur
 * einmal ab; 100 000 verschiedene Anhänge hat kein echter Tresor.
 */
export const MAX_INNER_BINARIES = 100_000;

/**
 * Obergrenze für das XML-Dokument (UTF-8-Byte), bevor es dem XML-Parser übergeben wird
 * (Sicherheitsaudit dos-4). Anhänge stehen nicht im XML, sondern im inneren Header. Der
 * DOM-Parser braucht ein Vielfaches davon an Arbeitsspeicher, auf dem Handy und im Service
 * Worker ist das die engere Grenze.
 *
 * 32 MiB (Nachprüfung; vorher 16 MiB): Eine KeePassXC-Datenbank mit 1500 Einträgen und je 10
 * Verlaufsfassungen hat schon 23 MiB XML (gemessen mit KeePassXC 2.7.6, rund 1,5 KB je Fassung);
 * 32 MiB reichen für etwa 2000 solcher Einträge. Preis (gemessen, Node 22, 2026-10): 2080 solche
 * Einträge (31,8 MiB XML) brauchen beim Einlesen 8 s und rund 1,4 GB zusätzlichen Speicher; mit
 * 1 GiB Heap scheitert das, mit 1,5 GiB nicht. Größere Dateien lehnt readKdbx mit KdbxError
 * „TooLarge“ ab.
 */
export const MAX_XML_BYTES = 32 * 1024 * 1024;
