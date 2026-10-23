/**
 * Gegenproben für die äußere KDBX-Hülle: manipulierte Header, feindliche Längenangaben,
 * absurde KDF-Parameter, Reihenfolge der Prüfungen und frische Zufallswerte beim Speichern.
 *
 * Jeder Test hier ist aus einem konkreten Verdacht entstanden. Tests mit „Regression“ im
 * Namen haben einen echten Fehler gefunden (der Test schlug vor der Korrektur fehl).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { DecryptedPayload } from "../contracts";
import type { CipherId, KdbxSettings, KdfParams } from "../model";
import { ByteWriter, concatBytes, utf8Decode, utf8Encode, uuidToBytes } from "./bytes";
import { gunzip, gzip } from "./compression";
import { CIPHER_UUID, ENCRYPTION_IV_LENGTH, HeaderFieldId, KDF_LIMITS, KDF_UUID } from "./constants";
import { decryptContainer, encryptContainer } from "./container";
import { sha256 } from "./crypto";
import { parseOuterHeader } from "./header";
import { parseInnerHeader } from "./inner-header";
import { parseKdfParameters, serializeKdfParameters, validateKdfParams } from "./kdf";
import { serializeVariantDictionary, type VariantDictionary } from "./variant-dictionary";

const code = (c: string) => expect.objectContaining({ code: c });
const PASSWORD = { password: "Gegenprobe-Passwort" };
const FAST_AES: KdfParams = { type: "aes", seed: new Uint8Array(32).fill(1), rounds: 10 };

type Argon2Params = Extract<KdfParams, { salt: Uint8Array }>;

function argon2(overrides: Partial<Argon2Params> = {}): Argon2Params {
  return {
    type: "argon2id",
    salt: new Uint8Array(32).fill(7),
    parallelism: 2,
    memoryBytes: 64 * 1024,
    iterations: 2,
    version: 0x13,
    ...overrides,
  };
}

function payload(settings: Partial<KdbxSettings> = {}): DecryptedPayload {
  return {
    settings: { versionMinor: 0, cipher: "aes256", compression: false, kdf: FAST_AES, ...settings },
    innerStreamId: "chacha20",
    innerStreamKey: new Uint8Array(64).fill(5),
    binaries: [{ data: utf8Encode("Anhang"), protected: true }],
    xml: utf8Encode(`<KeePassFile>${"<Entry/>".repeat(300)}</KeePassFile>`),
  };
}

/** Argon2-Parameter als Rohbytes – OHNE die Prüfung von serializeKdfParameters (wie in einem Fremd-Header). */
function rawArgon2Dict(iterations: bigint, memoryBytes: bigint, parallelism: number): Uint8Array {
  const dict: VariantDictionary = new Map([
    ["$UUID", { type: "bytes", value: uuidToBytes(KDF_UUID.argon2id) }],
    ["I", { type: "uint64", value: iterations }],
    ["M", { type: "uint64", value: memoryBytes }],
    ["P", { type: "uint32", value: parallelism }],
    ["S", { type: "bytes", value: new Uint8Array(32) }],
    ["V", { type: "uint32", value: 0x13 }],
  ]);
  return serializeVariantDictionary(dict);
}

/** Header-Felder (ID, Länge, Daten) hinter Signatur und Version 4.0. */
function rawHeader(fields: [number, Uint8Array][]): Uint8Array {
  const w = new ByteWriter().writeU32(0x9aa2d903).writeU32(0xb54bfb67).writeU32(0x00040000);
  for (const [id, data] of fields) w.writeU8(id).writeU32(data.length).writeBytes(data);
  return w.toBytes();
}

/**
 * Komplette „Datei“ mit frei gewählten KDF-Parametern: Header, SHA-256 (auf Wunsch falsch),
 * HMAC aus Nullen, leerer Endblock. So sieht ein manipulierter Fremd-Header aus.
 */
async function rawFile(kdfBytes: Uint8Array, options: { badHash?: boolean } = {}): Promise<Uint8Array> {
  const header = rawHeader([
    [HeaderFieldId.CipherId, uuidToBytes(CIPHER_UUID.aes256)],
    [HeaderFieldId.CompressionFlags, new ByteWriter().writeU32(0).toBytes()],
    [HeaderFieldId.MasterSeed, new Uint8Array(32)],
    [HeaderFieldId.EncryptionIv, new Uint8Array(16)],
    [HeaderFieldId.KdfParameters, kdfBytes],
    [HeaderFieldId.EndOfHeader, Uint8Array.of(13, 10, 13, 10)],
  ]);
  const hash = options.badHash ? new Uint8Array(32).fill(0xab) : await sha256(header);
  return concatBytes(header, hash, new Uint8Array(32), new Uint8Array(36));
}

// ---------------------------------------------------------------------------

describe("Gegenprobe: absurde KDF-Parameter", () => {
  it("Regression: zu großer Arbeitsaufwand (Speicher × Iterationen) wird abgelehnt", () => {
    // Alle diese Werte liegen innerhalb der Einzelgrenzen (Iterationen <= INT_MAX-1,
    // Speicher <= 1 GiB), würden hash-wasm aber Stunden bis Jahre rechnen lassen – und
    // hash-wasm blockiert dabei den ganzen Thread (Service Worker eingefroren).
    const absurd = [
      argon2({ memoryBytes: 8 * 1024, parallelism: 1, iterations: KDF_LIMITS.maxRounds }),
      argon2({ memoryBytes: 1024 ** 3, iterations: 1000 }),
      argon2({ memoryBytes: 64 * 1024 ** 2, iterations: 100_000 }),
      argon2({ type: "argon2d", memoryBytes: 1024 ** 3, iterations: 64 }),
    ];
    for (const params of absurd) {
      expect(() => validateKdfParams(params), `M=${params.memoryBytes} I=${params.iterations}`).toThrow(
        code("UnsupportedKdf"),
      );
    }
    // … auch beim Lesen aus dem Header (vor jeder Rechnung)
    expect(() => parseKdfParameters(rawArgon2Dict(BigInt(KDF_LIMITS.maxRounds), 8192n, 1))).toThrow(code("UnsupportedKdf"));
    expect(() => parseKdfParameters(rawArgon2Dict(1_000_000n, 64n * 1024n * 1024n, 4))).toThrow(code("UnsupportedKdf"));
  });

  it("übliche und großzügige echte Einstellungen bleiben erlaubt", () => {
    const usual = [
      argon2({ memoryBytes: 1024 ** 2, iterations: 2, parallelism: 2 }), // KeePass-Standard
      argon2({ memoryBytes: 64 * 1024 ** 2, iterations: 3, parallelism: 2 }), // Ownwarden-Standard
      argon2({ memoryBytes: 64 * 1024 ** 2, iterations: 500, parallelism: 8 }), // KeePassXC, 5 s auf schnellem PC
      argon2({ memoryBytes: 1024 ** 3, iterations: 10, parallelism: 4 }), // 1 GiB
      argon2({ memoryBytes: 1024 ** 2, iterations: 10_000, parallelism: 2 }), // KeePassXC-Warnschwelle
      argon2({ memoryBytes: 8 * 1024, iterations: 1_000_000, parallelism: 1 }),
    ];
    for (const params of usual) {
      expect(() => validateKdfParams(params), `M=${params.memoryBytes} I=${params.iterations}`).not.toThrow();
    }
  });

  it("Regression: decryptContainer lehnt einen Fremd-Header mit 2^31 Argon2-Iterationen sofort ab", { timeout: 10_000 }, async () => {
    // Korrekte Header-SHA-256: Nur die Parameterprüfung kann die Rechnung noch verhindern.
    const file = await rawFile(rawArgon2Dict(BigInt(KDF_LIMITS.maxRounds), 64n * 1024n * 1024n, 2));
    const start = performance.now();
    await expect(decryptContainer(file, PASSWORD)).rejects.toThrow(code("UnsupportedKdf"));
    expect(performance.now() - start).toBeLessThan(2000);
  });
});

describe("Gegenprobe: Reihenfolge der Prüfungen", () => {
  it("falsche Header-SHA-256 fällt VOR der (hier ~1,5 min teuren) AES-KDF auf", { timeout: 10_000 }, async () => {
    const expensive = serializeKdfParameters({ type: "aes", seed: new Uint8Array(32), rounds: KDF_LIMITS.maxRounds });
    const start = performance.now();
    await expect(decryptContainer(await rawFile(expensive, { badHash: true }), PASSWORD)).rejects.toThrow(code("Corrupt"));
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it("geänderter Header mit neu berechneter SHA-256 scheitert am Header-HMAC", async () => {
    const file = await encryptContainer(payload({ compression: true }), PASSWORD);
    const { headerBytes } = parseOuterHeader(file);
    // CompressionFlags-Daten: 12 Byte Signatur/Version + Feld 2 (1+4+16) + ID/Länge von Feld 3 (1+4)
    const tampered = file.slice();
    expect(tampered[38]).toBe(1);
    tampered[38] = 0;
    tampered.set(await sha256(tampered.subarray(0, headerBytes.length)), headerBytes.length);
    await expect(decryptContainer(tampered, PASSWORD)).rejects.toThrow(code("InvalidCredentials"));
  });

  it("ein kaputter letzter Datenblock wird am Block-HMAC erkannt, nicht erst am AES-Padding", async () => {
    const file = await encryptContainer(payload({ cipher: "aes256" }), PASSWORD);
    const tampered = file.slice();
    tampered[file.length - 36 - 1]! ^= 0x01; // letztes Chiffretext-Byte = Padding-Block
    await expect(decryptContainer(tampered, PASSWORD)).rejects.toThrow(/HMAC passt nicht/);
  });
});

describe("Gegenprobe: feindliche Längenangaben", () => {
  const MAX_U32 = 0xffffffff;

  it("äußerer Header: Feldlänge 2^32-1 und VariantDictionary-Längen 2^32-1 -> Corrupt", () => {
    const hugeField = new ByteWriter()
      .writeBytes(rawHeader([[HeaderFieldId.CipherId, uuidToBytes(CIPHER_UUID.aes256)]]))
      .writeU8(99)
      .writeU32(MAX_U32)
      .writeBytes(Uint8Array.of(1, 2, 3))
      .toBytes();
    expect(() => parseOuterHeader(hugeField)).toThrow(code("Corrupt"));

    // KDF-Parameter mit einem Namen, der angeblich 4 GiB lang ist
    const dict = new ByteWriter().writeU16(0x0100).writeU8(0x42).writeU32(MAX_U32).writeBytes(utf8Encode("$UUID")).toBytes();
    expect(() => parseOuterHeader(rawHeader([[HeaderFieldId.KdfParameters, dict]]))).toThrow(code("Corrupt"));
    // … und mit einem Wert, der angeblich 4 GiB lang ist
    const dictValue = new ByteWriter()
      .writeU16(0x0100)
      .writeU8(0x42)
      .writeU32(1)
      .writeBytes(utf8Encode("S"))
      .writeU32(MAX_U32)
      .writeBytes(new Uint8Array(8))
      .toBytes();
    expect(() => parseKdfParameters(dictValue)).toThrow(code("Corrupt"));
  });

  it("innerer Header: Feld- und Anhanglänge 2^32-1 -> Corrupt", () => {
    const streamId = new ByteWriter().writeU8(1).writeU32(4).writeU32(3).toBytes();
    for (const fieldId of [2, 3, 0]) {
      const bytes = concatBytes(streamId, new ByteWriter().writeU8(fieldId).writeU32(MAX_U32).writeU8(1).toBytes());
      expect(() => parseInnerHeader(bytes), `Feld ${fieldId}`).toThrow(code("Corrupt"));
    }
  });

  it("Datei endet mitten in Header-SHA-256 bzw. Header-HMAC -> Corrupt", async () => {
    const file = await encryptContainer(payload(), PASSWORD);
    const headerLength = parseOuterHeader(file).headerBytes.length;
    for (const cut of [headerLength, headerLength + 31, headerLength + 63]) {
      await expect(decryptContainer(file.subarray(0, cut), PASSWORD), `bei ${cut}`).rejects.toThrow(code("Corrupt"));
    }
  });
});

describe("Gegenprobe: Puffer-Sichten", () => {
  it("liest eine Datei, die mit krummem Offset in einem größeren Puffer liegt; Ergebnis hängt nicht am Puffer", async () => {
    const publicCustomData = serializeVariantDictionary(new Map([["x", { type: "string", value: "y" }]]));
    const original = payload({ publicCustomData, kdf: argon2() });
    const file = await encryptContainer(original, PASSWORD);
    const backing = new Uint8Array(file.length + 7);
    backing.set(file, 3);
    const decrypted = await decryptContainer(backing.subarray(3, 3 + file.length), PASSWORD);
    expect(utf8Decode(decrypted.xml)).toBe(utf8Decode(original.xml));

    const kdf = decrypted.settings.kdf as Argon2Params;
    const saltBefore = kdf.salt.slice();
    backing.fill(0);
    expect(kdf.salt).toEqual(saltBefore);
    expect(decrypted.settings.publicCustomData).toEqual(publicCustomData);
  });
});

describe("Gegenprobe: frische Zufallswerte beim Speichern", () => {
  it.each<[CipherId, KdfParams]>([
    ["aes256", FAST_AES],
    ["chacha20", FAST_AES],
    ["chacha20", argon2()],
  ])("%s / KDF %#: neuer Master-Seed, IV (richtige Länge), KDF-Salt; Eingabe unverändert", async (cipher, kdf) => {
    const original = payload({ cipher, kdf });
    const inputSalt = (kdf.type === "aes" ? kdf.seed : kdf.salt).slice();
    const [fileA, fileB] = [await encryptContainer(original, PASSWORD), await encryptContainer(original, PASSWORD)];
    const a = parseOuterHeader(fileA);
    const b = parseOuterHeader(fileB);
    const saltOf = (p: KdfParams) => (p.type === "aes" ? p.seed : p.salt);

    expect(a.header.encryptionIv.length).toBe(ENCRYPTION_IV_LENGTH[cipher as "aes256" | "chacha20"]);
    expect(b.header.encryptionIv.length).toBe(a.header.encryptionIv.length);
    expect(a.header.masterSeed).not.toEqual(b.header.masterSeed);
    expect(a.header.encryptionIv).not.toEqual(b.header.encryptionIv);
    expect(saltOf(a.header.kdf)).not.toEqual(saltOf(b.header.kdf));
    expect(saltOf(a.header.kdf)).not.toEqual(inputSalt);
    expect(saltOf(a.header.kdf).length).toBe(32);
    // Der erste Chiffretext-Block unterscheidet sich ebenfalls.
    const firstBlock = (f: Uint8Array, h: number) => f.subarray(h + 64 + 36, h + 64 + 36 + 64);
    expect(firstBlock(fileA, a.headerBytes.length)).not.toEqual(firstBlock(fileB, b.headerBytes.length));
    // Die Einstellungen des Aufrufers werden nicht verändert.
    expect(saltOf(original.settings.kdf)).toEqual(inputSalt);
  });
});

describe("Gegenprobe: Bibliothekscode läuft auch im Service Worker", () => {
  // Nur die Dateien dieser Stufe (Container); andere Teile prüfen ihre Dateien selbst.
  const STAGE_FILES = [
    "bytes.ts",
    "compression.ts",
    "constants.ts",
    "container.ts",
    "crypto.ts",
    "header.ts",
    "hmac-block-stream.ts",
    "inner-header.ts",
    "inner-stream.ts",
    "kdf.ts",
    "keys.ts",
    "settings.ts",
    "variant-dictionary.ts",
  ];
  const FORBIDDEN: [RegExp, string][] = [
    [/from\s+["']node:|import\(\s*["']node:/, "node:-Import"],
    [/from\s+["'](fs|path|os|zlib|crypto|child_process|buffer)["']/, "Node-Modul"],
    [/\brequire\(/, "require()"],
    [/\bBuffer\b/, "Buffer"],
    [/\bprocess\./, "process"],
    [/\bMath\.random\b/, "Math.random"],
    [/\bconsole\./, "console (könnte Geheimnisse protokollieren)"],
  ];

  it.each(STAGE_FILES)("%s nutzt keine Node-APIs, kein Math.random und protokolliert nichts", (file) => {
    const source = readFileSync(new URL(file, import.meta.url), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "") // Blockkommentare
      .replace(/^\s*\/\/.*$/gm, ""); // Zeilenkommentare
    for (const [pattern, what] of FORBIDDEN) {
      expect(pattern.test(source), `${file}: ${what}`).toBe(false);
    }
  });
});

describe("Gegenprobe: GZip", () => {
  it("abgeschnittene GZip-Daten und falsche CRC -> Corrupt (nicht stillschweigend gekürzt)", async () => {
    const packed = await gzip(utf8Encode("Hallo ".repeat(2000)));
    await expect(gunzip(packed.subarray(0, packed.length - 8))).rejects.toThrow(code("Corrupt"));
    await expect(gunzip(packed.subarray(0, packed.length >> 1))).rejects.toThrow(code("Corrupt"));
    const badCrc = packed.slice();
    badCrc[badCrc.length - 6]! ^= 0x01;
    await expect(gunzip(badCrc)).rejects.toThrow(code("Corrupt"));
  });
});
