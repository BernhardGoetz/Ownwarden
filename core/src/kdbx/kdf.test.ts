import { createHash } from "node:crypto";
import { ecb } from "@noble/ciphers/aes.js";
import { argon2d as nobleArgon2d, argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";
import { describe, expect, it } from "vitest";
import type { KdfParams } from "../model";
import { uuidToBytes } from "./bytes";
import { KDF_UUID } from "./constants";
import { aesKdf, parseKdfParameters, serializeKdfParameters, transformKey, validateKdfParams, withFreshKdfSalt } from "./kdf";
import { parseVariantDictionary, serializeVariantDictionary, type VariantDictionary, type VariantValue } from "./variant-dictionary";

const corrupt = expect.objectContaining({ code: "Corrupt" });
const unsupportedKdf = expect.objectContaining({ code: "UnsupportedKdf" });

/** Der Argon2-Zweig von KdfParams (type ist dort "argon2d" | "argon2id"). */
type Argon2Params = Extract<KdfParams, { salt: Uint8Array }>;

const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);
const SEED = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

/** Unabhängige Referenz: AES-KDF Block für Block mit AES-ECB aus @noble/ciphers. */
function referenceAesKdf(key: Uint8Array, seed: Uint8Array, rounds: number): Uint8Array {
  // noble erlaubt pro Instanz nur einen encrypt()-Aufruf, daher je Runde eine neue.
  let state = key.slice();
  for (let i = 0; i < rounds; i++) state = ecb(seed, { disablePadding: true }).encrypt(state);
  return new Uint8Array(createHash("sha256").update(state).digest());
}

function argon2Params(overrides: Partial<Argon2Params> = {}): Argon2Params {
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

function dictWith(entries: [string, VariantValue][]): Uint8Array {
  return serializeVariantDictionary(new Map(entries) as VariantDictionary);
}

describe("AES-KDF", () => {
  it.each([1, 2, 3, 5, 1000])("stimmt mit AES-ECB-Referenz überein (%i Runden, kleine Chunks)", async (rounds) => {
    // Chunk-Größe 2 testet die Übergänge zwischen WebCrypto-Aufrufen.
    expect(await aesKdf(KEY, SEED, rounds, 2)).toEqual(referenceAesKdf(KEY, SEED, rounds));
  });

  it("stimmt über die Standard-Chunkgrenze (65536 Blöcke) hinweg", async () => {
    const rounds = 65536 + 3;
    expect(await aesKdf(KEY, SEED, rounds)).toEqual(referenceAesKdf(KEY, SEED, rounds));
  });

  it("transformKey nutzt AES-KDF für type aes", async () => {
    const params: KdfParams = { type: "aes", seed: SEED, rounds: 10 };
    expect(await transformKey(KEY, params)).toEqual(referenceAesKdf(KEY, SEED, 10));
  });
});

describe("Argon2", () => {
  // Gegenprobe mit einer zweiten, unabhängigen Argon2-Implementierung (@noble/hashes).
  it.each(["argon2d", "argon2id"] as const)("%s stimmt mit @noble/hashes überein", async (type) => {
    // Speicher absichtlich kein Vielfaches von 1024: KDBX/KeePassXC runden auf KiB ab.
    const params = argon2Params({ memoryBytes: 64 * 1024 + 500, type });
    const reference = (type === "argon2d" ? nobleArgon2d : nobleArgon2id)(KEY, params.salt, {
      t: params.iterations,
      m: 64,
      p: params.parallelism,
      dkLen: 32,
      version: 0x13,
    });
    expect(await transformKey(KEY, params)).toEqual(reference);
  });

  it("argon2d und argon2id ergeben verschiedene Schlüssel", async () => {
    const id = await transformKey(KEY, argon2Params());
    const d = await transformKey(KEY, argon2Params({ type: "argon2d" }));
    expect(id).not.toEqual(d);
  });
});

describe("KDF-Parameter lesen und schreiben", () => {
  it("Argon2: Rundreise und Typen wie KeePassXC", () => {
    const params = argon2Params({ memoryBytes: 64 * 1024 * 1024, iterations: 3 });
    const bytes = serializeKdfParameters(params);
    expect(parseKdfParameters(bytes)).toEqual(params);

    const dict = parseVariantDictionary(bytes);
    expect([...dict.keys()]).toEqual(["$UUID", "I", "M", "P", "S", "V"]);
    expect(dict.get("$UUID")).toEqual({ type: "bytes", value: uuidToBytes(KDF_UUID.argon2id) });
    expect(dict.get("M")).toEqual({ type: "uint64", value: 64n * 1024n * 1024n });
    expect(dict.get("I")?.type).toBe("uint64");
    expect(dict.get("P")?.type).toBe("uint32");
    expect(dict.get("V")).toEqual({ type: "uint32", value: 0x13 });
  });

  it("AES-KDF: schreibt die alte KeePass-UUID, liest beide UUIDs", () => {
    const params: KdfParams = { type: "aes", seed: SEED, rounds: 6_000_000 };
    const bytes = serializeKdfParameters(params);
    const dict = parseVariantDictionary(bytes);
    expect(dict.get("$UUID")).toEqual({ type: "bytes", value: uuidToBytes(KDF_UUID.aesKdbx3) });
    expect(dict.get("R")).toEqual({ type: "uint64", value: 6_000_000n });
    expect(parseKdfParameters(bytes)).toEqual(params);

    const kdbx4Uuid = dictWith([
      ["$UUID", { type: "bytes", value: uuidToBytes(KDF_UUID.aesKdbx4) }],
      ["R", { type: "uint64", value: 10n }],
      ["S", { type: "bytes", value: SEED }],
    ]);
    expect(parseKdfParameters(kdbx4Uuid)).toEqual({ type: "aes", seed: SEED, rounds: 10 });
  });

  it("ist bei Zahlentypen nachsichtig (wie KeePassXC)", () => {
    const bytes = dictWith([
      ["$UUID", { type: "bytes", value: uuidToBytes(KDF_UUID.argon2d) }],
      ["S", { type: "bytes", value: new Uint8Array(16) }],
      ["P", { type: "uint64", value: 1n }],
      ["M", { type: "uint32", value: 1024 * 1024 }],
      ["I", { type: "int32", value: 2 }],
      ["V", { type: "uint64", value: 0x13n }],
      ["K", { type: "bytes", value: new Uint8Array(0) }], // leer = erlaubt
    ]);
    expect(parseKdfParameters(bytes)).toMatchObject({ type: "argon2d", parallelism: 1, memoryBytes: 1024 * 1024 });
  });

  it("lehnt Unbekanntes und Ungültiges ab", () => {
    const base: [string, VariantValue][] = [
      ["$UUID", { type: "bytes", value: uuidToBytes(KDF_UUID.argon2id) }],
      ["S", { type: "bytes", value: new Uint8Array(32) }],
      ["P", { type: "uint32", value: 2 }],
      ["M", { type: "uint64", value: 1024n * 1024n }],
      ["I", { type: "uint64", value: 2n }],
      ["V", { type: "uint32", value: 0x13 }],
    ];
    const replace = (key: string, value: VariantValue | undefined) => {
      const map = new Map(base);
      if (value === undefined) map.delete(key);
      else map.set(key, value);
      return serializeVariantDictionary(map);
    };

    expect(() => parseKdfParameters(replace("$UUID", { type: "bytes", value: new Uint8Array(16) }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("$UUID", undefined))).toThrow(corrupt);
    expect(() => parseKdfParameters(replace("S", undefined))).toThrow(corrupt);
    expect(() => parseKdfParameters(replace("S", { type: "string", value: "x" }))).toThrow(corrupt);
    expect(() => parseKdfParameters(replace("V", { type: "uint32", value: 0x10 }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("K", { type: "bytes", value: Uint8Array.of(1) }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("A", { type: "bytes", value: Uint8Array.of(1) }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("P", { type: "uint32", value: 0 }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("I", { type: "uint64", value: 0n }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("I", { type: "uint64", value: 2n ** 63n }))).toThrow(unsupportedKdf);
    expect(() => parseKdfParameters(replace("M", { type: "uint64", value: 1024n }))).toThrow(unsupportedKdf);
    // 3 TiB Speicher: würde den Browser lahmlegen
    expect(() => parseKdfParameters(replace("M", { type: "uint64", value: 3n << 40n }))).toThrow(unsupportedKdf);
    // Salt kürzer als 8 Byte
    expect(() => parseKdfParameters(replace("S", { type: "bytes", value: new Uint8Array(4) }))).toThrow(unsupportedKdf);
    // weniger als 8 KiB je Spur
    expect(() =>
      parseKdfParameters(replace("P", { type: "uint32", value: 200 })),
    ).toThrow(unsupportedKdf);
  });

  it("AES-KDF verlangt einen 32-Byte-Seed und gültige Runden", () => {
    expect(() => validateKdfParams({ type: "aes", seed: new Uint8Array(16), rounds: 1 })).toThrow(unsupportedKdf);
    expect(() => validateKdfParams({ type: "aes", seed: SEED, rounds: 0 })).toThrow(unsupportedKdf);
    expect(() => validateKdfParams({ type: "aes", seed: SEED, rounds: 1.5 })).toThrow(unsupportedKdf);
    expect(() => serializeKdfParameters({ type: "aes", seed: SEED, rounds: -1 })).toThrow(unsupportedKdf);
  });
});

describe("withFreshKdfSalt", () => {
  it("erneuert Salt bzw. Seed und behält alles andere", () => {
    const argon = argon2Params();
    const freshArgon = withFreshKdfSalt(argon);
    expect(freshArgon).toMatchObject({ ...argon, salt: expect.any(Uint8Array) });
    expect(freshArgon.type !== "aes" && freshArgon.salt).not.toEqual(argon.salt);

    const aes: KdfParams = { type: "aes", seed: SEED, rounds: 42 };
    const freshAes = withFreshKdfSalt(aes);
    expect(freshAes.type === "aes" && freshAes.rounds).toBe(42);
    expect(freshAes.type === "aes" && freshAes.seed.length).toBe(32);
    expect(freshAes.type === "aes" && freshAes.seed).not.toEqual(SEED);
  });
});
