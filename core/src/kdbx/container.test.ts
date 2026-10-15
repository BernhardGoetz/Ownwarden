import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { DecryptedPayload } from "../contracts";
import type { CipherId, KdbxSettings, KdfParams } from "../model";
import { utf8Encode } from "./bytes";
import { gunzip, gzip } from "./compression";
import { decryptContainer, defaultKdbxSettings, encryptContainer } from "./container";
import { aesCbcDecrypt } from "./crypto";
import { parseOuterHeader } from "./header";
import { compositeKey } from "./keys";
import { serializeVariantDictionary } from "./variant-dictionary";

const code = (c: string) => expect.objectContaining({ code: c });
/** Schneller Vergleich großer Byte-Arrays (toEqual braucht bei MiB-Größen Sekunden). */
const sameBytes = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const PASSWORD = { password: "Test-Passwort-ÄÖÜ" };

const FAST_AES: KdfParams = { type: "aes", seed: new Uint8Array(32).fill(1), rounds: 100 };
const FAST_ARGON2ID: KdfParams = {
  type: "argon2id",
  salt: new Uint8Array(32).fill(2),
  parallelism: 1,
  memoryBytes: 64 * 1024,
  iterations: 1,
  version: 0x13,
};
const FAST_ARGON2D: KdfParams = { ...FAST_ARGON2ID, type: "argon2d" };

function payload(settings: Partial<KdbxSettings> = {}): DecryptedPayload {
  return {
    settings: { versionMinor: 0, cipher: "aes256", compression: true, kdf: FAST_AES, ...settings },
    innerStreamId: "chacha20",
    innerStreamKey: new Uint8Array(64).fill(5),
    binaries: [
      { data: utf8Encode("Anhang 1"), protected: true },
      { data: new Uint8Array(3000).fill(7), protected: false },
    ],
    xml: utf8Encode(`<?xml version="1.0" encoding="UTF-8"?><KeePassFile>${"<Entry/>".repeat(500)}</KeePassFile>`),
  };
}

/** Vergleicht zwei Payloads, ohne den (bei jedem Speichern neuen) KDF-Salt. */
function withoutSalt(p: DecryptedPayload) {
  const kdf = { ...p.settings.kdf } as Record<string, unknown>;
  delete kdf.salt;
  delete kdf.seed;
  return { ...p, settings: { ...p.settings, kdf } };
}

describe("Container: Rundreise", () => {
  const cases: { cipher: CipherId; kdf: KdfParams; compression: boolean; versionMinor: 0 | 1 }[] = [
    { cipher: "aes256", kdf: FAST_AES, compression: true, versionMinor: 0 },
    { cipher: "aes256", kdf: FAST_ARGON2ID, compression: false, versionMinor: 1 },
    { cipher: "chacha20", kdf: FAST_ARGON2D, compression: true, versionMinor: 1 },
    { cipher: "chacha20", kdf: FAST_AES, compression: false, versionMinor: 0 },
  ];

  it.each(cases)("$cipher / $kdf.type / gzip=$compression / 4.$versionMinor", async (settings) => {
    const original = payload(settings);
    const file = await encryptContainer(original, PASSWORD);
    const decrypted = await decryptContainer(file, PASSWORD);
    expect(withoutSalt(decrypted)).toEqual(withoutSalt(original));
  });

  it("erzeugt bei jedem Speichern neuen Master-Seed, IV und KDF-Salt", async () => {
    const original = payload({ kdf: FAST_ARGON2ID });
    const a = parseOuterHeader(await encryptContainer(original, PASSWORD)).header;
    const b = parseOuterHeader(await encryptContainer(original, PASSWORD)).header;
    expect(a.masterSeed).not.toEqual(b.masterSeed);
    expect(a.encryptionIv).not.toEqual(b.encryptionIv);
    const saltA = a.kdf.type === "aes" ? a.kdf.seed : a.kdf.salt;
    const saltB = b.kdf.type === "aes" ? b.kdf.seed : b.kdf.salt;
    expect(saltA).not.toEqual(saltB);
    expect(saltA).not.toEqual(FAST_ARGON2ID.salt);
    // die übrigen KDF-Parameter bleiben
    expect(a.kdf).toMatchObject({ type: "argon2id", memoryBytes: 64 * 1024, iterations: 1, parallelism: 1 });
  });

  it("reicht PublicCustomData unverändert durch", async () => {
    const publicCustomData = serializeVariantDictionary(new Map([["Plugin.Info", { type: "string", value: "öffentlich" }]]));
    const decrypted = await decryptContainer(await encryptContainer(payload({ publicCustomData }), PASSWORD), PASSWORD);
    expect(decrypted.settings.publicCustomData).toEqual(publicCustomData);
  });

  it("schreibt Daten größer als ein HMAC-Block (1 MiB)", async () => {
    const big = { ...payload({ compression: false }), binaries: [{ data: new Uint8Array(1_500_000).fill(3), protected: false }] };
    const decrypted = await decryptContainer(await encryptContainer(big, PASSWORD), PASSWORD);
    expect(sameBytes(decrypted.binaries[0]!.data, big.binaries[0]!.data)).toBe(true);
  });

  it("defaultKdbxSettings: Argon2id 64 MiB / 3 / 2, AES-256, GZip, KDBX 4.0", async () => {
    const settings = defaultKdbxSettings();
    expect(settings).toMatchObject({
      versionMinor: 0,
      cipher: "aes256",
      compression: true,
      kdf: { type: "argon2id", memoryBytes: 64 * 1024 * 1024, iterations: 3, parallelism: 2, version: 0x13 },
    });
    expect(settings.publicCustomData).toBeUndefined();
    const salts = [defaultKdbxSettings(), settings].map((s) => (s.kdf.type === "aes" ? s.kdf.seed : s.kdf.salt));
    expect(salts[0]).not.toEqual(salts[1]);

    const decrypted = await decryptContainer(await encryptContainer(payload({ ...settings }), PASSWORD), PASSWORD);
    expect(decrypted.settings.kdf.type).toBe("argon2id");
  });
});

describe("Container: Zugangsdaten", () => {
  it("zusammengesetzter Schlüssel = SHA-256(SHA-256(Passwort) || Schlüsseldatei)", async () => {
    const sha = (...parts: Uint8Array[]) => {
      const h = createHash("sha256");
      for (const p of parts) h.update(p);
      return new Uint8Array(h.digest());
    };
    const keyFileKey = new Uint8Array(32).fill(4);
    const pw = utf8Encode("pw");
    expect(await compositeKey({ password: "pw" })).toEqual(sha(sha(pw)));
    expect(await compositeKey({ password: "pw", keyFileKey })).toEqual(sha(sha(pw), keyFileKey));
    expect(await compositeKey({ keyFileKey })).toEqual(sha(keyFileKey));
    // Leeres Passwort ist ein Passwort, kein fehlendes
    expect(await compositeKey({ password: "" })).toEqual(sha(sha(new Uint8Array(0))));
    await expect(compositeKey({})).rejects.toThrow(code("InvalidCredentials"));
    await expect(compositeKey({ keyFileKey: new Uint8Array(31) })).rejects.toThrow(code("InvalidCredentials"));
  });

  it("falsches Passwort -> InvalidCredentials", async () => {
    const file = await encryptContainer(payload(), PASSWORD);
    await expect(decryptContainer(file, { password: "falsch" })).rejects.toThrow(code("InvalidCredentials"));
    await expect(decryptContainer(file, { password: "" })).rejects.toThrow(code("InvalidCredentials"));
  });

  it("Schlüsseldatei allein und mit Passwort", async () => {
    const keyFileKey = new Uint8Array(32).fill(8);
    const fileOnly = await encryptContainer(payload(), { keyFileKey });
    await expect(decryptContainer(fileOnly, { keyFileKey })).resolves.toBeDefined();
    await expect(decryptContainer(fileOnly, PASSWORD)).rejects.toThrow(code("InvalidCredentials"));

    const both = await encryptContainer(payload(), { ...PASSWORD, keyFileKey });
    await expect(decryptContainer(both, { ...PASSWORD, keyFileKey })).resolves.toBeDefined();
    await expect(decryptContainer(both, PASSWORD)).rejects.toThrow(code("InvalidCredentials"));
  });
});

describe("Container: Beschädigung", () => {
  it("unterscheidet Header-Schaden, falschen HMAC und Block-Schaden", async () => {
    const file = await encryptContainer(payload(), PASSWORD);
    const headerLength = parseOuterHeader(file).headerBytes.length;
    const flip = (index: number) => {
      const copy = file.slice();
      copy[index]! ^= 0x01;
      return copy;
    };

    // Master-Seed im Header (Feld 4 beginnt nach Signatur, Version, Feld 2 und 3)
    await expect(decryptContainer(flip(12 + 21 + 9 + 10), PASSWORD)).rejects.toThrow(code("Corrupt"));
    // gespeicherte Header-Prüfsumme
    await expect(decryptContainer(flip(headerLength + 5), PASSWORD)).rejects.toThrow(code("Corrupt"));
    // gespeicherter Header-HMAC: nicht von falschem Passwort zu unterscheiden
    await expect(decryptContainer(flip(headerLength + 40), PASSWORD)).rejects.toThrow(code("InvalidCredentials"));
    // Daten im ersten Block, und Daten kurz vor dem Endblock (36 Byte)
    await expect(decryptContainer(flip(headerLength + 64 + 36 + 10), PASSWORD)).rejects.toThrow(code("Corrupt"));
    await expect(decryptContainer(flip(file.length - 36 - 5), PASSWORD)).rejects.toThrow(code("Corrupt"));
    // abgeschnitten
    await expect(decryptContainer(file.subarray(0, file.length - 36), PASSWORD)).rejects.toThrow(code("Corrupt"));
    await expect(decryptContainer(file.subarray(0, headerLength + 10), PASSWORD)).rejects.toThrow(code("Corrupt"));
  });

  it("lehnt nicht schreibbare Einstellungen ab", async () => {
    await expect(encryptContainer(payload({ cipher: "twofish" }), PASSWORD)).rejects.toThrow(code("UnsupportedCipher"));
    await expect(encryptContainer(payload({ kdf: { ...FAST_ARGON2ID, version: 0x10 } }), PASSWORD)).rejects.toThrow(
      code("UnsupportedKdf"),
    );
    await expect(encryptContainer({ ...payload(), innerStreamId: "rc4" as never }, PASSWORD)).rejects.toThrow(
      code("UnsupportedInnerStream"),
    );
  });
});

describe("Kompression und AES-Hilfen", () => {
  it("GZip-Rundreise und Größenbremse beim Entpacken", async () => {
    const data = new Uint8Array(1024 * 1024);
    const packed = await gzip(data);
    expect(packed.length).toBeLessThan(10_000);
    expect(sameBytes(await gunzip(packed), data)).toBe(true);
    await expect(gunzip(packed, 1000)).rejects.toThrow(code("Corrupt"));
    await expect(gunzip(Uint8Array.of(1, 2, 3, 4))).rejects.toThrow(code("Corrupt"));
  });

  it("AES-CBC mit kaputter Länge -> Corrupt", async () => {
    await expect(aesCbcDecrypt(new Uint8Array(32), new Uint8Array(16), new Uint8Array(15))).rejects.toThrow(code("Corrupt"));
  });
});
