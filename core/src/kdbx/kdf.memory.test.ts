/**
 * Argon2-Fehler von hash-wasm (eigene Datei, weil hash-wasm hier für alle Tests ersetzt wird).
 */
import { describe, expect, it, vi } from "vitest";
import { transformKey } from "./kdf";

vi.mock("hash-wasm", () => {
  // So scheitert hash-wasm 4.12, wenn es den WebAssembly-Speicher nicht anlegen kann.
  const fail = async () => {
    throw new RangeError("Invalid typed array length: 2147484672");
  };
  return { argon2d: fail, argon2id: fail };
});

describe("Argon2: Speicher lässt sich nicht reservieren", () => {
  it("meldet das verständlich statt mit der Meldung von hash-wasm (Sicherheitsaudit crypto-6)", async () => {
    const params = { type: "argon2id", salt: new Uint8Array(32), parallelism: 1, memoryBytes: 512 * 1024 * 1024, iterations: 1, version: 0x13 } as const;
    const error = await transformKey(new Uint8Array(32), params).catch((e: unknown) => e);
    expect(error).toMatchObject({ name: "KdbxError", code: "UnsupportedKdf" });
    expect((error as Error).message).toMatch(/512 MiB Arbeitsspeicher/);
    expect((error as Error).message).toMatch(/weniger Speicher/);
    expect((error as Error).message).not.toMatch(/typed array/);
  });
});
