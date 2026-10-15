import { createHash } from "node:crypto";
import { chacha20 } from "@noble/ciphers/chacha.js";
import { salsa20 } from "@noble/ciphers/salsa.js";
import { describe, expect, it } from "vitest";
import { utf8Decode, utf8Encode } from "./bytes";
import { createInnerStream, newInnerStreamKey } from "./inner-stream";

const KEY = Uint8Array.from({ length: 64 }, (_, i) => i);
const DATA = Uint8Array.from({ length: 300 }, (_, i) => (i * 13) & 0xff);

/** Unabhängig berechneter Schlüsselstrom (Schlüsselableitung mit Node-Krypto). */
function referenceKeystream(id: "chacha20" | "salsa20", length: number): Uint8Array {
  if (id === "chacha20") {
    const hash = createHash("sha512").update(KEY).digest();
    return chacha20(new Uint8Array(hash.subarray(0, 32)), new Uint8Array(hash.subarray(32, 44)), new Uint8Array(length));
  }
  const key = new Uint8Array(createHash("sha256").update(KEY).digest());
  const nonce = Uint8Array.of(0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a);
  return salsa20(key, nonce, new Uint8Array(length));
}

describe.each(["chacha20", "salsa20"] as const)("Innerer Zufallsstrom %s", (id) => {
  it("Schlüsselstrom entspricht der KeePass-Ableitung", () => {
    const keystream = createInnerStream(id, KEY).process(new Uint8Array(200));
    expect(keystream).toEqual(referenceKeystream(id, 200));
  });

  it("setzt den Strom über mehrere Aufrufe fort (beginnt nicht neu)", () => {
    const whole = createInnerStream(id, KEY).process(DATA);
    const stream = createInnerStream(id, KEY);
    // Stückelung über Blockgrenzen (64 Byte) hinweg, auch leere Stücke
    const pieces = [0, 1, 5, 58, 0, 64, 65, 107];
    const parts: number[] = [];
    let offset = 0;
    for (const length of pieces) {
      parts.push(...stream.process(DATA.subarray(offset, offset + length)));
      offset += length;
    }
    expect(offset).toBe(DATA.length);
    expect(Uint8Array.from(parts)).toEqual(whole);
  });

  it("Verschlüsseln und Entschlüsseln sind dieselbe Operation; Eingabe bleibt unverändert", () => {
    const secret = utf8Encode("Geheimes Passwort äöü");
    const copy = secret.slice();
    const encrypted = createInnerStream(id, KEY).process(secret);
    expect(secret).toEqual(copy);
    expect(encrypted).not.toEqual(secret);
    expect(utf8Decode(createInnerStream(id, KEY).process(encrypted))).toBe("Geheimes Passwort äöü");
  });
});

describe("createInnerStream / newInnerStreamKey", () => {
  it("lehnt unbekannte Ströme ab", () => {
    expect(() => createInnerStream("arcfour" as never, KEY)).toThrow(expect.objectContaining({ code: "UnsupportedInnerStream" }));
  });

  it("ChaCha20 und Salsa20 liefern verschiedene Ströme", () => {
    expect(createInnerStream("chacha20", KEY).process(new Uint8Array(32))).not.toEqual(
      createInnerStream("salsa20", KEY).process(new Uint8Array(32)),
    );
  });

  it("newInnerStreamKey liefert 64 zufällige Bytes", () => {
    const a = newInnerStreamKey();
    const b = newInnerStreamKey();
    expect(a.length).toBe(64);
    expect(a).not.toEqual(b);
  });
});
