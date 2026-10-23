/**
 * Geheime Zwischenwerte werden nach Gebrauch überschrieben (Sicherheitsaudit crypto-5).
 *
 * Die Tests zeichnen jeden Puffer auf, der an WebCrypto geht oder von dort kommt (und die
 * Zufallswerte), und prüfen NACH readKdbx/writeKdbx: Jeder dieser Puffer ist entweder öffentlich
 * (steht so auch in der Datei, z. B. Header oder Seed) oder mit Nullen überschrieben. Was
 * JavaScript nicht erreicht (Kopien in WebCrypto, CryptoKey-Objekte, hash-wasm, Strings im
 * Modell), prüfen sie nicht.
 */
import { describe, expect, it } from "vitest";
import type { KdfParams } from "../model";
import { createVaultClock } from "../merge/clock";
import { createEntry } from "../merge/vault-ops";
import { createNewVault, readKdbx, writeKdbx } from "./index";

const CREDENTIALS = { password: "Lösch-Test" };
const SECRET = "Geheimnis-im-Tresor-4711";
/** AES-KDF, damit auch die Zwischenstände der AES-KDF (WebCrypto) geprüft werden. */
const AES_KDF: KdfParams = { type: "aes", seed: new Uint8Array(32).fill(9), rounds: 1000 };

interface Recorded {
  what: string;
  bytes: Uint8Array;
}

const asBytes = (data: BufferSource): Uint8Array =>
  ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);

/** Ersetzt die WebCrypto-Funktionen (und getRandomValues) für die Dauer von `action` durch aufzeichnende Hüllen. */
async function recordDuring<T>(action: () => Promise<T>): Promise<{ result: T; recorded: Recorded[] }> {
  const recorded: Recorded[] = [];
  const crypto = globalThis.crypto as unknown as Record<string, unknown>;
  const subtle = globalThis.crypto.subtle as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  const original = { digest: subtle.digest!, importKey: subtle.importKey!, encrypt: subtle.encrypt!, decrypt: subtle.decrypt! };
  const getRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  subtle.digest = (algorithm, data) => {
    recorded.push({ what: "digest-Eingabe", bytes: asBytes(data as BufferSource) });
    return original.digest.call(globalThis.crypto.subtle, algorithm, data);
  };
  subtle.importKey = (format, keyData, ...rest) => {
    if (format === "raw") recorded.push({ what: "Rohschlüssel", bytes: asBytes(keyData as BufferSource) });
    return original.importKey.call(globalThis.crypto.subtle, format, keyData, ...rest);
  };
  for (const name of ["encrypt", "decrypt"] as const) {
    subtle[name] = async (algorithm, key, data) => {
      recorded.push({ what: `${name}-Eingabe`, bytes: asBytes(data as BufferSource) });
      const output = (await original[name].call(globalThis.crypto.subtle, algorithm, key, data)) as ArrayBuffer;
      recorded.push({ what: `${name}-Ausgabe`, bytes: new Uint8Array(output) });
      return output;
    };
  }
  crypto.getRandomValues = (array: Uint8Array<ArrayBuffer>) => {
    recorded.push({ what: "Zufallswerte", bytes: asBytes(array) });
    return getRandomValues(array);
  };
  try {
    return { result: await action(), recorded };
  } finally {
    for (const name of ["digest", "importKey", "encrypt", "decrypt"]) delete subtle[name];
    delete crypto.getRandomValues;
  }
}

/** Puffer, die weder öffentlich (Teil der Datei) noch überschrieben sind. */
function leftovers(recorded: Recorded[], file: Uint8Array): string[] {
  const fileBuffer = Buffer.from(file);
  return recorded
    .filter(({ bytes }) => bytes.some((b) => b !== 0) && fileBuffer.indexOf(Buffer.from(bytes)) < 0)
    .map(({ what, bytes }) => `${what} (${bytes.length} Byte)`);
}

function sampleVault(compression: boolean) {
  const vault = createNewVault({ name: "Löschen", now: Date.now(), kdf: AES_KDF, allowWeakKdf: true });
  vault.settings.compression = compression;
  createEntry(vault, vault.root.uuid, { Title: "Bank", Password: { value: SECRET, protected: true } }, createVaultClock(vault));
  return vault;
}

describe("Überschreiben geheimer Zwischenwerte (Sicherheitsaudit crypto-5)", () => {
  it.each([false, true])("readKdbx hinterlässt keine Schlüssel, AES-KDF-Zwischenstände oder Klartexte (gzip=%s)", async (compression) => {
    const file = await writeKdbx(sampleVault(compression), CREDENTIALS);
    const { result: vault, recorded } = await recordDuring(() => readKdbx(file, CREDENTIALS));
    expect(vault.root.entries[0]!.strings.get("Password")?.value).toBe(SECRET);
    expect(recorded.length).toBeGreaterThan(5);
    expect(leftovers(recorded, file)).toEqual([]);
  });

  it.each([false, true])("writeKdbx hinterlässt keine Schlüssel, keinen Klartext und keinen Schlüssel des inneren Stroms (gzip=%s)", async (compression) => {
    const vault = sampleVault(compression);
    // Das XML-Dokument: größte Ausgabe von TextEncoder während writeKdbx
    const encoded: Uint8Array[] = [];
    const encode = TextEncoder.prototype.encode;
    TextEncoder.prototype.encode = function (this: TextEncoder, input?: string) {
      const bytes = encode.call(this, input);
      encoded.push(bytes);
      return bytes;
    };
    let file: Uint8Array;
    let recorded: Recorded[];
    try {
      ({ result: file, recorded } = await recordDuring(() => writeKdbx(vault, CREDENTIALS)));
    } finally {
      TextEncoder.prototype.encode = encode;
    }
    expect((await readKdbx(file, CREDENTIALS)).root.entries[0]!.strings.get("Password")?.value).toBe(SECRET);
    // u. a. der 64-Byte-Schlüssel des inneren Stroms (Zufallswerte, die nicht in der Datei stehen)
    expect(recorded.some(({ what, bytes }) => what === "Zufallswerte" && bytes.length === 64)).toBe(true);
    expect(leftovers(recorded, file)).toEqual([]);
    const xml = encoded.reduce((a, b) => (b.length > a.length ? b : a));
    expect(xml.length).toBeGreaterThan(500);
    expect(xml.every((b) => b === 0)).toBe(true);
  });
});
