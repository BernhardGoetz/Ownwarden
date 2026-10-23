/**
 * Schlüsselableitung (KDF): macht aus dem zusammengesetzten Schlüssel (Passwort-Hash) mit
 * viel Rechenaufwand den „transformierten Schlüssel“. Das bremst Passwort-Rateversuche.
 *
 * KDBX 4 kennt drei Verfahren, alle in Header-Feld 11 als VariantDictionary beschrieben:
 *   - Argon2d und Argon2id (Bibliothek hash-wasm, WebAssembly)
 *   - AES-KDF: den 32-Byte-Schlüssel R-mal mit AES-256-ECB verschlüsseln (Schlüssel = Seed),
 *     danach SHA-256. Älteres Verfahren; KeePassXC-CLI legt Datenbanken noch damit an.
 *
 * Abgeglichen mit KeePassXC 2.7.6: src/crypto/kdf/Argon2Kdf.cpp, AesKdf.cpp, Kdf.cpp,
 * src/format/KeePass2.cpp (kdfFromParameters).
 */
import { argon2d, argon2id } from "hash-wasm";
import { KdbxError } from "../contracts";
import type { KdfParams } from "../model";
import { bytesToUuid, uuidToBytes, wipe } from "./bytes";
import { ARGON2_VERSION_13, KDF_FLOOR, KDF_LIMITS, KDF_UUID, KdfParamKey } from "./constants";
import { aesCbcEncrypt, importAesCbcKey, randomBytes, sha256 } from "./crypto";
import {
  getBytes,
  getInteger,
  parseVariantDictionary,
  serializeVariantDictionary,
  type VariantDictionary,
} from "./variant-dictionary";

/** Länge von neu erzeugten Salts/Seeds (wie KeePass und KeePassXC). */
const NEW_SALT_LENGTH = 32;

function unsupported(message: string): never {
  throw new KdbxError("UnsupportedKdf", message);
}

function corruptKdf(message: string): never {
  throw new KdbxError("Corrupt", `KDF-Parameter: ${message}`);
}

// ---------------------------------------------------------------------------
// Lesen und Schreiben der Parameter
// ---------------------------------------------------------------------------

/** Liest die KDF-Parameter aus den Rohbytes von Header-Feld 11 und prüft sie. */
export function parseKdfParameters(bytes: Uint8Array): KdfParams {
  const dict = parseVariantDictionary(bytes);
  const uuidBytes = getBytes(dict, KdfParamKey.Uuid);
  if (uuidBytes === undefined || uuidBytes.length !== 16) corruptKdf("$UUID fehlt oder ist keine UUID.");
  const uuid = bytesToUuid(uuidBytes);

  let params: KdfParams;
  if (uuid === KDF_UUID.argon2d || uuid === KDF_UUID.argon2id) {
    params = readArgon2Params(dict, uuid === KDF_UUID.argon2d ? "argon2d" : "argon2id");
  } else if (uuid === KDF_UUID.aesKdbx3 || uuid === KDF_UUID.aesKdbx4) {
    // Beide AES-KDF-UUIDs bedeuten dasselbe Verfahren (KeePassXC macht aus der alten die neue).
    params = readAesParams(dict);
  } else {
    unsupported(`Unbekannte Schlüsselableitung ${uuid}.`);
  }
  validateKdfParams(params);
  return params;
}

function readArgon2Params(dict: VariantDictionary, type: "argon2d" | "argon2id"): KdfParams {
  // K (Secret) und A (Associated Data) nutzt weder KeePass noch KeePassXC. KeePassXC
  // ignoriert sie beim Lesen sogar stillschweigend – dann käme ein anderer Schlüssel heraus
  // als beim Erzeuger der Datei. Wir lehnen solche Dateien lieber klar ab.
  for (const key of [KdfParamKey.Secret, KdfParamKey.AssocData]) {
    const extra = getBytes(dict, key);
    if (extra !== undefined && extra.length > 0) {
      unsupported(`Argon2-Parameter "${key}" (Secret/Associated Data) wird nicht unterstützt.`);
    }
  }
  return {
    type,
    salt: requireBytes(dict, KdfParamKey.Salt),
    parallelism: requireNumber(dict, KdfParamKey.Parallelism),
    memoryBytes: requireNumber(dict, KdfParamKey.Memory),
    iterations: requireNumber(dict, KdfParamKey.Iterations),
    version: requireNumber(dict, KdfParamKey.Version),
  };
}

function readAesParams(dict: VariantDictionary): KdfParams {
  return {
    type: "aes",
    seed: requireBytes(dict, KdfParamKey.Salt),
    rounds: requireNumber(dict, KdfParamKey.Rounds),
  };
}

function requireBytes(dict: VariantDictionary, key: string): Uint8Array {
  const value = getBytes(dict, key);
  if (value === undefined) corruptKdf(`"${key}" fehlt.`);
  return value;
}

/** Liest eine Ganzzahl; zu große Werte werden auf MAX_SAFE_INTEGER+1 gekappt (fällt in der Prüfung durch). */
function requireNumber(dict: VariantDictionary, key: string): number {
  const value = getInteger(dict, key);
  if (value === undefined) corruptKdf(`"${key}" fehlt.`);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) return Number.MAX_SAFE_INTEGER + 1;
  return Number(value);
}

/** Schreibt die KDF-Parameter als VariantDictionary (Inhalt von Header-Feld 11). */
export function serializeKdfParameters(params: KdfParams): Uint8Array {
  validateKdfParams(params);
  const dict: VariantDictionary = new Map();
  if (params.type === "aes") {
    // KeePassXC und KeePass schreiben für AES-KDF immer die ursprüngliche (KDBX-3-)UUID.
    dict.set(KdfParamKey.Uuid, { type: "bytes", value: uuidToBytes(KDF_UUID.aesKdbx3) });
    dict.set(KdfParamKey.Rounds, { type: "uint64", value: BigInt(params.rounds) });
    dict.set(KdfParamKey.Salt, { type: "bytes", value: params.seed });
    return serializeVariantDictionary(dict);
  }
  // Reihenfolge und Typen wie KeePassXC (Argon2Kdf::writeParameters, QVariantMap sortiert nach Name).
  const uuid = params.type === "argon2d" ? KDF_UUID.argon2d : KDF_UUID.argon2id;
  dict.set(KdfParamKey.Uuid, { type: "bytes", value: uuidToBytes(uuid) });
  dict.set(KdfParamKey.Iterations, { type: "uint64", value: BigInt(params.iterations) });
  dict.set(KdfParamKey.Memory, { type: "uint64", value: BigInt(params.memoryBytes) });
  dict.set(KdfParamKey.Parallelism, { type: "uint32", value: params.parallelism });
  dict.set(KdfParamKey.Salt, { type: "bytes", value: params.salt });
  dict.set(KdfParamKey.Version, { type: "uint32", value: params.version });
  return serializeVariantDictionary(dict);
}

// ---------------------------------------------------------------------------
// Prüfen und Erneuern
// ---------------------------------------------------------------------------

function checkRange(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    unsupported(`KDF-Parameter ${name} = ${value} liegt außerhalb von ${min}..${max}.`);
  }
}

/**
 * Prüft KDF-Parameter gegen die Grenzen von KeePassXC (plus engere Grenzen für Speicher,
 * Parallelität und Aufwand von Argon2 im Browser, siehe KDF_LIMITS). Wirft KdbxError("UnsupportedKdf"). Wird beim Lesen UND vor dem Schreiben
 * aufgerufen, damit Ownwarden nie eine Datei schreibt, die KeePassXC nicht öffnen kann.
 */
export function validateKdfParams(params: KdfParams): void {
  if (params.type === "aes") {
    // AES-256 braucht genau 32 Byte Schlüssel (KeePassXC/Botan scheitert sonst ebenfalls).
    if (params.seed.length !== 32) unsupported(`AES-KDF-Seed hat ${params.seed.length} statt 32 Byte.`);
    checkRange("R (Runden)", params.rounds, 1, KDF_LIMITS.maxRounds);
    return;
  }
  if (params.type !== "argon2d" && params.type !== "argon2id") {
    unsupported(`Unbekannte Schlüsselableitung "${(params as { type: string }).type}".`);
  }
  checkRange("S (Salt-Länge)", params.salt.length, KDF_LIMITS.minSaltLength, KDF_LIMITS.maxSaltLength);
  if (params.version !== ARGON2_VERSION_13) {
    // KeePassXC kennt auch 0x10; hash-wasm rechnet aber nur Argon2 v1.3 (KeePass schreibt immer 0x13).
    unsupported(`Argon2-Version 0x${params.version.toString(16)} wird nicht unterstützt (nur 0x13).`);
  }
  checkRange("P (Parallelität)", params.parallelism, 1, KDF_LIMITS.maxParallelism);
  checkRange("I (Iterationen)", params.iterations, 1, KDF_LIMITS.maxRounds);
  checkRange("M (Speicher in Byte)", params.memoryBytes, KDF_LIMITS.minMemoryBytes, Number.MAX_SAFE_INTEGER);
  if (params.memoryBytes > KDF_LIMITS.maxMemoryBytes) {
    unsupported(
      `Argon2 verlangt ${mebibytes(params.memoryBytes)} MiB Arbeitsspeicher, Ownwarden erlaubt höchstens ` +
        `${mebibytes(KDF_LIMITS.maxMemoryBytes)} MiB (mehr können Browser und Handy nicht reservieren). ` +
        "Bitte in KeePassXC unter Datenbank-Einstellungen → Sicherheit weniger Speicher einstellen.",
    );
  }
  // Argon2 verlangt mindestens 8 KiB je Spur (Lane); hash-wasm würde sonst einen Fehler werfen.
  if (argon2MemoryKiB(params.memoryBytes) < 8 * params.parallelism) {
    unsupported(`Argon2 braucht mindestens 8 KiB Speicher je Spur (P = ${params.parallelism}).`);
  }
  // Gesamtaufwand begrenzen (Begründung bei KDF_LIMITS): Jede Einzelgrenze kann eingehalten
  // sein und das Produkt trotzdem jahrelanges Rechnen bedeuten.
  if (argon2MemoryKiB(params.memoryBytes) * params.iterations > KDF_LIMITS.maxArgon2WorkKiBIterations) {
    unsupported(
      `Argon2 mit ${argon2MemoryKiB(params.memoryBytes)} KiB × ${params.iterations} Iterationen wäre zu langsam. ` +
        "Bitte in KeePassXC unter Datenbank-Einstellungen → Sicherheit eine kürzere Entschlüsselungszeit wählen.",
    );
  }
}

/** KDBX speichert den Speicher in Byte, Argon2 rechnet in KiB (abgerundet wie bei KeePassXC). */
function argon2MemoryKiB(memoryBytes: number): number {
  return Math.floor(memoryBytes / 1024);
}

/** Byte -> MiB für Meldungen (aufgerundet, damit „zu groß“ nie wie die Grenze selbst aussieht). */
function mebibytes(bytes: number): number {
  return Math.ceil(bytes / (1024 * 1024));
}

// ---------------------------------------------------------------------------
// Mindeststärke (Sicherheitsaudit crypto-2)
// ---------------------------------------------------------------------------

/**
 * Liegen die Parameter unter der Mindeststärke (KDF_FLOOR)? Liefert dann den Grund als
 * deutschen Satz, sonst null. Prüft NICHT die Gültigkeit (dafür validateKdfParams).
 *
 * Beim Anlegen eines Tresors lehnt createNewVault solche Werte ab. Bestehende Dateien lesen und
 * schreiben bleibt erlaubt; ob dann gewarnt oder nachgefragt wird, entscheidet der Aufrufer.
 */
export function kdfBelowFloor(params: KdfParams): string | null {
  if (params.type === "aes") {
    if (params.rounds >= KDF_FLOOR.aesRounds) return null;
    return (
      `AES-KDF mit ${params.rounds} Runden liegt unter der Mindeststärke von ` +
      `${KDF_FLOOR.aesRounds} Runden – das Master-Passwort ließe sich zu billig erraten.`
    );
  }
  const memoryKiB = argon2MemoryKiB(params.memoryBytes);
  if (KDF_FLOOR.argon2.some((row) => memoryKiB >= row.memoryKiB && params.iterations >= row.iterations)) return null;
  const rows = KDF_FLOOR.argon2.map((row) => `${row.memoryKiB / 1024} MiB × ${row.iterations}`).join(", ");
  return (
    `Argon2 mit ${(memoryKiB / 1024).toFixed(1).replace(".", ",")} MiB × ${params.iterations} Iterationen liegt unter ` +
    `der Mindeststärke (OWASP: ${rows}) – das Master-Passwort ließe sich zu billig erraten.`
  );
}

/**
 * Ist `a` schwächer als `b`, also das Erraten des Passworts mit `a` billiger? Für die Frage
 * „hat jemand die Schlüsselableitung abgeschwächt?“, z. B. beim Abgleich mit der zuletzt
 * bestätigten Einstellung. Regeln:
 *   - Argon2 -> AES-KDF: immer schwächer (AES-KDF ist nicht speicherhart).
 *   - AES-KDF -> Argon2: nur schwächer, wenn das neue Argon2 unter der Mindeststärke liegt,
 *     die alte AES-KDF aber nicht.
 *   - AES-KDF: weniger Runden.
 *   - Argon2: weniger Speicher ODER weniger „Speicher × Iterationen“. Parallelität und
 *     Argon2d/Argon2id spielen für die Kosten eines Angreifers keine wesentliche Rolle.
 */
export function kdfWeakerThan(a: KdfParams, b: KdfParams): boolean {
  if (a.type === "aes" && b.type === "aes") return a.rounds < b.rounds;
  if (a.type === "aes") return true;
  if (b.type === "aes") return kdfBelowFloor(a) !== null && kdfBelowFloor(b) === null;
  const memoryA = argon2MemoryKiB(a.memoryBytes);
  const memoryB = argon2MemoryKiB(b.memoryBytes);
  return memoryA < memoryB || memoryA * a.iterations < memoryB * b.iterations;
}

/** Kopie der Parameter mit neuem, zufälligem Salt bzw. Seed (für jedes Speichern). */
export function withFreshKdfSalt(params: KdfParams): KdfParams {
  if (params.type === "aes") return { ...params, seed: randomBytes(NEW_SALT_LENGTH) };
  return { ...params, salt: randomBytes(NEW_SALT_LENGTH) };
}

// ---------------------------------------------------------------------------
// Ableitung
// ---------------------------------------------------------------------------

/** Berechnet den transformierten Schlüssel (32 Byte) aus dem zusammengesetzten Schlüssel. */
export async function transformKey(compositeKey: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  validateKdfParams(params);
  if (params.type === "aes") return aesKdf(compositeKey, params.seed, params.rounds);

  const argon2 = params.type === "argon2d" ? argon2d : argon2id;
  try {
    return await argon2({
      password: compositeKey,
      salt: params.salt,
      parallelism: params.parallelism,
      iterations: params.iterations,
      memorySize: argon2MemoryKiB(params.memoryBytes),
      hashLength: 32,
      outputType: "binary",
    });
  } catch (error) {
    // Kein Speicher für WebAssembly: hash-wasm wirft dann einen RangeError („Invalid typed array
    // length“, „Array buffer allocation failed“ o. ä.) – verständlich melden (Sicherheitsaudit crypto-6).
    if (error instanceof RangeError) {
      unsupported(
        `Argon2 konnte die verlangten ${mebibytes(params.memoryBytes)} MiB Arbeitsspeicher nicht reservieren. ` +
          "Bitte in KeePassXC unter Datenbank-Einstellungen → Sicherheit weniger Speicher einstellen.",
      );
    }
    unsupported(`Argon2 fehlgeschlagen: ${(error as Error).message}`);
  }
}

/** Anzahl AES-Blöcke pro WebCrypto-Aufruf in aesKdf (64 Ki Blöcke = 1 MiB). */
const AES_KDF_CHUNK_BLOCKS = 64 * 1024;

/**
 * AES-KDF: beide 16-Byte-Hälften des Schlüssels je `rounds`-mal mit AES-256 verschlüsseln
 * (Schlüssel = Seed, Modus ECB), danach SHA-256 über die 32 Byte.
 *
 * WebCrypto kennt kein ECB. Wir nutzen deshalb eine bekannte Eigenschaft von CBC: Mit
 * Klartext aus lauter Nullblöcken und IV = x gilt
 *     C1 = AES(0 XOR x) = AES(x),  C2 = AES(0 XOR C1) = AES(C1),  ...
 * der n-te Chiffretextblock ist also genau x n-mal mit AES verschlüsselt. Das ist reines
 * AES aus WebCrypto (keine eigene Kryptografie) und etwa 5-mal schneller als AES in
 * JavaScript. Das von WebCrypto angehängte Padding (ein Block am Ende) ignorieren wir.
 *
 * @param chunkBlocks nur für Tests änderbar (Grenzfälle an Chunk-Grenzen)
 */
export async function aesKdf(
  key: Uint8Array,
  seed: Uint8Array,
  rounds: number,
  chunkBlocks = AES_KDF_CHUNK_BLOCKS,
): Promise<Uint8Array> {
  if (key.length !== 32) throw new RangeError("AES-KDF erwartet einen 32-Byte-Schlüssel.");
  const cryptoKey = await importAesCbcKey(seed, "encrypt");
  // Beide Hälften sind unabhängig voneinander (ECB) und können parallel laufen.
  const halves = [key.slice(0, 16), key.slice(16, 32)];
  const [left, right] = await Promise.all(halves.map((half) => repeatAesEncrypt(cryptoKey, half, rounds, chunkBlocks)));
  const transformed = new Uint8Array(32);
  transformed.set(left!, 0);
  transformed.set(right!, 16);
  const result = await sha256(transformed);
  wipe(...halves, left, right, transformed);
  return result;
}

/**
 * Verschlüsselt einen 16-Byte-Block `rounds`-mal mit AES (über die CBC-Eigenschaft, s. o.).
 * Jeder Zwischenstand (und jeder Chiffretext-Chunk, der alle Zwischenstände enthält) wird
 * überschrieben: Aus jedem einzelnen ließe sich mit dem öffentlichen Seed der zusammengesetzte
 * Schlüssel zurückrechnen (Sicherheitsaudit crypto-5). `block` überschreibt der Aufrufer.
 */
async function repeatAesEncrypt(
  cryptoKey: CryptoKey,
  block: Uint8Array,
  rounds: number,
  chunkBlocks: number,
): Promise<Uint8Array> {
  let state = block;
  let remaining = rounds;
  const zeros = new Uint8Array(Math.min(rounds, chunkBlocks) * 16);
  while (remaining > 0) {
    const count = Math.min(remaining, chunkBlocks);
    const ciphertext = await aesCbcEncrypt(cryptoKey, state, zeros.subarray(0, count * 16));
    // Block Nummer `count` (1-basiert) ist das Ergebnis; danach folgt nur noch der Padding-Block.
    const next = ciphertext.slice((count - 1) * 16, count * 16);
    wipe(ciphertext);
    if (state !== block) wipe(state);
    state = next;
    remaining -= count;
  }
  return state === block ? block.slice() : state;
}
