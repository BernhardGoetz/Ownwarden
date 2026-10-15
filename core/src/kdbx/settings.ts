/**
 * Standard-Einstellungen für NEUE Datenbanken, die Ownwarden anlegt.
 *
 * Bestehende Dateien behalten beim Speichern ihre Einstellungen (aus dem gelesenen Header);
 * nur Master-Seed, IV und KDF-Salt werden bei jedem Speichern neu erzeugt.
 */
import type { KdbxSettings } from "../model";
import { ARGON2_VERSION_13 } from "./constants";
import { randomBytes } from "./crypto";

/**
 * Argon2id mit 64 MiB Speicher, 3 Iterationen, Parallelität 2; AES-256; GZip; KDBX 4.0.
 *
 * Warum diese Werte: 64 MiB und 3 Iterationen entsprechen der zweiten Argon2id-Empfehlung
 * aus RFC 9106 („wenn wenig Speicher vorhanden ist“; dort mit 4 Spuren). Wir nehmen nur
 * 2 Spuren (Parallelität), weil hash-wasm im Browser ohnehin nur einen Thread nutzt.
 * KDBX 4.0 statt 4.1, weil der Container bei beiden gleich ist und ältere Programme 4.0
 * sicher lesen können; ob 4.1-Merkmale nötig sind, entscheidet der XML-Teil.
 */
export function defaultKdbxSettings(): KdbxSettings {
  return {
    versionMinor: 0,
    cipher: "aes256",
    compression: true,
    kdf: {
      type: "argon2id",
      salt: randomBytes(32),
      parallelism: 2,
      memoryBytes: 64 * 1024 * 1024,
      iterations: 3,
      version: ARGON2_VERSION_13,
    },
  };
}
