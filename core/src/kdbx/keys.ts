/**
 * Schlüssel-Kette von KDBX 4 (abgeglichen mit KeePassXC 2.7.6: CompositeKey, PasswordKey,
 * Kdbx4Reader/Kdbx4Writer, KeePass2::hmacKey):
 *
 *   zusammengesetzter Schlüssel = SHA-256( SHA-256(Passwort als UTF-8) [ || Schlüsseldatei-Schlüssel ] )
 *   transformierter Schlüssel  = KDF(zusammengesetzter Schlüssel)            -> kdf.ts
 *   Verschlüsselungsschlüssel  = SHA-256( Master-Seed || transformierter Schlüssel )
 *   HMAC-Basisschlüssel        = SHA-512( Master-Seed || transformierter Schlüssel || 0x01 )
 *
 * Der Master-Seed steht im Header und wird bei jedem Speichern neu ausgewürfelt. Deshalb
 * ändern sich Verschlüsselungs- und HMAC-Schlüssel bei jedem Speichern, auch wenn das
 * Passwort gleich bleibt.
 */
import { KdbxError } from "../contracts";
import type { Credentials } from "../model";
import { utf8Encode, wipe } from "./bytes";
import { sha256, sha512 } from "./crypto";

/** Länge des Schlüssels aus einer Schlüsseldatei (wie FileKey::rawKey bei KeePassXC). */
const KEY_FILE_KEY_LENGTH = 32;

/**
 * Bildet den zusammengesetzten Schlüssel. Reihenfolge wie bei KeePassXC und KeePass:
 * erst das Passwort, dann die Schlüsseldatei. Ein leeres Passwort ("") zählt als Passwort –
 * nur `undefined` bedeutet „kein Passwort“.
 */
export async function compositeKey(credentials: Credentials): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  if (credentials.password !== undefined) {
    const passwordBytes = utf8Encode(credentials.password);
    parts.push(await sha256(passwordBytes));
    wipe(passwordBytes);
  }
  if (credentials.keyFileKey !== undefined) {
    if (credentials.keyFileKey.length !== KEY_FILE_KEY_LENGTH) {
      throw new KdbxError("InvalidCredentials", "Der Schlüssel aus der Schlüsseldatei muss 32 Byte lang sein.");
    }
    parts.push(credentials.keyFileKey);
  }
  if (parts.length === 0) {
    throw new KdbxError("InvalidCredentials", "Weder Passwort noch Schlüsseldatei angegeben.");
  }
  const result = await sha256(...parts);
  if (credentials.password !== undefined) wipe(parts[0]);
  return result;
}

/** Die beiden Schlüssel, die aus Master-Seed und transformiertem Schlüssel entstehen. */
export interface MasterKeys {
  /** 32 Byte für AES-256 bzw. ChaCha20. */
  encryptionKey: Uint8Array;
  /** 64 Byte; daraus werden die HMAC-Schlüssel je Block abgeleitet (hmac-block-stream.ts). */
  hmacBaseKey: Uint8Array;
}

export async function deriveMasterKeys(masterSeed: Uint8Array, transformedKey: Uint8Array): Promise<MasterKeys> {
  const encryptionKey = await sha256(masterSeed, transformedKey);
  const hmacBaseKey = await sha512(masterSeed, transformedKey, Uint8Array.of(0x01));
  return { encryptionKey, hmacBaseKey };
}
