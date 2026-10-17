/**
 * KDBX-Datei <-> Modell in EINEM Schritt: der Einstieg für alle, die eine Tresor-Datei lesen
 * oder schreiben wollen (Sync-Codec, Kommandozeile, später die Browser-Erweiterung).
 *
 *   readKdbx:       Datei-Bytes + Zugangsdaten -> Vault
 *   writeKdbx:      Vault + Zugangsdaten       -> Datei-Bytes
 *   createNewVault: neue, leere Datenbank (nur im Speicher; speichern mit writeKdbx)
 *
 * Die eigentliche Arbeit machen die Bausteine dieses Ordners (siehe contracts.ts):
 *
 *   Lesen:     decryptContainer (container.ts)  äußere Hülle prüfen und entschlüsseln
 *           -> createInnerStream (inner-stream.ts) Schlüsselstrom für geschützte Werte
 *           -> parseVaultXml (xml.ts)          XML ins Modell, geschützte Werte entschlüsseln
 *
 *   Schreiben: newInnerStreamKey + createInnerStream("chacha20")
 *           -> serializeVaultXml (xml.ts)      Modell als XML, geschützte Werte verschlüsseln
 *           -> encryptContainer (container.ts) neue Hülle (neuer Master-Seed, IV, KDF-Salt)
 *
 * Läuft auch im Service Worker der Browser-Erweiterung (nur WebCrypto & Co., keine Node-APIs).
 */
import type { Credentials, KdfParams, Millis, Vault } from "../model";
import { NULL_UUID } from "../model";
import { decryptContainer, encryptContainer } from "./container";
import { createInnerStream, newInnerStreamKey } from "./inner-stream";
import { validateKdfParams } from "./kdf";
import { defaultKdbxSettings } from "./settings";
import { kdbxMinorVersionRequired, parseVaultXml, serializeVaultXml } from "./xml";
import { stripInvalidXmlChars } from "./xml-dom";

export { defaultKdbxSettings } from "./settings";
export { kdbxMinorVersionRequired } from "./xml";

// ---------------------------------------------------------------------------
// Lesen und Schreiben
// ---------------------------------------------------------------------------

/**
 * Liest eine KDBX-4-Datei. Wirft KdbxError (contracts.ts), z. B. "InvalidCredentials" bei
 * falschem Passwort oder "Corrupt" bei einer beschädigten Datei – nie ein Teilergebnis.
 */
export async function readKdbx(file: Uint8Array, credentials: Credentials): Promise<Vault> {
  const payload = await decryptContainer(file, credentials);
  // Für jedes Lesen ein FRISCHER Strom: Er ist zustandsbehaftet (siehe inner-stream.ts).
  const stream = createInnerStream(payload.innerStreamId, payload.innerStreamKey);
  return parseVaultXml(payload.xml, payload.binaries, stream, payload.settings);
}

/**
 * Schreibt eine KDBX-4-Datei. Verändert `vault` nicht.
 *
 * Bei JEDEM Aufruf neu: Schlüssel des inneren Stroms (immer ChaCha20, wie KeePassXC bei
 * KDBX 4), Master-Seed, IV und KDF-Salt. Die übrigen Einstellungen (Verschlüsselung,
 * Schlüsselableitung, Kompression) kommen aus `vault.settings`.
 *
 * KDBX-Version: Braucht die Datenbank Merkmale von KDBX 4.1 (z. B. Tags an Gruppen), wird
 * 4.1 geschrieben, sonst die Version aus `vault.settings` – so geht nie etwas verloren.
 */
export async function writeKdbx(vault: Vault, credentials: Credentials): Promise<Uint8Array> {
  const innerStreamKey = newInnerStreamKey();
  const versionMinor = Math.max(vault.settings.versionMinor, kdbxMinorVersionRequired(vault)) as 0 | 1;
  const settings = { ...vault.settings, versionMinor };
  const { xml, binaries } = serializeVaultXml({ ...vault, settings }, createInnerStream("chacha20", innerStreamKey));
  return encryptContainer({ settings, innerStreamId: "chacha20", innerStreamKey, binaries, xml }, credentials);
}

// ---------------------------------------------------------------------------
// Neue Datenbank
// ---------------------------------------------------------------------------

/** Name der Wurzelgruppe, wenn die Datenbank keinen Namen hat. */
export const DEFAULT_ROOT_GROUP_NAME = "Ownwarden";

/** Ordner-Icon von KeePass (Standard für Gruppen). */
const FOLDER_ICON = 48;

/** Verlaufsgrenzen wie bei KeePass/KeePassXC: 10 Fassungen, 6 MiB pro Eintrag. */
const DEFAULT_HISTORY_MAX_ITEMS = 10;
const DEFAULT_HISTORY_MAX_SIZE = 6 * 1024 * 1024;

export interface NewVaultOptions {
  /** Name der Datenbank (Meta/DatabaseName); die Wurzelgruppe heißt genauso (leer: "Ownwarden"). */
  name: string;
  /** Zeitpunkt der Erstellung (ms); wird auf ganze Sekunden abgerundet. */
  now: Millis;
  /**
   * Schlüsselableitung; Standard aus defaultKdbxSettings() (Argon2id, 64 MiB, 3 Iterationen,
   * 2 Spuren). Kleinere Werte nur für Tests – sie machen das Erraten des Passworts billiger.
   */
  kdf?: KdfParams;
}

/**
 * Neue, leere Datenbank (nur im Speicher; speichern mit writeKdbx).
 *
 * Festlegungen (wie bei einer neuen Datenbank in KeePassXC, damit sich die Datei dort
 * vertraut anfühlt):
 *   - KDBX 4.0, AES-256, GZip, Argon2id (defaultKdbxSettings). 4.0 genügt: writeKdbx hebt auf
 *     4.1 an, sobald ein 4.1-Merkmal benutzt wird.
 *   - Papierkorb EINGESCHALTET (KeePassXC-Standard): „Löschen“ verschiebt erst in den
 *     Papierkorb (recycleEntry), endgültig gelöscht wird erst dort. Die Papierkorb-Gruppe wird
 *     wie bei KeePassXC erst beim ersten Löschen angelegt (recycleBinUuid bis dahin NULL_UUID).
 *   - Verlauf: höchstens 10 Fassungen bzw. 6 MiB pro Eintrag (KeePassXC-Standard).
 *   - Keine eigenen Icons, kein CustomData, keine unbekannten Elemente (<MemoryProtection>
 *     usw. lässt Ownwarden weg; KeePassXC nimmt dann seine Standardwerte).
 *   - Alle Zeiten = `now`, auf ganze Sekunden abgerundet: KDBX speichert nur Sekunden, und so
 *     ist die neue Datenbank im Speicher genau das, was nach dem Speichern wieder gelesen wird.
 */
export function createNewVault(options: NewVaultOptions): Vault {
  const now = Math.floor(options.now / 1000) * 1000;
  if (!Number.isFinite(now)) throw new RangeError("createNewVault: ungültige Zeit now.");
  // Wie in vault-ops (Review kdbx-2): Zeichen, die der Writer entfernen müsste, ablehnen statt
  // still verändern – sonst wiche die Datenbank im Speicher von der Datei ab, und jeder Abgleich
  // schriebe erneut.
  if (stripInvalidXmlChars(options.name) !== options.name) {
    throw new RangeError(
      "Der Datenbankname enthält ein Zeichen, das KDBX nicht speichern kann. Nicht erlaubt sind Steuerzeichen außer " +
        "Tabulator und Zeilenumbruch, U+FFFE, U+FFFF und einzelne UTF-16-Surrogate.",
    );
  }
  const settings = defaultKdbxSettings();
  if (options.kdf !== undefined) {
    validateKdfParams(options.kdf);
    settings.kdf = options.kdf;
  }
  const times = { creation: now, lastModification: now, lastAccess: now, expiry: now, expires: false, usageCount: 0, locationChanged: now };
  return {
    settings,
    meta: {
      generator: "Ownwarden",
      databaseName: options.name,
      databaseNameChanged: now,
      recycleBinEnabled: true,
      recycleBinUuid: NULL_UUID,
      recycleBinChanged: now,
      historyMaxItems: DEFAULT_HISTORY_MAX_ITEMS,
      historyMaxSize: DEFAULT_HISTORY_MAX_SIZE,
      customIcons: [],
      customData: new Map(),
      unknown: [],
    },
    root: {
      uuid: newRandomUuid(),
      name: options.name === "" ? DEFAULT_ROOT_GROUP_NAME : options.name,
      notes: "",
      iconId: FOLDER_ICON,
      times,
      tags: [],
      customData: new Map(),
      groups: [],
      entries: [],
      unknown: [],
    },
    deletedObjects: [],
    rootUnknown: [],
  };
}

/** Zufällige UUID (16 Byte aus crypto.getRandomValues), Base64 wie in der KDBX-XML. */
function newRandomUuid(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
