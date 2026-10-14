/**
 * Ownwarden-Datenmodell: eine KDBX4-Datenbank als einfache TypeScript-Objekte.
 *
 * Dieses Modell ist der gemeinsame Vertrag zwischen
 *   - kdbx/   (Datei <-> Modell),
 *   - merge/  (zwei Modelle zusammenführen),
 *   - sync/   (Modell über WebDAV abgleichen).
 *
 * Grundsätze:
 *   - Zeiten sind Millisekunden seit 1970-01-01 UTC (`Millis`). KDBX speichert nur ganze
 *     Sekunden; aus einer Datei gelesene Zeiten sind daher Vielfache von 1000.
 *   - UUIDs sind Base64-Strings mit 16 Byte Inhalt, genau wie in der KDBX-XML.
 *   - Geschützte Werte (Passwörter usw.) liegen im Modell im Klartext vor; `protected`
 *     sagt nur, dass sie in der Datei mit dem inneren Zufallsstrom verschlüsselt werden.
 *   - XML-Elemente, die Ownwarden nicht kennt, werden unverändert aufbewahrt (`unknown`),
 *     damit eine Datei von KeePassXC nach dem Speichern durch Ownwarden nichts verliert.
 */

/** Millisekunden seit 1970-01-01T00:00:00Z. */
export type Millis = number;

/** Base64-kodierte 16-Byte-UUID, wie in der KDBX-XML. */
export type Uuid = string;

/** Die <Times>-Angaben einer Gruppe oder eines Eintrags. */
export interface KdbxTimes {
  creation: Millis;
  lastModification: Millis;
  lastAccess: Millis;
  expiry: Millis;
  expires: boolean;
  usageCount: number;
  /** Zeitpunkt der letzten Verschiebung in eine andere Gruppe. */
  locationChanged: Millis;
}

/** Ein Text-Feld eines Eintrags (<String>). */
export interface ProtectedString {
  value: string;
  /** In der Datei mit dem inneren Zufallsstrom geschützt (Protected="True"). */
  protected: boolean;
}

/** Ein Dateianhang eines Eintrags. Die Daten liegen direkt am Eintrag, nicht im Binär-Pool. */
export interface Attachment {
  /** Dateiname, innerhalb eines Eintrags eindeutig. */
  name: string;
  data: Uint8Array;
  /** Flag "geschützt" aus dem inneren Header der KDBX-Datei. */
  protected: boolean;
}

/** Ein Wert in einem CustomData-Wörterbuch. */
export interface CustomDataItem {
  value: string;
  /** Nur KDBX 4.1, nur in Meta zuverlässig (KeePassXC verwirft es bei Einträgen/Gruppen). */
  lastModified?: Millis;
}

/** CustomData-Wörterbuch (Schlüssel -> Wert). Die Reihenfolge der Map bleibt beim Schreiben erhalten. */
export type CustomData = Map<string, CustomDataItem>;

/**
 * Unbekannte XML-Kindelemente, als serialisierte XML-Strings in Originalreihenfolge.
 * Geschützte Werte darin stehen im Klartext mit Protected="True" und werden beim
 * Schreiben wieder verschlüsselt.
 */
export type UnknownXml = string[];

/** Ein Eintrag (<Entry>). */
export interface Entry {
  uuid: Uuid;
  iconId: number;
  customIconUuid?: Uuid;
  foregroundColor: string;
  backgroundColor: string;
  overrideUrl: string;
  tags: string[];
  times: KdbxTimes;
  /** Alle <String>-Felder: Title, UserName, Password, URL, Notes und eigene Felder. */
  strings: Map<string, ProtectedString>;
  attachments: Attachment[];
  customData: CustomData;
  /** Frühere Fassungen, älteste zuerst. Verlaufseinträge haben selbst keinen Verlauf. */
  history: Entry[];
  /** KDBX 4.1: Passwortqualität prüfen (Standard true). */
  qualityCheck?: boolean;
  /** KDBX 4.1: vorherige Elterngruppe. */
  previousParentGroup?: Uuid;
  /** Unbekannte Kindelemente, z. B. <AutoType>. */
  unknown: UnknownXml;
}

/** Eine Gruppe (<Group>). */
export interface Group {
  uuid: Uuid;
  name: string;
  notes: string;
  iconId: number;
  customIconUuid?: Uuid;
  times: KdbxTimes;
  /** KDBX 4.1 */
  tags: string[];
  customData: CustomData;
  /** KDBX 4.1 */
  previousParentGroup?: Uuid;
  groups: Group[];
  entries: Entry[];
  /** Unbekannte Kindelemente, z. B. <IsExpanded>, <EnableAutoType>, <LastTopVisibleEntry>. */
  unknown: UnknownXml;
}

/** Ein eigenes Icon aus <Meta><CustomIcons>. */
export interface CustomIcon {
  uuid: Uuid;
  data: Uint8Array;
  /** KDBX 4.1 */
  name?: string;
  /** KDBX 4.1 */
  lastModified?: Millis;
}

/** Datenbankweite Angaben (<Meta>). */
export interface Meta {
  generator: string;
  databaseName: string;
  databaseNameChanged: Millis;
  recycleBinEnabled: boolean;
  /** UUID der Papierkorb-Gruppe; NULL_UUID bedeutet „keiner“. */
  recycleBinUuid: Uuid;
  recycleBinChanged: Millis;
  /** Höchstzahl Verlaufseinträge pro Eintrag; -1 = unbegrenzt. */
  historyMaxItems: number;
  /** Höchstgröße des Verlaufs pro Eintrag in Byte; -1 = unbegrenzt. */
  historyMaxSize: number;
  customIcons: CustomIcon[];
  customData: CustomData;
  /** Unbekannte Kindelemente, z. B. <MemoryProtection>, <DatabaseDescription>. */
  unknown: UnknownXml;
}

/** Ein Lösch-Vermerk aus <DeletedObjects>. Die UUID kann auch zu einem Icon gehören. */
export interface DeletedObject {
  uuid: Uuid;
  deletionTime: Millis;
}

export type CipherId = "aes256" | "chacha20" | "twofish";

export type KdfParams =
  | {
      type: "argon2d" | "argon2id";
      salt: Uint8Array;
      parallelism: number;
      /** Speicherbedarf in Byte (KDBX-Parameter "M"). */
      memoryBytes: number;
      iterations: number;
      /** Argon2-Version, normalerweise 0x13. */
      version: number;
    }
  | {
      type: "aes";
      seed: Uint8Array;
      rounds: number;
    };

/** Einstellungen aus dem äußeren KDBX-Header, die beim Speichern erhalten bleiben sollen. */
export interface KdbxSettings {
  /** 0 = KDBX 4.0, 1 = KDBX 4.1 */
  versionMinor: 0 | 1;
  cipher: CipherId;
  compression: boolean;
  /** Salt/Seed werden beim Speichern neu erzeugt; die übrigen Parameter bleiben. */
  kdf: KdfParams;
  /** Rohes VariantDictionary aus Header-Feld 12, unverändert durchgereicht. */
  publicCustomData?: Uint8Array;
}

/** Eine komplette, entschlüsselte Datenbank. */
export interface Vault {
  settings: KdbxSettings;
  meta: Meta;
  root: Group;
  deletedObjects: DeletedObject[];
  /** Unbekannte Kindelemente von <Root>. */
  rootUnknown: UnknownXml;
}

/** Zugangsdaten zum Öffnen einer Datenbank. */
export interface Credentials {
  password?: string;
  /** Schlüsselinhalt einer Schlüsseldatei (32 Byte). Im Prototyp ungenutzt. */
  keyFileKey?: Uint8Array;
}

/** Standard-Feldnamen von KeePass. */
export const STANDARD_FIELDS = ["Title", "UserName", "Password", "URL", "Notes"] as const;

/** Die „leere“ UUID (16 Null-Bytes). */
export const NULL_UUID: Uuid = "AAAAAAAAAAAAAAAAAAAAAA==";
