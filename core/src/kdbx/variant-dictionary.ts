/**
 * VariantDictionary: das kleine Schlüssel-Wert-Format, in dem KDBX 4 die KDF-Parameter
 * (Header-Feld 11) und die „öffentlichen Zusatzdaten“ (Header-Feld 12) speichert.
 *
 * Aufbau (alles Little Endian):
 *   uint16  Version (0x0100; nur das obere Byte ist verbindlich)
 *   wiederholt:
 *     uint8   Typ (siehe VariantType; 0x00 = Ende)
 *     uint32  Länge des Namens, danach der Name als UTF-8
 *     uint32  Länge des Werts, danach der Wert
 *   uint8   0x00 (Ende)
 *
 * KeePassXC liest die Längen als uint32 (KeePass als int32); für gültige Dateien ist das
 * gleich. Wir prüfen jede Länge gegen die tatsächlich vorhandenen Bytes.
 */
import { displayText } from "../display-text";
import { VARIANT_DICTIONARY_CRITICAL_MASK, VARIANT_DICTIONARY_VERSION } from "./constants";
import { ByteReader, ByteWriter, corrupt, utf8Decode, utf8Encode } from "./bytes";

/** Typ-Bytes im VariantDictionary (KeePass2::VariantMapFieldType). */
export const VariantType = {
  End: 0x00,
  UInt32: 0x04,
  UInt64: 0x05,
  Bool: 0x08,
  Int32: 0x0c,
  Int64: 0x0d,
  String: 0x18,
  ByteArray: 0x42,
} as const;

/** Ein Wert mit seinem Typ – der Typ muss beim Zurückschreiben erhalten bleiben. */
export type VariantValue =
  | { type: "uint32"; value: number }
  | { type: "uint64"; value: bigint }
  | { type: "bool"; value: boolean }
  | { type: "int32"; value: number }
  | { type: "int64"; value: bigint }
  | { type: "string"; value: string }
  | { type: "bytes"; value: Uint8Array };

/** Die Map behält die Reihenfolge, in der die Einträge gelesen bzw. eingefügt wurden. */
export type VariantDictionary = Map<string, VariantValue>;

const CONTEXT = "VariantDictionary";

/**
 * Liest ein VariantDictionary. Wirft KdbxError("Corrupt") bei jedem Formatfehler.
 * Kommt ein Name doppelt vor, gewinnt – wie bei KeePassXC – der letzte.
 * Bytes nach dem Ende-Zeichen werden – ebenfalls wie bei KeePassXC – ignoriert.
 */
export function parseVariantDictionary(bytes: Uint8Array): VariantDictionary {
  const reader = new ByteReader(bytes, CONTEXT);
  const version = reader.readU16("Version");
  if ((version & VARIANT_DICTIONARY_CRITICAL_MASK) > (VARIANT_DICTIONARY_VERSION & VARIANT_DICTIONARY_CRITICAL_MASK)) {
    corrupt(`${CONTEXT}: Version 0x${version.toString(16)} wird nicht unterstützt.`);
  }

  const dict: VariantDictionary = new Map();
  for (let index = 0; ; index++) {
    const type = reader.readU8("Typ (fehlendes Ende-Zeichen?)");
    if (type === VariantType.End) return dict;

    const nameLength = reader.readU32(`Namenslänge von Eintrag ${index}`);
    const name = utf8Decode(reader.readView(nameLength, `Name von Eintrag ${index}`));
    const label = entryLabel(index, name);
    const valueLength = reader.readU32(`Wertlänge von ${label}`);
    const value = reader.readView(valueLength, `Wert von ${label}`);
    dict.set(name, decodeValue(type, label, value));
  }
}

/** Höchstlänge eines Namens in Fehlermeldungen; echte Namen sind kurz ("$UUID", "S", "KPXC_…"). */
const NAME_IN_MESSAGE_LENGTH = 32;

/**
 * Bezeichnung eines Eintrags für Fehlermeldungen. Der Name stammt aus dem äußeren Header, der
 * gelesen wird, BEVOR irgendetwas geprüft werden kann – ein Angreifer wählt ihn frei
 * (Terminal-Steuerzeichen, Zeilenumbrüche, Megabytes). Deshalb nur entschärft und gekürzt
 * (Sicherheitsaudit leak-1).
 */
function entryLabel(index: number, name: string): string {
  return `Eintrag ${index} ("${displayText(name, NAME_IN_MESSAGE_LENGTH)}")`;
}

/** Wandelt die Wert-Bytes je nach Typ um und prüft die Länge. `label` nennt den Eintrag (entryLabel). */
function decodeValue(type: number, label: string, value: Uint8Array): VariantValue {
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const expectLength = (length: number): void => {
    if (value.length !== length) {
      corrupt(`${CONTEXT}: ${label} hat ${value.length} statt ${length} Byte.`);
    }
  };

  switch (type) {
    case VariantType.UInt32:
      expectLength(4);
      return { type: "uint32", value: view.getUint32(0, true) };
    case VariantType.UInt64:
      expectLength(8);
      return { type: "uint64", value: view.getBigUint64(0, true) };
    case VariantType.Bool:
      expectLength(1);
      return { type: "bool", value: value[0] !== 0 };
    case VariantType.Int32:
      expectLength(4);
      return { type: "int32", value: view.getInt32(0, true) };
    case VariantType.Int64:
      expectLength(8);
      return { type: "int64", value: view.getBigInt64(0, true) };
    case VariantType.String:
      return { type: "string", value: utf8Decode(value) };
    case VariantType.ByteArray:
      // Kopie, damit das Ergebnis nicht am (großen) Eingabepuffer hängt.
      return { type: "bytes", value: value.slice() };
    default:
      return corrupt(`${CONTEXT}: unbekannter Typ 0x${type.toString(16)} bei ${label}.`);
  }
}

/** Schreibt ein VariantDictionary (Version 0x0100), Einträge in Map-Reihenfolge. */
export function serializeVariantDictionary(dict: VariantDictionary): Uint8Array {
  const writer = new ByteWriter();
  writer.writeU16(VARIANT_DICTIONARY_VERSION);
  for (const [name, item] of dict) {
    const { typeByte, bytes } = encodeValue(item);
    const nameBytes = utf8Encode(name);
    writer.writeU8(typeByte);
    writer.writeU32(nameBytes.length).writeBytes(nameBytes);
    writer.writeU32(bytes.length).writeBytes(bytes);
  }
  writer.writeU8(VariantType.End);
  return writer.toBytes();
}

function encodeValue(item: VariantValue): { typeByte: number; bytes: Uint8Array } {
  const w = new ByteWriter();
  switch (item.type) {
    case "uint32":
      return { typeByte: VariantType.UInt32, bytes: w.writeU32(item.value).toBytes() };
    case "uint64":
      return { typeByte: VariantType.UInt64, bytes: w.writeU64(item.value).toBytes() };
    case "bool":
      return { typeByte: VariantType.Bool, bytes: w.writeU8(item.value ? 1 : 0).toBytes() };
    case "int32":
      return { typeByte: VariantType.Int32, bytes: w.writeI32(item.value).toBytes() };
    case "int64":
      return { typeByte: VariantType.Int64, bytes: w.writeI64(item.value).toBytes() };
    case "string":
      return { typeByte: VariantType.String, bytes: utf8Encode(item.value) };
    case "bytes":
      return { typeByte: VariantType.ByteArray, bytes: item.value };
  }
}

/**
 * Liest einen ganzzahligen Wert, egal mit welchem Ganzzahl-Typ er gespeichert ist.
 * KeePassXC ist hier ebenso nachsichtig (QVariant::toUInt usw.). Liefert undefined,
 * wenn der Eintrag fehlt; wirft Corrupt, wenn er kein Ganzzahl-Typ ist.
 */
export function getInteger(dict: VariantDictionary, name: string): bigint | undefined {
  const item = dict.get(name);
  if (item === undefined) return undefined;
  switch (item.type) {
    case "uint32":
    case "int32":
      return BigInt(item.value);
    case "uint64":
    case "int64":
      return item.value;
    default:
      return corrupt(`${CONTEXT}: "${displayText(name, NAME_IN_MESSAGE_LENGTH)}" ist keine Zahl (Typ ${item.type}).`);
  }
}

/** Liest ein Byte-Array; undefined, wenn es fehlt; Corrupt bei falschem Typ. */
export function getBytes(dict: VariantDictionary, name: string): Uint8Array | undefined {
  const item = dict.get(name);
  if (item === undefined) return undefined;
  if (item.type !== "bytes") {
    corrupt(`${CONTEXT}: "${displayText(name, NAME_IN_MESSAGE_LENGTH)}" ist kein Byte-Array (Typ ${item.type}).`);
  }
  return item.value;
}
