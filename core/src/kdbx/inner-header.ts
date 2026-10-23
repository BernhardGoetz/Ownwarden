/**
 * Innerer Header von KDBX 4: steht am Anfang des entschlüsselten (und entpackten) Inhalts,
 * direkt vor der XML-Datenbank.
 *
 * Felder (wiederholt): 1 Byte ID, uint32 LE Länge, Daten.
 *   0  Ende (Daten leer)
 *   1  Nummer des inneren Zufallsstroms (uint32 LE: 2 = Salsa20, 3 = ChaCha20)
 *   2  Schlüssel des inneren Zufallsstroms (KeePassXC: 64 Byte)
 *   3  Anhang für den Binär-Pool: 1 Flag-Byte (0x01 = „geschützt“), danach die Daten.
 *      Die Reihenfolge der Anhänge ergibt den Pool-Index, auf den die XML per
 *      <Value Ref="n"/> verweist.
 *
 * Abgeglichen mit KeePassXC 2.7.6: Kdbx4Reader::readInnerHeaderField,
 * Kdbx4Writer::writeInnerHeaderField/writeAttachments, KdbxReader::setInnerRandomStreamID.
 */
import { KdbxError, type InnerStreamId, type PoolBinary } from "../contracts";
import { ByteReader, ByteWriter, corrupt } from "./bytes";
import { BINARY_FLAG_PROTECTED, InnerHeaderFieldId, InnerStreamNumber, MAX_INNER_BINARIES } from "./constants";

export interface InnerHeader {
  innerStreamId: InnerStreamId;
  innerStreamKey: Uint8Array;
  binaries: PoolBinary[];
}

const CONTEXT = "Innerer Header";

/**
 * Liest den inneren Header. Liefert ihn zusammen mit dem Rest (= XML-Bytes, als Sicht auf
 * `plaintext`). Unbekannte Feld-IDs werden wie bei KeePassXC übersprungen.
 */
export function parseInnerHeader(plaintext: Uint8Array): { header: InnerHeader; xml: Uint8Array } {
  const reader = new ByteReader(plaintext, CONTEXT);
  let innerStreamId: InnerStreamId | undefined;
  let innerStreamKey: Uint8Array | undefined;
  const binaries: PoolBinary[] = [];

  for (;;) {
    const fieldId = reader.readU8("Feld-ID");
    const length = reader.readU32(`Länge von Feld ${fieldId}`);
    const data = reader.readView(length, `Daten von Feld ${fieldId}`);
    if (fieldId === InnerHeaderFieldId.End) break;

    switch (fieldId) {
      case InnerHeaderFieldId.InnerRandomStreamId:
        innerStreamId = decodeStreamId(data);
        break;
      case InnerHeaderFieldId.InnerRandomStreamKey:
        innerStreamKey = data.slice();
        break;
      case InnerHeaderFieldId.Binary:
        // Sofort abbrechen, nicht erst am Ende zählen (Sicherheitsaudit crypto-4)
        if (binaries.length === MAX_INNER_BINARIES) corrupt(`${CONTEXT}: mehr als ${MAX_INNER_BINARIES} Anhänge.`);
        binaries.push(decodeBinary(data, binaries.length));
        break;
      default:
        // Unbekanntes Feld: überspringen (KeePassXC tut dasselbe).
        break;
    }
  }

  if (innerStreamId === undefined) corrupt(`${CONTEXT}: Nummer des inneren Zufallsstroms fehlt.`);
  if (innerStreamKey === undefined || innerStreamKey.length === 0) {
    corrupt(`${CONTEXT}: Schlüssel des inneren Zufallsstroms fehlt.`);
  }
  return { header: { innerStreamId, innerStreamKey, binaries }, xml: reader.readRest() };
}

function decodeStreamId(data: Uint8Array): InnerStreamId {
  if (data.length !== 4) corrupt(`${CONTEXT}: Die Stromnummer muss 4 Byte lang sein.`);
  const number = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, true);
  if (number === InnerStreamNumber.ChaCha20) return "chacha20";
  if (number === InnerStreamNumber.Salsa20) return "salsa20";
  throw new KdbxError("UnsupportedInnerStream", `Innerer Zufallsstrom Nr. ${number} wird nicht unterstützt.`);
}

function decodeBinary(data: Uint8Array, index: number): PoolBinary {
  if (data.length < 1) corrupt(`${CONTEXT}: Anhang ${index} hat kein Flag-Byte.`);
  // Kopie: Anhänge leben lange im Modell und sollen nicht am großen Klartextpuffer hängen.
  return { protected: (data[0]! & BINARY_FLAG_PROTECTED) !== 0, data: data.slice(1) };
}

/** Schreibt den inneren Header (inklusive Ende-Feld); die XML folgt direkt danach. */
export function serializeInnerHeader(header: InnerHeader): Uint8Array {
  if (header.innerStreamId !== "chacha20" && header.innerStreamId !== "salsa20") {
    throw new KdbxError("UnsupportedInnerStream", `Unbekannter innerer Zufallsstrom "${String(header.innerStreamId)}".`);
  }
  if (header.innerStreamKey.length === 0) throw new RangeError("Der Schlüssel des inneren Zufallsstroms ist leer.");
  const streamNumber = header.innerStreamId === "chacha20" ? InnerStreamNumber.ChaCha20 : InnerStreamNumber.Salsa20;
  const writer = new ByteWriter();

  writeField(writer, InnerHeaderFieldId.InnerRandomStreamId, new ByteWriter().writeU32(streamNumber).toBytes());
  writeField(writer, InnerHeaderFieldId.InnerRandomStreamKey, header.innerStreamKey);
  let count = 0;
  for (const binary of header.binaries) {
    // Nie eine Datei schreiben, die parseInnerHeader ablehnen würde
    if (++count > MAX_INNER_BINARIES) throw new RangeError(`Mehr als ${MAX_INNER_BINARIES} Anhänge können nicht gespeichert werden.`);
    const flags = binary.protected ? BINARY_FLAG_PROTECTED : 0;
    // Flag-Byte und Daten bilden zusammen den Feldinhalt.
    writer.writeU8(InnerHeaderFieldId.Binary).writeU32(1 + binary.data.length).writeU8(flags).writeBytes(binary.data);
  }
  writeField(writer, InnerHeaderFieldId.End, new Uint8Array(0));
  return writer.toBytes();
}

function writeField(writer: ByteWriter, fieldId: number, data: Uint8Array): void {
  writer.writeU8(fieldId).writeU32(data.length).writeBytes(data);
}

/**
 * Länge, die serializeInnerHeader ergäbe – ohne die Anhänge zu kopieren. So kann
 * encryptContainer einen zu großen Inhalt ablehnen, bevor es Hunderte MiB zusammensetzt.
 */
export function innerHeaderLength(header: InnerHeader): number {
  // Strom-Nummer (5 + 4), Strom-Schlüssel (5 + n), Ende (5); je Anhang 5 + Flag-Byte + Daten
  let length = 19 + header.innerStreamKey.length;
  for (const binary of header.binaries) length += 6 + binary.data.length;
  return length;
}
