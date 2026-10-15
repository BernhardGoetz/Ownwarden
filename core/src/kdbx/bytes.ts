/**
 * Kleine Hilfen zum Lesen und Schreiben von Binärdaten (Little Endian, wie in KDBX).
 *
 * Wichtig: Alles, was aus einer Datei gelesen wird, ist „nicht vertrauenswürdig“. Der
 * `ByteReader` prüft deshalb vor JEDEM Zugriff, ob genug Bytes vorhanden sind, und wirft
 * sonst einen `KdbxError("Corrupt")`. So kann eine kaputte oder manipulierte Datei nie
 * über das Pufferende hinaus lesen oder riesige Speicherblöcke anfordern.
 */
import { KdbxError } from "../contracts";

/** Wirft einen Fehler „Datei beschädigt“. */
export function corrupt(message: string): never {
  throw new KdbxError("Corrupt", message);
}

/** Liest Werte nacheinander aus einem Byte-Array, mit Längenprüfung. */
export class ByteReader {
  private pos = 0;
  private readonly view: DataView;

  /**
   * @param data    die zu lesenden Bytes
   * @param context Name des Bereichs für Fehlermeldungen (z. B. "äußerer Header")
   */
  constructor(
    private readonly data: Uint8Array,
    private readonly context: string,
  ) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  /** Aktuelle Leseposition (Bytes ab Anfang). */
  get offset(): number {
    return this.pos;
  }

  /** Anzahl noch nicht gelesener Bytes. */
  get remaining(): number {
    return this.data.length - this.pos;
  }

  /** Stellt sicher, dass noch `count` Bytes vorhanden sind. */
  private need(count: number, what: string): void {
    if (!Number.isInteger(count) || count < 0 || count > this.remaining) {
      corrupt(`${this.context}: ${what} ist abgeschnitten (Position ${this.pos}, benötigt ${count} Byte).`);
    }
  }

  readU8(what = "Byte"): number {
    this.need(1, what);
    return this.view.getUint8(this.pos++);
  }

  readU16(what = "uint16"): number {
    this.need(2, what);
    const value = this.view.getUint16(this.pos, true);
    this.pos += 2;
    return value;
  }

  readU32(what = "uint32"): number {
    this.need(4, what);
    const value = this.view.getUint32(this.pos, true);
    this.pos += 4;
    return value;
  }

  readI32(what = "int32"): number {
    this.need(4, what);
    const value = this.view.getInt32(this.pos, true);
    this.pos += 4;
    return value;
  }

  readU64(what = "uint64"): bigint {
    this.need(8, what);
    const value = this.view.getBigUint64(this.pos, true);
    this.pos += 8;
    return value;
  }

  readI64(what = "int64"): bigint {
    this.need(8, what);
    const value = this.view.getBigInt64(this.pos, true);
    this.pos += 8;
    return value;
  }

  /** Liest `count` Bytes als KOPIE (unabhängig vom Eingabepuffer). */
  readBytes(count: number, what = "Daten"): Uint8Array {
    this.need(count, what);
    const bytes = this.data.slice(this.pos, this.pos + count);
    this.pos += count;
    return bytes;
  }

  /**
   * Liest `count` Bytes als SICHT auf den Eingabepuffer (ohne Kopie, für große Blöcke).
   * Achtung: Änderungen am Eingabepuffer sind in der Sicht sichtbar.
   */
  readView(count: number, what = "Daten"): Uint8Array {
    this.need(count, what);
    const bytes = this.data.subarray(this.pos, this.pos + count);
    this.pos += count;
    return bytes;
  }

  /** Alle restlichen Bytes als Sicht. */
  readRest(): Uint8Array {
    return this.readView(this.remaining);
  }
}

/**
 * Prüft, dass `value` eine ganze Zahl im Bereich [min, max] ist. DataView würde zu große
 * Werte sonst stillschweigend abschneiden (modulo 2^n) – eine falsche Längenangabe in der
 * Datei wäre die Folge.
 */
function checkIntRange(value: number, min: number, max: number, typeName: string): void {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`Kein ${typeName}: ${value}`);
  }
}

/** Sammelt Bytes und setzt sie am Ende zu einem Array zusammen. */
export class ByteWriter {
  private readonly parts: Uint8Array[] = [];
  private length = 0;

  writeU8(value: number): this {
    checkIntRange(value, 0, 0xff, "uint8");
    return this.writeBytes(Uint8Array.of(value));
  }

  writeU16(value: number): this {
    checkIntRange(value, 0, 0xffff, "uint16");
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    return this.writeBytes(bytes);
  }

  writeU32(value: number): this {
    return this.writeBytes(u32le(value));
  }

  writeI32(value: number): this {
    checkIntRange(value, -0x80000000, 0x7fffffff, "int32");
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setInt32(0, value, true);
    return this.writeBytes(bytes);
  }

  writeU64(value: bigint): this {
    return this.writeBytes(u64le(value));
  }

  writeI64(value: bigint): this {
    if (value < -(2n ** 63n) || value > 2n ** 63n - 1n) {
      throw new RangeError(`Kein int64: ${value}`);
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigInt64(0, value, true);
    return this.writeBytes(bytes);
  }

  writeBytes(bytes: Uint8Array): this {
    this.parts.push(bytes);
    this.length += bytes.length;
    return this;
  }

  toBytes(): Uint8Array {
    return concatBytes(...this.parts);
  }

  get byteLength(): number {
    return this.length;
  }
}

/** uint32 als 4 Byte Little Endian. */
export function u32le(value: number): Uint8Array {
  checkIntRange(value, 0, 0xffffffff, "uint32");
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

/** uint64 als 8 Byte Little Endian. */
export function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new RangeError(`Kein uint64: ${value}`);
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

/** Hängt mehrere Byte-Arrays aneinander. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * Vergleicht zwei Byte-Arrays in konstanter Zeit (bezogen auf den Inhalt). Für den Vergleich
 * von Prüfsummen und HMACs, damit die Laufzeit nicht verrät, ab welchem Byte sie abweichen.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Überschreibt geheime Zwischenwerte mit Nullen (so gut es in JavaScript eben geht). */
export function wipe(...arrays: (Uint8Array | undefined)[]): void {
  for (const a of arrays) a?.fill(0);
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8");

export function utf8Encode(text: string): Uint8Array {
  return textEncoder.encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** "31c1f2e6-bf71-4350-be58-05216afc5aff" -> 16 Byte (in Schreibreihenfolge). */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`Ungültige UUID: ${uuid}`);
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** 16 Byte -> "31c1f2e6-bf71-4350-be58-05216afc5aff" (für Vergleiche und Fehlermeldungen). */
export function bytesToUuid(bytes: Uint8Array): string {
  const hex = toHex(bytes);
  if (bytes.length !== 16) return hex;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * Liefert die Bytes so, dass WebCrypto/Blob sie annehmen: TypeScript verlangt einen
 * Puffer vom Typ `ArrayBuffer` (nicht `SharedArrayBuffer`). Kopiert nur, wenn nötig.
 */
export function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer) return bytes as Uint8Array<ArrayBuffer>;
  return new Uint8Array(bytes);
}
