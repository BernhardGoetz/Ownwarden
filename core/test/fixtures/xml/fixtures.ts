/**
 * Test-Hilfen für die XML-Schicht (src/kdbx/xml*.ts). Nur für Tests – darf Node-APIs nutzen.
 *
 * Bewusst UNABHÄNGIG vom getesteten Code gebaut:
 *   - `ReferenceStream` erzeugt den Schlüsselstrom direkt mit ChaCha20 aus @noble/ciphers
 *     (nicht über createInnerStream).
 *   - `encryptProtectedText` / `decryptProtectedText` finden geschützte Werte per regulärem
 *     Ausdruck im XML-Text, nicht über den XML-Baum. Stimmen beide Wege überein, ist die
 *     Dokumentreihenfolge richtig.
 *
 * Fixtures in diesem Ordner speichern geschützte Werte im KLARTEXT
 * (<Value Protected="True">geheim</Value>); `encryptProtectedText` macht daraus eine
 * „echte“ XML-Datenbank mit Chiffretext.
 */
import { chacha20 } from "@noble/ciphers/chacha.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { InnerStreamCipher, PoolBinary } from "../../../src/contracts";
import type { Attachment, Entry, Group, KdbxTimes, Vault } from "../../../src/model";

const FIXTURE_DIR = dirname(fileURLToPath(import.meta.url));

/** Liest eine XML-Fixture aus diesem Ordner als Text. */
export function readXmlFixture(name: string): string {
  return readFileSync(join(FIXTURE_DIR, name), "utf8");
}

// ---------------------------------------------------------------------------
// Referenz-Schlüsselstrom
// ---------------------------------------------------------------------------

/**
 * Einfacher, unabhängiger Ersatz für den inneren Zufallsstrom: ChaCha20-Schlüsselstrom ab
 * Block 0, fortlaufend verbraucht. Zwei Ströme mit gleichem `seed` liefern dieselben Bytes.
 */
export class ReferenceStream implements InnerStreamCipher {
  private keystream = new Uint8Array(0);
  private offset = 0;
  private readonly key: Uint8Array;
  private readonly nonce: Uint8Array;

  constructor(seed = 1) {
    this.key = new Uint8Array(32).fill(seed);
    this.nonce = new Uint8Array(12).fill(seed ^ 0x5a);
  }

  /** Anzahl bisher verbrauchter Bytes. */
  get consumed(): number {
    return this.offset;
  }

  process(data: Uint8Array): Uint8Array {
    this.ensure(this.offset + data.length);
    const out = data.map((byte, i) => byte ^ this.keystream[this.offset + i]!);
    this.offset += data.length;
    return out;
  }

  private ensure(length: number): void {
    if (this.keystream.length >= length) return;
    const size = Math.max(length, this.keystream.length * 2, 4096);
    this.keystream = chacha20(this.key, this.nonce, new Uint8Array(size));
  }
}

/** Strom, der nichts verändert (Chiffretext = Klartext). Für lesbare Erwartungswerte. */
export const identityStream = (): InnerStreamCipher => ({ process: (data) => data.slice() });

// ---------------------------------------------------------------------------
// Geschützte Werte im XML-Text (per regulärem Ausdruck)
// ---------------------------------------------------------------------------

/**
 * Ein Element mit Protected="True" (beliebige Schreibweise oder "1", wie KeePassXC) und
 * reinem Textinhalt. Gruppe 1: Start-Tag, 3: Inhalt, 4: End-Tag.
 */
const PROTECTED_ELEMENT = /(<([A-Za-z_][\w.-]*)\b[^>]*\sProtected="(?:true|1)"[^>]*>)([^<]*)(<\/\2>)/gi;

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function unescapeXml(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (match, name: string) => {
    if (name.startsWith("#x") || name.startsWith("#X")) return String.fromCodePoint(parseInt(name.slice(2), 16));
    if (name.startsWith("#")) return String.fromCodePoint(parseInt(name.slice(1), 10));
    return ENTITIES[name] ?? match;
  });
}

/** Ersetzt jeden geschützten Klartext-Wert (in Dokumentreihenfolge) durch Base64-Chiffretext. */
export function encryptProtectedText(xml: string, stream: InnerStreamCipher): string {
  return xml.replace(PROTECTED_ELEMENT, (_match, startTag: string, _name: string, text: string, endTag: string) => {
    const plaintext = new TextEncoder().encode(unescapeXml(text));
    if (plaintext.length === 0) return `${startTag}${endTag}`;
    return `${startTag}${Buffer.from(stream.process(plaintext)).toString("base64")}${endTag}`;
  });
}

/** Entschlüsselt alle geschützten Werte eines XML-Texts in Dokumentreihenfolge. */
export function decryptProtectedText(xml: string, stream: InnerStreamCipher): string[] {
  return [...xml.matchAll(PROTECTED_ELEMENT)].map((match) => {
    const ciphertext = Uint8Array.from(Buffer.from(match[3]!, "base64"));
    return new TextDecoder().decode(ciphertext.length === 0 ? ciphertext : stream.process(ciphertext));
  });
}

// ---------------------------------------------------------------------------
// Binär-Pool der Fixture keepassxc-4.1.xml
// ---------------------------------------------------------------------------

export const NOTE_ATTACHMENT = new TextEncoder().encode("Notiz-Anhang äöü\n");
export const IMAGE_ATTACHMENT = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3]);
export const OLD_ATTACHMENT = new TextEncoder().encode("alte Fassung");

/** Pool passend zu keepassxc-4.1.xml (Ref 0, 1, 2); KeePassXC setzt das Schutz-Flag immer. */
export function keepassxcFixtureBinaries(): PoolBinary[] {
  return [
    { data: NOTE_ATTACHMENT, protected: true },
    { data: IMAGE_ATTACHMENT, protected: true },
    { data: OLD_ATTACHMENT, protected: true },
  ];
}

// ---------------------------------------------------------------------------
// Beispiel-Modell
// ---------------------------------------------------------------------------

/** Deterministische Test-UUID: 16 Byte mit dem Wert `n`. */
export function testUuid(n: number): string {
  return Buffer.alloc(16, n).toString("base64");
}

/** Zeitstempel in ganzen Sekunden (so, wie sie aus einer Datei kommen). */
const T = (iso: string) => Date.parse(iso);

function times(base: string, overrides: Partial<KdbxTimes> = {}): KdbxTimes {
  return {
    creation: T(base),
    lastModification: T(base) + 60_000,
    lastAccess: T(base) + 120_000,
    expiry: T("2030-01-01T00:00:00Z"),
    expires: false,
    usageCount: 0,
    locationChanged: T(base),
    ...overrides,
  };
}

function entry(uuidNumber: number, title: string, overrides: Partial<Entry> = {}): Entry {
  return {
    uuid: testUuid(uuidNumber),
    iconId: 0,
    foregroundColor: "",
    backgroundColor: "",
    overrideUrl: "",
    tags: [],
    times: times("2026-02-01T10:00:00Z"),
    strings: new Map([
      ["Title", { value: title, protected: false }],
      ["Password", { value: `${title}-passwort`, protected: true }],
    ]),
    attachments: [],
    customData: new Map(),
    history: [],
    unknown: [],
    ...overrides,
  };
}

function group(uuidNumber: number, name: string, overrides: Partial<Group> = {}): Group {
  return {
    uuid: testUuid(uuidNumber),
    name,
    notes: "",
    iconId: 48,
    times: times("2026-01-01T09:00:00Z"),
    tags: [],
    customData: new Map(),
    groups: [],
    entries: [],
    unknown: [],
    ...overrides,
  };
}

/**
 * Ein Modell, das möglichst viele Besonderheiten enthält. Mit `kdbx41 = false` enthält es
 * keine 4.1-Merkmale (dann muss auch der 4.0-Rundlauf verlustfrei sein).
 */
export function sampleVault(kdbx41: boolean): Vault {
  const lastModified = kdbx41 ? { lastModified: T("2026-03-03T03:03:03Z") } : {};
  // Gleicher Inhalt, aber verschiedene Array-Objekte: Der Pool muss trotzdem zusammenfassen.
  const shared = (): Attachment => ({ name: "geteilt.txt", data: new TextEncoder().encode("geteilter Inhalt"), protected: true });

  const mail = entry(10, "Mail", {
    iconId: 12,
    customIconUuid: testUuid(90),
    foregroundColor: "#112233",
    backgroundColor: "#445566",
    overrideUrl: "cmd://browser %1",
    tags: ["Mail", "Privat"],
    times: times("2026-02-01T10:00:00Z", { expires: true, usageCount: 42 }),
    strings: new Map([
      ["Title", { value: "Mail", protected: false }],
      ["UserName", { value: "alice@example.org", protected: false }],
      ["Password", { value: "Pa$$w0rd & <äöü>   €", protected: true }],
      ["Notes", { value: "Zeile 1\r\nZeile 2\n\tEingerückt  ", protected: false }],
      ["Leer geschützt", { value: "", protected: true }],
      ["Nur Leerzeichen", { value: "   ", protected: false }],
      ["KPEX_PASSKEY_PRIVATE_KEY_PEM", { value: "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----", protected: true }],
    ]),
    attachments: [
      shared(),
      { name: "offen.bin", data: Uint8Array.from([0, 255, 1, 254]), protected: false },
      { name: "gleich-aber-offen.txt", data: new TextEncoder().encode("geteilter Inhalt"), protected: false },
    ],
    customData: new Map([
      ["Ownwarden.FieldTimes", { value: '{"s:Password":1770000000000}', ...lastModified }],
      ["Typ", { value: "login" }],
    ]),
    history: [
      entry(10, "Mail", {
        times: times("2026-01-15T10:00:00Z"),
        attachments: [shared()],
        unknown: ["<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence/></AutoType>"],
      }),
      entry(10, "Mail alt", {
        times: times("2026-01-20T10:00:00Z"),
        attachments: [{ name: "nur-im-verlauf.txt", data: new TextEncoder().encode("Verlauf"), protected: true }],
        customData: new Map([["Typ", { value: "login" }]]),
      }),
    ],
    unknown: [
      "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence>{PASSWORD}</DefaultSequence><Association><Window>Mail*</Window><KeystrokeSequence/></Association></AutoType>",
      '<PluginData><Secret Protected="True">im unbekannten Element</Secret></PluginData>',
    ],
    ...(kdbx41 ? { qualityCheck: false, previousParentGroup: testUuid(3) } : {}),
  });

  const bank = group(2, "Bank", {
    notes: "Konten",
    customIconUuid: testUuid(90),
    entries: [
      entry(20, "Giro", {
        attachments: [{ ...shared(), name: "kopie.txt" }],
        strings: new Map([
          ["Title", { value: "Giro", protected: false }],
          ["PIN", { value: "0815", protected: true }],
        ]),
      }),
    ],
    unknown: ["<IsExpanded>False</IsExpanded>", "<EnableAutoType>false</EnableAutoType>"],
    ...(kdbx41 ? { tags: ["Finanzen"], previousParentGroup: testUuid(3) } : {}),
  });

  const recycleBin = group(3, "Papierkorb", { iconId: 43 });

  return {
    settings: {
      versionMinor: kdbx41 ? 1 : 0,
      cipher: "aes256",
      compression: true,
      kdf: { type: "argon2id", salt: new Uint8Array(32), parallelism: 2, memoryBytes: 64 * 1024 * 1024, iterations: 3, version: 0x13 },
    },
    meta: {
      generator: "Ownwarden",
      databaseName: "Beispiel",
      databaseNameChanged: T("2026-01-01T00:00:00Z"),
      recycleBinEnabled: true,
      recycleBinUuid: testUuid(3),
      recycleBinChanged: T("2026-01-01T00:00:01Z"),
      historyMaxItems: 10,
      historyMaxSize: -1,
      customIcons: [
        {
          uuid: testUuid(90),
          data: Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]),
          ...(kdbx41 ? { name: "Icon", lastModified: T("2026-04-04T04:04:04Z") } : {}),
        },
      ],
      customData: new Map([
        ["KPXC_DECRYPTION_TIME_PREFERENCE", { value: "1000", ...lastModified }],
        ["_LAST_MODIFIED", { value: "Thu Oct 15 11:11:11 2026 GMT" }],
      ]),
      unknown: [
        "<DatabaseDescription>Beschreibung</DatabaseDescription>",
        "<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes></MemoryProtection>",
        '<FremdesMeta Version="2"><Wert Protected="True">meta-geheimnis</Wert></FremdesMeta>',
      ],
    },
    root: group(1, "Root", {
      notes: "Wurzel",
      entries: [mail],
      groups: [bank, recycleBin],
      customData: new Map([["Gruppen-Daten", { value: "x", ...lastModified }]]),
      unknown: ["<IsExpanded>True</IsExpanded>", "<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>"],
      ...(kdbx41 ? { tags: ["Wurzel-Tag"] } : {}),
    }),
    deletedObjects: [
      { uuid: testUuid(70), deletionTime: T("2026-05-05T05:05:05Z") },
      { uuid: testUuid(71), deletionTime: T("2026-06-06T06:06:06Z") },
    ],
    rootUnknown: ['<FremdeWurzel><Geheim Protected="True">wurzel-geheimnis</Geheim></FremdeWurzel>'],
  };
}
