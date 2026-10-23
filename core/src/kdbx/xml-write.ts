/**
 * Modell (Vault) -> XML-Baum, in Reihenfolge und Form wie KeePassXC 2.7.6
 * (src/format/KdbxXmlWriter.cpp), damit KeePassXC und KeePass die Datei ohne Warnungen lesen.
 *
 * Geschützte Werte stehen im Baum noch im KLARTEXT mit Protected="True". Verschlüsselt wird
 * erst der fertige Baum in Dokumentreihenfolge (xml-protected.ts) – nur so landen auch
 * geschützte Werte in unbekannten Elementen an der richtigen Stelle des Zufallsstroms.
 *
 * KDBX-4.1-Elemente (QualityCheck, PreviousParentGroup, Gruppen-Tags, Icon-Name/-Zeit,
 * LastModificationTime in CustomData) werden nur geschrieben, wenn
 * `vault.settings.versionMinor === 1` ist. Ob eine Datenbank 4.1 braucht, sagt
 * `kdbxMinorVersionRequired` (xml.ts).
 *
 * Grundregel: Was xml-read.ts als kaputt ablehnt, wird hier gar nicht erst geschrieben,
 * sondern als Modellfehler gemeldet (RangeError/Error, kein KdbxError). Sonst würde eine
 * Datei hochgeladen, die danach weder Ownwarden noch KeePassXC öffnen kann.
 */
import { KdbxError, type PoolBinary } from "../contracts";
import {
  NULL_UUID,
  type Attachment,
  type CustomData,
  type CustomIcon,
  type DeletedObject,
  type Entry,
  type Group,
  type KdbxTimes,
  type Meta,
  type Vault,
} from "../model";
import { cloneXmlElement, parseXml, requireValidXmlChars, xmlElement, type XmlElement } from "./xml-dom";
import { ENTRY_ELEMENTS, GROUP_ELEMENTS, META_ELEMENTS, ROOT_ELEMENTS } from "./xml-read";
import { encodeBase64, encodeBool, encodeInteger, encodeTime, encodeUuid, formatTags } from "./xml-values";

// ---------------------------------------------------------------------------
// Binär-Pool
// ---------------------------------------------------------------------------

/**
 * Baut den Binär-Pool für den inneren Header neu auf: Gleiche Anhänge (gleiche Bytes UND
 * gleiches Schutz-Flag) werden nur einmal gespeichert und von allen Einträgen und
 * Verlaufseinträgen über denselben Index referenziert. Die Indizes werden in der
 * Reihenfolge der ersten Verwendung im Dokument vergeben (wie KeePassXC).
 */
export class BinaryPoolBuilder {
  private readonly pool: PoolBinary[] = [];
  /** Indizes der Pool-Einträge je Datenlänge – nur gleich lange Anhänge können gleich sein. */
  private readonly indicesByLength = new Map<number, number[]>();

  /** Liefert den Pool-Index für diesen Anhang (legt ihn bei Bedarf an). */
  add(attachment: Attachment): number {
    const candidates = this.indicesByLength.get(attachment.data.length) ?? [];
    for (const index of candidates) {
      const existing = this.pool[index]!;
      if (existing.protected === attachment.protected && sameBytes(existing.data, attachment.data)) return index;
    }
    const index = this.pool.length;
    this.pool.push({ data: attachment.data, protected: attachment.protected });
    candidates.push(index);
    this.indicesByLength.set(attachment.data.length, candidates);
    return index;
  }

  /** Der fertige Pool (Reihenfolge = Index). */
  binaries(): PoolBinary[] {
    return [...this.pool];
  }
}

/** Bytevergleich ohne Zeitkonstanz (Anhänge sind keine Prüfsummen); gleiches Objekt = sofort gleich. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Reihenfolge der Kind-Elemente
// ---------------------------------------------------------------------------

/**
 * Platzhalter in den Reihenfolge-Listen: Hierhin kommen unbekannte Elemente, deren Namen
 * auch KeePassXC nicht kennt (z. B. von Plugins), in ihrer Originalreihenfolge.
 */
const FOREIGN = "*";

/**
 * Schreibreihenfolge von KeePassXC. Enthalten sind auch Elemente, die Ownwarden nur als
 * „unbekannt“ durchreicht (z. B. MemoryProtection, AutoType): So stehen sie nach dem
 * Speichern wieder genau dort, wo KeePassXC sie hinschreiben würde.
 */
const META_ORDER = [
  "Generator",
  "DatabaseName",
  "DatabaseNameChanged",
  "DatabaseDescription",
  "DatabaseDescriptionChanged",
  "DefaultUserName",
  "DefaultUserNameChanged",
  "MaintenanceHistoryDays",
  "Color",
  "MasterKeyChanged",
  "MasterKeyChangeRec",
  "MasterKeyChangeForce",
  "MemoryProtection",
  "CustomIcons",
  "RecycleBinEnabled",
  "RecycleBinUUID",
  "RecycleBinChanged",
  "EntryTemplatesGroup",
  "EntryTemplatesGroupChanged",
  "LastSelectedGroup",
  "LastTopVisibleGroup",
  "HistoryMaxItems",
  "HistoryMaxSize",
  "SettingsChanged",
  "CustomData",
  FOREIGN,
];

const ROOT_ORDER = ["Group", "DeletedObjects", FOREIGN];

const GROUP_ORDER = [
  "UUID",
  "Name",
  "Notes",
  "Tags",
  "IconID",
  "CustomIconUUID",
  "Times",
  "IsExpanded",
  "DefaultAutoTypeSequence",
  "EnableAutoType",
  "EnableSearching",
  "LastTopVisibleEntry",
  "CustomData",
  "PreviousParentGroup",
  FOREIGN,
  // Einträge und Untergruppen stehen immer am Ende (erst alle Einträge, dann die Gruppen).
  "Entry",
  "Group",
];

const ENTRY_ORDER = [
  "UUID",
  "IconID",
  "CustomIconUUID",
  "ForegroundColor",
  "BackgroundColor",
  "OverrideURL",
  "Tags",
  "Times",
  "QualityCheck",
  "PreviousParentGroup",
  "String",
  "Binary",
  "AutoType",
  "CustomData",
  FOREIGN,
  // Der Verlauf steht bei KeePassXC immer am Ende eines Eintrags.
  "History",
];

/** Wie ein Container (<Meta>, <Root>, <Group>, <Entry>) seine Kinder anordnet. */
interface ContainerLayout {
  name: string;
  /** Schreibreihenfolge von KeePassXC, mit FOREIGN als Platz für Fremdes. */
  order: readonly string[];
  /** Elemente, die der Leser selbst auswertet – sie dürfen nicht in `unknown` stehen. */
  modelled: ReadonlySet<string>;
}

const META_LAYOUT: ContainerLayout = { name: "Meta", order: META_ORDER, modelled: META_ELEMENTS };
const ROOT_LAYOUT: ContainerLayout = { name: "Root", order: ROOT_ORDER, modelled: ROOT_ELEMENTS };
const GROUP_LAYOUT: ContainerLayout = { name: "Group", order: GROUP_ORDER, modelled: GROUP_ELEMENTS };
const ENTRY_LAYOUT: ContainerLayout = { name: "Entry", order: ENTRY_ORDER, modelled: ENTRY_ELEMENTS };

/**
 * Fügt die bekannten Elemente (schon in KeePassXC-Reihenfolge erzeugt) und die
 * unbekannten Elemente aus dem Modell zusammen. Jedes Element bekommt den Rang seines
 * Namens in `layout.order`; die Sortierung ist stabil, gleichrangige Elemente behalten also
 * ihre Reihenfolge (bekannte vor unbekannten).
 *
 * Die unbekannten Elemente untereinander behalten IMMER ihre Reihenfolge aus dem Modell
 * (model.ts: „in Originalreihenfolge“). Deshalb darf der Rang eines unbekannten Elements nie
 * kleiner sein als der seines Vorgängers in `unknown`. Beispiel KeePass 2.x: Es schreibt
 * <SettingsChanged> direkt nach <Generator>, KeePassXC erst nach <HistoryMaxSize>. Ohne
 * diese Regel würde <SettingsChanged> hinter <DatabaseDescription> usw. rutschen, und nach
 * dem nächsten Einlesen hätte das Modell eine andere Reihenfolge als vorher (ein
 * Scheinunterschied für den Merge). Für Dateien von KeePassXC ändert sich nichts: Dort
 * stehen die unbekannten Elemente schon in aufsteigendem Rang.
 */
function arrange(
  known: XmlElement[],
  unknown: readonly string[],
  layout: ContainerLayout,
  parseUnknown: (xml: string) => XmlElement,
): XmlElement[] {
  const foreignRank = layout.order.indexOf(FOREIGN);
  const rank = (element: XmlElement) => {
    const index = layout.order.indexOf(element.name);
    return index >= 0 ? index : foreignRank;
  };
  const ranked = known.map((element) => ({ element, rank: rank(element) }));
  let previousUnknownRank = 0;
  for (const xml of unknown) {
    const element = parseUnknown(xml);
    // Sonst entstünde eine Datei, die Ownwarden selbst nicht mehr lesen kann (z. B. zwei <Times>).
    if (layout.modelled.has(element.name)) {
      throw new Error(`Modell: <${element.name}> gehört nicht in die unbekannten Elemente von <${layout.name}>.`);
    }
    // Nie über FOREIGN hinaus: dahinter stehen nur noch Entry/Group bzw. History.
    previousUnknownRank = Math.min(Math.max(rank(element), previousUnknownRank), foreignRank);
    ranked.push({ element, rank: previousUnknownRank });
  }
  return ranked
    .map((item, position) => ({ ...item, position }))
    .sort((a, b) => a.rank - b.rank || a.position - b.position)
    .map((item) => item.element);
}

// ---------------------------------------------------------------------------
// Baum aufbauen
// ---------------------------------------------------------------------------

/** Baut das komplette Dokument <KeePassFile>. Füllt dabei `pool` mit den Anhängen. */
export function buildVaultDocument(vault: Vault, pool: BinaryPoolBuilder): XmlElement {
  return new VaultWriter(vault.settings.versionMinor === 1, pool).buildKeePassFile(vault);
}

class VaultWriter {
  /**
   * Bereits eingelesene unbekannte Elemente. Viele sind identisch (z. B. <AutoType> in jedem
   * Eintrag und Verlaufseintrag); jedes nur einmal mit xmldom einzulesen spart bei großen
   * Datenbanken Sekunden.
   */
  private readonly unknownCache = new Map<string, XmlElement>();

  constructor(
    /** true = KDBX 4.1: auch die 4.1-Elemente schreiben. */
    private readonly kdbx41: boolean,
    private readonly pool: BinaryPoolBuilder,
  ) {}

  /** Unbekanntes Element aus dem Modell -> eigene Kopie im Baum (wird später verschlüsselt). */
  private readonly parseUnknown = (xml: string): XmlElement => {
    let element = this.unknownCache.get(xml);
    if (element === undefined) {
      try {
        // allowInvalidChars: Geschützte Werte stehen hier im Klartext, als &#1; usw. (siehe
        // serializeElement). Ungeschützter Text mit solchen Zeichen scheitert später an escapeText.
        element = parseXml(xml, "Modell: unbekanntes XML-Element", { allowInvalidChars: true });
      } catch (error) {
        // Ein Fehler im Modell, keine kaputte Datei: kein KdbxError (Sicherheitsaudit xml-4).
        if (error instanceof KdbxError) throw new Error(error.message, { cause: error });
        throw error;
      }
      this.unknownCache.set(xml, element);
    }
    // Kopie, weil encryptProtectedValues den Baum verändert: Ein gemeinsam genutztes
    // Element würde sonst mehrfach verschlüsselt.
    return cloneXmlElement(element);
  };

  buildKeePassFile(vault: Vault): XmlElement {
    return xmlElement("KeePassFile", [this.buildMeta(vault.meta), this.buildRoot(vault)]);
  }

  private buildMeta(meta: Meta): XmlElement {
    const known = [
      text("Generator", meta.generator),
      text("DatabaseName", meta.databaseName),
      time("DatabaseNameChanged", meta.databaseNameChanged),
      this.buildCustomIcons(meta.customIcons),
      bool("RecycleBinEnabled", meta.recycleBinEnabled),
      uuid("RecycleBinUUID", meta.recycleBinUuid),
      time("RecycleBinChanged", meta.recycleBinChanged),
      historyLimit("HistoryMaxItems", meta.historyMaxItems),
      historyLimit("HistoryMaxSize", meta.historyMaxSize),
      ...this.buildCustomData(meta.customData, "Meta"),
    ];
    return xmlElement("Meta", arrange(known, meta.unknown, META_LAYOUT, this.parseUnknown));
  }

  /** <CustomIcons> schreibt KeePassXC immer, auch leer. */
  private buildCustomIcons(icons: CustomIcon[]): XmlElement {
    return xmlElement(
      "CustomIcons",
      icons.map((icon) => {
        const children = [requiredUuid("UUID", icon.uuid, "Icon")];
        if (this.kdbx41 && icon.name !== undefined) children.push(text("Name", icon.name));
        if (this.kdbx41 && icon.lastModified !== undefined) children.push(time("LastModificationTime", icon.lastModified));
        children.push(text("Data", encodeBase64(icon.data)));
        return xmlElement("Icon", children);
      }),
    );
  }

  private buildRoot(vault: Vault): XmlElement {
    const known = [this.buildGroup(vault.root), this.buildDeletedObjects(vault.deletedObjects)];
    return xmlElement("Root", arrange(known, vault.rootUnknown, ROOT_LAYOUT, this.parseUnknown));
  }

  /** <DeletedObjects> schreibt KeePassXC immer, auch leer. */
  private buildDeletedObjects(deleted: DeletedObject[]): XmlElement {
    return xmlElement(
      "DeletedObjects",
      deleted.map((object) =>
        xmlElement("DeletedObject", [
          requiredUuid("UUID", object.uuid, "Lösch-Vermerk"),
          time("DeletionTime", object.deletionTime),
        ]),
      ),
    );
  }

  private buildGroup(group: Group): XmlElement {
    const known: XmlElement[] = [
      requiredUuid("UUID", group.uuid, "Gruppe"),
      text("Name", group.name),
      text("Notes", group.notes),
    ];
    // Gruppen-Tags gibt es erst ab KDBX 4.1; KeePassXC schreibt sie nur, wenn welche da sind.
    if (this.kdbx41 && group.tags.length > 0) known.push(text("Tags", formatTags(group.tags)));
    known.push(iconId(group.iconId));
    if (group.customIconUuid !== undefined) known.push(uuid("CustomIconUUID", group.customIconUuid));
    known.push(this.buildTimes(group.times));
    known.push(...this.buildCustomData(group.customData, `Gruppe ${group.uuid}`));
    if (this.kdbx41 && group.previousParentGroup !== undefined) {
      known.push(uuid("PreviousParentGroup", group.previousParentGroup));
    }
    // Erst alle Einträge, dann die Untergruppen – das ist auch die Reihenfolge, in der die
    // Anhänge in den Binär-Pool kommen (= Dokumentreihenfolge).
    for (const entry of group.entries) known.push(this.buildEntry(entry, false));
    for (const child of group.groups) known.push(this.buildGroup(child));
    return xmlElement("Group", arrange(known, group.unknown, GROUP_LAYOUT, this.parseUnknown));
  }

  private buildEntry(entry: Entry, isHistoryItem: boolean): XmlElement {
    const known: XmlElement[] = [requiredUuid("UUID", entry.uuid, "Eintrag"), iconId(entry.iconId)];
    if (entry.customIconUuid !== undefined) known.push(uuid("CustomIconUUID", entry.customIconUuid));
    known.push(
      text("ForegroundColor", entry.foregroundColor),
      text("BackgroundColor", entry.backgroundColor),
      text("OverrideURL", entry.overrideUrl),
      text("Tags", formatTags(entry.tags)),
      this.buildTimes(entry.times),
    );
    if (this.kdbx41) {
      // KeePassXC schreibt QualityCheck nur als "False"; ein ausdrückliches true im Modell
      // schreiben wir trotzdem mit, damit es beim Lesen erhalten bleibt.
      if (entry.qualityCheck !== undefined) known.push(bool("QualityCheck", entry.qualityCheck));
      if (entry.previousParentGroup !== undefined) known.push(uuid("PreviousParentGroup", entry.previousParentGroup));
    }
    for (const [key, value] of entry.strings) {
      // In XML ungültige Zeichen kann die Datei nicht speichern. Früher wurden sie still
      // entfernt; dann fielen z. B. "PIN" mit und ohne U+0001 zu einem Feld zusammen
      // (Sicherheitsaudit xml-2). Jetzt: ablehnen, mit Eintrag und Feldname in der Meldung.
      requireValidXmlChars(key, `Eintrag ${entry.uuid}: Feldname`);
      known.push(
        xmlElement("String", [
          text("Key", key),
          xmlElement("Value", value.value, value.protected ? { Protected: "True" } : {}),
        ]),
      );
    }
    known.push(...this.buildAttachments(entry));
    known.push(...this.buildCustomData(entry.customData, `Eintrag ${entry.uuid}`));
    // KeePassXC schreibt <History> bei jedem Eintrag (auch leer), nie in Verlaufseinträgen.
    // Ein Verlauf IM Verlaufseintrag ist im Format nicht vorgesehen und wird nicht geschrieben.
    if (!isHistoryItem) {
      known.push(xmlElement("History", entry.history.map((item) => this.buildEntry(item, true))));
    }
    return xmlElement("Entry", arrange(known, entry.unknown, ENTRY_LAYOUT, this.parseUnknown));
  }

  /** <Binary><Key>Dateiname</Key><Value Ref="n"/></Binary> je Anhang. */
  private buildAttachments(entry: Entry): XmlElement[] {
    const names = new Set<string>();
    return entry.attachments.map((attachment) => {
      // Doppelte Namen kann keine KDBX-Anwendung darstellen (Anhänge sind dort ein
      // Wörterbuch); KeePassXC würde einen davon still verlieren. Lieber laut abbrechen.
      // Ungültige XML-Zeichen werden nicht mehr entfernt, sondern abgelehnt (wie bei Feldnamen).
      requireValidXmlChars(attachment.name, `Eintrag ${entry.uuid}: Anhang-Name`);
      if (names.has(attachment.name)) {
        throw new Error(`Eintrag ${entry.uuid}: Anhang "${attachment.name}" ist doppelt vorhanden.`);
      }
      names.add(attachment.name);
      const ref = this.pool.add(attachment);
      return xmlElement("Binary", [text("Key", attachment.name), xmlElement("Value", [], { Ref: String(ref) })]);
    });
  }

  private buildTimes(times: KdbxTimes): XmlElement {
    return xmlElement("Times", [
      time("LastModificationTime", times.lastModification),
      time("CreationTime", times.creation),
      time("LastAccessTime", times.lastAccess),
      time("ExpiryTime", times.expiry),
      bool("Expires", times.expires),
      integer("UsageCount", times.usageCount),
      time("LocationChanged", times.locationChanged),
    ]);
  }

  /** <CustomData> nur, wenn es Einträge gibt (wie KeePassXC). `owner` nennt Meta/Gruppe/Eintrag. */
  private buildCustomData(customData: CustomData, owner: string): XmlElement[] {
    if (customData.size === 0) return [];
    const items = [...customData].map(([key, item]) => {
      // Wie bei Feldnamen: Schlüssel mit ungültigen Zeichen ablehnen. Früher fielen z. B. "K" und
      // "K" + U+0001 beim Schreiben still zusammen, beim Lesen gewann der letzte (Sicherheitsaudit xml-2).
      requireValidXmlChars(key, `${owner}: CustomData-Schlüssel`);
      const children = [text("Key", key), text("Value", item.value)];
      if (this.kdbx41 && item.lastModified !== undefined) children.push(time("LastModificationTime", item.lastModified));
      return xmlElement("Item", children);
    });
    return [xmlElement("CustomData", items)];
  }
}

// ---------------------------------------------------------------------------
// Einzelne Elemente
// ---------------------------------------------------------------------------

function text(name: string, value: string): XmlElement {
  return xmlElement(name, value);
}

function bool(name: string, value: boolean): XmlElement {
  return xmlElement(name, encodeBool(value));
}

function integer(name: string, value: number): XmlElement {
  return xmlElement(name, encodeInteger(value, name));
}

function time(name: string, value: number): XmlElement {
  return xmlElement(name, encodeTime(value));
}

function uuid(name: string, value: string): XmlElement {
  return xmlElement(name, encodeUuid(value, name));
}

/** UUID eines Eintrags, einer Gruppe, eines Icons oder Lösch-Vermerks: nie die Null-UUID. */
function requiredUuid(name: string, value: string, owner: string): XmlElement {
  const element = uuid(name, value);
  if (element.children[0] === NULL_UUID) throw new RangeError(`${owner}: Die Null-UUID ist als UUID nicht erlaubt.`);
  return element;
}

/** <IconID>: Nummer eines eingebauten Icons, nie negativ (das liest kein Programm). */
function iconId(value: number): XmlElement {
  if (value < 0) throw new RangeError(`IconID: Icon-Nummer darf nicht negativ sein: ${value}`);
  return integer("IconID", value);
}

/** HistoryMaxItems/HistoryMaxSize: -1 = unbegrenzt, kleinere Werte sind ungültig. */
function historyLimit(name: string, value: number): XmlElement {
  if (value < -1) throw new RangeError(`${name}: Wert muss -1 (unbegrenzt) oder größer sein: ${value}`);
  return integer(name, value);
}
