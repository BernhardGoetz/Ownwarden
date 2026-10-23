/**
 * XML-Baum -> Modell (Vault).
 *
 * Voraussetzung: Die geschützten Werte sind bereits in Dokumentreihenfolge entschlüsselt
 * (xml-protected.ts); ihr Klartext steht in `ReadContext.plaintexts`.
 *
 * Grundregeln:
 *   - Pflichtangaben fehlen (z. B. UUID eines Eintrags, Wurzelgruppe) oder Werte sind
 *     ungültig (kaputtes Base64, keine Zahl …) -> KdbxError("Corrupt") mit deutscher Meldung.
 *   - Optionale Angaben fehlen -> sinnvolle Standardwerte (Zeiten: 0 = 1970-01-01).
 *   - Ein bekanntes Element, das höchstens einmal vorkommen darf, kommt doppelt vor -> Fehler.
 *   - Unbekannte Kind-Elemente von <Meta>, <Group>, <Entry> und <Root> werden als kompakter
 *     XML-Text in `unknown` aufbewahrt (geschützte Werte darin im Klartext mit
 *     Protected="True"), damit beim Speichern nichts verloren geht.
 *   - Fehlermeldungen nennen Elementnamen, Feldnamen und UUIDs, aber nie Feldinhalte. Namen aus
 *     der Datei nur über displayText (Sicherheitsaudit leak-1).
 *   - Doppelte UUIDs von Gruppen/Einträgen: Das spätere Vorkommen bekommt eine neue,
 *     abgeleitete UUID (duplicate-uuids.ts), damit beim Zusammenführen nichts verloren geht.
 *
 * Elementnamen abgeglichen mit KeePassXC 2.7.6 (src/format/KdbxXmlReader.cpp).
 */
import type { PoolBinary } from "../contracts";
import { displayText } from "../display-text";
import {
  NULL_UUID,
  type Attachment,
  type CustomData,
  type CustomIcon,
  type DeletedObject,
  type Entry,
  type Group,
  type KdbxSettings,
  type KdbxTimes,
  type Meta,
  type ProtectedString,
  type Uuid,
  type Vault,
} from "../model";
import { bytesEqual, corrupt } from "./bytes";
import { repairDuplicateUuids, type UuidOwner } from "./duplicate-uuids";
import { childElements, plainText, serializeElement, type XmlElement } from "./xml-dom";
import { isProtectedElement } from "./xml-protected";
import {
  decodeBase64,
  decodeBool,
  decodeInteger,
  decodeTime,
  decodeUtf8Value,
  decodeUuid,
  isTrueAttribute,
  parseTags,
} from "./xml-values";

/** Was der Leser außer dem Baum braucht. */
export interface ReadContext {
  /** Klartext jedes geschützten Elements (aus decryptProtectedValues). */
  plaintexts: Map<XmlElement, Uint8Array>;
  /** Binär-Pool aus dem inneren Header; <Binary><Value Ref="n"/> verweist hierauf. */
  binaries: PoolBinary[];
}

/** Standardwerte von KeePass/KeePassXC für fehlende Meta-Angaben. */
const DEFAULT_HISTORY_MAX_ITEMS = 10;
const DEFAULT_HISTORY_MAX_SIZE = 6 * 1024 * 1024;

// Elemente, die Ownwarden selbst auswertet. Alles andere ist „unbekannt“ und wird aufbewahrt.
const KEEPASS_FILE_ELEMENTS = new Set(["Meta", "Root"]);
export const META_ELEMENTS: ReadonlySet<string> = new Set([
  "Generator",
  "DatabaseName",
  "DatabaseNameChanged",
  "RecycleBinEnabled",
  "RecycleBinUUID",
  "RecycleBinChanged",
  "HistoryMaxItems",
  "HistoryMaxSize",
  "CustomIcons",
  "CustomData",
  // Nur KDBX 3, in KDBX 4 bedeutungslos. Sie werden absichtlich VERWORFEN: Ein alter
  // Header-Hash passt nach dem Speichern nie mehr, und ein alter Binär-Pool in <Meta>
  // würde bei KeePassXC den neu aufgebauten Pool aus dem inneren Header überschreiben.
  "HeaderHash",
  "Binaries",
]);
export const ROOT_ELEMENTS: ReadonlySet<string> = new Set(["Group", "DeletedObjects"]);
export const GROUP_ELEMENTS: ReadonlySet<string> = new Set([
  "UUID",
  "Name",
  "Notes",
  "IconID",
  "CustomIconUUID",
  "Times",
  "Tags",
  "PreviousParentGroup",
  "CustomData",
  "Entry",
  "Group",
]);
export const ENTRY_ELEMENTS: ReadonlySet<string> = new Set([
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
  "CustomData",
  "History",
]);
const TIMES_ELEMENTS = new Set([
  "LastModificationTime",
  "CreationTime",
  "LastAccessTime",
  "ExpiryTime",
  "Expires",
  "UsageCount",
  "LocationChanged",
]);

/**
 * Feld-, Anhangs- oder CustomData-Name aus der Datei für Meldungen, in Anführungszeichen. Er darf
 * Zeilenumbrüche, C1-Steuer- und Bidi-Zeichen enthalten und Megabytes lang sein: nur entschärft
 * und gekürzt (Sicherheitsaudit leak-1).
 */
function quoted(name: string): string {
  return `"${displayText(name)}"`;
}

/**
 * Die Kind-Elemente eines Elements, nach Namen einsortiert. Kinder, deren Name nicht in
 * `known` steht, kommen in Originalreihenfolge nach `unknown`.
 */
class Children {
  private readonly byName = new Map<string, XmlElement[]>();
  readonly unknown: XmlElement[] = [];

  constructor(
    parent: XmlElement,
    known: ReadonlySet<string>,
    private readonly context: string,
  ) {
    for (const child of childElements(parent)) {
      if (!known.has(child.name)) {
        this.unknown.push(child);
        continue;
      }
      const list = this.byName.get(child.name);
      if (list) list.push(child);
      else this.byName.set(child.name, [child]);
    }
  }

  /** Das Element mit diesem Namen oder undefined; mehr als eines ist ein Fehler. */
  optional(name: string): XmlElement | undefined {
    const list = this.byName.get(name);
    if (list && list.length > 1) corrupt(`${this.context}: <${name}> kommt mehrfach vor.`);
    return list?.[0];
  }

  /** Das Element mit diesem Namen; fehlt es, ist die Datei kaputt. */
  required(name: string): XmlElement {
    const element = this.optional(name);
    if (element === undefined) corrupt(`${this.context}: <${name}> fehlt.`);
    return element;
  }

  /** Alle Elemente mit diesem Namen, in Dokumentreihenfolge. */
  all(name: string): XmlElement[] {
    return this.byName.get(name) ?? [];
  }
}

/** Liest das Wurzelelement <KeePassFile> in ein Modell. */
export function readVault(document: XmlElement, settings: KdbxSettings, context: ReadContext): Vault {
  return new VaultReader(context).readKeePassFile(document, settings);
}

/**
 * Gruppen und Einträge (ohne Verlaufseinträge) in Dokumentreihenfolge. Das Modell trennt
 * Einträge und Untergruppen einer Gruppe; die Reihenfolge untereinander steht nur im XML.
 * `group` ist die aus `element` gelesene Gruppe: Ihre Einträge und Untergruppen stehen in
 * derselben Reihenfolge wie die <Entry>- bzw. <Group>-Kinder von `element`.
 */
function ownersInDocumentOrder(element: XmlElement, group: Group): UuidOwner[] {
  const owners: UuidOwner[] = [];
  const visit = (groupElement: XmlElement, current: Group): void => {
    owners.push({ kind: "group", group: current });
    let entryIndex = 0;
    let groupIndex = 0;
    for (const child of childElements(groupElement)) {
      if (child.name === "Entry") owners.push({ kind: "entry", entry: current.entries[entryIndex++]! });
      else if (child.name === "Group") visit(child, current.groups[groupIndex++]!);
    }
  };
  visit(element, group);
  return owners;
}

/** Alle UUIDs der Datei außer denen von Gruppen und Einträgen: Verlaufseinträge, DeletedObjects. */
function otherUuids(vault: Vault): Uuid[] {
  const uuids = vault.deletedObjects.map((deleted) => deleted.uuid);
  const visit = (group: Group): void => {
    for (const entry of group.entries) for (const item of entry.history) uuids.push(item.uuid);
    group.groups.forEach(visit);
  };
  visit(vault.root);
  return uuids;
}

class VaultReader {
  constructor(private readonly context: ReadContext) {}

  // -------------------------------------------------------------------------
  // Datei, Meta, Root
  // -------------------------------------------------------------------------

  readKeePassFile(document: XmlElement, settings: KdbxSettings): Vault {
    if (document.name !== "KeePassFile") corrupt(`XML-Datenbank: Wurzelelement ist <${displayText(document.name)}> statt <KeePassFile>.`);
    // Andere Kinder als <Meta> und <Root> sieht kein bekanntes Programm vor; sie fallen weg.
    const children = new Children(document, KEEPASS_FILE_ELEMENTS, "KeePassFile");
    const metaElement = children.optional("Meta");
    const rootElement = children.required("Root");

    const root = new Children(rootElement, ROOT_ELEMENTS, "Root");
    const groupElement = root.optional("Group");
    if (groupElement === undefined) corrupt("Root: Die Wurzelgruppe fehlt.");
    const deletedObjectsElement = root.optional("DeletedObjects");

    const vault: Vault = {
      settings,
      meta: this.readMeta(metaElement),
      root: this.readGroup(groupElement),
      deletedObjects: deletedObjectsElement ? this.readDeletedObjects(deletedObjectsElement) : [],
      rootUnknown: this.unknownToStrings(root.unknown),
    };
    // Erst wenn ALLES gelesen ist: Alle UUIDs der Datei müssen bekannt sein (Review kdbx-1).
    repairDuplicateUuids(ownersInDocumentOrder(groupElement, vault.root), otherUuids(vault));
    return vault;
  }

  private readMeta(element: XmlElement | undefined): Meta {
    if (element === undefined) {
      // Eine Datei ganz ohne <Meta> ist ungewöhnlich, aber lesbar (KeePassXC: Standardwerte).
      return this.readMeta({ name: "Meta", attributes: new Map(), children: [] });
    }
    const c = new Children(element, META_ELEMENTS, "Meta");
    const customIcons = c.optional("CustomIcons");
    return {
      generator: this.string(c.optional("Generator"), "Meta/Generator"),
      databaseName: this.string(c.optional("DatabaseName"), "Meta/DatabaseName"),
      databaseNameChanged: this.time(c.optional("DatabaseNameChanged"), "Meta/DatabaseNameChanged"),
      recycleBinEnabled: this.bool(c.optional("RecycleBinEnabled"), "Meta/RecycleBinEnabled", true),
      recycleBinUuid: this.optionalUuid(c.optional("RecycleBinUUID"), "Meta/RecycleBinUUID") ?? NULL_UUID,
      recycleBinChanged: this.time(c.optional("RecycleBinChanged"), "Meta/RecycleBinChanged"),
      historyMaxItems: this.historyLimit(c.optional("HistoryMaxItems"), "Meta/HistoryMaxItems", DEFAULT_HISTORY_MAX_ITEMS),
      historyMaxSize: this.historyLimit(c.optional("HistoryMaxSize"), "Meta/HistoryMaxSize", DEFAULT_HISTORY_MAX_SIZE),
      customIcons: customIcons ? this.readCustomIcons(customIcons) : [],
      customData: this.readCustomData(c.optional("CustomData"), "Meta/CustomData"),
      unknown: this.unknownToStrings(c.unknown),
    };
  }

  /** HistoryMaxItems/HistoryMaxSize: -1 = unbegrenzt, kleinere Werte sind ungültig. */
  private historyLimit(element: XmlElement | undefined, what: string, fallback: number): number {
    const value = this.integer(element, what, fallback);
    if (value < -1) corrupt(`${what}: Wert muss -1 (unbegrenzt) oder größer sein.`);
    return value;
  }

  private readCustomIcons(element: XmlElement): CustomIcon[] {
    const icons: CustomIcon[] = [];
    for (const iconElement of childElements(element)) {
      if (iconElement.name !== "Icon") continue; // wie KeePassXC: Fremdes überspringen
      const c = new Children(iconElement, new Set(["UUID", "Data", "Name", "LastModificationTime"]), "Meta/CustomIcons/Icon");
      const icon: CustomIcon = {
        uuid: this.requiredUuid(c.optional("UUID"), "Meta/CustomIcons/Icon/UUID"),
        data: decodeBase64(this.text(c.required("Data"), "Meta/CustomIcons/Icon/Data"), "Meta/CustomIcons/Icon/Data"),
      };
      const name = c.optional("Name");
      if (name !== undefined) icon.name = this.text(name, "Meta/CustomIcons/Icon/Name");
      const lastModified = c.optional("LastModificationTime");
      if (lastModified !== undefined && this.text(lastModified, "Meta/CustomIcons/Icon").trim() !== "") {
        icon.lastModified = this.time(lastModified, "Meta/CustomIcons/Icon/LastModificationTime");
      }
      icons.push(icon);
    }
    return icons;
  }

  private readDeletedObjects(element: XmlElement): DeletedObject[] {
    const deleted: DeletedObject[] = [];
    for (const objectElement of childElements(element)) {
      if (objectElement.name !== "DeletedObject") continue;
      const what = "DeletedObjects/DeletedObject";
      const c = new Children(objectElement, new Set(["UUID", "DeletionTime"]), what);
      // Ohne UUID oder Zeit wäre der Lösch-Vermerk wertlos; ihn still zu verwerfen könnte
      // beim Zusammenführen gelöschte Einträge zurückbringen. Daher: Fehler.
      const uuid = this.requiredUuid(c.optional("UUID"), `${what}/UUID`);
      const timeElement = c.required("DeletionTime");
      if (this.text(timeElement, what).trim() === "") corrupt(`${what} ${uuid}: <DeletionTime> ist leer.`);
      deleted.push({ uuid, deletionTime: this.time(timeElement, `${what}/DeletionTime`) });
    }
    return deleted;
  }

  // -------------------------------------------------------------------------
  // Gruppen
  // -------------------------------------------------------------------------

  private readGroup(element: XmlElement): Group {
    const c = new Children(element, GROUP_ELEMENTS, "Gruppe");
    const uuid = this.requiredUuid(c.optional("UUID"), "Gruppe/UUID");
    const what = `Gruppe ${uuid}`;
    const group: Group = {
      uuid,
      name: this.string(c.optional("Name"), `${what}/Name`),
      notes: this.string(c.optional("Notes"), `${what}/Notes`),
      iconId: this.iconId(c.optional("IconID"), `${what}/IconID`),
      times: this.readTimes(c.optional("Times"), `${what}/Times`),
      tags: parseTags(this.string(c.optional("Tags"), `${what}/Tags`)),
      customData: this.readCustomData(c.optional("CustomData"), `${what}/CustomData`),
      // Reihenfolge wie in der Datei: KeePass/KeePassXC schreiben erst alle Einträge,
      // dann alle Untergruppen.
      groups: c.all("Group").map((child) => this.readGroup(child)),
      entries: c.all("Entry").map((child) => this.readEntry(child, false)),
      unknown: this.unknownToStrings(c.unknown),
    };
    const customIconUuid = this.optionalUuid(c.optional("CustomIconUUID"), `${what}/CustomIconUUID`);
    if (customIconUuid !== undefined) group.customIconUuid = customIconUuid;
    const previousParent = this.optionalUuid(c.optional("PreviousParentGroup"), `${what}/PreviousParentGroup`);
    if (previousParent !== undefined) group.previousParentGroup = previousParent;
    return group;
  }

  // -------------------------------------------------------------------------
  // Einträge
  // -------------------------------------------------------------------------

  private readEntry(element: XmlElement, isHistoryItem: boolean): Entry {
    const c = new Children(element, ENTRY_ELEMENTS, isHistoryItem ? "Verlaufseintrag" : "Eintrag");
    const uuid = this.requiredUuid(c.optional("UUID"), "Eintrag/UUID");
    const what = `${isHistoryItem ? "Verlaufseintrag" : "Eintrag"} ${uuid}`;

    const strings = new Map<string, ProtectedString>();
    for (const stringElement of c.all("String")) this.readEntryString(stringElement, strings, what);
    const attachments: Attachment[] = [];
    for (const binaryElement of c.all("Binary")) this.readEntryBinary(binaryElement, attachments, what);

    const entry: Entry = {
      uuid,
      iconId: this.iconId(c.optional("IconID"), `${what}/IconID`),
      foregroundColor: this.string(c.optional("ForegroundColor"), `${what}/ForegroundColor`),
      backgroundColor: this.string(c.optional("BackgroundColor"), `${what}/BackgroundColor`),
      overrideUrl: this.string(c.optional("OverrideURL"), `${what}/OverrideURL`),
      tags: parseTags(this.string(c.optional("Tags"), `${what}/Tags`)),
      times: this.readTimes(c.optional("Times"), `${what}/Times`),
      strings,
      attachments,
      customData: this.readCustomData(c.optional("CustomData"), `${what}/CustomData`),
      history: this.readHistory(c.optional("History"), isHistoryItem, what),
      unknown: this.unknownToStrings(c.unknown),
    };
    const customIconUuid = this.optionalUuid(c.optional("CustomIconUUID"), `${what}/CustomIconUUID`);
    if (customIconUuid !== undefined) entry.customIconUuid = customIconUuid;
    const qualityCheck = c.optional("QualityCheck");
    if (qualityCheck !== undefined && this.text(qualityCheck, what).trim() !== "") {
      entry.qualityCheck = this.bool(qualityCheck, `${what}/QualityCheck`, true);
    }
    const previousParent = this.optionalUuid(c.optional("PreviousParentGroup"), `${what}/PreviousParentGroup`);
    if (previousParent !== undefined) entry.previousParentGroup = previousParent;
    return entry;
  }

  /** <String><Key>Name</Key><Value Protected="True">…</Value></String> */
  private readEntryString(element: XmlElement, strings: Map<string, ProtectedString>, what: string): void {
    const c = new Children(element, new Set(["Key", "Value"]), `${what}/String`);
    const key = this.text(c.required("Key"), `${what}/String/Key`);
    const valueElement = c.required("Value");
    const value = this.text(valueElement, `${what}/String ${quoted(key)}`);
    // ProtectInMemory="True" steht in unverschlüsselten XML-Exporten: Der Wert ist Klartext,
    // soll beim Speichern aber geschützt werden.
    const isProtected = isProtectedElement(valueElement) || isTrueAttribute(valueElement.attributes.get("ProtectInMemory"));

    const existing = strings.get(key);
    // Wie KeePassXC: Ein doppeltes Feld ist nur erlaubt, wenn das frühere leer war.
    if (existing !== undefined && existing.value !== "") corrupt(`${what}: Feld ${quoted(key)} kommt doppelt vor.`);
    strings.set(key, { value, protected: isProtected });
  }

  /** <Binary><Key>Dateiname</Key><Value Ref="n"/></Binary> */
  private readEntryBinary(element: XmlElement, attachments: Attachment[], what: string): void {
    const c = new Children(element, new Set(["Key", "Value"]), `${what}/Binary`);
    const name = this.text(c.required("Key"), `${what}/Binary/Key`);
    const valueElement = c.required("Value");
    const attachment = { name, ...this.resolveAttachmentData(valueElement, `${what}/Anhang ${quoted(name)}`) };

    const existing = attachments.find((a) => a.name === name);
    if (existing === undefined) {
      attachments.push(attachment);
    } else if (existing.protected !== attachment.protected || !bytesEqual(existing.data, attachment.data)) {
      corrupt(`${what}: Anhang ${quoted(name)} kommt doppelt mit unterschiedlichem Inhalt vor.`);
    }
    // Doppelt mit gleichem Inhalt: einmal reicht.
  }

  /** Daten eines Anhangs: aus dem Binär-Pool (Ref) oder – in sehr alten Dateien – direkt im XML. */
  private resolveAttachmentData(valueElement: XmlElement, what: string): { data: Uint8Array; protected: boolean } {
    const ref = valueElement.attributes.get("Ref");
    if (ref !== undefined) {
      if (!/^\s*\d{1,9}\s*$/.test(ref)) corrupt(`${what}: ungültiger Verweis Ref="…" auf den Binär-Pool.`);
      const index = Number(ref);
      const binary = this.context.binaries[index];
      if (binary === undefined) {
        corrupt(`${what}: verweist auf Pool-Eintrag ${index}, der Binär-Pool hat aber nur ${this.context.binaries.length}.`);
      }
      // Die Daten werden NICHT kopiert: Mehrere Einträge (und Verlaufseinträge) mit
      // demselben Anhang teilen sich dasselbe Array. Es darf daher nie verändert werden.
      return { data: binary.data, protected: binary.protected };
    }
    // Inline-Daten (Format-Kompatibilität wie bei KeePassXC): Base64, ggf. geschützt.
    const plaintext = this.context.plaintexts.get(valueElement);
    if (plaintext !== undefined) return { data: plaintext, protected: true };
    return { data: decodeBase64(plainText(valueElement, what), what), protected: false };
  }

  private readHistory(element: XmlElement | undefined, isHistoryItem: boolean, what: string): Entry[] {
    if (element === undefined) return [];
    // KeePassXC lehnt das ebenfalls ab („History element in history entry“).
    if (isHistoryItem) corrupt(`${what}: Ein Verlaufseintrag darf selbst keinen Verlauf haben.`);
    return childElements(element)
      .filter((child) => child.name === "Entry")
      .map((child) => this.readEntry(child, true));
  }

  // -------------------------------------------------------------------------
  // Gemeinsame Bausteine
  // -------------------------------------------------------------------------

  private readTimes(element: XmlElement | undefined, what: string): KdbxTimes {
    const c = element ? new Children(element, TIMES_ELEMENTS, what) : undefined;
    const get = (name: string) => c?.optional(name);
    return {
      creation: this.time(get("CreationTime"), `${what}/CreationTime`),
      lastModification: this.time(get("LastModificationTime"), `${what}/LastModificationTime`),
      lastAccess: this.time(get("LastAccessTime"), `${what}/LastAccessTime`),
      expiry: this.time(get("ExpiryTime"), `${what}/ExpiryTime`),
      expires: this.bool(get("Expires"), `${what}/Expires`, false),
      usageCount: this.integer(get("UsageCount"), `${what}/UsageCount`, 0),
      locationChanged: this.time(get("LocationChanged"), `${what}/LocationChanged`),
    };
  }

  /**
   * <CustomData><Item><Key/><Value/><LastModificationTime/>?</Item>…</CustomData>
   * LastModificationTime wird in jeder Version gelesen (wie KeePassXC), aber nur in
   * KDBX 4.1 geschrieben. Doppelte Schlüssel: der letzte gewinnt (wie KeePassXC).
   */
  private readCustomData(element: XmlElement | undefined, what: string): CustomData {
    const customData: CustomData = new Map();
    if (element === undefined) return customData;
    for (const itemElement of childElements(element)) {
      if (itemElement.name !== "Item") continue;
      const c = new Children(itemElement, new Set(["Key", "Value", "LastModificationTime"]), `${what}/Item`);
      const key = this.text(c.required("Key"), `${what}/Item/Key`);
      const value = this.text(c.required("Value"), `${what}/Item ${quoted(key)}`);
      const lastModifiedElement = c.optional("LastModificationTime");
      const hasLastModified = lastModifiedElement !== undefined && this.text(lastModifiedElement, what).trim() !== "";
      customData.set(
        key,
        hasLastModified
          ? { value, lastModified: this.time(lastModifiedElement, `${what}/Item ${quoted(key)}/LastModificationTime`) }
          : { value },
      );
    }
    return customData;
  }

  /**
   * Unbekannte Elemente als kompakten XML-Text. Geschützte Werte darin werden durch ihren
   * Klartext ersetzt (Protected="True" bleibt stehen), damit sie beim Speichern mit dem
   * dann neuen Zufallsstrom wieder verschlüsselt werden können.
   */
  private unknownToStrings(elements: XmlElement[]): string[] {
    return elements.map((element) => serializeElement(this.withPlaintext(element)));
  }

  private withPlaintext(element: XmlElement): XmlElement {
    if (this.context.plaintexts.has(element)) {
      return { ...element, children: [this.text(element, `Geschützter Wert in <${displayText(element.name)}>`)] };
    }
    return {
      ...element,
      children: element.children.map((child) => (typeof child === "string" ? child : this.withPlaintext(child))),
    };
  }

  // -------------------------------------------------------------------------
  // Einzelwerte
  // -------------------------------------------------------------------------

  /** Text eines Elements; bei geschützten Elementen der entschlüsselte Klartext. */
  private text(element: XmlElement, what: string): string {
    const plaintext = this.context.plaintexts.get(element);
    if (plaintext !== undefined) return decodeUtf8Value(plaintext, what);
    return plainText(element, what);
  }

  private string(element: XmlElement | undefined, what: string): string {
    return element === undefined ? "" : this.text(element, what);
  }

  /** Wahrheitswert; ein fehlendes oder leeres Element ergibt `fallback`. */
  private bool(element: XmlElement | undefined, what: string, fallback: boolean): boolean {
    const text = this.string(element, what);
    return text.trim() === "" ? fallback : decodeBool(text, what);
  }

  /** Ganze Zahl; ein fehlendes oder leeres Element ergibt `fallback`. */
  private integer(element: XmlElement | undefined, what: string, fallback: number): number {
    const text = this.string(element, what);
    return text.trim() === "" ? fallback : decodeInteger(text, what);
  }

  private iconId(element: XmlElement | undefined, what: string): number {
    const value = this.integer(element, what, 0);
    if (value < 0) corrupt(`${what}: Icon-Nummer darf nicht negativ sein.`);
    return value;
  }

  /** Zeit; ein fehlendes oder leeres Element ergibt 0 (1970-01-01). */
  private time(element: XmlElement | undefined, what: string): number {
    const text = this.string(element, what);
    return text.trim() === "" ? 0 : decodeTime(text, what);
  }

  /** UUID, die vorhanden und nicht die Null-UUID sein muss. */
  private requiredUuid(element: XmlElement | undefined, what: string): Uuid {
    const uuid = this.optionalUuid(element, what);
    if (uuid === undefined) corrupt(`${what}: UUID fehlt oder ist leer.`);
    return uuid;
  }

  /** UUID oder undefined, wenn das Element fehlt, leer ist oder die Null-UUID enthält. */
  private optionalUuid(element: XmlElement | undefined, what: string): Uuid | undefined {
    const text = this.string(element, what);
    if (text.trim() === "") return undefined;
    const uuid = decodeUuid(text, what);
    return uuid === NULL_UUID ? undefined : uuid;
  }
}
