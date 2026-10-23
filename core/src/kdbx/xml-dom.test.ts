import { describe, expect, it } from "vitest";
import { MAX_XML_BYTES } from "./constants";
import {
  MAX_XML_DEPTH,
  MAX_XML_NODES,
  childElements,
  escapeAttribute,
  escapeText,
  findXmlLimitViolation,
  parseXml,
  plainText,
  serializeDocument,
  serializeElement,
  xmlElement,
} from "./xml-dom";

const corrupt = expect.objectContaining({ name: "KdbxError", code: "Corrupt" });

/** Fehlermeldung von `run` (wirft `run` nicht, schlägt der Test fehl). */
function errorOf(run: () => unknown): Error {
  try {
    run();
  } catch (error) {
    return error as Error;
  }
  throw new Error("Es wurde ein Fehler erwartet.");
}

describe("parseXml: sicher einlesen", () => {
  it("lehnt DOCTYPE und ENTITY ab (Schutz vor XXE und Entity-Bomben)", () => {
    const xxe = '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>';
    expect(() => parseXml(xxe, "Test")).toThrow(corrupt);
    expect(() => parseXml(xxe, "Test")).toThrow(/DOCTYPE/);
    expect(() => parseXml("<a><!ENTITY x 'y'></a>", "Test")).toThrow(corrupt);
    expect(() => parseXml("<!doctype a><a/>", "Test")).toThrow(corrupt);
  });

  it("meldet kaputtes XML als KdbxError Corrupt", () => {
    for (const bad of ["", "kein xml", "<a><b></a>", "<a/><b/>", "<a>&unbekannt;</a>", "<a x='1' x='2'/>", "<a>x < y</a>"]) {
      expect(() => parseXml(bad, "Test"), bad).toThrow(corrupt);
    }
  });

  it("verwirft Einrückung zwischen Elementen, Kommentare und Verarbeitungsanweisungen", () => {
    const root = parseXml("<a>\n\t<!-- c -->\n\t<b>1</b>\n\t<?pi x?>\n\t<c/>\n</a>", "Test");
    expect(root.children).toHaveLength(2);
    expect(childElements(root).map((e) => e.name)).toEqual(["b", "c"]);
  });

  it("behält Text vollständig: Leerzeichen, CDATA, Zeichenreferenzen, \\r", () => {
    expect(plainText(parseXml("<v>   </v>", "T"), "T")).toBe("   ");
    expect(plainText(parseXml("<v><![CDATA[x<y]]>&amp;z</v>", "T"), "T")).toBe("x<y&z");
    expect(plainText(parseXml("<v>a&#13;\nb</v>", "T"), "T")).toBe("a\r\nb");
    // Rohe Zeilenenden werden wie in XML 1.0 vereinheitlicht ...
    expect(plainText(parseXml("<v>a\r\nb\rc</v>", "T"), "T")).toBe("a\nb\nc");
    // ... aber NICHT U+0085/U+2028/U+2029 (das wäre XML 1.1 und verfälschte Werte).
    expect(plainText(parseXml("<v>a b\u0085c d</v>", "T"), "T")).toBe("a b\u0085c d");
  });

  it("liest Attribute in Originalreihenfolge", () => {
    const root = parseXml('<v Protected="True" Other="x &amp; y"/>', "T");
    expect([...root.attributes]).toEqual([
      ["Protected", "True"],
      ["Other", "x & y"],
    ]);
  });

  it("verlangt bei plainText reinen Text", () => {
    expect(() => plainText(parseXml("<v>a<b/></v>", "T"), "T")).toThrow(/nur Text/);
  });

  it("begrenzt die Verschachtelungstiefe", () => {
    const depth = MAX_XML_DEPTH + 5;
    const deep = "<a>".repeat(depth) + "</a>".repeat(depth);
    expect(() => parseXml(deep, "T")).toThrow(/zu tief verschachtelt/);
    const ok = "<a>".repeat(100) + "</a>".repeat(100);
    expect(parseXml(ok, "T").name).toBe("a");
  });

  it("lehnt 40 000 verschachtelte Elemente mit xmlns in Millisekunden ab, bevor xmldom läuft (Sicherheitsaudit xml-1)", () => {
    const n = 40_000;
    for (const open of ['<x xmlns:a="u">', "<x>"]) {
      const xml = `<?xml version="1.0"?><KeePassFile>${open.repeat(n)}${"</x>".repeat(n)}</KeePassFile>`;
      const start = performance.now();
      expect(() => parseXml(xml, "T")).toThrow(corrupt);
      expect(performance.now() - start).toBeLessThan(1000);
    }
  });

  it("lehnt Text über MAX_XML_BYTES Zeichen ab (Sicherheitsaudit dos-4)", () => {
    const xml = `<a>${" ".repeat(MAX_XML_BYTES)}</a>`;
    expect(() => parseXml(xml, "T")).toThrow(corrupt);
    expect(() => parseXml(xml, "T")).toThrow(/zu groß/);
  });

  it("lehnt dichtes XML mit mehr als MAX_XML_NODES Bestandteilen ab, bevor xmldom Speicher belegt (Sicherheitsaudit dos-4)", () => {
    // 4 MiB "<a/>" wären für xmldom über eine Million Elemente (über 1 GB Speicher); eine echte
    // Datei braucht über 30 Byte je Element.
    expect(MAX_XML_NODES).toBe(MAX_XML_BYTES / 16);
    const xml = `<KeePassFile>${"<a/>".repeat(MAX_XML_NODES)}</KeePassFile>`;
    const start = performance.now();
    expect(() => parseXml(xml, "T")).toThrow(/T: XML hat zu viele Bestandteile/);
    expect(performance.now() - start).toBeLessThan(1000);
    expect(() => parseXml(`<a b="1">${'<c d="2"/>'.repeat(10)}</a>`, "T")).not.toThrow();
  });

  it("lehnt Namensräume ab: KDBX-XML benutzt nie welche (Sicherheitsaudit xml-4, xml-5)", () => {
    for (const bad of [
      '<KeePassFile xmlns:p="urn:x"><Root/></KeePassFile>',
      '<KeePassFile xmlns="urn:x"><Root/></KeePassFile>',
      '<KeePassFile><Root><p:Entry xmlns:p="urn:x"><UUID/></p:Entry></Root></KeePassFile>',
      "<KeePassFile><Root><p:Entry/></Root></KeePassFile>",
      "<KeePassFile><xml:Entry/></KeePassFile>",
      '<KeePassFile><Value xml:space="preserve">x</Value></KeePassFile>',
      '<KeePassFile xmlns:p="urn:x"><Value p:Protected="True">x</Value></KeePassFile>',
    ]) {
      expect(() => parseXml(bad, "T"), bad).toThrow(corrupt);
    }
    // Attributnamen, die nur so ähnlich aussehen, sind keine Namensraum-Deklarationen.
    expect([...parseXml('<a xmlnsX="1" Xxmlns="2"/>', "T").attributes.keys()]).toEqual(["xmlnsX", "Xxmlns"]);
  });

  it("behandelt Warnungen von xmldom (nachlässige Syntax) als Fehler (Sicherheitsaudit xml-5)", () => {
    for (const lax of [
      "<a><Value Protected=True>x</Value></a>",
      '<a><Value Protected="True"Foo="1">x</Value></a>',
      '<a><Value\u0080Protected="True">x</Value></a>',
      "<a><Value Protected>x</Value></a>",
      '<a><Value Protected"True">x</Value></a>',
    ]) {
      expect(() => parseXml(lax, "T"), lax).toThrow(corrupt);
    }
    // Die Warnung „Ersatzzeichen U+FFFD gefunden“ ist keine Syntaxfrage: Der Wert bleibt erhalten.
    expect(plainText(parseXml("<v>a�b</v>", "T"), "T")).toBe("a�b");
  });

  it("lehnt in XML 1.0 verbotene Zeichen ab, roh und als Zeichenreferenz (Sicherheitsaudit xml-2)", () => {
    const forbidden = [
      "\u0000",
      "\u0001",
      "\u000B",
      "\u001F",
      "\uFFFE",
      "\uFFFF",
      "\uD800",
      "\uDC00",
      "&#0;",
      "&#1;",
      "&#x1;",
      "&#11;",
      "&#xB;",
      "&#xFFFE;",
      "&#65535;",
      "&#xD800;",
      "&#56320;",
      "&#x110000;",
    ];
    for (const bad of forbidden) {
      expect(() => parseXml(`<v>a${bad}b</v>`, "T"), `Text ${JSON.stringify(bad)}`).toThrow(corrupt);
      expect(() => parseXml(`<v x="a${bad}b"/>`, "T"), `Attribut ${JSON.stringify(bad)}`).toThrow(corrupt);
      // In CDATA ist "&#1;" keine Zeichenreferenz, sondern erlaubter Text; dort zählen nur rohe Zeichen.
      if (!bad.startsWith("&")) {
        expect(() => parseXml(`<v><![CDATA[a${bad}b]]></v>`, "T"), `CDATA ${JSON.stringify(bad)}`).toThrow(corrupt);
      }
    }
    expect(plainText(parseXml("<v><![CDATA[&#1;]]></v>", "T"), "T")).toBe("&#1;");
    expect(() => parseXml("<v>&#1;</v>", "T")).toThrow(/ungültiges Zeichen \(U\+0001\)/);
    // Erlaubt bleiben Tab, LF, CR, alles ab U+0020 außer U+FFFE/U+FFFF und gültige Surrogat-Paare.
    expect(plainText(parseXml("<v>\t\n&#9;&#10;&#13;&#x85;\u0085\u007F&#xFFFD;😀&#x1F600;</v>", "T"), "T")).toBe(
      "\t\n\t\n\r\u0085\u0085\u007F�😀😀",
    );
    // Für unbekannte Elemente AUS DEM MODELL (geschützte Werte im Klartext) bleiben sie lesbar.
    expect(plainText(parseXml("<v>a&#1;b</v>", "T", { allowInvalidChars: true }), "T")).toBe("a\u0001b");
  });

  it("gibt fremden Text aus Meldungen von xmldom nur entschärft weiter (Sicherheitsaudit leak-1)", () => {
    const message = errorOf(() => parseXml("<a></a\u001b[2J\u202EX>", "T")).message;
    expect(message).toMatch(/kein gültiges XML/);
    expect(message).not.toMatch(/[\u001b\u202E]/);
    expect(message).toContain("\\x1b");
  });
});

describe("findXmlLimitViolation: lineare Vorprüfung vor xmldom (Sicherheitsaudit xml-1)", () => {
  const limits = { maxLength: 1_000_000, maxDepth: 4, maxNamespaceDeclarations: 2, maxNodes: 100_000 };
  const check = (xml: string) => findXmlLimitViolation(xml, limits);

  it("zählt die Tiefe über Start- und End-Tags; leere Elemente und Text sind keine eigene Ebene", () => {
    expect(check("<a><b><c><d/></c></b></a>")).toBeUndefined();
    expect(check("<a><b><c><d>Text</d></c></b></a>")).toBeUndefined();
    expect(check("<a><b><c><d><e/></d></c></b></a>")).toBe("XML ist zu tief verschachtelt (mehr als 4 Ebenen)");
    expect(check("<a><b><c><d><e></e></d></c></b></a>")).toMatch(/zu tief/);
    expect(check(`<a>${"<b><c/></b>".repeat(1000)}<b><c><d/></c></b></a>`)).toBeUndefined();
  });

  it("zählt nichts in Kommentaren, CDATA, Verarbeitungsanweisungen und Attributwerten (auch mit >)", () => {
    const hidden = '<x xmlns:a="1"><x xmlns:b="2"><x xmlns:c="3"><x><x>';
    const xml =
      `<?xml version="1.0" encoding="UTF-8"?><!-- ${hidden} --><a><!-- > ${hidden} - -->` +
      `<![CDATA[ > ${hidden} ]]><?pi > ${hidden} ?><b c=">>" d='>"' e = "x" f='a="b"'/>` +
      `<b>></b>]]></a><!-- Ende -->`;
    expect(check(xml)).toBeUndefined();
  });

  it("zählt Namensraum-Deklarationen, die gleichzeitig gelten (auch xmlns ohne Präfix)", () => {
    expect(check('<a xmlns="u" xmlns:p="v"><b/></a>')).toBeUndefined();
    expect(check('<a xmlns:p="v"><b xmlns:q="w" xmlns:r="x"/></a>')).toBe(
      "zu viele Namensraum-Deklarationen (mehr als 2 gleichzeitig gültige)",
    );
    expect(check("<a xmlns:p = 'v' xmlns:q='w'><b xmlns='x'></b></a>")).toMatch(/Namensraum/);
    // Fehlender Leerraum zwischen Attributen (xmldom warnt nur) zählt trotzdem.
    expect(check('<a xmlns:p="v"xmlns:q="w"xmlns:r="x"/>')).toMatch(/Namensraum/);
    // Geschwister: Deklarationen eines geschlossenen Elements gelten nicht mehr (Apache mod_dav
    // deklariert in JEDER <response> drei Namensräume).
    expect(check(`<a xmlns:d="DAV:">${'<r xmlns:p="1"><s/></r>'.repeat(1000)}</a>`)).toBeUndefined();
    // Nur "xmlns" und "xmlns:…" sind Deklarationen.
    expect(findXmlLimitViolation('<a xmlnsX="1" Xxmlns="2" p:xmlns="3"/>', { ...limits, maxNamespaceDeclarations: 0 })).toBeUndefined();
    expect(findXmlLimitViolation('<a b="1" xmlns="u"/>', { ...limits, maxNamespaceDeclarations: 0 })).toBe(
      "Namensraum-Deklarationen (xmlns) sind nicht erlaubt",
    );
  });

  it("lehnt ab, was xmldom anders zerlegen könnte als die Vorprüfung", () => {
    for (const odd of [
      "<a b=c/>",
      "<a xmlns:p/>",
      '<a xmlns:p"u"/>',
      '<a\u0080xmlns:p="u"/>',
      '<a b="1"\u0085xmlns:p="u"/>',
      '<a b="1"\u2028xmlns:p="u"/>',
      '<a b="1"\u0001xmlns:p="u"/>',
      "<a/ >",
      "<a",
      '<a b="1',
      "<a><!-- x",
      "<a><![CDATA[ x",
      "<a><?pi x",
      "<a></a",
      "<a><!ELEMENT a ANY></a>",
      "<a><![IGNORE[x]]></a>",
      "<a><=b/></a>",
      "< a/>",
      "</a>",
    ]) {
      expect(check(odd), JSON.stringify(odd)).toMatch(/^kein gültiges XML/);
    }
  });

  it("zählt Elemente, Attribute, Kommentare, Verarbeitungsanweisungen und CDATA, nicht aber Text und End-Tags (Sicherheitsaudit dos-4)", () => {
    const five = { ...limits, maxNodes: 5 };
    expect(findXmlLimitViolation('<a b="1" c="2"><!--x--><d/>Text</a>', five)).toBeUndefined();
    expect(findXmlLimitViolation('<a b="1" c="2"><!--x--><d/><e/></a>', five)).toBe(
      "XML hat zu viele Bestandteile (mehr als 5 Elemente, Attribute, Kommentare usw.)",
    );
    expect(findXmlLimitViolation("<?xml version='1.0'?><a><![CDATA[x]]><?p?><b/><c/></a>", five)).toMatch(/zu viele Bestandteile/);
    expect(findXmlLimitViolation(`<a>${"Text &amp; mehr".repeat(1000)}</a>`, five)).toBeUndefined();
  });

  it("prüft die Länge, bevor es irgendetwas anderes tut", () => {
    expect(check("<a/>" + " ".repeat(limits.maxLength))).toBe("XML ist zu groß (mehr als 1000000 Zeichen)");
  });

  it("braucht lineare Zeit, auch für bösartig verschachtelte oder lange Dokumente", () => {
    const n = 80_000;
    const unlimited = { maxLength: Infinity, maxDepth: Infinity, maxNamespaceDeclarations: Infinity, maxNodes: Infinity };
    const documents = [
      '<x xmlns:a="u">'.repeat(n) + "</x>".repeat(n),
      `<a ${Array.from({ length: n }, (_, i) => `xmlns:p${i}="u"`).join(" ")}/>`,
      `<a>${"<!---->".repeat(n)}${"<?p?>".repeat(n)}${"<![CDATA[]]>".repeat(n)}${'<b c=">"/>'.repeat(n)}</a>`,
    ];
    for (const xml of documents) {
      const start = performance.now();
      expect(findXmlLimitViolation(xml, unlimited)).toBeUndefined();
      expect(performance.now() - start).toBeLessThan(500);
    }
  });
});

describe("Ausgabe", () => {
  it("formatiert wie KeePassXC: Tabs, leere Elemente als <X/>, Text in einer Zeile", () => {
    const doc = xmlElement("KeePassFile", [
      xmlElement("Meta", [xmlElement("Generator", "Ownwarden"), xmlElement("DatabaseName", "")]),
      xmlElement("Value", "zwei\nZeilen", { Protected: "True" }),
    ]);
    expect(serializeDocument(doc)).toBe(
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
        "<KeePassFile>\n" +
        "\t<Meta>\n" +
        "\t\t<Generator>Ownwarden</Generator>\n" +
        "\t\t<DatabaseName/>\n" +
        "\t</Meta>\n" +
        '\t<Value Protected="True">zwei\nZeilen</Value>\n' +
        "</KeePassFile>\n",
    );
  });

  it("gibt unbekannte Elemente kompakt aus", () => {
    const element = parseXml("<AutoType>\n\t<Enabled>True</Enabled>\n\t<DefaultSequence/>\n</AutoType>", "T");
    expect(serializeElement(element)).toBe("<AutoType><Enabled>True</Enabled><DefaultSequence/></AutoType>");
  });

  it("maskiert Text und Attribute wie KeePassXC, \\r als Zeichenreferenz", () => {
    expect(escapeText(`a & b < c > d "e" 'f'\r\n\tg`)).toBe("a &amp; b &lt; c &gt; d &quot;e&quot; 'f'&#13;\n\tg");
    expect(escapeAttribute('x"y\n\tz')).toBe("x&quot;y&#10;&#9;z");
  });

  it("lehnt Zeichen, die in XML 1.0 verboten sind, ab, statt sie still zu entfernen (Sicherheitsaudit xml-2)", () => {
    for (const bad of ["a\u0000b", "\u0001", "c\u000Bd", "\uFFFE", "\uFFFF", "x\uD800y", "\uDC00z", "\uDE00\uD83D"]) {
      expect(() => escapeText(bad), JSON.stringify(bad)).toThrow(RangeError);
      expect(() => escapeAttribute(bad), JSON.stringify(bad)).toThrow(RangeError);
    }
    expect(() => escapeText("a\u000Bb")).toThrow(/U\+000B/);
    // Gültige Surrogat-Paare (Emoji) und erlaubte Steuerzeichen bleiben.
    expect(escapeText("😀\u0085\u007F\t")).toBe("😀\u0085\u007F\t");
  });

  it("liest die eigene Ausgabe wieder genauso ein", () => {
    const original = xmlElement("Root", [
      xmlElement("Text", "Zeile 1\r\nZeile 2 & <b> \"q\"     "),
      xmlElement("Empty"),
      xmlElement("Attr", [], { A: "a\tb\nc\"d" }),
    ]);
    const reparsed = parseXml(serializeDocument(original), "T");
    expect(reparsed).toEqual(original);
  });
});
