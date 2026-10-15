import { describe, expect, it } from "vitest";
import {
  MAX_XML_DEPTH,
  childElements,
  escapeAttribute,
  escapeText,
  parseXml,
  plainText,
  serializeDocument,
  serializeElement,
  xmlElement,
} from "./xml-dom";

const corrupt = expect.objectContaining({ name: "KdbxError", code: "Corrupt" });

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

  it("entfernt Zeichen, die in XML 1.0 verboten sind (wie KeePassXC)", () => {
    expect(escapeText("a\u0000b\u0001c\u000Bd￾e￿f")).toBe("abcdef");
    // Einzelne Surrogate weg, gültige Paare (Emoji) bleiben.
    expect(escapeText("x\uD800y\uDC00z😀")).toBe("xyz😀");
    // Erlaubte Steuerzeichen bleiben.
    expect(escapeText("\u0085\u007F")).toBe("\u0085\u007F");
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
