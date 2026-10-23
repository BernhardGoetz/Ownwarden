import { describe, expect, it } from "vitest";
import { displayText } from "./display-text";

describe("displayText (Sicherheitsaudit leak-1)", () => {
  it("lässt normalen Text unverändert", () => {
    expect(displayText("Tresor.kdbx – Übersicht 😀")).toBe("Tresor.kdbx – Übersicht 😀");
  });

  it("macht Terminal-Steuerzeichen und Zeilenumbrüche sichtbar", () => {
    expect(displayText("a\u001b[31mrot\u0007\r\nFehler: gefälscht")).toBe("a\\x1b[31mrot\\x07\\x0d\\x0aFehler: gefälscht");
    expect(displayText("x\u009b2Jy\u007f")).toBe("x\\x9b2Jy\\x7f");
  });

  it("macht Bidi-Steuerzeichen, Zeilentrenner und einzelne Surrogate sichtbar", () => {
    expect(displayText("abc\u202etxt.exe")).toBe("abc\\u202etxt.exe");
    expect(displayText("a\u2028b\u2066c")).toBe("a\\u2028b\\u2066c");
    expect(displayText("a\ud800b\udc00c")).toBe("a\\ud800b\\udc00c");
  });

  it("kürzt lange Texte", () => {
    const long = "x".repeat(1000);
    expect(displayText(long)).toBe(`${"x".repeat(80)}…`);
    expect(displayText(long, 10)).toBe(`${"x".repeat(10)}…`);
  });
});
