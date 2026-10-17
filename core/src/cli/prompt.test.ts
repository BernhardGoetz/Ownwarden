/**
 * Passwort-Abfrage über eine Pipe (prompt.ts, Review cli-1): Die Frage erscheint immer; in Git
 * Bash unter Windows ohne Terminal (dort ist die Eingabe sichtbar) mit einer deutlichen Warnung.
 */
import { PassThrough, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createPrompter, inputLikelyVisible, VISIBLE_INPUT_WARNING } from "./prompt";

function pipeWith(lines: string): NodeJS.ReadStream {
  const input = new PassThrough();
  input.end(lines);
  return input as unknown as NodeJS.ReadStream;
}

function collector(): { stream: NodeJS.WritableStream; text: () => string } {
  let text = "";
  const stream = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      text += chunk.toString("utf8");
      callback();
    },
  });
  return { stream, text: () => text };
}

describe("Passwort-Abfrage über eine Pipe", () => {
  it("liest eine Zeile pro Abfrage und zeigt die Frage auf stderr", async () => {
    const output = collector();
    const prompter = createPrompter(pipeWith("erstes\nzweites\n"), output.stream, "linux", {});
    expect(prompter.interactive).toBe(false);
    expect(await prompter.hidden("Master-Passwort: ")).toBe("erstes");
    expect(await prompter.hidden("WebDAV-Passwort: ")).toBe("zweites");
    expect(await prompter.hidden("Noch eins: ")).toBe("");
    prompter.close();
    expect(output.text()).toBe("Master-Passwort: WebDAV-Passwort: Noch eins: ");
    expect(output.text()).not.toContain("erstes");
  });

  it("Git Bash unter Windows ohne Terminal: Warnung, dass die Eingabe sichtbar ist", async () => {
    const output = collector();
    const prompter = createPrompter(pipeWith("geheim\n"), output.stream, "win32", { MSYSTEM: "MINGW64" });
    expect(await prompter.hidden("Master-Passwort: ")).toBe("geheim");
    prompter.close();
    expect(output.text()).toBe(`${VISIBLE_INPUT_WARNING}\nMaster-Passwort: `);
  });

  it("inputLikelyVisible: nur Windows + MSYSTEM + kein Terminal", () => {
    expect(inputLikelyVisible(undefined, "win32", { MSYSTEM: "MINGW64" })).toBe(true);
    expect(inputLikelyVisible(true, "win32", { MSYSTEM: "MINGW64" })).toBe(false);
    expect(inputLikelyVisible(undefined, "win32", {})).toBe(false);
    expect(inputLikelyVisible(undefined, "linux", { MSYSTEM: "MINGW64" })).toBe(false);
  });
});
