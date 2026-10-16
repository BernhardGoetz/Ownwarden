/**
 * Verdeckte Passwort-Abfrage für die Kommandozeile (nur Node).
 *
 *   - Am Terminal (TTY): Eingabe wird NICHT angezeigt (Rohmodus); Rücktaste löscht,
 *     Strg+C bricht ab. Die Frage geht nach stderr, damit stdout sauber bleibt.
 *   - Über eine Pipe (z. B. Tests, Skripte): eine Zeile pro Abfrage. Mehrere Abfragen
 *     hintereinander (Master-Passwort, dann WebDAV-Passwort) lesen nacheinander die Zeilen
 *     derselben Eingabe – darum EIN gemeinsamer Zeilenleser statt eines neuen pro Abfrage
 *     (ein neuer würde bereits gepufferte Zeilen verlieren).
 *
 * Ähnlich wie promptHidden in webdav-probe.ts, dort genügt aber eine einzige Abfrage.
 */
import { createInterface, type Interface } from "node:readline";

export interface Prompter {
  /** Fragt verdeckt; liefert "" bei Ende der Eingabe. */
  hidden(question: string): Promise<string>;
  /** true, wenn die Eingabe ein Terminal ist (dann z. B. neues Passwort zweimal abfragen). */
  readonly interactive: boolean;
  /** Gibt die Eingabe frei (sonst wartet Node evtl. weiter auf stdin). */
  close(): void;
}

export function createPrompter(input: NodeJS.ReadStream = process.stdin, output: NodeJS.WriteStream = process.stderr): Prompter {
  return input.isTTY ? new TerminalPrompter(input, output) : new PipePrompter(input);
}

/** Pipe: eine Zeile pro Abfrage, über einen gemeinsamen Zeilenleser. */
class PipePrompter implements Prompter {
  readonly interactive = false;
  private reader: Interface | undefined;
  private readonly lines: string[] = [];
  private readonly waiting: ((line: string) => void)[] = [];
  private ended = false;

  constructor(private readonly input: NodeJS.ReadStream) {}

  hidden(_question: string): Promise<string> {
    this.start();
    const line = this.lines.shift();
    if (line !== undefined) return Promise.resolve(line);
    if (this.ended) return Promise.resolve("");
    return new Promise((resolvePromise) => this.waiting.push(resolvePromise));
  }

  close(): void {
    this.reader?.close();
  }

  /** Erst bei der ersten Abfrage lesen: Befehle ohne Passwort sollen stdin nicht anfassen. */
  private start(): void {
    if (this.reader !== undefined) return;
    this.reader = createInterface({ input: this.input, crlfDelay: Infinity });
    this.reader.on("line", (line) => {
      const waiter = this.waiting.shift();
      if (waiter !== undefined) waiter(line);
      else this.lines.push(line);
    });
    this.reader.on("close", () => {
      this.ended = true;
      for (const waiter of this.waiting.splice(0)) waiter("");
    });
  }
}

/** Terminal: Rohmodus, nichts wird angezeigt. */
class TerminalPrompter implements Prompter {
  readonly interactive = true;

  constructor(
    private readonly input: NodeJS.ReadStream,
    private readonly output: NodeJS.WriteStream,
  ) {}

  hidden(question: string): Promise<string> {
    const { input, output } = this;
    output.write(question);
    return new Promise((resolvePromise, reject) => {
      let value = "";
      const finish = (error?: Error) => {
        input.off("data", onData);
        input.setRawMode(false);
        input.pause();
        output.write("\n");
        if (error === undefined) resolvePromise(value);
        else reject(error);
      };
      const onData = (chunk: string) => {
        for (const char of chunk) {
          if (char === "\r" || char === "\n" || char === "\u0004") return finish();
          if (char === "\u0003") return finish(new Error("Abgebrochen."));
          if (char === "\u007f" || char === "\b") {
            value = Array.from(value).slice(0, -1).join("");
            continue;
          }
          value += char;
        }
      };
      input.setRawMode(true);
      input.setEncoding("utf8");
      input.on("data", onData);
      input.resume();
    });
  }

  close(): void {
    this.input.pause();
  }
}
