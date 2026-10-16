/**
 * Kommandozeile (npm run proto) und KeePassXC 2.7.6 an DERSELBEN Datei – die Zusage aus der
 * README „Die Datei lässt sich jederzeit mit KeePassXC öffnen“, in beide Richtungen:
 *
 *   1. Die Kommandozeile legt an: Gruppe, Eintrag mit Passwort, eigenes geschütztes Feld,
 *      Anhang (Binärdaten), einen Eintrag im Papierkorb (rm).
 *   2. KeePassXC öffnet die Datei ohne Warnungen und sieht alles; der von Ownwarden angelegte
 *      „Papierkorb“ ist auch für KeePassXC DER Papierkorb (rm in KeePassXC verschiebt dorthin,
 *      statt einen zweiten anzulegen).
 *   3. KeePassXC ändert ein Passwort; die Kommandozeile zeigt die Änderung (nur mit --reveal im
 *      Klartext) und kann danach weiter ändern.
 * Wird übersprungen ohne keepassxc-cli.
 */
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTmpDir, exportKpxcAttachment, hasKeepassxc, kpxcDbInfo, listKpxc, removeTmpDir, runKpxcOk, showKpxcEntry } from "../helpers/keepassxc";
import { KPXC_XML_WARNING, readKdbxFile, TEST_KDF, waitForNextSecond } from "../helpers/kdbx-files";
import { ENV, runCli, type CliIo } from "../../src/cli/ownwarden-proto";

const MASTER = "Cli-Kpxc-Master-äöü";
const SCAN = new Uint8Array(randomBytes(3000));

async function cli(args: string[], env: Record<string, string> = {}): Promise<{ code: number; output: string }> {
  const lines: string[] = [];
  const io: CliIo = {
    env: { [ENV.master]: MASTER, ...env },
    out: (line) => lines.push(line),
    err: (line) => lines.push(line),
    promptHidden: async () => "",
    interactive: false,
    newVaultKdf: TEST_KDF,
  };
  const code = await runCli(args, io);
  return { code, output: lines.join("\n") };
}

describe.skipIf(!hasKeepassxc())("Kommandozeile und KeePassXC an derselben Datei", () => {
  let dir: string;
  let path: string;
  beforeAll(async () => {
    dir = createTmpDir("cli-keepassxc");
    path = join(dir, "tresor.kdbx");
    writeFileSync(join(dir, "scan.bin"), SCAN);
    const steps: [string[], Record<string, string>?][] = [
      [["init", path, "--name", "CLI-Tresor"]],
      [["add", path, "--title", "Giro", "--user", "bob", "--group", "Bank", "--password"], { [ENV.entryPassword]: "giro-pw-1" }],
      [["set", path, "Bank/Giro", "PIN", "-", "--protect"], { [ENV.fieldValue]: "4711" }],
      [["attach", path, "Giro", join(dir, "scan.bin")]],
      [["add", path, "--title", "Alt"]],
      [["rm", path, "Alt"]],
      [["add", path, "--title", "Forum"]],
    ];
    for (const [args, env] of steps) expect((await cli(args, env)).code, args.join(" ")).toBe(0);
  });
  afterAll(() => {
    if (dir) removeTmpDir(dir);
  });

  it("KeePassXC öffnet die Datei ohne Warnungen und sieht Gruppen, Felder, Anhang und Papierkorb", async () => {
    const exported = await runKpxcOk(["export", "-q", "-f", "xml", path], `${MASTER}\n`);
    expect(exported.stderr).not.toMatch(KPXC_XML_WARNING);
    expect((await listKpxc(path, MASTER, { recursive: true })).filter((line) => !line.endsWith("/")).sort()).toEqual([
      "Bank/Giro",
      "Forum",
      "Papierkorb/Alt",
    ]);
    expect(await showKpxcEntry(path, MASTER, "Bank/Giro", { showProtected: true, attributes: ["UserName", "Password", "PIN"] })).toBe("bob\ngiro-pw-1\n4711\n");
    expect(Buffer.from(await exportKpxcAttachment(path, MASTER, "Bank/Giro", "scan.bin")).equals(Buffer.from(SCAN))).toBe(true);
    expect((await kpxcDbInfo(path, MASTER)).Name).toBe("CLI-Tresor");
  });

  it("rm in KeePassXC benutzt den von Ownwarden angelegten Papierkorb (kein zweiter)", async () => {
    await runKpxcOk(["rm", "-q", path, "Forum"], `${MASTER}\n`);
    const vault = await readKdbxFile(path, MASTER);
    expect(vault.root.groups.map((group) => group.name).sort()).toEqual(["Bank", "Papierkorb"]);
    expect((await cli(["ls", path])).output.split("\n").slice(1).sort()).toEqual(["Bank/Giro\tbob\t", "Papierkorb/Alt\t\t", "Papierkorb/Forum\t\t"]);
  });

  it("KeePassXC ändert das Passwort: die Kommandozeile zeigt es nur mit --reveal und kann weiter ändern", async () => {
    await waitForNextSecond();
    await runKpxcOk(["edit", "-q", "-p", path, "Bank/Giro"], `${MASTER}\ngiro-pw-kpxc\n`);
    const show = await cli(["show", path, "Bank/Giro"]);
    expect(show.output).not.toContain("giro-pw-kpxc");
    expect(show.output).toContain("Verlauf: 3 frühere Fassung(en)"); // PIN und Anhang (Ownwarden), Passwort (KeePassXC)
    expect((await cli(["show", path, "Bank/Giro", "--reveal"])).output).toContain("Passwort: giro-pw-kpxc");

    expect((await cli(["set", path, "Bank/Giro", "UserName", "bob2"])).code).toBe(0);
    expect(await showKpxcEntry(path, MASTER, "Bank/Giro", { showProtected: true, attributes: ["UserName", "Password", "PIN"] })).toBe("bob2\ngiro-pw-kpxc\n4711\n");
  });
});
