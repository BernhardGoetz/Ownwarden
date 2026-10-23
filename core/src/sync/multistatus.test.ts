import { describe, expect, it } from "vitest";
import { parseMultistatus } from "./multistatus";

describe("parseMultistatus", () => {
  it("liest href, getetag und Ordner-Kennzeichen (Präfix d:, wie Nextcloud/SabreDAV)", () => {
    const xml = `<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">
  <d:response>
    <d:href>/remote.php/webdav/ownwarden-backups/</d:href>
    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/webdav/ownwarden-backups/t.20261015-000000-000.kdbx</d:href>
    <d:propstat>
      <d:prop><d:getetag>&quot;6f1c&quot;</d:getetag><d:resourcetype/><oc:id>123</oc:id></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
    <d:propstat><d:prop><d:getcontenttype/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
  </d:response>
</d:multistatus>`;
    const resources = parseMultistatus(xml);
    expect(resources).toHaveLength(2);
    expect(resources[0]).toMatchObject({ href: "/remote.php/webdav/ownwarden-backups/", isCollection: true });
    expect(resources[1]!.href).toBe("/remote.php/webdav/ownwarden-backups/t.20261015-000000-000.kdbx");
    expect(resources[1]!.isCollection).toBe(false);
    expect(resources[1]!.props.get("getetag")).toBe('"6f1c"');
    // fremder Namensraum und 404-Eigenschaften fehlen
    expect(resources[1]!.props.has("id")).toBe(false);
    expect(resources[1]!.props.has("getcontenttype")).toBe(false);
  });

  it("versteht andere Präfixe und den Standard-Namensraum", () => {
    const upper = `<D:multistatus xmlns:D="DAV:"><D:response><D:href>/a</D:href><D:propstat><D:prop><D:getetag>W/"1"</D:getetag></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`;
    const plain = `<multistatus xmlns="DAV:"><response><href>/b</href><propstat><prop><getetag>"2"</getetag></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>`;
    expect(parseMultistatus(upper)[0]!.props.get("getetag")).toBe('W/"1"');
    expect(parseMultistatus(plain)[0]!.props.get("getetag")).toBe('"2"');
  });

  it("lehnt DOCTYPE/ENTITY, kaputtes XML und falsche Wurzel ab", () => {
    expect(() => parseMultistatus('<!DOCTYPE x [<!ENTITY a "b">]><d:multistatus xmlns:d="DAV:"/>')).toThrow(/DOCTYPE/);
    expect(() => parseMultistatus("<d:multistatus xmlns:d='DAV:'><d:response>")).toThrow(/kein gültiges XML/);
    expect(() => parseMultistatus("<multistatus/>")).toThrow(/multistatus/);
    expect(() => parseMultistatus("<html><body>Login</body></html>")).toThrow(/multistatus/);
    expect(() => parseMultistatus('<d:multistatus xmlns:d="DAV:"><d:response/></d:multistatus>')).toThrow(/href/);
  });

  it("leere Antwort ergibt eine leere Liste", () => {
    expect(parseMultistatus('<d:multistatus xmlns:d="DAV:"/>')).toEqual([]);
  });

  it("lehnt verschachtelte Namensraum-Deklarationen in Millisekunden ab, bevor xmldom läuft (Sicherheitsaudit xml-1)", () => {
    for (const n of [40_000, 80_000]) {
      const xml =
        `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${'<x xmlns:a="u">'.repeat(n)}${"</x>".repeat(n)}` +
        `<d:response><d:href>/f</d:href></d:response></d:multistatus>`;
      const start = performance.now();
      expect(() => parseMultistatus(xml)).toThrow(/PROPFIND-Antwort: XML ist zu tief verschachtelt/);
      expect(performance.now() - start).toBeLessThan(1000);
    }
  });

  it("begrenzt Größe, Tiefe und gleichzeitig gültige Namensraum-Deklarationen (Sicherheitsaudit xml-1)", () => {
    const wrap = (inner: string, attributes = "") => `<d:multistatus xmlns:d="DAV:"${attributes}>${inner}</d:multistatus>`;
    expect(() => parseMultistatus(wrap(" ".repeat(4 * 1024 * 1024)))).toThrow(/PROPFIND-Antwort: XML ist zu groß \(mehr als 4 MiB\)/);
    expect(() => parseMultistatus(wrap("<x>".repeat(32) + "</x>".repeat(32)))).toThrow(/zu tief verschachtelt/);
    expect(parseMultistatus(wrap("<x>".repeat(31) + "</x>".repeat(31)))).toEqual([]);
    const declarations = Array.from({ length: 64 }, (_, i) => ` xmlns:p${i}="u${i}"`).join("");
    expect(() => parseMultistatus(wrap("", declarations))).toThrow(/zu viele Namensraum-Deklarationen/);
  });

  it("lehnt dichtes XML mit mehr als 50 000 Bestandteilen ab, bevor xmldom Speicher belegt (Sicherheitsaudit xml-1, dos-4)", () => {
    // 4 MiB "<a/>" wären für xmldom eine Million Elemente (rund 1 GB Speicher, ohne Schlüssel).
    const wrap = (inner: string) => `<d:multistatus xmlns:d="DAV:">${inner}</d:multistatus>`;
    const start = performance.now();
    expect(() => parseMultistatus(wrap("<a/>".repeat(1_000_000)))).toThrow(/PROPFIND-Antwort: XML hat zu viele Bestandteile/);
    expect(() => parseMultistatus(wrap("<a/>".repeat(50_000)))).toThrow(/zu viele Bestandteile/);
    expect(performance.now() - start).toBeLessThan(1000);
    expect(parseMultistatus(wrap("<a/>".repeat(49_998)))).toEqual([]);
  });

  it("liest Antworten, die in jeder <response> Namensräume deklarieren (wie Apache mod_dav)", () => {
    const response = (i: number) =>
      `<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:g0="DAV:">` +
      `<D:href>/dav/t.${i}.kdbx</D:href><D:propstat><D:prop><lp1:getetag>"${i}"</lp1:getetag>` +
      `<D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype><D:owner><D:href>me</D:href></D:owner></D:activelock></D:lockdiscovery>` +
      `</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`;
    const xml = `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">${Array.from({ length: 200 }, (_, i) => response(i)).join("\n")}</D:multistatus>`;
    const resources = parseMultistatus(xml);
    expect(resources).toHaveLength(200);
    expect(resources[199]!.props.get("getetag")).toBe('"199"');
  });

  it("Fehlermeldungen enthalten keinen rohen Server-Text (Sicherheitsaudit leak-1)", () => {
    const E = "\u001b[2K\u001b[1A\u001b[31mFAKE: Server kompromittiert\u202E <b>x</b>";
    for (const xml of [
      `<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response></d:href${E}></d:response></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:"></d:multistatus${E}>`,
      `<d:multistatus xmlns:d="DAV:"><d:response>${E}</d:resp></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:"><x:${E}/></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:"><d:response>&${E};</d:response></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:" xmlns:${E}="x"></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:"><d:response ${E}="1"/></d:multistatus>`,
      `<d:multistatus xmlns:d="DAV:"><![CDATA[${E}</d:multistatus>`,
      `${E}<d:multistatus xmlns:d="DAV:"/>`,
      `<d:multistatus xmlns:d="DAV:"></d:multistatus ${"\u001b".repeat(100_000)}>`,
    ]) {
      let message = "";
      try {
        parseMultistatus(xml);
      } catch (error) {
        message = (error as Error).message;
      }
      const label = JSON.stringify(xml.slice(0, 120));
      expect(message, label).toMatch(/^PROPFIND-Antwort/);
      expect(message, label).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202A-\u202E]/);
      expect(message.length, label).toBeLessThan(500);
    }
  });
});
