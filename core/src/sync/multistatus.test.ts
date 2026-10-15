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
});
