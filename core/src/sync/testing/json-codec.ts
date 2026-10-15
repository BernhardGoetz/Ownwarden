/**
 * NUR FÜR TESTS: ein VaultCodec, der das Modell als JSON speichert (ohne Verschlüsselung).
 * Schnell und durchschaubar – für Tests der Sync-Schleife, bei denen es auf das Dateiformat
 * nicht ankommt. Maps und Byte-Arrays werden als {"$map": […]} bzw. {"$bytes": "<Base64>"}
 * abgelegt, damit decode(encode(v)) wieder genau dasselbe Modell liefert.
 *
 * Zähler `encodes`/`decodes` zeigen, wie oft der Codec benutzt wurde.
 */
import type { VaultCodec } from "../../contracts";
import type { Vault } from "../../model";

export interface CountingCodec extends VaultCodec {
  encodes: number;
  decodes: number;
}

export function createJsonCodec(): CountingCodec {
  const codec: CountingCodec = {
    encodes: 0,
    decodes: 0,
    async encode(vault) {
      codec.encodes += 1;
      return new TextEncoder().encode(JSON.stringify(vault, replacer));
    },
    async decode(file) {
      codec.decodes += 1;
      return JSON.parse(new TextDecoder().decode(file), reviver) as Vault;
    },
  };
  return codec;
}

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Map) return { $map: [...value] };
  if (value instanceof Uint8Array) {
    let binary = "";
    for (const byte of value) binary += String.fromCharCode(byte);
    return { $bytes: btoa(binary) };
  }
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (typeof value !== "object" || value === null) return value;
  if ("$map" in value) return new Map((value as { $map: [unknown, unknown][] }).$map);
  if ("$bytes" in value) return Uint8Array.from(atob((value as { $bytes: string }).$bytes), (char) => char.charCodeAt(0));
  return value;
}
