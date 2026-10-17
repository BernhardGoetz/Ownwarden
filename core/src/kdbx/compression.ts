/**
 * GZip-Kompression des KDBX-Inhalts über die Web-Standard-APIs CompressionStream und
 * DecompressionStream (gibt es im Browser, im Service Worker und in Node 18+).
 *
 * Beim Entpacken wird die Größe begrenzt: Eine kleine, manipulierte Datei könnte sonst zu
 * Gigabytes aufgeblasen werden („Zip-Bombe“).
 */
import { KdbxError } from "../contracts";
import { asBufferSource, concatByteArrays } from "./bytes";
import { MAX_PAYLOAD_BYTES } from "./constants";

export async function gzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([asBufferSource(data)]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Entpackt GZip-Daten. Wirft KdbxError("Corrupt"), wenn die Daten kein gültiges GZip sind
 * oder entpackt größer als `maxBytes` würden.
 */
export async function gunzip(data: Uint8Array, maxBytes = MAX_PAYLOAD_BYTES): Promise<Uint8Array> {
  const stream = new Blob([asBufferSource(data)]).stream().pipeThrough(new DecompressionStream("gzip"));
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new KdbxError("Corrupt", "Entpackter Inhalt ist unplausibel groß.");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof KdbxError) throw error;
    throw new KdbxError("Corrupt", `GZip-Daten sind beschädigt: ${(error as Error).message}`);
  }
  return concatByteArrays(chunks);
}
