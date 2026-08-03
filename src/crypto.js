// Chunked AES-256-GCM for files of arbitrary size.
//
// Wire format:
//   magic "OTK1" | 8-byte random nonce prefix | repeated [u32be ct_len][ciphertext||tag]
//   one chunk per CHUNK_BYTES of plaintext.
//
// The IV for chunk n is `prefix || u32be(n)`. GCM is catastrophic under IV
// reuse, so two things guarantee freshness: every sealed file gets a brand new
// random key AND a brand new random prefix, and the counter is per-file. A
// 96-bit IV built this way is never reused across files or within one.
//
// Streaming in chunks (rather than one giant encrypt) keeps memory flat and
// lets a browser seal a file larger than available RAM.

const MAGIC = new TextEncoder().encode('OTK1');
const MAGIC_LEN = 4;
const PREFIX_LEN = 8;
const HEADER_LEN = MAGIC_LEN + PREFIX_LEN;
const CHUNK_BYTES = 1 << 20; // 1 MiB

function ivFor(prefix, counter) {
  const iv = new Uint8Array(12);
  iv.set(prefix);
  new DataView(iv.buffer).setUint32(8, counter);
  return iv;
}

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

/** Mint a fresh 256-bit content key. One per sealed file, never reused. */
export function generateKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function sha256Hex(blobOrBytes) {
  const buf = blobOrBytes instanceof Blob ? await blobOrBytes.arrayBuffer() : blobOrBytes;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encrypt a Blob/File. Runs entirely on the sender's machine — the escrow
 * service never receives the plaintext or the ciphertext.
 */
export async function seal(file, keyBytes, onProgress) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const prefix = crypto.getRandomValues(new Uint8Array(PREFIX_LEN));
  const parts = [MAGIC, prefix];
  let counter = 0;
  for (let offset = 0; offset < file.size; offset += CHUNK_BYTES) {
    const chunk = await file.slice(offset, offset + CHUNK_BYTES).arrayBuffer();
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivFor(prefix, counter++) }, key, chunk),
    );
    parts.push(u32be(ct.length), ct);
    onProgress?.(Math.min(offset + CHUNK_BYTES, file.size), file.size);
  }
  return new Blob(parts, { type: 'application/octet-stream' });
}

/**
 * Decrypt a sealed Blob. Throws if the key is wrong or a single byte was
 * altered in transit: GCM's authentication tag IS the integrity check, so
 * nothing else has to be trusted to notice tampering.
 */
export async function open(sealed, keyBytes, mime, onProgress) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const header = new Uint8Array(await sealed.slice(0, HEADER_LEN).arrayBuffer());
  if (new TextDecoder().decode(header.slice(0, MAGIC_LEN)) !== 'OTK1') {
    throw new Error('Not a sealed file (bad header) — wrong file, or corrupted in transit.');
  }
  const prefix = header.slice(MAGIC_LEN, HEADER_LEN);
  const parts = [];
  let offset = HEADER_LEN;
  let counter = 0;
  while (offset < sealed.size) {
    const lenBuf = new Uint8Array(await sealed.slice(offset, offset + 4).arrayBuffer());
    const len = new DataView(lenBuf.buffer).getUint32(0);
    offset += 4;
    const ct = await sealed.slice(offset, offset + len).arrayBuffer();
    offset += len;
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivFor(prefix, counter++) }, key, ct,
    );
    parts.push(pt);
    onProgress?.(offset, sealed.size);
  }
  return new Blob(parts, { type: mime || 'application/octet-stream' });
}

export const FORMAT = { MAGIC_LEN, PREFIX_LEN, HEADER_LEN, CHUNK_BYTES };
