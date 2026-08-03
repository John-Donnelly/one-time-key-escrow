import { describe, it, expect } from 'vitest';
import { seal, open, generateKey, sha256Hex, FORMAT } from '../src/crypto.js';

const blobOf = (bytes) => new Blob([bytes]);
// crypto.getRandomValues refuses more than 65,536 bytes per call.
const rand = (n) => {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) {
    crypto.getRandomValues(out.subarray(o, Math.min(o + 65536, n)));
  }
  return out;
};

describe('chunked AES-256-GCM', () => {
  it('round-trips a small payload', async () => {
    const key = generateKey();
    const plain = rand(1024);
    const sealed = await seal(blobOf(plain), key);
    const opened = await open(sealed, key);
    expect(new Uint8Array(await opened.arrayBuffer())).toEqual(plain);
  });

  it('round-trips a payload spanning several chunks', async () => {
    const key = generateKey();
    const plain = rand(FORMAT.CHUNK_BYTES * 2 + 17);
    const sealed = await seal(blobOf(plain), key);
    const opened = await open(sealed, key);
    expect(new Uint8Array(await opened.arrayBuffer())).toEqual(plain);
  });

  it('round-trips an empty payload', async () => {
    const key = generateKey();
    const sealed = await seal(blobOf(new Uint8Array(0)), key);
    expect(sealed.size).toBe(FORMAT.HEADER_LEN);
    expect((await open(sealed, key)).size).toBe(0);
  });

  it('rejects the wrong key', async () => {
    const sealed = await seal(blobOf(rand(512)), generateKey());
    await expect(open(sealed, generateKey())).rejects.toThrow();
  });

  it('rejects a single flipped ciphertext byte', async () => {
    const key = generateKey();
    const sealed = await seal(blobOf(rand(4096)), key);
    const bytes = new Uint8Array(await sealed.arrayBuffer());
    bytes[bytes.length - 1] ^= 0x01;            // last byte is inside the GCM tag
    await expect(open(new Blob([bytes]), key)).rejects.toThrow();
  });

  it('rejects a truncated payload', async () => {
    const key = generateKey();
    const sealed = await seal(blobOf(rand(4096)), key);
    const bytes = new Uint8Array(await sealed.arrayBuffer());
    await expect(open(new Blob([bytes.slice(0, bytes.length - 8)]), key)).rejects.toThrow();
  });

  it('rejects a foreign header', async () => {
    await expect(open(new Blob([rand(64)]), generateKey()))
      .rejects.toThrow(/bad header/);
  });

  it('never reuses an IV prefix across seals', async () => {
    const key = generateKey();
    const prefixOf = async (b) =>
      [...new Uint8Array(await b.slice(FORMAT.MAGIC_LEN, FORMAT.HEADER_LEN).arrayBuffer())].join();
    const seen = new Set();
    for (let i = 0; i < 32; i++) seen.add(await prefixOf(await seal(blobOf(rand(64)), key)));
    expect(seen.size).toBe(32);
  });

  it('produces different ciphertext for identical plaintext and key', async () => {
    const key = generateKey();
    const plain = blobOf(rand(2048));
    const a = new Uint8Array(await (await seal(plain, key)).arrayBuffer());
    const b = new Uint8Array(await (await seal(plain, key)).arrayBuffer());
    expect(a).not.toEqual(b);
  });

  it('reports progress monotonically up to the total', async () => {
    const key = generateKey();
    const seen = [];
    await seal(blobOf(rand(FORMAT.CHUNK_BYTES * 2)), key, (done, total) => seen.push([done, total]));
    expect(seen.at(-1)).toEqual([FORMAT.CHUNK_BYTES * 2, FORMAT.CHUNK_BYTES * 2]);
    expect(seen.map(([d]) => d)).toEqual([...seen.map(([d]) => d)].sort((x, y) => x - y));
  });

  it('hashes blobs and byte arrays identically', async () => {
    const bytes = rand(256);
    expect(await sha256Hex(blobOf(bytes))).toBe(await sha256Hex(bytes));
  });
});
