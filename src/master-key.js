// The escrowed content key is never stored in the clear. It sits wrapped under
// a service master key held as a platform secret, so a dump of the durable
// store alone yields nothing openable.
//
// This is defence in depth, not the primary control: the primary control is
// that the key is destroyed on first claim. Wrapping only narrows the window
// in which a stored key exists at all.
import { b64, fromB64 } from './util.js';

async function masterCryptoKey(secretB64, usages) {
  return crypto.subtle.importKey('raw', fromB64(secretB64), 'AES-GCM', false, usages);
}

export async function wrapKey(rawKey, masterB64) {
  const mk = await masterCryptoKey(masterB64, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mk, rawKey));
  return { iv: b64(iv), ct: b64(ct) };
}

export async function unwrapKey(wrapped, masterB64) {
  const mk = await masterCryptoKey(masterB64, ['decrypt']);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(wrapped.iv) }, mk, fromB64(wrapped.ct)),
  );
}
