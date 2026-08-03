# one-time-key-escrow

[![CI](https://github.com/John-Donnelly/one-time-key-escrow/actions/workflows/ci.yml/badge.svg)](https://github.com/John-Donnelly/one-time-key-escrow/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Node](https://img.shields.io/badge/node-%E2%89%A520-339933?logo=node.js&logoColor=white)

**A key that can be claimed exactly once.**

Chunked AES-256-GCM sealing that runs entirely on the sender's machine, plus an
escrow that hands out the content key a single time and destroys it in the same
write that releases it.

The escrow holds a *key*, never a file. Sealed bytes travel by whatever channel
the sender already trusts — email, a shared drive, a USB stick. The service is
consulted at seal time and at open time and is custodian of neither the
plaintext nor the ciphertext, so compromising it yields no documents.

```
SEALED ──claim (atomic burn)──▶ OPENED ──90 days──▶ purged
   │
   └──expiry │ cancel │ lockout──▶ ASH ──90 days──▶ purged
```

## Why this is interesting

**The burn is atomic.** The write that releases the key is the same write that
removes it. There is no window — not one scheduler tick — in which the key has
been handed to a caller and still exists in storage:

```js
const wrapped = s.wrapped_key;
// the secrets are destructured out, so they are absent from the object
// that is about to be persisted
const { wrapped_key, token_hash, pin_hash, ...rest } = s;
Object.assign(rest, { status: State.OPENED, claimed_at: this.#now() });
await this.#storage.put('s', rest);
```

**Concurrency is handled in the class, not delegated to the host.** A Durable
Object already serialises requests per object id, so on Workers the internal
queue is redundant. It exists because `await` inside `claim()` yields to the
event loop: without serialisation two concurrent claimants could both observe
`status === SEALED` before either wrote back, and both would receive the same
one-time key. The guarantee belongs to the code, and there is a test that eight
simultaneous claims produce exactly one winner.

**GCM is used carefully.** AES-GCM fails catastrophically under IV reuse. Every
sealed file gets a fresh random 256-bit key *and* a fresh random 8-byte nonce
prefix; the per-chunk IV is `prefix || u32be(chunkIndex)`. Sealing the same
bytes with the same key twice produces different ciphertext, and there is a test
asserting prefixes never repeat across seals.

**Tampering is caught by construction.** The GCM authentication tag *is* the
integrity check — no separate checksum is trusted to notice a flipped byte or a
truncated payload. Both cases are tested.

**Two factors, neither stored.** Opening needs the token from the link and an
out-of-band PIN. Only their hashes are persisted, so the escrow cannot
reconstruct either from its own records; the PIN hash is salted with the record
id so identical PINs across records don't collide. Five wrong attempts destroy
the key outright — after lockout the correct credentials no longer help, because
there is nothing left to release.

**Chunking is what makes it practical.** Streaming 1 MiB at a time keeps memory
flat, so a browser can seal a file larger than its available RAM.

## Install

```bash
npm install
npm test
```

## Use

```js
import { seal, open, generateKey } from 'one-time-key-escrow/crypto';
import { Escrow } from 'one-time-key-escrow';

// --- sender, in the browser -------------------------------------------
const key = generateKey();
const sealedBlob = await seal(file, key);      // plaintext never leaves the machine
// ...send sealedBlob however you like; escrow `key` under a token + PIN

// --- escrow, server side ----------------------------------------------
const escrow = new Escrow({ storage, masterKeyB64: env.MASTER_KEY });
await escrow.seal({ id, key, token, pin, ttlSeconds: 86_400 });

// --- recipient ---------------------------------------------------------
const { key: released } = await escrow.claim({ token, pin });  // works once
const plaintext = await open(sealedBlob, released);
```

`storage` needs `get` / `put` / `deleteAll` / `setAlarm` — exactly the surface a
Durable Object's `state.storage` already provides. It is injected so the core is
testable without a Workers runtime; `test/memory-storage.js` is a 15-line
in-memory implementation.

## Layout

| File | What it is |
| --- | --- |
| `src/crypto.js` | Chunked AES-256-GCM seal/open. Runs in any WebCrypto environment. |
| `src/escrow.js` | The state machine, the atomic burn, and the serialisation queue. Runtime-agnostic. |
| `src/master-key.js` | Wraps the escrowed key at rest under a service master key. |
| `src/worker.js` | A minimal Cloudflare Worker + Durable Object binding the core to HTTP. |
| `test/` | 32 tests covering the crypto format and every state transition. |

## Wire format

```
"OTK1"                     4 bytes, magic
nonce prefix               8 bytes, random per seal
repeat until end of file:
  ct_len                   4 bytes, u32 big-endian
  ciphertext || GCM tag    ct_len bytes
```

Per-chunk IV is `prefix || u32be(index)` — 96 bits, never repeated within a file
(the counter) or across files (the random prefix and the fresh key).

## Threat model

Defends against a compromised or dishonest escrow service, an intercepted link,
and a replayed open. The service never holds the file in any form, so it cannot
disclose one; a claimed link is permanently dead; a wrong PIN is rate-limited to
five attempts before the key is destroyed.

Does **not** defend against a compromised sender or recipient endpoint — if the
plaintext is readable on the machine that seals or opens it, none of this
matters. Nor does it hide metadata the caller chooses to store in `meta`.

`MASTER_KEY` wrapping is defence in depth, not the primary control. The primary
control is that the key is destroyed on first claim; wrapping only narrows the
window in which a stored key exists at all.

## Deploy

`wrangler.jsonc` ships with placeholder ids. Set your own, then:

```bash
wrangler secret put MASTER_KEY        # 32 random bytes, base64
wrangler deploy
```

The worker deliberately has no authentication in front of `/seal` and no rate
limiting in front of `/claim` — this repository demonstrates the escrow
mechanism, not a finished product. Add both before exposing it.

## License

MIT — see [LICENSE](LICENSE).
