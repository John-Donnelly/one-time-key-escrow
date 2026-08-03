// One-time key escrow: the state machine, independent of any runtime.
//
//   SEALED ──claim (atomic burn)──▶ OPENED ──retention──▶ purged
//      │
//      └──expiry / cancel / lockout──▶ ASH ──retention──▶ purged
//
// The escrow holds a *key*, never a file. The sealed bytes travel by whatever
// channel the sender already trusts; this service is consulted at seal time and
// at open time and is custodian of neither the plaintext nor the ciphertext.
//
// `storage` is injected so the core is testable without a Workers runtime.
// It needs get(k) / put(k, v) / deleteAll() / setAlarm(ms), which is exactly
// the surface a Durable Object's `state.storage` already provides.

import { sha256Hex, timingSafeEqual } from './util.js';
import { wrapKey, unwrapKey } from './master-key.js';

export const MAX_PIN_ATTEMPTS = 5;
export const PURGE_AFTER_MS = 90 * 24 * 3600 * 1000; // erase 90 days after a terminal state

export const State = { SEALED: 'SEALED', OPENED: 'OPENED', ASH: 'ASH' };

export class Escrow {
  #storage;
  #masterKeyB64;
  #now;
  #queue = Promise.resolve();

  constructor({ storage, masterKeyB64, now = () => Date.now() }) {
    this.#storage = storage;
    this.#masterKeyB64 = masterKeyB64;
    this.#now = now;
  }

  /**
   * Run `fn` after every previously queued operation has settled.
   *
   * A Durable Object already serialises requests per object id, so under
   * Workers this queue is redundant. It is here so the guarantee belongs to
   * this class rather than to the host: an `await` inside claim() yields to
   * the event loop, and without serialisation two concurrent claimants could
   * both read `status === SEALED` before either wrote back. That would hand
   * the same one-time key to two callers.
   */
  #serialise(fn) {
    const result = this.#queue.then(fn);
    this.#queue = result.then(() => undefined, () => undefined);
    return result;
  }

  #read() { return this.#storage.get('s'); }

  seal(args) { return this.#serialise(() => this.#sealImpl(args)); }
  claim(args) { return this.#serialise(() => this.#claimImpl(args)); }
  burn(reason) { return this.#serialise(() => this.#burnImpl(reason)); }
  status() { return this.#serialise(() => this.#statusImpl()); }
  onAlarm() { return this.#serialise(() => this.#onAlarmImpl()); }

  /**
   * Escrow a content key. `token` is the secret in the link; `pin` is the
   * out-of-band second factor. Neither is stored — only their hashes, so the
   * escrow cannot reconstruct either from its own records.
   */
  async #sealImpl({ id, key, token, pin, ttlSeconds, meta = {} }) {
    if (await this.#read()) throw new EscrowError('exists', 409);
    const record = {
      id,
      status: State.SEALED,
      sealed_at: this.#now(),
      fail_count: 0,
      wrapped_key: await wrapKey(key, this.#masterKeyB64),
      token_hash: await sha256Hex(token),
      // The PIN is salted with the record id so identical PINs across records
      // do not produce identical hashes.
      pin_hash: await sha256Hex(pin + id),
      meta,
    };
    await this.#storage.put('s', record);
    await this.#storage.setAlarm(this.#now() + ttlSeconds * 1000);
    return { id, status: State.SEALED };
  }

  /**
   * Claim the key. THE ATOMIC BURN.
   *
   * A Durable Object is single-threaded per id: everything between reading the
   * record and the final put() is one uninterruptible step, so concurrent
   * claimants are serialised and exactly one can observe status === SEALED.
   * The write that releases the key is the same write that removes it — there
   * is no window in which the key has been handed out but still exists.
   */
  async #claimImpl({ token, pin }) {
    const s = await this.#read();
    if (!s) throw new EscrowError('unknown', 404);
    if (s.status !== State.SEALED) throw new EscrowError('gone', 410, { reason: s.status });

    const tokenOk = timingSafeEqual(await sha256Hex(token), s.token_hash);
    const pinOk = timingSafeEqual(await sha256Hex(pin + s.id), s.pin_hash);

    if (!tokenOk || !pinOk) {
      s.fail_count += 1;
      await this.#storage.put('s', s);
      if (s.fail_count >= MAX_PIN_ATTEMPTS) {
        await this.#burnImpl('too_many_attempts');
        throw new EscrowError('gone', 410, { reason: 'too_many_attempts' });
      }
      throw new EscrowError('denied', 403, {
        attempts_remaining: MAX_PIN_ATTEMPTS - s.fail_count,
      });
    }

    const wrapped = s.wrapped_key;
    // Destructure the secrets out: they are absent from the object that is
    // about to be written back, so they cease to exist at rest on this write.
    const { wrapped_key, token_hash, pin_hash, ...rest } = s;
    Object.assign(rest, { status: State.OPENED, claimed_at: this.#now() });
    await this.#storage.put('s', rest);
    await this.#storage.setAlarm(this.#now() + PURGE_AFTER_MS);

    return { key: await unwrapKey(wrapped, this.#masterKeyB64), meta: rest.meta };
  }

  /** Destroy the key without releasing it: expiry, sender cancel, or lockout. */
  async #burnImpl(reason) {
    const s = await this.#read();
    if (!s || s.status !== State.SEALED) return { ok: true };
    const { wrapped_key, token_hash, pin_hash, ...rest } = s;
    Object.assign(rest, { status: State.ASH, burned_at: this.#now(), burn_reason: reason });
    await this.#storage.put('s', rest);
    await this.#storage.setAlarm(this.#now() + PURGE_AFTER_MS);
    return { ok: true, reason };
  }

  /** Non-secret view for the sender: never exposes key material or hashes. */
  async #statusImpl() {
    const s = await this.#read();
    if (!s) throw new EscrowError('unknown', 404);
    const { wrapped_key, token_hash, pin_hash, ...safe } = s;
    return safe;
  }

  /** Alarm handler: expire a still-sealed record, or purge a terminal one. */
  async #onAlarmImpl() {
    const s = await this.#read();
    if (!s) return { action: 'none' };
    if (s.status === State.SEALED) {
      await this.#burnImpl('expired_unclaimed');
      return { action: 'expired' };
    }
    await this.#storage.deleteAll();
    return { action: 'purged' };
  }
}

export class EscrowError extends Error {
  constructor(code, status, detail = {}) {
    super(code);
    this.name = 'EscrowError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}
