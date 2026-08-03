import { describe, it, expect, beforeEach } from 'vitest';
import { Escrow, EscrowError, State, MAX_PIN_ATTEMPTS, PURGE_AFTER_MS } from '../src/escrow.js';
import { generateKey } from '../src/crypto.js';
import { MemoryStorage } from './memory-storage.js';

const MASTER = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const SEAL = { id: 'rec-1', token: 'link-secret', pin: '4821', ttlSeconds: 3600 };

let storage; let clock; let escrow;

beforeEach(() => {
  storage = new MemoryStorage();
  clock = 1_000_000;
  escrow = new Escrow({ storage, masterKeyB64: MASTER, now: () => clock });
});

const sealKey = async (key = generateKey()) => {
  await escrow.seal({ ...SEAL, key });
  return key;
};

describe('escrow lifecycle', () => {
  it('releases the exact key that was sealed', async () => {
    const key = await sealKey();
    const { key: got } = await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    expect(got).toEqual(key);
  });

  it('refuses to seal twice over the same record', async () => {
    await sealKey();
    await expect(sealKey()).rejects.toMatchObject({ code: 'exists', status: 409 });
  });

  it('releases the key exactly once', async () => {
    await sealKey();
    await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    await expect(escrow.claim({ token: SEAL.token, pin: SEAL.pin }))
      .rejects.toMatchObject({ code: 'gone', status: 410 });
  });

  it('serialises concurrent claims so only one wins', async () => {
    await sealKey();
    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => escrow.claim({ token: SEAL.token, pin: SEAL.pin })),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('destroys key material in the same write that releases it', async () => {
    await sealKey();
    await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    const stored = await storage.get('s');
    expect(stored.status).toBe(State.OPENED);
    expect(stored).not.toHaveProperty('wrapped_key');
    expect(stored).not.toHaveProperty('token_hash');
    expect(stored).not.toHaveProperty('pin_hash');
  });

  it('rejects a wrong token and a wrong pin', async () => {
    await sealKey();
    await expect(escrow.claim({ token: 'nope', pin: SEAL.pin }))
      .rejects.toMatchObject({ code: 'denied', status: 403 });
    await expect(escrow.claim({ token: SEAL.token, pin: '0000' }))
      .rejects.toMatchObject({ code: 'denied', status: 403 });
  });

  it('still opens for the right credentials after a failed attempt', async () => {
    const key = await sealKey();
    await expect(escrow.claim({ token: SEAL.token, pin: '0000' })).rejects.toThrow();
    const { key: got } = await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    expect(got).toEqual(key);
  });

  it('burns the key after too many failed pins', async () => {
    await sealKey();
    for (let i = 1; i < MAX_PIN_ATTEMPTS; i++) {
      await expect(escrow.claim({ token: SEAL.token, pin: '0000' }))
        .rejects.toMatchObject({ code: 'denied' });
    }
    await expect(escrow.claim({ token: SEAL.token, pin: '0000' }))
      .rejects.toMatchObject({ code: 'gone', detail: { reason: 'too_many_attempts' } });
    // correct credentials no longer help — the key is gone, not merely locked
    await expect(escrow.claim({ token: SEAL.token, pin: SEAL.pin }))
      .rejects.toMatchObject({ code: 'gone' });
    expect((await storage.get('s')).status).toBe(State.ASH);
  });

  it('counts down attempts in the error detail', async () => {
    await sealKey();
    await expect(escrow.claim({ token: SEAL.token, pin: '0000' }))
      .rejects.toMatchObject({ detail: { attempts_remaining: MAX_PIN_ATTEMPTS - 1 } });
  });

  it('salts the pin with the record id', async () => {
    await escrow.seal({ ...SEAL, id: 'rec-a', key: generateKey() });
    const a = (await storage.get('s')).pin_hash;
    const other = new MemoryStorage();
    await new Escrow({ storage: other, masterKeyB64: MASTER, now: () => clock })
      .seal({ ...SEAL, id: 'rec-b', key: generateKey() });
    expect(a).not.toBe((await other.get('s')).pin_hash);
  });

  it('cancelling burns the key without releasing it', async () => {
    await sealKey();
    await escrow.burn('cancelled');
    await expect(escrow.claim({ token: SEAL.token, pin: SEAL.pin }))
      .rejects.toMatchObject({ code: 'gone' });
    expect(await storage.get('s')).not.toHaveProperty('wrapped_key');
  });

  it('cancelling an already-opened record is a no-op', async () => {
    await sealKey();
    await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    await expect(escrow.burn('cancelled')).resolves.toEqual({ ok: true });
    expect((await storage.get('s')).status).toBe(State.OPENED);
  });

  it('claiming an unknown record is a 404', async () => {
    await expect(escrow.claim({ token: SEAL.token, pin: SEAL.pin }))
      .rejects.toMatchObject({ code: 'unknown', status: 404 });
  });
});

describe('expiry and retention', () => {
  it('arms an alarm at the ttl when sealed', async () => {
    await sealKey();
    expect(storage.alarmAt).toBe(clock + SEAL.ttlSeconds * 1000);
  });

  it('expires a record that was never claimed', async () => {
    await sealKey();
    expect(await escrow.onAlarm()).toEqual({ action: 'expired' });
    expect((await storage.get('s')).burn_reason).toBe('expired_unclaimed');
  });

  it('arms the retention alarm once terminal', async () => {
    await sealKey();
    await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    expect(storage.alarmAt).toBe(clock + PURGE_AFTER_MS);
  });

  it('erases the record entirely on the retention alarm', async () => {
    await sealKey();
    await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    expect(await escrow.onAlarm()).toEqual({ action: 'purged' });
    expect(storage.size).toBe(0);
    await expect(escrow.status()).rejects.toMatchObject({ code: 'unknown' });
  });

  it('an alarm on an absent record does nothing', async () => {
    expect(await escrow.onAlarm()).toEqual({ action: 'none' });
  });
});

describe('status disclosure', () => {
  it('never exposes key material or credential hashes', async () => {
    await sealKey();
    const s = await escrow.status();
    expect(s).toMatchObject({ id: SEAL.id, status: State.SEALED });
    for (const secret of ['wrapped_key', 'token_hash', 'pin_hash']) {
      expect(s).not.toHaveProperty(secret);
    }
  });

  it('carries caller metadata through the lifecycle', async () => {
    await escrow.seal({ ...SEAL, key: generateKey(), meta: { label: 'contract' } });
    const { meta } = await escrow.claim({ token: SEAL.token, pin: SEAL.pin });
    expect(meta).toEqual({ label: 'contract' });
  });
});

describe('EscrowError', () => {
  it('carries a code and an http status', () => {
    const e = new EscrowError('gone', 410, { reason: 'ASH' });
    expect(e).toBeInstanceOf(Error);
    expect([e.code, e.status, e.detail.reason]).toEqual(['gone', 410, 'ASH']);
  });
});
