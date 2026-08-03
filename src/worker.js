// Minimal Cloudflare Workers surface over the escrow.
//
// Deliberately small: this repository demonstrates the escrow mechanism, not a
// product. There is no billing, no accounts, no delivery — a real deployment
// would add authentication in front of /seal and rate limiting in front of
// /claim.

import { Escrow, EscrowError } from './escrow.js';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const [, action, id] = url.pathname.split('/');
    if (!id) return json({ error: 'missing id' }, 400);

    const stub = env.ESCROW.get(env.ESCROW.idFromName(id));
    return stub.fetch(new Request(`https://escrow/${action}`, {
      method: req.method,
      headers: req.headers,
      body: req.method === 'GET' ? undefined : await req.text(),
    }));
  },
};

export class EscrowDO {
  constructor(state, env) {
    this.state = state;
    this.escrow = new Escrow({ storage: state.storage, masterKeyB64: env.MASTER_KEY });
  }

  async fetch(req) {
    const action = new URL(req.url).pathname.slice(1);
    try {
      switch (action) {
        case 'seal': {
          const { id, key_b64, token, pin, ttl_seconds, meta } = await req.json();
          return json(await this.escrow.seal({
            id,
            key: Uint8Array.from(atob(key_b64), (c) => c.charCodeAt(0)),
            token, pin, ttlSeconds: ttl_seconds, meta,
          }));
        }
        case 'claim': {
          const { token, pin } = await req.json();
          const { key, meta } = await this.escrow.claim({ token, pin });
          return json({ key_b64: btoa(String.fromCharCode(...key)), meta });
        }
        case 'burn':
          return json(await this.escrow.burn('cancelled'));
        case 'status':
          return json(await this.escrow.status());
        default:
          return json({ error: 'not found' }, 404);
      }
    } catch (err) {
      if (err instanceof EscrowError) return json({ error: err.code, ...err.detail }, err.status);
      throw err;
    }
  }

  async alarm() {
    await this.escrow.onAlarm();
  }
}
