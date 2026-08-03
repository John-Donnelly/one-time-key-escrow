/**
 * The slice of Durable Object storage the escrow uses. Values are structured-
 * cloned on the way in and out so a test cannot mutate stored state by holding
 * a reference — the real runtime serialises, and tests should not be more
 * forgiving than production.
 */
export class MemoryStorage {
  #map = new Map();
  alarmAt = null;

  async get(k) {
    return this.#map.has(k) ? structuredClone(this.#map.get(k)) : undefined;
  }
  async put(k, v) { this.#map.set(k, structuredClone(v)); }
  async deleteAll() { this.#map.clear(); this.alarmAt = null; }
  async setAlarm(ms) { this.alarmAt = ms; }
  get size() { return this.#map.size; }
}
