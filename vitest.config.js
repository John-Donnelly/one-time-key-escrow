import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    // The multi-chunk round-trip encrypts and decrypts 2 MiB through WebCrypto
    // a megabyte at a time. That is comfortably under a second locally and
    // several seconds on a loaded CI runner, so the 5s default is too tight.
    testTimeout: 30_000,
  },
});
