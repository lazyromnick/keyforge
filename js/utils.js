/**
 * utils.js — KeyForge Utilities
 * Password generation, entropy/strength scoring, clipboard, ZIP export, UUID
 */
'use strict';

const Utils = (() => {

  /* ────────────────────────────────────────────────
     Character sets
  ──────────────────────────────────────────────── */
  const SETS = {
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?/~`',
  };
  const AMBIGUOUS = /[O0lI1]/g;

  /* ────────────────────────────────────────────────
     Secure random integer in [0, max)
  ──────────────────────────────────────────────── */
  function secureRandInt(max) {
    const array = new Uint32Array(1);
    let rand;
    // Rejection sampling to avoid modulo bias
    const limit = Math.floor(0xFFFFFFFF / max) * max;
    do {
      crypto.getRandomValues(array);
      rand = array[0];
    } while (rand >= limit);
    return rand % max;
  }

  /* ────────────────────────────────────────────────
     Fisher-Yates shuffle (cryptographically random)
  ──────────────────────────────────────────────── */
  function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = secureRandInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  /* ────────────────────────────────────────────────
     Password Generation
  ──────────────────────────────────────────────── */

  /**
   * @param {{
   *   length: number,
   *   upper: boolean,
   *   lower: boolean,
   *   numbers: boolean,
   *   symbols: boolean,
   *   excludeAmbiguous: boolean
   * }} options
   * @returns {string}
   */
  function generatePassword(options) {
    const { length, upper, lower, numbers, symbols, excludeAmbiguous } = options;

    // Build pool
    let pool = '';
    const required = [];

    if (upper) {
      let s = SETS.upper;
      if (excludeAmbiguous) s = s.replace(AMBIGUOUS, '');
      pool += s;
      required.push(s[secureRandInt(s.length)]);
    }
    if (lower) {
      let s = SETS.lower;
      if (excludeAmbiguous) s = s.replace(AMBIGUOUS, '');
      pool += s;
      required.push(s[secureRandInt(s.length)]);
    }
    if (numbers) {
      let s = SETS.numbers;
      if (excludeAmbiguous) s = s.replace(AMBIGUOUS, '');
      pool += s;
      required.push(s[secureRandInt(s.length)]);
    }
    if (symbols) {
      const s = SETS.symbols;
      pool += s;
      required.push(s[secureRandInt(s.length)]);
    }

    if (!pool.length) return '';

    // Fill remaining slots randomly
    const remaining = length - required.length;
    const chars = [...required];
    for (let i = 0; i < remaining; i++) {
      chars.push(pool[secureRandInt(pool.length)]);
    }

    // Shuffle to avoid predictable positions for required chars
    return secureShuffle(chars).join('');
  }

  /* ────────────────────────────────────────────────
     Password Strength Scoring
     Returns: 0 = weak, 1 = fair, 2 = strong, 3 = great
  ──────────────────────────────────────────────── */

  /**
   * Estimate entropy bits: log2(poolSize ^ length)
   */
  function estimateEntropy(pw) {
    let pool = 0;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 30;
    if (pool === 0) return 0;
    return Math.floor(pw.length * Math.log2(pool));
  }

  /**
   * @returns {{ score: 0|1|2|3, label: string, entropy: number }}
   */
  function passwordStrength(pw) {
    if (!pw || pw.length < 4) return { score: 0, label: 'Weak', entropy: 0 };

    const entropy = estimateEntropy(pw);

    let score;
    if      (entropy >= 100) score = 3; // great
    else if (entropy >= 70)  score = 2; // strong
    else if (entropy >= 45)  score = 1; // fair
    else                     score = 0; // weak

    // Penalties
    if (pw.length < 8)  score = Math.min(score, 0);
    if (pw.length < 12) score = Math.min(score, 1);

    const labels = ['Weak', 'Fair', 'Strong', 'Great'];
    return { score, label: labels[score], entropy };
  }

  /* ────────────────────────────────────────────────
     UUID v4 (crypto-based)
  ──────────────────────────────────────────────── */
  function uuid() {
    return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
      (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16)
    );
  }

  /* ────────────────────────────────────────────────
     Clipboard helpers
  ──────────────────────────────────────────────── */

  async function copyToClipboard(text) {
    await navigator.clipboard.writeText(text);
  }

  async function clearClipboard() {
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Silently fail if user has navigated away
    }
  }

  /* ────────────────────────────────────────────────
     ZIP export (no external library — pure JS)
     Minimal ZIP creator: stores files uncompressed (STORE method)
  ──────────────────────────────────────────────── */

  /**
   * Build a minimal ZIP file in-memory.
   * Files are stored (no compression) — sufficient for JSON/text.
   *
   * @param {{ name: string, content: string }[]} files
   * @returns {Uint8Array}
   */
  function buildZip(files) {
    const enc     = new TextEncoder();
    const parts   = [];
    const central = [];
    let offset    = 0;

    for (const file of files) {
      const data     = enc.encode(file.content);
      const nameBytes= enc.encode(file.name);
      const crc      = crc32(data);
      const localHeader = buildLocalHeader(nameBytes, data, crc);

      parts.push(localHeader, data);

      central.push(buildCentralDir(nameBytes, data, crc, offset));
      offset += localHeader.length + data.length;
    }

    const centralData = concat(central);
    const eocd        = buildEOCD(files.length, centralData.length, offset);

    return concat([...parts, centralData, eocd]);
  }

  function buildLocalHeader(nameBytes, data, crc) {
    const buf = new DataView(new ArrayBuffer(30 + nameBytes.length));
    buf.setUint32(0,  0x504B0304, true); // signature
    buf.setUint16(4,  20, true);          // version needed
    buf.setUint16(6,  0, true);           // flags
    buf.setUint16(8,  0, true);           // STORE
    buf.setUint16(10, 0, true);           // mod time
    buf.setUint16(12, 0, true);           // mod date
    buf.setUint32(14, crc >>> 0, true);
    buf.setUint32(18, data.length, true);
    buf.setUint32(22, data.length, true);
    buf.setUint16(26, nameBytes.length, true);
    buf.setUint16(28, 0, true);
    const out = new Uint8Array(buf.buffer);
    for (let i = 0; i < nameBytes.length; i++) out[30 + i] = nameBytes[i];
    return out;
  }

  function buildCentralDir(nameBytes, data, crc, localOffset) {
    const buf = new DataView(new ArrayBuffer(46 + nameBytes.length));
    buf.setUint32(0,  0x504B0102, true); // signature
    buf.setUint16(4,  20, true);
    buf.setUint16(6,  20, true);
    buf.setUint16(8,  0, true);
    buf.setUint16(10, 0, true);           // STORE
    buf.setUint16(12, 0, true);
    buf.setUint16(14, 0, true);
    buf.setUint32(16, crc >>> 0, true);
    buf.setUint32(20, data.length, true);
    buf.setUint32(24, data.length, true);
    buf.setUint16(28, nameBytes.length, true);
    buf.setUint16(30, 0, true);
    buf.setUint16(32, 0, true);
    buf.setUint16(34, 0, true);
    buf.setUint16(36, 0, true);
    buf.setUint32(38, 0, true);
    buf.setUint32(42, localOffset, true);
    const out = new Uint8Array(buf.buffer);
    for (let i = 0; i < nameBytes.length; i++) out[46 + i] = nameBytes[i];
    return out;
  }

  function buildEOCD(count, centralSize, centralOffset) {
    const buf = new DataView(new ArrayBuffer(22));
    buf.setUint32(0,  0x504B0506, true); // signature
    buf.setUint16(4,  0, true);
    buf.setUint16(6,  0, true);
    buf.setUint16(8,  count, true);
    buf.setUint16(10, count, true);
    buf.setUint32(12, centralSize, true);
    buf.setUint32(16, centralOffset, true);
    buf.setUint16(20, 0, true);
    return new Uint8Array(buf.buffer);
  }

  function concat(arrays) {
    const total  = arrays.reduce((s, a) => s + a.length, 0);
    const result = new Uint8Array(total);
    let pos = 0;
    for (const a of arrays) { result.set(a, pos); pos += a.length; }
    return result;
  }

  /* CRC-32 table */
  const CRC32_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
      t[i] = c;
    }
    return t;
  })();

  function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (const byte of data) crc = CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  /**
   * Trigger a ZIP download in the browser.
   * @param {Uint8Array} zipBytes
   * @param {string} filename
   */
  function downloadZip(zipBytes, filename) {
    const blob = new Blob([zipBytes], { type: 'application/zip' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  /* ────────────────────────────────────────────────
     DOM helpers
  ──────────────────────────────────────────────── */
  function qs(sel, ctx = document) { return ctx.querySelector(sel); }
  function qsa(sel, ctx = document) { return [...ctx.querySelectorAll(sel)]; }

  /* ────────────────────────────────────────────────
     Public API
  ──────────────────────────────────────────────── */
  return {
    generatePassword,
    passwordStrength,
    uuid,
    copyToClipboard,
    clearClipboard,
    buildZip,
    downloadZip,
    qs,
    qsa,
  };

})();
