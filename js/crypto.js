/**
 * crypto.js — KeyForge Encryption Layer
 * Uses Web Crypto API: PBKDF2 key derivation + AES-GCM encryption
 * Nothing is ever stored in plaintext.
 */
'use strict';

const CryptoLayer = (() => {

  const PBKDF2_ITERATIONS = 310_000;
  const SALT_LENGTH       = 32;
  const IV_LENGTH         = 12;

  /* ────────────────────────────────────────────────
     Key Derivation
  ──────────────────────────────────────────────── */

  /**
   * Derive an AES-GCM CryptoKey from the master password + salt.
   * @param {string} password
   * @param {Uint8Array} salt
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(password, salt) {
    const enc    = new TextEncoder();
    const rawKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name:       'PBKDF2',
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash:       'SHA-256',
      },
      rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /* ────────────────────────────────────────────────
     Encrypt
  ──────────────────────────────────────────────── */

  /**
   * Encrypt a plaintext string.
   * Returns a base64-encoded payload: salt(32) + iv(12) + ciphertext.
   * @param {string} plaintext
   * @param {CryptoKey} key
   * @returns {Promise<string>} base64 payload
   */
  async function encrypt(plaintext, key) {
    const enc  = new TextEncoder();
    const iv   = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const data = enc.encode(plaintext);

    const cipherBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    );

    const cipherBytes = new Uint8Array(cipherBuffer);
    // Pack: iv(12) + cipher
    const packed = new Uint8Array(iv.length + cipherBytes.length);
    packed.set(iv, 0);
    packed.set(cipherBytes, iv.length);

    return btoa(String.fromCharCode(...packed));
  }

  /* ────────────────────────────────────────────────
     Decrypt
  ──────────────────────────────────────────────── */

  /**
   * Decrypt a base64-encoded payload produced by encrypt().
   * @param {string} b64payload
   * @param {CryptoKey} key
   * @returns {Promise<string>} plaintext
   */
  async function decrypt(b64payload, key) {
    const packed = Uint8Array.from(atob(b64payload), c => c.charCodeAt(0));
    const iv          = packed.slice(0, IV_LENGTH);
    const cipherBytes = packed.slice(IV_LENGTH);

    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      cipherBytes
    );

    return new TextDecoder().decode(plainBuffer);
  }

  /* ────────────────────────────────────────────────
     Salt helpers
  ──────────────────────────────────────────────── */

  function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  }

  function saltToBase64(salt) {
    return btoa(String.fromCharCode(...salt));
  }

  function base64ToSalt(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  /* ────────────────────────────────────────────────
     Password strength check (used for master pw)
  ──────────────────────────────────────────────── */

  /**
   * Returns 0–4 strength score for a password.
   */
  function masterPasswordStrength(pw) {
    if (!pw || pw.length < 8) return 0;
    let score = 0;
    if (pw.length >= 12)                   score++;
    if (pw.length >= 18)                   score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw))                  score++;
    if (/[^A-Za-z0-9]/.test(pw))           score++;
    return Math.min(4, score);
  }

  /* ────────────────────────────────────────────────
     Vault verification token
     We store an encrypted known plaintext so we can
     verify the master password is correct on unlock.
  ──────────────────────────────────────────────── */

  const VERIFY_TOKEN = 'KEYFORGE_VAULT_OK';

  async function createVerificationToken(key) {
    return await encrypt(VERIFY_TOKEN, key);
  }

  async function verifyKey(encryptedToken, key) {
    try {
      const plain = await decrypt(encryptedToken, key);
      return plain === VERIFY_TOKEN;
    } catch {
      return false;
    }
  }

  /* ────────────────────────────────────────────────
     Public API
  ──────────────────────────────────────────────── */
  return {
    deriveKey,
    encrypt,
    decrypt,
    generateSalt,
    saltToBase64,
    base64ToSalt,
    masterPasswordStrength,
    createVerificationToken,
    verifyKey,
  };

})();
