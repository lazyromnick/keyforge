/**
 * storage.js — KeyForge Local Storage Manager v2
 * Encrypted vault CRUD + PIN management.
 */
'use strict';

const StorageManager = (() => {

  const STORAGE_KEY    = 'keyforge_vault';
  const SCHEMA_VERSION = 2;

  /* ── Internal helpers ── */
  function loadRaw() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }
  function saveRaw(data) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  /* ── Vault existence ── */
  function vaultExists() {
    const raw = loadRaw();
    return raw !== null && raw.verificationToken !== undefined;
  }

  /* ── Init vault ── */
  function initVault(saltB64, verificationToken) {
    const vault = {
      version: SCHEMA_VERSION,
      salt: saltB64,
      verificationToken,
      pin: null,          // encrypted PIN stored here when set
      entries: [],
    };
    saveRaw(vault);
  }

  /* ── Salt & verification ── */
  function getSalt()              { return loadRaw()?.salt ?? null; }
  function getVerificationToken() { return loadRaw()?.verificationToken ?? null; }

  /* ── PIN ── */
  /** Returns the encrypted PIN payload (or null if not set). */
  function getEncryptedPin()    { return loadRaw()?.pin ?? null; }
  /** Returns true if a PIN has been configured. */
  function hasPIN()             { return !!getEncryptedPin(); }

  /**
   * Save an encrypted PIN value.
   * @param {string} encryptedPin — base64 AES-GCM ciphertext produced by CryptoLayer.encrypt()
   */
  function saveEncryptedPin(encryptedPin) {
    const raw = loadRaw();
    if (!raw) throw new Error('Vault not initialised');
    raw.pin = encryptedPin;
    saveRaw(raw);
  }

  /** Remove the stored PIN. */
  function clearPin() {
    const raw = loadRaw();
    if (!raw) return;
    raw.pin = null;
    saveRaw(raw);
  }

  /* ── CRUD ── */
  function getAllEntries()   { return loadRaw()?.entries ?? []; }

  function addEntry(entry) {
    const raw = loadRaw();
    if (!raw) throw new Error('Vault not initialised');
    raw.entries.push(entry);
    saveRaw(raw);
  }

  function updateEntry(id, updates) {
    const raw = loadRaw();
    if (!raw) throw new Error('Vault not initialised');
    const idx = raw.entries.findIndex(e => e.id === id);
    if (idx === -1) throw new Error(`Entry ${id} not found`);
    raw.entries[idx] = { ...raw.entries[idx], ...updates };
    saveRaw(raw);
  }

  function deleteEntry(id) {
    const raw = loadRaw();
    if (!raw) throw new Error('Vault not initialised');
    raw.entries = raw.entries.filter(e => e.id !== id);
    saveRaw(raw);
  }

  /* ── Export ── */
  function exportVaultJSON() {
    const raw = loadRaw();
    return raw ? JSON.stringify(raw, null, 2) : '{}';
  }

  /* ── Wipe ── */
  function wipeVault() { localStorage.removeItem(STORAGE_KEY); }

  /* ── Public ── */
  return {
    vaultExists,
    initVault,
    getSalt,
    getVerificationToken,
    getEncryptedPin,
    hasPIN,
    saveEncryptedPin,
    clearPin,
    getAllEntries,
    addEntry,
    updateEntry,
    deleteEntry,
    exportVaultJSON,
    wipeVault,
  };

})();
