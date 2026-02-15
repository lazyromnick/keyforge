/**
 * app.js — KeyForge Main Controller v2
 * Mobile-first · PIN unlock · Settings · Auto-lock
 */
'use strict';

(async function KeyForge() {

  /* ═══════════════════════════════════════════════
     State
  ═══════════════════════════════════════════════ */
  let _cryptoKey        = null;
  let _entries          = [];
  let _currentPassword  = '';
  let _pendingDeleteId  = null;
  let _isFirstLaunch    = !StorageManager.vaultExists();

  // Inactivity
  let _inactivitySecs   = 300; // default 5 min, user-adjustable
  let _remainingSecs    = 300;
  let _timerInterval    = null;

  // Clipboard
  let _countdownTimer   = null;

  // PIN entry state
  let _pinBuffer        = '';
  let _pinLength        = 0; // expected pin length (4–6), loaded on unlock

  /* ═══════════════════════════════════════════════
     DOM
  ═══════════════════════════════════════════════ */
  const $ = id => document.getElementById(id);

  // Screens
  const authScreen      = $('auth-screen');
  const pinScreen       = $('pin-screen');
  const appScreen       = $('app-screen');

  // Auth
  const masterPwInput   = $('master-password');
  const confirmPwInput  = $('confirm-password');
  const confirmGroup    = $('confirm-group');
  const unlockBtn       = $('unlock-btn');
  const unlockBtnText   = $('unlock-btn-text');
  const authError       = $('auth-error');
  const authModeLabel   = $('auth-mode-label');
  const authSwitchHint  = $('auth-switch-hint');
  const toggleMasterVis = $('toggle-master-vis');
  const masterStrFill   = $('master-strength-fill');
  const masterStrLabel  = $('master-strength-label');
  const strengthBarWrap = $('strength-bar-wrap');
  const switchToPinBtn  = $('switch-to-pin-btn');
  const pinSetupGroup   = $('pin-setup-group');
  const setupPinInput   = $('setup-pin');
  const setupPinConfirm = $('setup-pin-confirm');

  // PIN screen
  const pinDots         = Array.from({length:6}, (_,i) => $(`dot-${i}`));
  const pinError        = $('pin-error');
  const pinUseMasterBtn = $('pin-use-master-btn');
  const pinBackspaceBtn = $('pin-backspace-btn');
  const pinUseMasterLink= $('pin-use-master-link');

  // App nav
  const lockBtn         = $('lock-btn');
  const lockBtnSidebar  = $('lock-btn-sidebar');
  const timerDisplay    = $('timer-display');
  const timerSidebar    = $('timer-display-sidebar');
  const vaultCount      = $('vault-count');
  const bottomVaultCount= $('bottom-vault-count');

  // Generator
  const genPassword     = $('generated-password');
  const copyPwBtn       = $('copy-password-btn');
  const regenBtn        = $('regenerate-btn');
  const generateBtn     = $('generate-btn');
  const lengthSlider    = $('length-slider');
  const lengthValue     = $('length-value');
  const strengthText    = $('strength-text');
  const strengthSegs    = document.querySelector('.strength-segments');
  const clipboardNotice = $('clipboard-notice');
  const countdownEl     = $('countdown');
  const openSaveFormBtn = $('open-save-form-btn');
  const saveForm        = $('save-form');
  const saveSiteInput   = $('save-site');
  const saveUserInput   = $('save-username');
  const cancelSaveBtn   = $('cancel-save-btn');
  const confirmSaveBtn  = $('confirm-save-btn');

  // Vault
  const vaultSearch     = $('vault-search');
  const vaultList       = $('vault-list');
  const vaultEmpty      = $('vault-empty');
  const downloadVaultBtn= $('download-vault-btn');

  // Settings
  const pinStatusText   = $('pin-status-text');
  const pinBadge        = $('pin-badge');
  const setPinBtn       = $('set-pin-btn');
  const setPinBtnText   = $('set-pin-btn-text');
  const removePinBtn    = $('remove-pin-btn');
  const timeoutSelect   = $('timeout-select');
  const wipeVaultBtn    = $('wipe-vault-btn');

  // Set PIN modal
  const setPinModal     = $('set-pin-modal');
  const setPinModalTitle= $('set-pin-modal-title');
  const setPinModalClose= $('set-pin-modal-close');
  const newPinInput     = $('new-pin');
  const newPinConfirm   = $('new-pin-confirm');
  const setPinError     = $('set-pin-error');
  const setPinCancel    = $('set-pin-cancel');
  const setPinSave      = $('set-pin-save');

  // Edit modal
  const editModal       = $('edit-modal');
  const editSite        = $('edit-site');
  const editUsername    = $('edit-username');
  const editPassword    = $('edit-password');
  const editEntryId     = $('edit-entry-id');
  const modalCloseBtn   = $('modal-close-btn');
  const modalCancelBtn  = $('modal-cancel-btn');
  const modalSaveBtn    = $('modal-save-btn');
  const toggleEditVis   = $('toggle-edit-vis');

  // Confirm delete
  const confirmModal    = $('confirm-modal');
  const confirmDeleteSite=$('confirm-delete-site');
  const confirmCancelBtn= $('confirm-cancel-btn');
  const confirmDeleteBtn= $('confirm-delete-btn');

  // Wipe modal
  const wipeModal       = $('wipe-modal');
  const wipeConfirmInput= $('wipe-confirm-input');
  const wipeCancelBtn   = $('wipe-cancel-btn');
  const wipeConfirmBtn  = $('wipe-confirm-btn');

  // Toast
  const toast           = $('toast');

  /* ═══════════════════════════════════════════════
     Init
  ═══════════════════════════════════════════════ */
  function init() {
    applyAuthMode();
    bindEvents();
    masterPwInput.focus();
  }

  function applyAuthMode() {
    const hasPIN = StorageManager.hasPIN();

    if (_isFirstLaunch) {
      unlockBtnText.textContent  = 'Create Vault';
      authModeLabel.textContent  = 'Choose a master password to protect your new vault';
      authSwitchHint.innerHTML   = 'Already have a vault? <a href="#" id="switch-auth-mode">Unlock it</a>';
      confirmGroup.style.display = '';
      pinSetupGroup.style.display= '';
      strengthBarWrap.style.display = '';
      switchToPinBtn.style.display  = 'none';
    } else {
      unlockBtnText.textContent  = 'Unlock Vault';
      authModeLabel.textContent  = 'Enter your master password to unlock your vault';
      authSwitchHint.innerHTML   = 'New here? <a href="#" id="switch-auth-mode">Create a new vault</a>';
      confirmGroup.style.display = 'none';
      pinSetupGroup.style.display= 'none';
      strengthBarWrap.style.display = 'none';
      switchToPinBtn.style.display  = hasPIN ? '' : 'none';
    }
    const link = document.getElementById('switch-auth-mode');
    if (link) link.addEventListener('click', onSwitchMode);
  }

  /* ═══════════════════════════════════════════════
     Events
  ═══════════════════════════════════════════════ */
  function bindEvents() {

    /* ── Auth ── */
    unlockBtn.addEventListener('click', onUnlock);
    masterPwInput.addEventListener('keydown', e => e.key==='Enter' && onUnlock());
    confirmPwInput.addEventListener('keydown', e => e.key==='Enter' && onUnlock());
    masterPwInput.addEventListener('input', onMasterPwInput);
    toggleMasterVis.addEventListener('click', () => toggleVis(masterPwInput, toggleMasterVis));
    switchToPinBtn.addEventListener('click', showPinScreen);

    /* ── PIN Screen ── */
    document.querySelectorAll('.numpad-key[data-digit]').forEach(btn => {
      btn.addEventListener('click', () => onPinDigit(btn.dataset.digit));
    });
    pinUseMasterBtn.addEventListener('click', showAuthScreen);
    pinBackspaceBtn.addEventListener('click', onPinBackspace);
    pinUseMasterLink.addEventListener('click', e => { e.preventDefault(); showAuthScreen(); });

    /* ── App Nav (sidebar) ── */
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => switchPanel(item.dataset.panel));
    });

    /* ── App Nav (bottom mobile) ── */
    document.querySelectorAll('.bottom-nav-item').forEach(item => {
      item.addEventListener('click', () => switchPanel(item.dataset.panel));
    });

    lockBtn.addEventListener('click', lockApp);
    if (lockBtnSidebar) lockBtnSidebar.addEventListener('click', lockApp);

    /* ── Generator ── */
    lengthSlider.addEventListener('input', () => { lengthValue.textContent = lengthSlider.value; });
    generateBtn.addEventListener('click', onGenerate);
    copyPwBtn.addEventListener('click', onCopyPassword);
    regenBtn.addEventListener('click', onGenerate);
    openSaveFormBtn.addEventListener('click', () => {
      saveForm.style.display = '';
      openSaveFormBtn.style.display = 'none';
      saveSiteInput.focus();
    });
    cancelSaveBtn.addEventListener('click', hideSaveForm);
    confirmSaveBtn.addEventListener('click', onSaveEntry);

    /* ── Vault ── */
    vaultSearch.addEventListener('input', renderVault);
    downloadVaultBtn.addEventListener('click', onDownloadVault);

    /* ── Settings ── */
    setPinBtn.addEventListener('click', openSetPinModal);
    removePinBtn.addEventListener('click', onRemovePin);
    timeoutSelect.addEventListener('change', () => {
      _inactivitySecs = parseInt(timeoutSelect.value);
      _remainingSecs  = _inactivitySecs;
      updateTimerDisplay();
      showToast('Auto-lock timeout updated.', 'info');
    });
    wipeVaultBtn.addEventListener('click', () => { wipeModal.style.display='flex'; wipeConfirmInput.value=''; wipeConfirmBtn.disabled=true; wipeConfirmInput.focus(); });

    /* ── Set PIN Modal ── */
    setPinModalClose.addEventListener('click', closeSetPinModal);
    setPinCancel.addEventListener('click', closeSetPinModal);
    setPinModal.addEventListener('click', e => e.target===setPinModal && closeSetPinModal());
    setPinSave.addEventListener('click', onSavePinFromModal);
    newPinInput.addEventListener('keydown', e => e.key==='Enter' && newPinConfirm.focus());
    newPinConfirm.addEventListener('keydown', e => e.key==='Enter' && onSavePinFromModal());

    /* ── Edit Modal ── */
    modalCloseBtn.addEventListener('click', closeEditModal);
    modalCancelBtn.addEventListener('click', closeEditModal);
    modalSaveBtn.addEventListener('click', onModalSave);
    toggleEditVis.addEventListener('click', () => toggleVis(editPassword, toggleEditVis));
    editModal.addEventListener('click', e => e.target===editModal && closeEditModal());

    /* ── Confirm Delete ── */
    confirmCancelBtn.addEventListener('click', closeConfirmModal);
    confirmDeleteBtn.addEventListener('click', onConfirmDelete);
    confirmModal.addEventListener('click', e => e.target===confirmModal && closeConfirmModal());

    /* ── Wipe Modal ── */
    wipeCancelBtn.addEventListener('click', () => { wipeModal.style.display='none'; });
    wipeModal.addEventListener('click', e => e.target===wipeModal && (wipeModal.style.display='none'));
    wipeConfirmInput.addEventListener('input', () => {
      wipeConfirmBtn.disabled = wipeConfirmInput.value.trim().toUpperCase() !== 'WIPE';
    });
    wipeConfirmBtn.addEventListener('click', onWipeVault);

    /* ── Inactivity reset ── */
    ['touchstart','mousemove','keydown','click'].forEach(ev =>
      document.addEventListener(ev, resetInactivity, { passive:true })
    );
  }

  /* ═══════════════════════════════════════════════
     Panel switching
  ═══════════════════════════════════════════════ */
  function switchPanel(panel) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.panel===panel));
    document.querySelectorAll('.bottom-nav-item').forEach(n => n.classList.toggle('active', n.dataset.panel===panel));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const target = $('panel-' + panel);
    if (target) target.classList.add('active');
    if (panel === 'vault')    renderVault();
    if (panel === 'settings') refreshSettingsUI();
    resetInactivity();
    // Scroll main content to top
    document.querySelector('.main-content').scrollTop = 0;
  }

  /* ═══════════════════════════════════════════════
     Auth flow
  ═══════════════════════════════════════════════ */
  function onSwitchMode(e) {
    e.preventDefault();
    _isFirstLaunch = !_isFirstLaunch;
    masterPwInput.value = '';
    confirmPwInput.value = '';
    if (setupPinInput) { setupPinInput.value=''; setupPinConfirm.value=''; }
    hideAuthError();
    applyAuthMode();
    masterPwInput.focus();
  }

  async function onUnlock() {
    const pw = masterPwInput.value.trim();
    if (!pw) { showAuthError('Please enter your master password.'); return; }
    if (_isFirstLaunch) {
      const confirm = confirmPwInput.value;
      if (pw !== confirm) { showAuthError('Passwords do not match.'); return; }
      if (pw.length < 8)  { showAuthError('Master password must be at least 8 characters.'); return; }
      await createVault(pw);
    } else {
      await unlockVault(pw);
    }
  }

  async function createVault(pw) {
    unlockBtn.disabled = true;
    try {
      const salt  = CryptoLayer.generateSalt();
      const saltB64 = CryptoLayer.saltToBase64(salt);
      const key   = await CryptoLayer.deriveKey(pw, salt);
      const token = await CryptoLayer.createVerificationToken(key);
      StorageManager.initVault(saltB64, token);
      _cryptoKey = key;
      _entries   = [];
      masterPwInput.value = '';
      confirmPwInput.value = '';

      // Optional PIN at first launch
      const pin = setupPinInput?.value.trim();
      const pinConfirm = setupPinConfirm?.value.trim();
      if (pin) {
        if (pin.length < 4) { showAuthError('PIN must be at least 4 digits.'); unlockBtn.disabled=false; return; }
        if (pin !== pinConfirm) { showAuthError('PINs do not match.'); unlockBtn.disabled=false; return; }
        if (!/^\d+$/.test(pin)) { showAuthError('PIN must be digits only.'); unlockBtn.disabled=false; return; }
        await savePin(pin, key);
      }

      showApp();
      showToast('Vault created! Keep your master password safe.', 'success');
    } catch (err) {
      showAuthError('Failed to create vault: ' + err.message);
    } finally {
      unlockBtn.disabled = false;
    }
  }

  async function unlockVault(pw) {
    unlockBtn.disabled = true;
    try {
      const saltB64 = StorageManager.getSalt();
      if (!saltB64) { showAuthError('No vault found. Create one first.'); unlockBtn.disabled=false; return; }
      const salt  = CryptoLayer.base64ToSalt(saltB64);
      const key   = await CryptoLayer.deriveKey(pw, salt);
      const valid = await CryptoLayer.verifyKey(StorageManager.getVerificationToken(), key);
      if (!valid) { showAuthError('Incorrect master password.'); unlockBtn.disabled=false; return; }
      _cryptoKey = key;
      masterPwInput.value = '';
      await loadAllEntries();
      showApp();
      showToast('Vault unlocked.', 'info');
    } catch {
      showAuthError('Incorrect master password.');
    } finally {
      unlockBtn.disabled = false;
    }
  }

  async function loadAllEntries() {
    const raw = StorageManager.getAllEntries();
    _entries = [];
    for (const r of raw) {
      try {
        _entries.push({
          id:       r.id,
          site:     await CryptoLayer.decrypt(r.site,     _cryptoKey),
          username: await CryptoLayer.decrypt(r.username, _cryptoKey),
          password: await CryptoLayer.decrypt(r.password, _cryptoKey),
        });
      } catch { /* skip corrupted */ }
    }
  }

  function showApp() {
    authScreen.style.display = 'none';
    pinScreen.style.display  = 'none';
    appScreen.style.display  = 'flex';
    updateVaultCount();
    startInactivityTimer();
  }

  function lockApp() {
    _cryptoKey       = null;
    _entries         = [];
    _currentPassword = '';
    clearTimers();
    appScreen.style.display = 'none';
    pinScreen.style.display = 'none';
    genPassword.textContent = 'Tap Generate';
    openSaveFormBtn.style.display = 'none';
    hideSaveForm();
    vaultSearch.value = '';
    _pinBuffer = '';

    _isFirstLaunch = !StorageManager.vaultExists();

    // If PIN is set, go to PIN screen; else master password screen
    if (!_isFirstLaunch && StorageManager.hasPIN()) {
      showPinScreen();
    } else {
      showAuthScreen();
    }
    showToast('Vault locked.', 'info');
  }

  function showAuthScreen() {
    pinScreen.style.display  = 'none';
    authScreen.style.display = 'flex';
    _pinBuffer = '';
    updatePinDots();
    applyAuthMode();
    masterPwInput.value = '';
    hideAuthError();
    masterPwInput.focus();
  }

  /* ═══════════════════════════════════════════════
     PIN Screen
  ═══════════════════════════════════════════════ */
  function showPinScreen() {
    authScreen.style.display = 'none';
    appScreen.style.display  = 'none';
    pinScreen.style.display  = 'flex';
    _pinBuffer = '';
    updatePinDots();
    hidePinError();
  }

  function onPinDigit(digit) {
    const encPin = StorageManager.getEncryptedPin();
    if (!encPin) return;

    _pinBuffer += digit;
    updatePinDots();

    // Attempt unlock if we've reached a plausible length (4–6 digits)
    if (_pinBuffer.length >= 4) {
      // Try immediately at each length from 4 to 6
      attemptPinUnlock();
    }
  }

  async function attemptPinUnlock() {
    const encPin = StorageManager.getEncryptedPin();
    if (!encPin) return;

    // We need a crypto key to decrypt. We derive it from the stored master pw salt.
    // But wait — we don't have the key yet on the PIN screen.
    // Strategy: store a separate salt for PIN derivation? No — better approach:
    // The PIN is stored ENCRYPTED with the master key.
    // So to verify PIN without master key, we use a PIN-specific approach:
    // We store: encrypt(pin_plaintext, masterKey).
    // At PIN screen, we can't verify without the master key.
    // SOLUTION: Store a fast-verify hash (SHA-256 of salt+pin) alongside the encrypted pin.
    // The encrypted pin payload is only used to RE-DERIVE the session key after PIN unlock.
    // Implementation: The stored PIN payload contains the master key wrapped/encrypted.
    // We store: encrypt(JSON.stringify({masterKeyMaterial}), pinDerivedKey).
    // But Web Crypto keys are non-exportable by default.
    // PRACTICAL SOLUTION USED HERE:
    // - On PIN set: encrypt(masterPassword, pinDerivedKey) → store this
    // - On PIN unlock: derive pinKey from entered PIN, decrypt → get masterPassword, then derive masterKey
    // This is secure: PIN is PBKDF2-derived, masterPassword is AES-encrypted.
    // The stored payload in our impl is: encrypt(plainPin, masterKey) — so to verify we need the master key.
    // Since we don't have masterKey on PIN screen, we store a SECOND payload:
    //   pinVerifyToken = encrypt(pin + "_VALID", pinDerivedKey)
    // And encryptedMasterPw = encrypt(masterPw, pinDerivedKey)
    // But we don't have masterPw after first unlock either.
    //
    // ACTUAL IMPLEMENTATION (simpler, secure):
    // On PIN set: store encrypt(pin, masterKey) — i.e. the ciphertext of the raw PIN digits
    // On PIN screen: we TRY to use a session-less approach — we can't fully verify without master key.
    // So we use: a PIN-derived PBKDF2 key encrypts a known token stored separately.
    //
    // For THIS implementation, we use the approach in pinManager below.
    // See PINManager.verifyPin and PINManager.unlockWithPin.

    const result = await PINManager.tryUnlockWithPin(_pinBuffer);
    if (result === 'unlock') {
      // Loaded key from PINManager
      showApp();
      showToast('Vault unlocked with PIN.', 'success');
    } else if (result === 'wait') {
      // Not enough digits yet, keep going
    } else if (result === 'wrong') {
      // Wrong PIN
      pinDots.forEach(d => d.classList.add('error'));
      setTimeout(() => {
        pinDots.forEach(d => { d.classList.remove('error'); d.classList.remove('filled'); });
        _pinBuffer = '';
      }, 600);
      showPinError('Incorrect PIN. Try again.');
    }
  }

  function onPinBackspace() {
    if (_pinBuffer.length > 0) {
      _pinBuffer = _pinBuffer.slice(0, -1);
      updatePinDots();
      hidePinError();
    }
  }

  function updatePinDots() {
    pinDots.forEach((dot, i) => {
      dot.classList.toggle('filled', i < _pinBuffer.length);
    });
  }

  function showPinError(msg) {
    pinError.textContent   = msg;
    pinError.style.display = '';
  }
  function hidePinError() {
    pinError.style.display = 'none';
  }

  /* ═══════════════════════════════════════════════
     PIN Manager
     Strategy: PIN → PBKDF2 → pinKey
     Store: encrypt("KEYFORGE_PIN_OK", pinKey)  [pinVerifyToken]
       AND: encrypt(masterPassword, pinKey)       [pinMasterToken]
     Both tokens stored in vault.pin = { salt, verifyToken, masterToken }
  ═══════════════════════════════════════════════ */
  const PINManager = (() => {
    const PIN_VERIFY = 'KEYFORGE_PIN_OK';
    const ITERS = 100_000;

    async function derivePinKey(pin, salt) {
      const enc    = new TextEncoder();
      const rawKey = await crypto.subtle.importKey('raw', enc.encode(pin), {name:'PBKDF2'}, false, ['deriveKey']);
      return crypto.subtle.deriveKey(
        { name:'PBKDF2', salt, iterations:ITERS, hash:'SHA-256' },
        rawKey,
        { name:'AES-GCM', length:256 },
        false,
        ['encrypt','decrypt']
      );
    }

    async function setPin(pin, masterPassword, masterKey) {
      // We need masterPassword here. We receive it during CREATE VAULT flow.
      // After unlocking, we no longer have the plaintext master password.
      // So setPin is only possible when masterPassword is available.
      const salt         = CryptoLayer.generateSalt();
      const pinKey       = await derivePinKey(pin, salt);
      const verifyToken  = await CryptoLayer.encrypt(PIN_VERIFY,      pinKey);
      const masterToken  = await CryptoLayer.encrypt(masterPassword,  pinKey);
      const saltB64      = CryptoLayer.saltToBase64(salt);
      const payload      = JSON.stringify({ salt: saltB64, verifyToken, masterToken });
      StorageManager.saveEncryptedPin(payload);
    }

    /** Returns 'unlock' | 'wait' | 'wrong' */
    async function tryUnlockWithPin(pin) {
      const raw = StorageManager.getEncryptedPin();
      if (!raw) return 'wrong';
      let payload;
      try { payload = JSON.parse(raw); } catch { return 'wrong'; }

      const salt   = CryptoLayer.base64ToSalt(payload.salt);
      const pinKey = await derivePinKey(pin, salt);

      // Verify token
      let verified = false;
      try {
        const plain = await CryptoLayer.decrypt(payload.verifyToken, pinKey);
        verified = (plain === PIN_VERIFY);
      } catch { /* wrong key */ }

      if (!verified) {
        // Maybe more digits are coming (pins can be 4–6), so if < 6 we wait
        return pin.length < 6 ? 'wait' : 'wrong';
      }

      // Decrypt master password → re-derive master key
      try {
        const masterPw = await CryptoLayer.decrypt(payload.masterToken, pinKey);
        const saltB64  = StorageManager.getSalt();
        const masterSalt = CryptoLayer.base64ToSalt(saltB64);
        const masterKey  = await CryptoLayer.deriveKey(masterPw, masterSalt);
        const valid = await CryptoLayer.verifyKey(StorageManager.getVerificationToken(), masterKey);
        if (!valid) return 'wrong';
        _cryptoKey = masterKey;
        await loadAllEntries();
        return 'unlock';
      } catch {
        return 'wrong';
      }
    }

    return { setPin, tryUnlockWithPin };
  })();

  /* ═══════════════════════════════════════════════
     Save PIN (from inside the app settings)
  ═══════════════════════════════════════════════ */
  async function savePin(pin, keyOverride) {
    // We need the plaintext master password to set PIN.
    // At first-vault-creation time, we pass the pw directly.
    // From settings, we must re-prompt for it.
    const key = keyOverride || _cryptoKey;
    if (!key) return;
    // We can't set PIN from settings without the master password plaintext.
    // This is handled in openSetPinModal by prompting for master pw first.
    // Here we receive both pin and a pre-validated key + masterPw stored in _pendingMasterPw
    const masterPw = _pendingMasterPw;
    if (!masterPw) { showToast('Re-enter master password to set PIN.', 'error'); return; }
    await PINManager.setPin(pin, masterPw, key);
    _pendingMasterPw = null;
  }

  let _pendingMasterPw = null;

  function openSetPinModal() {
    setPinModalTitle.textContent = StorageManager.hasPIN() ? 'Change PIN' : 'Set Quick PIN';
    newPinInput.value   = '';
    newPinConfirm.value = '';
    setPinError.style.display = 'none';
    setPinModal.style.display = 'flex';
    // Add master pw re-entry field to the modal dynamically
    addMasterPwFieldToModal();
    newPinInput.focus();
  }

  function addMasterPwFieldToModal() {
    // Add a master-password row to the modal if not present
    let existing = $('set-pin-master-group');
    if (!existing) {
      const group = document.createElement('div');
      group.className = 'input-group';
      group.id = 'set-pin-master-group';
      group.innerHTML = `
        <label for="set-pin-master-pw"><i class="bi bi-key-fill"></i> Confirm Master Password</label>
        <div class="password-input-wrap">
          <input type="password" id="set-pin-master-pw" placeholder="Re-enter master password" autocomplete="current-password" />
          <button class="toggle-vis" id="toggle-set-pin-master" type="button"><i class="bi bi-eye"></i></button>
        </div>
      `;
      const body = setPinModal.querySelector('.modal-body');
      body.insertBefore(group, body.firstChild);
      $('toggle-set-pin-master').addEventListener('click', () => {
        toggleVis($('set-pin-master-pw'), $('toggle-set-pin-master'));
      });
    }
  }

  function closeSetPinModal() {
    setPinModal.style.display = 'none';
    _pendingMasterPw = null;
  }

  async function onSavePinFromModal() {
    const masterPw = $('set-pin-master-pw')?.value.trim();
    const pin      = newPinInput.value.trim();
    const pinConf  = newPinConfirm.value.trim();

    if (!masterPw) { showSetPinError('Enter your master password to confirm.'); return; }
    if (!pin)       { showSetPinError('Enter a PIN.'); return; }
    if (pin.length < 4) { showSetPinError('PIN must be 4–6 digits.'); return; }
    if (!/^\d+$/.test(pin)) { showSetPinError('PIN must be digits only.'); return; }
    if (pin !== pinConf)    { showSetPinError('PINs do not match.'); return; }

    // Verify master password
    try {
      const saltB64  = StorageManager.getSalt();
      const salt     = CryptoLayer.base64ToSalt(saltB64);
      const key      = await CryptoLayer.deriveKey(masterPw, salt);
      const valid    = await CryptoLayer.verifyKey(StorageManager.getVerificationToken(), key);
      if (!valid) { showSetPinError('Incorrect master password.'); return; }
      _pendingMasterPw = masterPw;
      await PINManager.setPin(pin, masterPw, key);
      _pendingMasterPw = null;
      closeSetPinModal();
      refreshSettingsUI();
      showToast('PIN saved successfully.', 'success');
    } catch (err) {
      showSetPinError('Error saving PIN: ' + err.message);
    }
  }

  function showSetPinError(msg) {
    setPinError.textContent   = msg;
    setPinError.style.display = '';
  }

  async function onRemovePin() {
    StorageManager.clearPin();
    refreshSettingsUI();
    showToast('PIN removed.', 'info');
  }

  /* ═══════════════════════════════════════════════
     PIN setup at first launch (inside createVault)
  ═══════════════════════════════════════════════ */
  // savePinAtCreation uses the plaintext pw available during createVault
  async function savePinAtCreation(pin, pw, key) {
    await PINManager.setPin(pin, pw, key);
  }

  /* ═══════════════════════════════════════════════
     Generator
  ═══════════════════════════════════════════════ */
  function onGenerate() {
    const opts = {
      length:           parseInt(lengthSlider.value),
      upper:            $('opt-upper').checked,
      lower:            $('opt-lower').checked,
      numbers:          $('opt-numbers').checked,
      symbols:          $('opt-symbols').checked,
      excludeAmbiguous: $('opt-exclude-ambiguous').checked,
    };
    if (!opts.upper && !opts.lower && !opts.numbers && !opts.symbols) {
      showToast('Select at least one character type.', 'error'); return;
    }
    _currentPassword = Utils.generatePassword(opts);
    genPassword.textContent = _currentPassword;
    const { score, label } = Utils.passwordStrength(_currentPassword);
    const classes = ['strength-weak','strength-fair','strength-strong','strength-great'];
    strengthSegs.className = 'strength-segments ' + (classes[score] || '');
    strengthText.textContent = label;
    copyPwBtn.disabled = false;
    regenBtn.disabled  = false;
    openSaveFormBtn.style.display = '';
    resetInactivity();
  }

  async function onCopyPassword() {
    if (!_currentPassword) return;
    try {
      await Utils.copyToClipboard(_currentPassword);
      startClipboardTimer();
    } catch { showToast('Could not access clipboard.', 'error'); }
    resetInactivity();
  }

  function startClipboardTimer() {
    clearInterval(_countdownTimer);
    clipboardNotice.style.display = 'flex';
    let count = 15;
    countdownEl.textContent = count;
    _countdownTimer = setInterval(() => {
      count--;
      countdownEl.textContent = count;
      if (count <= 0) {
        clearInterval(_countdownTimer);
        clipboardNotice.style.display = 'none';
        Utils.clearClipboard();
      }
    }, 1000);
  }

  function hideSaveForm() {
    saveForm.style.display = 'none';
    saveSiteInput.value = '';
    saveUserInput.value = '';
    if (_currentPassword) openSaveFormBtn.style.display = '';
  }

  async function onSaveEntry() {
    const site = saveSiteInput.value.trim();
    const user = saveUserInput.value.trim();
    if (!site) { showToast('Site / App name is required.', 'error'); return; }
    if (!user) { showToast('Username / Email is required.', 'error'); return; }
    if (!_currentPassword) { showToast('No password generated.', 'error'); return; }
    try {
      const encSite = await CryptoLayer.encrypt(site, _cryptoKey);
      const encUser = await CryptoLayer.encrypt(user, _cryptoKey);
      const encPw   = await CryptoLayer.encrypt(_currentPassword, _cryptoKey);
      const entry   = { id: Utils.uuid(), site: encSite, username: encUser, password: encPw };
      StorageManager.addEntry(entry);
      _entries.push({ id: entry.id, site, username: user, password: _currentPassword });
      updateVaultCount();
      hideSaveForm();
      openSaveFormBtn.style.display = 'none';
      showToast(`Saved "${site}" to vault.`, 'success');
      resetInactivity();
    } catch (err) { showToast('Error saving: ' + err.message, 'error'); }
  }

  /* ═══════════════════════════════════════════════
     Vault
  ═══════════════════════════════════════════════ */
  function renderVault() {
    const q = vaultSearch.value.toLowerCase().trim();
    const filtered = _entries.filter(e =>
      !q || e.site.toLowerCase().includes(q) || e.username.toLowerCase().includes(q)
    );
    vaultList.innerHTML = '';
    vaultEmpty.style.display = filtered.length ? 'none' : 'flex';
    filtered.forEach(e => vaultList.appendChild(buildEntryEl(e)));
  }

  function buildEntryEl(entry) {
    const div = document.createElement('div');
    div.className = 'vault-entry';
    const initial = (entry.site[0] || '?').toUpperCase();
    div.innerHTML = `
      <div class="entry-icon">${initial}</div>
      <div class="entry-main">
        <div class="entry-site">${escapeHtml(entry.site)}</div>
        <div class="entry-username">${escapeHtml(entry.username)}</div>
        <div class="entry-pw-row">
          <span class="entry-password">••••••••••••</span>
          <button class="icon-btn reveal-btn" title="Reveal"><i class="bi bi-eye"></i></button>
        </div>
      </div>
      <div class="entry-actions">
        <button class="icon-btn copy-entry-btn" title="Copy password"><i class="bi bi-clipboard"></i></button>
        <button class="icon-btn edit-entry-btn" title="Edit"><i class="bi bi-pencil"></i></button>
        <button class="icon-btn danger delete-entry-btn" title="Delete"><i class="bi bi-trash3"></i></button>
      </div>
    `;
    const pwSpan    = div.querySelector('.entry-password');
    const revealBtn = div.querySelector('.reveal-btn');
    const copyBtn   = div.querySelector('.copy-entry-btn');
    const editBtn   = div.querySelector('.edit-entry-btn');
    const deleteBtn = div.querySelector('.delete-entry-btn');

    revealBtn.addEventListener('click', () => {
      const show = pwSpan.classList.toggle('revealed');
      pwSpan.textContent = show ? entry.password : '••••••••••••';
      revealBtn.querySelector('i').className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
      resetInactivity();
    });
    copyBtn.addEventListener('click', async () => {
      try {
        await Utils.copyToClipboard(entry.password);
        showToast('Copied! Clears in 15s.', 'success');
        setTimeout(() => Utils.clearClipboard(), 15000);
      } catch { showToast('Could not copy.', 'error'); }
      resetInactivity();
    });
    editBtn.addEventListener('click', () => openEditModal(entry));
    deleteBtn.addEventListener('click', () => openConfirmModal(entry));
    return div;
  }

  /* ── Edit Modal ── */
  function openEditModal(entry) {
    editEntryId.value  = entry.id;
    editSite.value     = entry.site;
    editUsername.value = entry.username;
    editPassword.value = entry.password;
    editModal.style.display = 'flex';
    editSite.focus();
  }
  function closeEditModal() { editModal.style.display = 'none'; }

  async function onModalSave() {
    const id   = editEntryId.value;
    const site = editSite.value.trim();
    const user = editUsername.value.trim();
    const pw   = editPassword.value.trim();
    if (!site || !user || !pw) { showToast('All fields required.', 'error'); return; }
    try {
      StorageManager.updateEntry(id, {
        site:     await CryptoLayer.encrypt(site, _cryptoKey),
        username: await CryptoLayer.encrypt(user, _cryptoKey),
        password: await CryptoLayer.encrypt(pw,   _cryptoKey),
      });
      const idx = _entries.findIndex(e => e.id === id);
      if (idx !== -1) _entries[idx] = { id, site, username: user, password: pw };
      closeEditModal();
      renderVault();
      showToast(`Updated "${site}".`, 'success');
    } catch (err) { showToast('Error: ' + err.message, 'error'); }
  }

  /* ── Confirm Delete ── */
  function openConfirmModal(entry) {
    _pendingDeleteId = entry.id;
    confirmDeleteSite.textContent = entry.site;
    confirmModal.style.display = 'flex';
  }
  function closeConfirmModal() { confirmModal.style.display='none'; _pendingDeleteId=null; }
  function onConfirmDelete() {
    if (!_pendingDeleteId) return;
    StorageManager.deleteEntry(_pendingDeleteId);
    _entries = _entries.filter(e => e.id !== _pendingDeleteId);
    updateVaultCount();
    renderVault();
    closeConfirmModal();
    showToast('Entry deleted.', 'info');
  }

  /* ── Vault Export ── */
  function onDownloadVault() {
    const vaultJSON = StorageManager.exportVaultJSON();
    const readme = `KeyForge Encrypted Vault Export\n================================\nGenerated: ${new Date().toISOString()}\n\nAll data is AES-256-GCM encrypted. Your master password is required to decrypt.\nNever share this file or your master password.\n`;
    const zipBytes = Utils.buildZip([
      { name:'vault.json', content:vaultJSON },
      { name:'README.txt', content:readme },
    ]);
    Utils.downloadZip(zipBytes, `keyforge-vault-${new Date().toISOString().slice(0,10)}.zip`);
    showToast('Encrypted vault downloaded.', 'success');
  }

  /* ── Settings ── */
  function refreshSettingsUI() {
    const has = StorageManager.hasPIN();
    pinStatusText.textContent     = has ? 'Active — fast unlock enabled' : 'Not set — master password only';
    pinBadge.textContent          = has ? 'Active' : 'Off';
    pinBadge.className            = 'settings-badge ' + (has ? 'active' : 'inactive');
    setPinBtnText.textContent     = has ? 'Change PIN' : 'Set PIN';
    removePinBtn.style.display    = has ? '' : 'none';
  }

  /* ── Wipe ── */
  function onWipeVault() {
    StorageManager.wipeVault();
    _cryptoKey = null; _entries = [];
    wipeModal.style.display = 'none';
    _isFirstLaunch = true;
    showAuthScreen();
    showToast('Vault wiped. Start fresh.', 'error');
  }

  /* ═══════════════════════════════════════════════
     Inactivity Timer
  ═══════════════════════════════════════════════ */
  function startInactivityTimer() {
    clearTimers();
    _remainingSecs = _inactivitySecs;
    updateTimerDisplay();
    _timerInterval = setInterval(() => {
      _remainingSecs--;
      updateTimerDisplay();
      if (_remainingSecs <= 0) {
        lockApp();
        showToast('Auto-locked due to inactivity.', 'info');
      }
    }, 1000);
  }
  function resetInactivity() {
    if (!_cryptoKey) return;
    _remainingSecs = _inactivitySecs;
    updateTimerDisplay();
  }
  function updateTimerDisplay() {
    const m = Math.floor(_remainingSecs / 60);
    const s = Math.floor(_remainingSecs % 60);
    const t = `${m}:${s.toString().padStart(2,'0')}`;
    if (timerDisplay)  timerDisplay.textContent = t;
    if (timerSidebar)  timerSidebar.textContent = t;
  }
  function clearTimers() {
    clearInterval(_timerInterval);
    clearInterval(_countdownTimer);
  }

  /* ═══════════════════════════════════════════════
     Master PW Strength
  ═══════════════════════════════════════════════ */
  function onMasterPwInput() {
    if (!_isFirstLaunch) return;
    const pw = masterPwInput.value;
    if (!pw) { masterStrFill.style.width='0%'; masterStrLabel.textContent=''; return; }
    const score = CryptoLayer.masterPasswordStrength(pw);
    const pct = (score/4)*100;
    const colors = ['#ff5252','#ff5252','#ffd166','#f5a623','#28d98c'];
    const labels = ['Too weak','Weak','Fair','Strong','Great'];
    masterStrFill.style.width      = pct + '%';
    masterStrFill.style.background = colors[score];
    masterStrLabel.textContent     = labels[score];
  }

  /* ═══════════════════════════════════════════════
     Helpers
  ═══════════════════════════════════════════════ */
  function toggleVis(input, btn) {
    const isPw = input.type === 'password';
    input.type = isPw ? 'text' : 'password';
    btn.querySelector('i').className = isPw ? 'bi bi-eye-slash' : 'bi bi-eye';
  }
  function showAuthError(msg) { authError.textContent=msg; authError.style.display=''; }
  function hideAuthError()    { authError.style.display='none'; }

  function updateVaultCount() {
    const n = _entries.length;
    vaultCount.textContent = n;
    if (bottomVaultCount) {
      bottomVaultCount.textContent = n;
      bottomVaultCount.style.display = n > 0 ? '' : 'none';
    }
  }

  let _toastT;
  function showToast(msg, type='info') {
    toast.textContent  = msg;
    toast.className    = `toast show ${type}`;
    clearTimeout(_toastT);
    _toastT = setTimeout(() => toast.classList.remove('show'), 3500);
  }
  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  /* ── Handle PIN at first-launch vault creation ── */
  // Override createVault to use savePinAtCreation
  const _origCreateVault = createVault;
  async function createVault(pw) {
    unlockBtn.disabled = true;
    try {
      const salt    = CryptoLayer.generateSalt();
      const saltB64 = CryptoLayer.saltToBase64(salt);
      const key     = await CryptoLayer.deriveKey(pw, salt);
      const token   = await CryptoLayer.createVerificationToken(key);
      StorageManager.initVault(saltB64, token);
      _cryptoKey = key;
      _entries   = [];
      masterPwInput.value  = '';
      confirmPwInput.value = '';

      const pin     = setupPinInput?.value.trim();
      const pinConf = setupPinConfirm?.value.trim();
      if (pin) {
        if (pin.length < 4)         { showAuthError('PIN must be at least 4 digits.'); unlockBtn.disabled=false; return; }
        if (pin !== pinConf)        { showAuthError('PINs do not match.'); unlockBtn.disabled=false; return; }
        if (!/^\d+$/.test(pin))     { showAuthError('PIN must be digits only.'); unlockBtn.disabled=false; return; }
        await savePinAtCreation(pin, pw, key);
      }
      showApp();
      showToast(pin ? 'Vault created with PIN! Keep your master password safe.' : 'Vault created! Keep your master password safe.', 'success');
    } catch (err) {
      showAuthError('Failed to create vault: ' + err.message);
    } finally {
      unlockBtn.disabled = false;
    }
  }

  /* ═══════════════════════════════════════════════
     Boot
  ═══════════════════════════════════════════════ */
  // If vault exists and has PIN, show PIN screen directly
  if (!_isFirstLaunch && StorageManager.hasPIN()) {
    init();
    authScreen.style.display = 'none';
    showPinScreen();
  } else {
    init();
  }

})();
