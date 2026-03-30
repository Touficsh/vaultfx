/**
 * VaultFX — Credential Password Reveal & Management
 * ===================================================
 * Security rules:
 *  • Passwords are NEVER stored in the DOM, JS variables, or browser storage
 *  • Passwords are fetched via AJAX only when the user clicks "Reveal"
 *  • Password is displayed for N seconds (configurable), then auto-hidden
 *  • Clipboard is cleared automatically after N seconds
 *  • Reveal button is completely absent from DOM for restricted_viewer role
 *    (enforced server-side; this JS file also never generates one)
 */

'use strict';

const Credentials = {
  // Active reveal timers: { credentialKey: timerIds }
  activeTimers: {},

  /**
   * Reveals a credential password.
   *
   * @param {string} type   'manager' or 'coverage'
   * @param {number} id     Credential ID
   * @param {HTMLElement} btn  The reveal button element
   */
  async reveal(type, id, btn) {
    const key = `${type}-${id}`;

    // If already revealing, cancel it
    if (this.activeTimers[key]) {
      this.hide(type, id, btn);
      return;
    }

    // Disable button during fetch
    btn.disabled = true;
    const originalHtml = btn.innerHTML;
    btn.innerHTML = `<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 12a9 9 0 1 1-9-9"/></svg>`;

    try {
      const fd = new FormData();
      fd.set('type', type);
      fd.set('id', String(id));

      const { ok, data } = await VaultFX.postForm('api/reveal-password.php', fd);

      if (!ok || !data.success) {
        VaultFX.toast('error', data.message ?? 'Failed to retrieve password.');
        btn.disabled  = false;
        btn.innerHTML = originalHtml;
        return;
      }

      const password    = data.data.password;
      const timeout     = data.data.reveal_timeout ?? 30;
      const fieldEl     = document.getElementById(`pw-field-${key}`);
      const timerEl     = document.getElementById(`pw-timer-${key}`);
      const copyBtn     = document.getElementById(`pw-copy-${key}`);

      if (!fieldEl) {
        VaultFX.toast('error', 'UI error: password display field not found.');
        btn.disabled  = false;
        btn.innerHTML = originalHtml;
        return;
      }

      // Display the password
      fieldEl.textContent = password;
      fieldEl.classList.add('revealed');

      // Update button to "Hide"
      btn.disabled = false;
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
          <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
        <span>Hide</span>
      `;
      btn.title = 'Click to hide password';

      // Enable copy button
      if (copyBtn) {
        copyBtn.disabled = false;
        copyBtn.onclick  = () => this.copyPassword(type, id, password);
      }

      // Start countdown timer
      let remaining = timeout;

      const updateTimer = () => {
        if (timerEl) timerEl.textContent = `${remaining}s`;
      };

      updateTimer();

      const interval = setInterval(() => {
        remaining--;
        updateTimer();
        if (remaining <= 0) {
          this.hide(type, id, btn, originalHtml);
        }
      }, 1000);

      this.activeTimers[key] = { interval, password, btn, originalHtml, copyBtn };

    } catch (err) {
      console.error('Reveal error:', err);
      VaultFX.toast('error', 'An unexpected error occurred.');
      btn.disabled  = false;
      btn.innerHTML = originalHtml;
    }
  },

  /**
   * Hides a revealed password and clears all state.
   */
  hide(type, id, btn, originalHtml) {
    const key    = `${type}-${id}`;
    const timers = this.activeTimers[key];

    if (timers) {
      clearInterval(timers.interval);
      delete this.activeTimers[key];
    }

    const fieldEl = document.getElementById(`pw-field-${key}`);
    const timerEl = document.getElementById(`pw-timer-${key}`);
    const copyBtn = document.getElementById(`pw-copy-${key}`);

    if (fieldEl) {
      fieldEl.textContent = '••••••••••••';
      fieldEl.classList.remove('revealed');
    }

    if (timerEl) timerEl.textContent = '';
    if (copyBtn) copyBtn.disabled = true;

    if (btn) {
      btn.disabled  = false;
      btn.innerHTML = originalHtml ?? `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
        <span>Reveal</span>
      `;
      btn.title = 'Click to reveal password';
    }
  },

  /**
   * Copies a password to clipboard, then auto-clears it.
   * The password must already be in memory from the reveal call.
   */
  async copyPassword(type, id, password) {
    const key    = `${type}-${id}`;
    const timers = this.activeTimers[key];
    const pw     = password ?? timers?.password;

    if (!pw) {
      VaultFX.toast('warning', 'Please reveal the password first.');
      return;
    }

    const timeout = (timers ? parseInt(document.getElementById(`pw-timer-${key}`)?.textContent) : 30) || 30;

    await VaultFX.copyToClipboard(pw, timeout * 1000);
  },

  /**
   * Hides ALL currently revealed passwords.
   * Called on page unload or navigation.
   */
  hideAll() {
    Object.keys(this.activeTimers).forEach(key => {
      const [type, id] = key.split('-');
      const timers     = this.activeTimers[key];
      if (timers) {
        this.hide(type, parseInt(id), timers.btn, timers.originalHtml);
      }
    });
  },

  /**
   * Creates the HTML for a password reveal row.
   * Must be generated server-side for restricted_viewer (who gets no reveal UI).
   * This helper is for dynamic content.
   */
  buildRevealHtml(type, id, canReveal) {
    const key = `${type}-${id}`;

    if (!canReveal) {
      // Restricted viewer: no reveal UI in DOM at all
      return `<span class="credential-password-field font-mono text-muted">••••••••</span>`;
    }

    return `
      <div class="credential-password">
        <span id="pw-field-${key}" class="credential-password-field font-mono">••••••••••••</span>
        <span id="pw-timer-${key}" class="reveal-timer"></span>
        <button
          id="pw-copy-${key}"
          class="btn btn-ghost btn-icon btn-sm"
          disabled
          title="Copy to clipboard"
          onclick="Credentials.copyPassword('${VaultFX.escapeHtml(type)}', ${parseInt(id)})">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </button>
        <button
          id="pw-reveal-${key}"
          class="btn btn-outline btn-sm"
          title="Click to reveal password"
          onclick="Credentials.reveal('${VaultFX.escapeHtml(type)}', ${parseInt(id)}, this)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
          <span>Reveal</span>
        </button>
      </div>
    `;
  },
};

// ── Password Generator UI ─────────────────────────────────────
const PasswordGenerator = {
  async generate(targetInputId) {
    const length  = parseInt(document.getElementById('gen-length')?.value ?? 20);
    const upper   = document.getElementById('gen-upper')?.checked ? '1' : '0';
    const lower   = document.getElementById('gen-lower')?.checked ? '1' : '0';
    const digits  = document.getElementById('gen-digits')?.checked ? '1' : '0';
    const special = document.getElementById('gen-special')?.checked ? '1' : '0';

    const fd = new FormData();
    fd.set('length', String(length));
    fd.set('upper', upper);
    fd.set('lower', lower);
    fd.set('digits', digits);
    fd.set('special', special);

    const { ok, data } = await VaultFX.postForm(
      `api/managers.php?action=generate-password`, fd
    );

    if (ok && data.success) {
      const input = document.getElementById(targetInputId);
      if (input) {
        input.value = data.data.password;
        input.type  = 'text';
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    } else {
      VaultFX.toast('error', 'Failed to generate password.');
    }
  },
};

// ── Password Strength Meter ───────────────────────────────────
function initPasswordStrength(inputId, meterId) {
  const input = document.getElementById(inputId);
  const meter = document.getElementById(meterId);
  if (!input || !meter) return;

  input.addEventListener('input', () => {
    const val      = input.value;
    let strength   = 0;

    if (val.length >= 12)            strength++;
    if (/[A-Z]/.test(val))          strength++;
    if (/[0-9]/.test(val))          strength++;
    if (/[^a-zA-Z0-9]/.test(val))   strength++;

    meter.dataset.strength = val.length === 0 ? '0' : String(Math.max(1, strength));
  });
}

// Hide passwords on page visibility change (browser tab switch)
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    Credentials.hideAll();
  }
});

// Hide passwords before page navigates away
window.addEventListener('beforeunload', () => Credentials.hideAll());
