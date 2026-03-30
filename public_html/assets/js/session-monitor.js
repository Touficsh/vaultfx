/**
 * VaultFX — Session Monitor
 * ==========================
 * Pings the server every 5 minutes to keep session alive.
 * Shows a warning countdown at 5 minutes before idle timeout.
 * Auto-logs out when timeout expires.
 * Detects user activity to reset idle timer.
 */

'use strict';

const SessionMonitor = {
  pingInterval:    5 * 60 * 1000,   // 5 minutes
  warnAt:          5 * 60,          // seconds remaining when warning shows
  pingTimer:       null,
  countdownTimer:  null,
  warningEl:       null,
  isWarning:       false,
  remaining:       0,

  init() {
    this.warningEl = document.getElementById('session-warning');
    if (!this.warningEl) {
      this.createWarningUI();
    }

    // Start periodic ping
    this.schedulePing();

    // Track user activity
    ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(event => {
      document.addEventListener(event, () => this.onActivity(), { passive: true });
    });
  },

  /**
   * Schedules the next session ping.
   */
  schedulePing() {
    clearTimeout(this.pingTimer);
    this.pingTimer = setTimeout(() => this.ping(), this.pingInterval);
  },

  /**
   * Pings the server and processes the response.
   */
  async ping() {
    try {
      const res  = await fetch('api/session-ping.php', {
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token':     VaultFX.csrfToken(),
        },
        cache: 'no-store',
      });

      if (!res.ok) {
        this.handleExpired();
        return;
      }

      const data = await res.json();

      if (!data.authenticated || data.remaining <= 0) {
        this.handleExpired();
        return;
      }

      // Update CSRF token
      if (data.csrf_token) VaultFX.updateCsrfToken(data.csrf_token);

      this.remaining = data.remaining;

      if (this.remaining <= this.warnAt) {
        this.showWarning();
      } else {
        this.hideWarning();
        this.schedulePing();
      }
    } catch (e) {
      // Network error — keep trying but less frequently
      this.pingTimer = setTimeout(() => this.ping(), 30000);
    }
  },

  /**
   * Called on user activity — resets ping cycle.
   */
  onActivity() {
    if (this.isWarning) return; // Don't interrupt active warning
    this.schedulePing();
  },

  /**
   * Shows the session expiry warning with countdown.
   */
  showWarning() {
    if (!this.warningEl) return;
    this.isWarning = true;
    this.warningEl.classList.add('visible');

    // Start countdown
    let seconds = this.remaining;
    const updateCountdown = () => {
      const el = document.getElementById('session-countdown');
      if (el) {
        const m = Math.floor(seconds / 60).toString().padStart(2, '0');
        const s = (seconds % 60).toString().padStart(2, '0');
        el.textContent = `${m}:${s}`;
      }
      if (seconds <= 0) {
        this.handleExpired();
      }
    };

    updateCountdown();
    clearInterval(this.countdownTimer);
    this.countdownTimer = setInterval(() => {
      seconds--;
      updateCountdown();
    }, 1000);
  },

  /**
   * Hides the warning (e.g., after user extends session).
   */
  hideWarning() {
    if (!this.warningEl) return;
    this.isWarning = false;
    this.warningEl.classList.remove('visible');
    clearInterval(this.countdownTimer);
  },

  /**
   * Extends the session by pinging the server immediately.
   */
  async extendSession() {
    this.hideWarning();
    await this.ping();
    VaultFX.toast('success', 'Session extended.');
  },

  /**
   * Called when session has expired — redirect to login.
   */
  handleExpired() {
    clearTimeout(this.pingTimer);
    clearInterval(this.countdownTimer);
    Credentials.hideAll(); // Clear any revealed passwords

    // Show expired message briefly before redirect
    if (this.warningEl) {
      this.warningEl.innerHTML = `
        <div class="session-warning-title">⚠ Session Expired</div>
        <div class="session-warning-msg">Your session has expired. Redirecting to login...</div>
      `;
      this.warningEl.classList.add('visible');
    }

    setTimeout(() => {
      window.location.href = '?page=login&reason=timeout';
    }, 2000);
  },

  /**
   * Creates the warning UI element if not in the page HTML.
   */
  createWarningUI() {
    this.warningEl = document.createElement('div');
    this.warningEl.className = 'session-warning';
    this.warningEl.id = 'session-warning';
    this.warningEl.innerHTML = `
      <div class="session-warning-title">⚠ Session Expiring Soon</div>
      <div class="session-warning-msg">Your session will expire due to inactivity in:</div>
      <div class="session-warning-time" id="session-countdown">05:00</div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary btn-sm" style="flex:1" onclick="SessionMonitor.extendSession()">Stay Logged In</button>
        <button class="btn btn-outline btn-sm" onclick="window.location.href='?page=logout'">Log Out</button>
      </div>
    `;
    document.body.appendChild(this.warningEl);
  },
};

document.addEventListener('DOMContentLoaded', () => SessionMonitor.init());
