/**
 * VaultFX — Main Application JavaScript
 * ========================================
 * Handles: CSRF, AJAX, toast notifications, modals,
 * dark/light mode, tabs, and general UI utilities.
 *
 * NO credentials are ever cached or stored client-side.
 * CSRF token is read from meta tag and sent as custom header.
 */

'use strict';

// ── CSRF ─────────────────────────────────────────────────────
const VaultFX = {
  /**
   * Returns the current CSRF token from the meta tag.
   * The token is rotated by the server on each API call.
   */
  csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content ?? '';
  },

  /**
   * Updates the CSRF token (after server rotates it).
   */
  updateCsrfToken(newToken) {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && newToken) meta.content = newToken;

    // Also update all hidden CSRF form fields on the page
    document.querySelectorAll('input[name="csrf_token"]').forEach(el => {
      el.value = newToken;
    });
  },

  // ── Fetch/AJAX ──────────────────────────────────────────────

  /**
   * Sends an AJAX request with CSRF header and returns parsed JSON.
   *
   * @param  {string} url
   * @param  {Object} options  Fetch options (method, body, etc.)
   * @returns {Promise<Object>} Parsed response JSON
   */
  async fetch(url, options = {}) {
    const headers = {
      'X-Requested-With':  'XMLHttpRequest',
      'X-CSRF-Token':      this.csrfToken(),
      ...options.headers,
    };

    // Don't set Content-Type for FormData (browser sets it with boundary)
    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }

    try {
      const res  = await fetch(url, { ...options, headers });
      const json = await res.json();

      // Update CSRF token if server rotated it
      if (json._csrf) this.updateCsrfToken(json._csrf);

      return { ok: res.ok, status: res.status, data: json };
    } catch (err) {
      console.error('VaultFX fetch error:', err);
      return { ok: false, status: 0, data: { success: false, message: 'Network error.' } };
    }
  },

  /**
   * POST form data as FormData (includes CSRF).
   */
  async postForm(url, formData) {
    formData.set('csrf_token', this.csrfToken());
    return this.fetch(url, { method: 'POST', body: formData });
  },

  /**
   * POST JSON body.
   */
  async post(url, data = {}) {
    data.csrf_token = this.csrfToken();
    return this.fetch(url, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // ── Toasts ──────────────────────────────────────────────────

  toastContainer: null,

  initToasts() {
    this.toastContainer = document.getElementById('toast-container');
    if (!this.toastContainer) {
      this.toastContainer = document.createElement('div');
      this.toastContainer.id = 'toast-container';
      this.toastContainer.className = 'toast-container';
      document.body.appendChild(this.toastContainer);
    }
  },

  /**
   * Shows a toast notification.
   * @param {string} type    'success' | 'error' | 'warning' | 'info'
   * @param {string} message Text to display
   * @param {number} duration Ms before auto-dismiss (0 = no auto-dismiss)
   */
  toast(type = 'info', message = '', duration = 4000) {
    if (!this.toastContainer) this.initToasts();

    const icons = {
      success: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
      error:   `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`,
      warning: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
      info:    `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] ?? icons.info}</span>
      <span class="toast-message">${this.escapeHtml(message)}</span>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;padding:2px;margin-left:8px;flex-shrink:0;">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    `;

    this.toastContainer.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        toast.classList.add('hiding');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
        setTimeout(() => toast.remove(), 300); // Fallback
      }, duration);
    }
  },

  // ── Modals ──────────────────────────────────────────────────

  /**
   * Opens a modal by ID.
   */
  openModal(id) {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    // Close on overlay click
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) this.closeModal(id);
    }, { once: true });

    // Close on Escape
    const handler = (e) => {
      if (e.key === 'Escape') { this.closeModal(id); document.removeEventListener('keydown', handler); }
    };
    document.addEventListener('keydown', handler);
  },

  closeModal(id) {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.classList.remove('active');
    document.body.style.overflow = '';
  },

  /**
   * Shows a confirmation modal and resolves a promise when confirmed/cancelled.
   *
   * @param  {Object} opts  { title, message, confirmText, confirmClass, requireTyping }
   * @returns {Promise<boolean>}
   */
  confirm(opts = {}) {
    return new Promise((resolve) => {
      const {
        title         = 'Confirm Action',
        message       = 'Are you sure?',
        confirmText   = 'Confirm',
        confirmClass  = 'btn-danger',
        requireTyping = null,  // If set, user must type this string to confirm
      } = opts;

      // Remove any existing confirm modal
      document.getElementById('vfx-confirm-modal')?.remove();

      const modal = document.createElement('div');
      modal.id = 'vfx-confirm-modal';
      modal.className = 'modal-overlay active';
      modal.innerHTML = `
        <div class="modal" style="max-width:420px">
          <div class="modal-header">
            <h3 class="modal-title">${this.escapeHtml(title)}</h3>
            <button class="modal-close" id="vfx-confirm-cancel-x">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
          </div>
          <div class="modal-body">
            <p style="color:var(--text-secondary);font-size:0.9rem;line-height:1.6">${this.escapeHtml(message)}</p>
            ${requireTyping ? `
              <div class="form-group mt-4">
                <label class="form-label">Type <strong>${this.escapeHtml(requireTyping)}</strong> to confirm:</label>
                <input type="text" id="vfx-confirm-type-input" class="form-control" placeholder="${this.escapeHtml(requireTyping)}" autocomplete="off">
              </div>
            ` : ''}
          </div>
          <div class="modal-footer">
            <button class="btn btn-outline" id="vfx-confirm-cancel">Cancel</button>
            <button class="btn ${confirmClass}" id="vfx-confirm-ok" ${requireTyping ? 'disabled' : ''}>${this.escapeHtml(confirmText)}</button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);

      const cleanup = (result) => {
        modal.classList.remove('active');
        setTimeout(() => modal.remove(), 200);
        document.body.style.overflow = '';
        resolve(result);
      };

      modal.querySelector('#vfx-confirm-cancel').addEventListener('click', () => cleanup(false));
      modal.querySelector('#vfx-confirm-cancel-x').addEventListener('click', () => cleanup(false));
      modal.querySelector('#vfx-confirm-ok').addEventListener('click', () => cleanup(true));

      modal.addEventListener('click', (e) => { if (e.target === modal) cleanup(false); });

      // Typing confirmation
      if (requireTyping) {
        const input = modal.querySelector('#vfx-confirm-type-input');
        const btn   = modal.querySelector('#vfx-confirm-ok');
        input.addEventListener('input', () => {
          btn.disabled = input.value !== requireTyping;
        });
      }
    });
  },

  // ── Tabs ────────────────────────────────────────────────────

  initTabs(containerEl) {
    const tabs   = containerEl.querySelectorAll('.tab-btn');
    const panels = containerEl.querySelectorAll('.tab-panel');

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        tabs.forEach(t => t.classList.remove('active'));
        panels.forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        containerEl.querySelector(`#tab-${target}`)?.classList.add('active');
      });
    });
  },

  // ── Theme ────────────────────────────────────────────────────

  toggleTheme() {
    const current = document.documentElement.dataset.theme ?? 'dark';
    const next    = current === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;

    // Save preference to server
    const fd = new FormData();
    fd.set('theme', next);
    fd.set('csrf_token', this.csrfToken());
    fetch('api/users.php?action=set-theme', { method: 'POST', body: fd,
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRF-Token': this.csrfToken() }
    });
  },

  // ── HTML Escaping ────────────────────────────────────────────

  escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },

  // ── Skeleton Loading ─────────────────────────────────────────

  showSkeleton(container, count = 3) {
    container.innerHTML = Array.from({ length: count }, () => `
      <div style="display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)">
        <div class="skeleton" style="width:40px;height:40px;border-radius:8px;flex-shrink:0"></div>
        <div style="flex:1;display:flex;flex-direction:column;gap:8px;padding-top:4px">
          <div class="skeleton skeleton-text" style="width:60%"></div>
          <div class="skeleton skeleton-text sm" style="width:40%"></div>
        </div>
      </div>
    `).join('');
  },

  // ── Copy to clipboard ─────────────────────────────────────────

  async copyToClipboard(text, clearAfterMs = 30000) {
    try {
      await navigator.clipboard.writeText(text);
      this.toast('success', 'Copied to clipboard. Will clear in ' + (clearAfterMs / 1000) + 's.');

      if (clearAfterMs > 0) {
        setTimeout(async () => {
          try {
            // Only clear if clipboard still contains our text
            const current = await navigator.clipboard.readText();
            if (current === text) {
              await navigator.clipboard.writeText('');
            }
          } catch (e) {
            // Clipboard API may not allow reading — that's OK
          }
        }, clearAfterMs);
      }
    } catch (e) {
      this.toast('error', 'Clipboard access denied. Copy manually.');
    }
  },

  // ── Init ─────────────────────────────────────────────────────

  init() {
    this.initToasts();

    // Close modal buttons
    document.querySelectorAll('.modal-close, [data-dismiss="modal"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modal = btn.closest('.modal-overlay');
        if (modal) this.closeModal(modal.id);
      });
    });

    // Open modal buttons
    document.querySelectorAll('[data-modal]').forEach(btn => {
      btn.addEventListener('click', () => this.openModal(btn.dataset.modal));
    });

    // Initialize all tab containers
    document.querySelectorAll('[data-tabs]').forEach(el => this.initTabs(el));

    // Theme toggle button
    document.getElementById('theme-toggle')?.addEventListener('click', () => this.toggleTheme());

    // Flash messages from PHP
    const flash = document.getElementById('php-flash');
    if (flash) {
      this.toast(flash.dataset.type, flash.dataset.message);
      flash.remove();
    }

    // Handle accordion toggles
    document.querySelectorAll('.accordion-header').forEach(header => {
      header.addEventListener('click', () => {
        const item = header.closest('.accordion-item');
        item.classList.toggle('open');
      });
    });
  },
};

document.addEventListener('DOMContentLoaded', () => VaultFX.init());
