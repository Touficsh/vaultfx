/**
 * VaultFX — Global Search
 * ========================
 * Debounced search across servers, managers, and coverage accounts.
 * Results are scoped to user's access server-side.
 */

'use strict';

const Search = {
  input:       null,
  results:     null,
  debounceTimer: null,
  debounceMs:  300,
  minChars:    2,

  init() {
    this.input   = document.getElementById('global-search');
    this.results = document.getElementById('search-results');

    if (!this.input || !this.results) return;

    this.input.addEventListener('input', () => this.onInput());
    this.input.addEventListener('focus', () => {
      if (this.input.value.length >= this.minChars) {
        this.results.classList.add('visible');
      }
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.header-search')) {
        this.results.classList.remove('visible');
      }
    });

    // Keyboard navigation
    this.input.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.results.classList.remove('visible');
        this.input.blur();
      }
    });
  },

  onInput() {
    clearTimeout(this.debounceTimer);
    const q = this.input.value.trim();

    if (q.length < this.minChars) {
      this.results.classList.remove('visible');
      return;
    }

    // Show skeleton while fetching
    this.showSkeleton();

    this.debounceTimer = setTimeout(() => this.search(q), this.debounceMs);
  },

  async search(q) {
    try {
      const res  = await fetch(`api/search.php?q=${encodeURIComponent(q)}`, {
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'X-CSRF-Token':     VaultFX.csrfToken(),
        },
        cache: 'no-store',
      });

      const json = await res.json();

      if (!json.success) {
        this.showEmpty('Search failed.');
        return;
      }

      this.render(json.data.results, json.data.query);
    } catch (e) {
      this.showEmpty('Search unavailable.');
    }
  },

  render(results, query) {
    if (!results || results.length === 0) {
      this.showEmpty(`No results for "${VaultFX.escapeHtml(query)}".`);
      return;
    }

    this.results.innerHTML = results.map(r => `
      <a class="search-result-item" href="${VaultFX.escapeHtml(r.url)}">
        <span class="search-result-type ${r.type}">${this.typeLabel(r.type)}</span>
        <div class="search-result-info">
          <div class="search-result-label">${this.highlight(r.label, query)}</div>
          <div class="search-result-sub">${VaultFX.escapeHtml(r.sublabel ?? '')}
            ${r.login_number ? ` · <span class="font-mono">${VaultFX.escapeHtml(r.login_number)}</span>` : ''}
          </div>
        </div>
      </a>
    `).join('');

    this.results.classList.add('visible');
  },

  showSkeleton() {
    this.results.innerHTML = `
      <div style="padding:12px 14px;display:flex;flex-direction:column;gap:10px">
        ${Array(3).fill(`
          <div style="display:flex;gap:10px;align-items:center">
            <div class="skeleton" style="width:60px;height:20px;border-radius:4px"></div>
            <div style="flex:1;display:flex;flex-direction:column;gap:6px">
              <div class="skeleton skeleton-text" style="width:50%"></div>
              <div class="skeleton skeleton-text sm" style="width:35%"></div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
    this.results.classList.add('visible');
  },

  showEmpty(message) {
    this.results.innerHTML = `
      <div style="padding:20px;text-align:center;color:var(--text-muted);font-size:0.875rem">
        ${VaultFX.escapeHtml(message)}
      </div>
    `;
    this.results.classList.add('visible');
  },

  typeLabel(type) {
    return { server: 'Server', manager: 'Manager', coverage: 'Coverage' }[type] ?? type;
  },

  highlight(text, query) {
    const escaped    = VaultFX.escapeHtml(text);
    const escapedQ   = VaultFX.escapeHtml(query);
    const pattern    = new RegExp('(' + escapedQ.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
    return escaped.replace(pattern, '<mark style="background:var(--accent-soft);color:var(--accent);border-radius:2px;padding:0 1px">$1</mark>');
  },
};

document.addEventListener('DOMContentLoaded', () => Search.init());
