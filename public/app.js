const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let entries = [];
let timerHandle = null;
let query = '';
let editingId = null;
let categoryFilterValue = '';
let draggedId = null;
let idleTimerHandle = null;

/* ---------- Theme ---------- */
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem('otp-theme', t);
}
(function initTheme() {
  const saved = localStorage.getItem('otp-theme');
  const prefers = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  applyTheme(saved || prefers);
})();
$('#themeBtn')?.addEventListener('click', () => {
  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});

/* ---------- Toast ---------- */
let toastTimer;
function toast(msg, type = '') {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show ' + type;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

/* ---------- TOTP ---------- */
function b32decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  str = str.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  let bits = '';
  for (const c of str) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error('invalid base32');
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  return bytes;
}
function algoName(a) {
  const m = { 'SHA-1': 'SHA-1', 'SHA1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA256': 'SHA-256', 'SHA-512': 'SHA-512', 'SHA512': 'SHA-512' };
  return m[a] || 'SHA-1';
}
async function totp(secret, period = 30, digits = 6, algo = 'SHA-1', ts = Date.now()) {
  const keyBytes = b32decode(secret);
  const counter = Math.floor(ts / 1000 / period);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  let c = counter;
  for (let i = 7; i >= 0; i--) { view.setUint8(i, c & 0xff); c = Math.floor(c / 256); }
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: algoName(algo) }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, buf);
  const bytes = new Uint8Array(sig);
  const offset = bytes[bytes.length - 1] & 0x0f;
  const code = ((bytes[offset] & 0x7f) << 24 | bytes[offset + 1] << 16 | bytes[offset + 2] << 8 | bytes[offset + 3]) % (10 ** digits);
  return code.toString().padStart(digits, '0');
}
function remaining(period) { return period - (Math.floor(Date.now() / 1000) % period); }

/* ---------- API ---------- */
async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  const ct = res.headers.get('content-type') || '';
  const data = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data?.error || res.statusText);
  return data;
}

function showView(name) {
  $('#loadingView').classList.add('hidden');
  $('#loginView').classList.toggle('hidden', name !== 'login');
  $('#dashView').classList.toggle('hidden', name !== 'dash');
}

/* ---------- Auth ---------- */
async function checkAuth() {
  try {
    const r = await api('/api/me');
    if (r.authenticated) { showView('dash'); await loadEntries(); startTimer(); }
    else showView('login');
  } catch { showView('login'); }
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#loginError').textContent = '';
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ password: $('#password').value }) });
    $('#password').value = '';
    showView('dash');
    await loadEntries();
    startTimer();
    toast('Berhasil masuk', 'success');
  } catch (err) {
    $('#loginError').textContent = err.message;
  }
});

$('#logoutBtn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' }).catch(() => {});
  stopTimer();
  showView('login');
  toast('Sesi diakhiri');
});

/* ---------- Entries ---------- */
async function loadEntries() {
  const r = await api('/api/entries');
  entries = r.entries || [];
  render();
}

function sortedEntries(list) {
  const pinned = list.filter(e => e.pinned);
  const rest = list.filter(e => !e.pinned);
  return [...pinned, ...rest];
}
function filtered() {
  let list = entries;
  if (query) {
    const q = query.toLowerCase();
    list = list.filter(e => (e.name || '').toLowerCase().includes(q) || (e.issuer || '').toLowerCase().includes(q) || (e.category || '').toLowerCase().includes(q));
  }
  if (categoryFilterValue) list = list.filter(e => (e.category || '') === categoryFilterValue);
  return sortedEntries(list);
}

function render() {
  const grid = $('#entries');
  grid.innerHTML = '';
  updateCategoryFilter();
  const list = filtered();
  $('#countPill').textContent = entries.length + ' akun';
  if (!entries.length) {
    $('#empty').classList.remove('hidden');
    grid.classList.add('hidden');
    return;
  }
  $('#empty').classList.add('hidden');
  grid.classList.remove('hidden');
  if (!list.length) {
    grid.innerHTML = '<p class="muted" style="grid-column:1/-1;text-align:center;padding:40px 0;">Tidak ada akun yang cocok.</p>';
    return;
  }
  for (const e of list) {
    const card = document.createElement('div');
    card.className = 'otp-card' + (e.pinned ? ' pinned' : '');
    card.dataset.id = e.id;
    card.draggable = (!query && !categoryFilterValue);
    card.innerHTML = `
      <div class="card-top">
        <div>
          <div class="issuer">${escapeHtml(e.issuer || 'Tanpa penerbit')}${e.category ? ' · <span class="tag">' + escapeHtml(e.category) + '</span>' : ''}</div>
          <div class="name">${escapeHtml(e.name || 'OTP')}</div>
        </div>
        <div style="display:flex;gap:4px;align-items:center">
          <button data-pin class="icon-btn" title="Pin/Favorit" aria-label="Pin">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="${e.pinned ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          </button>
          <button data-copy class="icon-btn copy-btn" title="Salin kode" aria-label="Salin kode">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </div>
      <div class="code" data-code title="Klik untuk menyalin">••••••</div>
      <div class="progress" data-progress><div data-bar style="width:0%"></div></div>
      <div class="otp-actions">
        <span class="drag-handle" title="Seret untuk ubah urutan">⋮⋮</span>
        <button data-edit class="btn-ghost">Edit</button>
        <button data-del class="btn-ghost">Hapus</button>
      </div>
    `;
    const copyCode = async () => {
      const code = card.querySelector('[data-code]').textContent.replace(/\s/g, '');
      try { await navigator.clipboard.writeText(code); toast('Kode disalin', 'success'); }
      catch { toast('Gagal menyalin', 'error'); }
    };
    card.querySelector('[data-copy]').addEventListener('click', copyCode);
    card.querySelector('[data-code]').addEventListener('click', copyCode);
    card.querySelector('[data-pin]').addEventListener('click', async () => {
      await api('/api/entries/' + encodeURIComponent(e.id), { method: 'PUT', body: JSON.stringify({ pinned: !e.pinned }) });
      await loadEntries();
    });
    card.querySelector('[data-edit]').addEventListener('click', () => openEditModal(e));
    card.querySelector('[data-del]').addEventListener('click', async () => {
      const ok = await confirmAction('Hapus akun ini? Tindakan tidak dapat dibatalkan.');
      if (!ok) return;
      await api('/api/entries/' + encodeURIComponent(e.id), { method: 'DELETE' });
      toast('Akun dihapus', 'success');
      await loadEntries();
    });
    // Drag and drop
    card.addEventListener('dragstart', (ev) => {
      draggedId = e.id;
      card.classList.add('dragging');
      try { ev.dataTransfer.effectAllowed = 'move'; } catch {}
    });
    card.addEventListener('dragover', (ev) => {
      if (!draggedId || draggedId === e.id) return;
      ev.preventDefault();
      card.classList.add('drag-over');
    });
    card.addEventListener('dragleave', () => card.classList.remove('drag-over'));
    card.addEventListener('drop', async (ev) => {
      ev.preventDefault();
      card.classList.remove('drag-over');
      if (!draggedId || draggedId === e.id) return;
      if (query || categoryFilterValue) return;
      const displayed = sortedEntries(entries);
      const from = displayed.findIndex(x => x.id === draggedId);
      const to = displayed.findIndex(x => x.id === e.id);
      if (from < 0 || to < 0) return;
      const arr = [...displayed];
      const [moved] = arr.splice(from, 1);
      arr.splice(to, 0, moved);
      entries = arr;
      render();
      try { await api('/api/reorder', { method: 'POST', body: JSON.stringify({ ids: entries.map(x => x.id) }) }); }
      catch (err) { toast(err.message, 'error'); await loadEntries(); }
    });
    card.addEventListener('dragend', () => {
      draggedId = null;
      grid.querySelectorAll('.otp-card').forEach(c => c.classList.remove('dragging', 'drag-over'));
    });

    grid.appendChild(card);
  }
  updateCodes();
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function updateCodes() {
  for (const e of entries) {
    const card = document.querySelector(`.otp-card[data-id="${CSS.escape(e.id)}"]`);
    if (!card) continue;
    const p = e.period || 30;
    try {
      const code = await totp(e.secret, p, e.digits || 6, e.algorithm || 'SHA-1');
      const codeEl = card.querySelector('[data-code]');
      codeEl.textContent = code.replace(/(.{3})/g, '$1 ').trim();
      codeEl.classList.add('fresh');
      setTimeout(() => codeEl.classList.remove('fresh'), 400);
    } catch {
      card.querySelector('[data-code]').textContent = 'ERROR';
    }
    const rem = remaining(p);
    const bar = card.querySelector('[data-bar]');
    const prog = card.querySelector('[data-progress]');
    bar.style.width = (rem / p * 100) + '%';
    prog.classList.toggle('warn', rem <= 5);
  }
}

function startTimer() { stopTimer(); timerHandle = setInterval(updateCodes, 1000); updateCodes(); }
function stopTimer() { if (timerHandle) { clearInterval(timerHandle); timerHandle = null; } }

/* ---------- Search ---------- */
$('#searchInput').addEventListener('input', (e) => { query = e.target.value; render(); });
function closeCatFilter() { $('#catFilter').classList.remove('open'); $('#categoryFilterMenu').classList.add('hidden'); }
function openCatFilter() { $('#catFilter').classList.add('open'); $('#categoryFilterMenu').classList.remove('hidden'); }
$('#categoryFilterBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  if ($('#categoryFilterMenu').classList.contains('hidden')) openCatFilter(); else closeCatFilter();
});
document.addEventListener('click', (e) => {
  if (!$('#catFilter').contains(e.target)) closeCatFilter();
});
function selectCategory(val) {
  categoryFilterValue = val;
  $('#categoryFilterLabel').textContent = val || 'Semua kategori';
  closeCatFilter();
  render();
}
function updateCategoryFilter() {
  const cats = [...new Set(entries.map(e => e.category).filter(Boolean))].sort();
  const menu = $('#categoryFilterMenu');
  const items = [''].concat(cats);
  menu.innerHTML = items.map(c => {
    const label = c || 'Semua kategori';
    const active = c === categoryFilterValue ? ' active' : '';
    return `<div class="cat-filter-item${active}" data-val="${escapeHtml(c)}">${escapeHtml(label)}</div>`;
  }).join('');
  menu.querySelectorAll('.cat-filter-item').forEach(el => {
    el.addEventListener('click', () => selectCategory(el.dataset.val));
  });
  $('#categoryFilterLabel').textContent = categoryFilterValue || 'Semua kategori';
}

/* ---------- Add modal ---------- */
function openModal(id) { $(id).classList.remove('hidden'); }
function closeModal(id) { $(id).classList.add('hidden'); }
function confirmAction(message) {
  return new Promise((resolve) => {
    $('#confirmMsg').textContent = message;
    openModal('#confirmModal');
    const okBtn = $('#confirmOk');
    const cancelEls = $$('[data-close-confirm]');
    const cleanup = () => {
      closeModal('#confirmModal');
      okBtn.removeEventListener('click', onOk);
      cancelEls.forEach(el => el.removeEventListener('click', onCancel));
    };
    const onOk = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    okBtn.addEventListener('click', onOk);
    cancelEls.forEach(el => el.addEventListener('click', onCancel));
  });
}
function resetAddModal() {
  editingId = null;
  $('#addModal h2').textContent = 'Tambah Akun OTP';
  const submitBtn = $('#addForm button[type="submit"]');
  if (submitBtn) submitBtn.textContent = 'Simpan Akun';
  $('#addForm').reset();
  $('#pinnedInput').checked = false;
}
$$('[data-close]').forEach(b => b.addEventListener('click', () => {
  closeModal('#addModal'); closeModal('#importModal');
  resetAddModal();
}));
$('#addBtn').addEventListener('click', () => { resetAddModal(); openModal('#addModal'); });
$('#emptyAdd').addEventListener('click', () => { resetAddModal(); openModal('#addModal'); });
function openEditModal(e) {
  editingId = e.id;
  $('#addModal h2').textContent = 'Edit Akun OTP';
  const submitBtn = $('#addForm button[type="submit"]');
  if (submitBtn) submitBtn.textContent = 'Simpan Perubahan';
  $('#otpauthInput').value = '';
  $('#nameInput').value = e.name || '';
  $('#issuerInput').value = e.issuer || '';
  $('#secretInput').value = e.secret || '';
  $('#algoInput').value = e.algorithm || 'SHA-1';
  $('#digitsInput').value = e.digits || 6;
  $('#periodInput').value = e.period || 30;
  $('#categoryInput').value = e.category || '';
  $('#pinnedInput').checked = !!e.pinned;
  openModal('#addModal');
}
$('#addCancel')?.addEventListener('click', () => closeModal('#addModal'));
$('#addForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const uri = $('#otpauthInput').value.trim();
  const payload = uri ? { uri, category: $('#categoryInput').value.trim(), pinned: $('#pinnedInput').checked } : {
    name: $('#nameInput').value.trim(),
    issuer: $('#issuerInput').value.trim(),
    secret: $('#secretInput').value.trim(),
    algorithm: $('#algoInput').value,
    digits: parseInt($('#digitsInput').value),
    period: parseInt($('#periodInput').value),
    category: $('#categoryInput').value.trim(),
    pinned: $('#pinnedInput').checked,
  };
  try {
    if (editingId) {
      await api('/api/entries/' + encodeURIComponent(editingId), { method: 'PUT', body: JSON.stringify(payload) });
      toast('Akun diperbarui', 'success');
    } else {
      await api('/api/entries', { method: 'POST', body: JSON.stringify(payload) });
      toast('Akun ditambahkan', 'success');
    }
    closeModal('#addModal');
    resetAddModal();
    await loadEntries();
  } catch (err) { toast(err.message, 'error'); }
});

/* ---------- Export ---------- */
$('#exportBtn').addEventListener('click', () => {
  if (!entries.length) { toast('Tidak ada akun untuk diexport', 'error'); return; }
  const lines = entries.map(e => {
    const issuer = e.issuer || '';
    const name = e.name || 'OTP';
    const label = issuer ? `${issuer}:${name}` : name;
    const algo = (e.algorithm || 'SHA-1').replace('-', '');
    const params = new URLSearchParams();
    params.set('secret', e.secret);
    if (issuer) params.set('issuer', issuer);
    params.set('algorithm', algo);
    params.set('digits', e.digits || 6);
    params.set('period', e.period || 30);
    return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
  });
  const blob = new Blob([lines.join('\\n') + '\\n'], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'otp-manager-export.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast(`Export ${entries.length} akun`, 'success');
});

/* ---------- Import modal ---------- */
$('#importBtn').addEventListener('click', () => openModal('#importModal'));
$('#emptyImport').addEventListener('click', () => openModal('#importModal'));
$('#importCancel')?.addEventListener('click', () => closeModal('#importModal'));
$('#importFile').addEventListener('change', async (ev) => {
  const f = ev.target.files[0];
  if (!f) return;
  $('#importText').value = await f.text();
  $('#importFileName').textContent = f.name;
});
$('#importDo').addEventListener('click', async () => {
  const text = $('#importText').value;
  $('#importStatus').textContent = 'Mengimport...';
  $('#importStatus').className = 'status';
  try {
    const r = await api('/api/import', { method: 'POST', body: JSON.stringify({ text }) });
    const parts = [];
    if (r.added) parts.push(`${r.added} baru`);
    if (r.updated) parts.push(`${r.updated} diperbarui`);
    if (r.skipped) parts.push(`${r.skipped} dilewati`);
    $('#importStatus').textContent = parts.length ? `Hasil: ${parts.join(', ')}.` : 'Tidak ada akun yang diimport.';
    $('#importStatus').className = 'status success';
    toast(parts.length ? `Import ${parts.join(', ')}` : 'Tidak ada akun baru', 'success');
    await loadEntries();
  } catch (err) {
    $('#importStatus').textContent = err.message;
    $('#importStatus').className = 'status error';
    toast(err.message, 'error');
  }
});

/* ---------- Lock ---------- */
function doLock() {
  api('/api/logout', { method: 'POST' }).catch(() => {});
  stopTimer();
  showView('login');
  toast('Aplikasi dikunci', 'success');
}
$('#lockBtn').addEventListener('click', doLock);
let lastActivity = Date.now();
['mousemove', 'keydown', 'click', 'touchstart', 'scroll'].forEach(ev => {
  window.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true });
});
setInterval(() => {
  if ($('#dashView').classList.contains('hidden')) return;
  if (Date.now() - lastActivity > 5 * 60 * 1000) doLock();
}, 30000);

checkAuth();