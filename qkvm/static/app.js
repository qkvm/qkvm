'use strict';

// --- small helpers -------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const prefs = {
  get(key, fallback) {
    try { return localStorage.getItem('qkvm.' + key) ?? fallback; } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem('qkvm.' + key, value); } catch { /* private mode */ }
  },
};

// h('button', { class: 'primary', onclick: fn }, 'Save') -> element. Text children are never parsed as HTML.
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === 'spellcheck') {
      // The one property whose "false" has to be said: left out, the browser checks spelling, and some
      // browsers send what is typed (commands, addresses, a revealed password) to a spelling service.
      el.setAttribute('spellcheck', String(Boolean(value)));
      continue;
    }
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (key in el) el[key] = value;
    else el.setAttribute(key, value === true ? '' : value);
  }
  el.append(...children.flat(Infinity).filter(child => child != null && child !== false));
  return el;
}

// Line icons on a 24x24 grid (Feather set). Each is a list of [shape, attributes].
const ICONS = {
  sun: [['circle', { cx: 12, cy: 12, r: 4 }],
    ['path', { d: 'M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41' }]],
  moon: [['path', { d: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z' }]],
  system: [['rect', { x: 2, y: 3, width: 20, height: 14, rx: 2 }], ['path', { d: 'M8 21h8M12 17v4' }]],
  eye: [['path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  eyeOff: [['path', { d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24' }],
    ['path', { d: 'M1 1l22 22' }]],
  check: [['path', { d: 'M20 6L9 17l-5-5' }]],
  grid: [['rect', { x: 3, y: 3, width: 7, height: 7, rx: 1 }], ['rect', { x: 14, y: 3, width: 7, height: 7, rx: 1 }],
    ['rect', { x: 3, y: 14, width: 7, height: 7, rx: 1 }], ['rect', { x: 14, y: 14, width: 7, height: 7, rx: 1 }]],
  power: [['path', { d: 'M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10' }]],
  shield: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }]],
  search: [['circle', { cx: 11, cy: 11, r: 8 }], ['path', { d: 'M21 21l-4.35-4.35' }]],
  plus: [['path', { d: 'M12 5v14M5 12h14' }]],
  x: [['path', { d: 'M18 6L6 18M6 6l12 12' }]],
  sliders: [['path', { d: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6' }]],
  maximize: [['path', { d: 'M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3' }]],
  minimize: [['path', { d: 'M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3' }]],
  external: [['path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3' }]],
  code: [['path', { d: 'M16 18l6-6-6-6M8 6l-6 6 6 6' }]],
  bell: [['path', { d: 'M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0' }]],
  tv: [['rect', { x: 2, y: 7, width: 20, height: 15, rx: 2 }], ['path', { d: 'M17 2l-5 5-5-5' }]],
  zap: [['path', { d: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z' }]],
  rotate: [['path', { d: 'M23 4v6h-6M20.49 15a9 9 0 1 1-2.12-9.36L23 10' }]],
  alert: [['path', { d: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01' }]],
  info: [['circle', { cx: 12, cy: 12, r: 10 }], ['path', { d: 'M12 16v-4M12 8h.01' }]],
  lock: [['rect', { x: 3, y: 11, width: 18, height: 11, rx: 2 }], ['path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }]],
  wifiOff: [['path', { d: 'M1 1l22 22M16.72 11.06A10.94 10.94 0 0 1 19 12.55M5 12.55a10.94 10.94 0 0 1 5.17-2.39M10.71 5.05A16 16 0 0 1 22.58 9M1.42 9a15.91 15.91 0 0 1 4.7-2.88M8.53 16.11a6 6 0 0 1 6.95 0M12 20h.01' }]],
  edit: [['path', { d: 'M12 20h9M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z' }]],
  activity: [['path', { d: 'M22 12h-4l-3 9L9 3l-3 9H2' }]],
  clock: [['circle', { cx: 12, cy: 12, r: 10 }], ['path', { d: 'M12 6v6l4 2' }]],
  logOut: [['path', { d: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9' }]],
  users: [['path', { d: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75' }],
    ['circle', { cx: 9, cy: 7, r: 4 }]],
  globe: [['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z' }]],
  list: [['path', { d: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01' }]],
  columns: [['path', { d: 'M12 3h7a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-7m0-18H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h7m0-18v18' }]],
  checkSquare: [['path', { d: 'M9 11l3 3L22 4M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11' }]],
  type: [['path', { d: 'M4 7V4h16v3M9 20h6M12 4v16' }]],
  command: [['path', { d: 'M18 3a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3 3 3 0 0 0 3-3 3 3 0 0 0-3-3H6a3 3 0 0 0-3 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3 3 3 0 0 0-3 3 3 3 0 0 0 3 3h12a3 3 0 0 0 3-3 3 3 0 0 0-3-3z' }]],
  coffee: [['path', { d: 'M18 8h1a4 4 0 0 1 0 8h-1M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8zM6 1v3M10 1v3M14 1v3' }]],
  enter: [['path', { d: 'M9 10l-5 5 5 5M20 4v7a4 4 0 0 1-4 4H4' }]],
  star: [['path', { d: 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z' }]],
  download: [['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3' }]],
  upload: [['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12' }]],
  archive: [['path', { d: 'M21 8v13H3V8M1 3h22v5H1zM10 12h4' }]],
  chevronLeft: [['path', { d: 'M15 18l-6-6 6-6' }]],
  chevronRight: [['path', { d: 'M9 18l6-6-6-6' }]],
  chevronDown: [['path', { d: 'M6 9l6 6 6-6' }]],
};
const SVG_NS = 'http://www.w3.org/2000/svg';

function icon(name, extraClass) {
  const el = document.createElementNS(SVG_NS, 'svg');
  const attrs = {
    viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2,
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true',
    class: extraClass ? `icon ${extraClass}` : 'icon',
  };
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  // A name that is not in the list draws nothing. It must not be what keeps a dialog from opening (a tab
  // without an icon once did: the whole of Settings); tests/test_page.py is what says a name is missing.
  for (const [tag, shapeAttrs] of ICONS[name] || []) {
    const shape = document.createElementNS(SVG_NS, tag);
    for (const [key, value] of Object.entries(shapeAttrs)) shape.setAttribute(key, value);
    el.append(shape);
  }
  return el;
}

function still() {
  return matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// A change of the page, shown as a movement. The movement is decoration: a change that comes while the one
// before is still on its way takes over from it (a key held down in the search box does, thirty times a
// second), and so does a window that goes out of sight. The browser says that by refusing the earlier
// one's `ready`, which is nobody's fault and is not reported as one. What `update` itself throws still is:
// the browser tells that through another promise, and that one is left alone.
function moving(update) {
  const movement = document.startViewTransition(update);
  movement.ready.catch(() => {});
  return movement;
}

// Runs `update` as one animated change. Each [element, name] pair in `named` glides from where
// it was to where it ends up; without browser support (or with motion turned off) it just runs.
function glide(update, named = []) {
  if (!document.startViewTransition || still() || document.hidden || named.length > 80) {
    update();
    return;
  }
  for (const [el, name] of named) el.style.viewTransitionName = name;
  const clear = () => { for (const [el] of named) el.style.viewTransitionName = ''; };
  moving(update).finished.then(clear, clear);
}

class ApiError extends Error {
  constructor(message, code, status, data = null) {
    super(message);
    this.code = code;
    this.status = status;
    this.data = data;  // what else the server said: which device this one is the same as, for instance
  }
}

// An action is over when the KVM says so, and typing a long text takes it more than a minute.
// Giving up on it sooner would invite a second click, and the text typed twice.
const ACTION_PATIENCE = 150000;  // ms

async function api(method, path, body, patience = 30000) {
  let res;
  try {
    res = await fetch(path, {
      method,
      cache: 'no-store',
      signal: AbortSignal.timeout(patience),
      // The server refuses any change that doesn't carry this header (cross-site pages can't send it).
      headers: { 'X-QKVM': '1', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (ex) {
    if (ex.name === 'TimeoutError') throw new ApiError('qKVM took too long to answer', 'timeout', 0);
    throw new ApiError('qKVM is not responding', 'network', 0);
  }
  let data = null;
  try { data = await res.json(); } catch { /* empty or not JSON */ }
  if (!res.ok) {
    if (res.status === 401 && data?.code === 'unauthorized') sessionExpired();
    if (res.status === 403 && data?.code === 'totp_required') mustEnroll();
    throw new ApiError(data?.message || `Request failed (HTTP ${res.status})`, data?.code || 'error', res.status, data);
  }
  return data;
}

const TOAST_ICONS = { ok: 'check', error: 'alert', info: 'info' };

function toast(message, kind = 'info') {
  const box = $('#toasts');
  // Modal dialogs sit above the page, so the toasts have to live inside the topmost one.
  const host = [...document.querySelectorAll('dialog[open]')].pop() || document.body;
  if (box.parentElement !== host) host.append(box);
  const el = h('div', { class: `toast ${kind}` }, icon(TOAST_ICONS[kind] || 'info'), h('span', {}, message));
  box.append(el);
  // Long enough to read: errors stay longer, and so does a longer sentence.
  const stay = Math.min(12000, Math.max(kind === 'error' ? 8000 : 4000, message.length * 70));
  setTimeout(() => {
    el.classList.add('leaving');  // plays the exit animation
    setTimeout(() => el.remove(), 300);
  }, stay);
}

// A notice that stays for as long as something is under way. Returns what takes it away again.
function working(message) {
  const box = $('#toasts');
  const host = [...document.querySelectorAll('dialog[open]')].pop() || document.body;
  if (box.parentElement !== host) host.append(box);
  const el = h('div', { class: 'toast working', role: 'status' }, h('span', { class: 'spinner' }), h('span', {}, message));
  box.append(el);
  return () => el.remove();
}

// size: '' (a form) or 'wide' (settings, the action menu).
let dialogsOpened = 0;

function openDialog(title, build, { size = '' } = {}) {
  const heading = h('h2', { id: `dialog-title-${++dialogsOpened}` }, title);
  const dialog = h('dialog', { class: size ? `dialog ${size}` : 'dialog', 'aria-labelledby': heading.id });
  const close = () => dialog.close();
  const body = h('div', { class: 'dialog-body' });
  dialog.append(
    h('header', { class: 'dialog-head' },
      heading,
      h('button', { type: 'button', class: 'icon-btn ghost', title: 'Close', 'aria-label': 'Close', onclick: close }, icon('x'))),
    body,
  );
  dialog.addEventListener('close', () => {
    const box = $('#toasts');
    if (dialog.contains(box)) document.body.append(box);
    setTimeout(() => dialog.remove(), 300);  // after it has faded out
  });
  document.body.append(dialog);
  // Opened before it is filled: only then can a builder put the focus on its first field.
  // (Opening by itself puts it on the Close button, where typing goes nowhere and Enter closes.)
  dialog.showModal();
  build(body, close);
  return dialog;
}

function confirmBox({ title, message, action, danger = true }) {
  return new Promise(resolve => {
    let answer = false;
    const dialog = openDialog(title, (body, close) => {
      body.append(
        h('p', {}, message),
        h('div', { class: 'actions' },
          h('button', { type: 'button', onclick: close }, 'Cancel'),
          h('button', {
            type: 'button',
            class: danger ? 'danger' : 'primary',
            onclick: () => { answer = true; close(); },
          }, action)),
      );
    });
    dialog.addEventListener('close', () => resolve(answer));
  });
}

function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', {}, label), input, hint && h('small', {}, hint));
}

function check(input, label, hint) {
  return h('label', { class: 'check' }, input, h('span', {}, label), hint && h('small', {}, hint));
}

// What a section of Settings is made of: one shape for all of them.
// Its first line says what it is and has, at its right, what one does in the section as a whole (add, save,
// export): `does`, which every section is handed. Under it come blocks, each a small heading and a frame of
// lines. Every line reads the same way: what it is at the left, with a sentence under it where one is
// needed; what one does about it at the right. A `field` and a `check` put into a block are such lines; a
// `setting` is one whose right-hand side is a button, or just what is so. A list is framed the same way. What
// explains stands before the first block (class "intro") or after the last ("footnote"), never under a button.
function block(title, ...lines) {
  return h('section', { class: 'block' }, title && h('h3', {}, title), h('div', { class: 'lines' }, lines));
}

function setting(label, hint, ...does) {
  return h('div', { class: 'setting' },
    h('div', { class: 'what' }, h('strong', {}, label), hint && h('small', {}, hint)),
    h('div', { class: 'does' }, does));
}

// A list in the same frame: its table, or one line that says there is nothing in it yet.
function listed(table, nothing) {
  return h('section', { class: 'block' }, h('div', { class: 'lines' }, table || h('p', { class: 'nothing' }, nothing)));
}

// A section whose lines are saved together has its Save in its first line, like every section's main button:
// outside the form it sends, and tied to it by the form's id.
function saves(form, label = 'Save') {
  const button = h('button', { type: 'submit', class: 'primary' }, label);
  button.setAttribute('form', form.id);
  return button;
}

// Shows a spinner on a button while its work runs, and stops a double click from sending things twice.
async function busy(button, work) {
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try {
    return await work();
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

// "3 min ago" for a number of seconds.
function ago(seconds) {
  if (seconds < 10) return 'just now';
  if (seconds < 90) return `${Math.round(seconds)} s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 129600) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

// A password box with a show/hide button. Returns { el, input }.
function passwordField(label, props, hint) {
  const input = h('input', { type: 'password', spellcheck: false, ...props });
  const toggle = h('button', { type: 'button', class: 'reveal' }, icon('eye', 'i-show'), icon('eyeOff', 'i-hide'));
  const reveal = show => {
    input.type = show ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(show));
    toggle.title = show ? 'Hide password' : 'Show password';
    toggle.setAttribute('aria-label', toggle.title);
  };
  reveal(false);
  toggle.addEventListener('click', () => {
    reveal(input.type === 'password');
    input.focus();
  });
  input.addEventListener('conceal', () => reveal(false));
  const el = h('label', { class: 'field' },
    h('span', {}, label),
    h('span', { class: 'password-box' }, input, toggle),
    hint && h('small', {}, hint));
  return { el, input };
}

// A shown password is an ordinary text box, and browsers remember what was typed into those.
// Turn every one back into a password box before its form is submitted.
document.addEventListener('submit', event => {
  for (const input of event.target.querySelectorAll('.password-box input')) input.dispatchEvent(new Event('conceal'));
}, true);

// Live feedback while choosing a password: a strength bar, and the rules ticked off as they are met.
function passwordCoach(password, again) {
  const bar = h('div', { class: 'strength', role: 'img' }, h('i'), h('i'), h('i'), h('i'));
  const word = h('span', { class: 'strength-label' });
  const rule = () => h('li', {}, icon('check'), h('span', {}));
  const [length, variety, match] = [rule(), rule(), rule()];
  $('span', variety).textContent = 'Hard to guess: 16+ characters, or letters mixed with numbers and symbols';
  $('span', match).textContent = 'Both entries match';
  const state = { longEnough: false, matches: false };

  const update = () => {
    const value = password.value;
    const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(kind => kind.test(value)).length;
    state.longEnough = value.length >= minPassword;
    state.matches = value.length > 0 && value === again.value;
    const varied = state.longEnough && (value.length >= 16 || kinds >= 3);
    const repetitive = new Set(value).size < 5;

    let score = 0;
    if (value) score = 1;
    if (state.longEnough && !repetitive) {
      score = 2 + (value.length >= 14 || kinds >= 3) + (value.length >= 18 || (value.length >= 14 && kinds >= 3));
    }
    const words = ['', state.longEnough ? 'Weak' : 'Too short', 'Fair', 'Good', 'Strong'];
    bar.dataset.score = score;
    bar.setAttribute('aria-label', `Password strength: ${words[score] || 'not entered'}`);
    word.textContent = words[score];

    const short = value && !state.longEnough ? ` (${value.length} of ${minPassword})` : '';
    $('span', length).textContent = `At least ${minPassword} characters${short}`;
    length.classList.toggle('met', state.longEnough);
    variety.classList.toggle('met', varied);
    match.classList.toggle('met', state.matches);
  };
  password.addEventListener('input', update);
  again.addEventListener('input', update);
  update();

  return {
    meter: h('div', { class: 'strength-row' }, bar, word),
    rules: h('ul', { class: 'rules' }, length, variety, match),
    // What still stands in the way of submitting, if anything.
    problem: () => {
      if (!state.longEnough) return `Use at least ${minPassword} characters.`;
      if (!state.matches) return 'The two passwords are not the same.';
      return null;
    },
  };
}

// Problems nothing else caught: keep a trace, and say so instead of failing silently.
let pageErrors = 0;
function reportPageError(error) {
  const text = String(error?.message || error);
  if (text.includes('ResizeObserver')) return;  // a harmless browser notice, not a fault
  console.error(error);
  pageErrors += 1;
  if (pageErrors <= 2) toast('Something went wrong on this page. Reload it if anything looks stuck.', 'error');
}
window.addEventListener('error', event => reportPageError(event.error || event.message));
window.addEventListener('unhandledrejection', event => reportPageError(event.reason));

// --- theme ------------------------------------------------------------------------

const THEMES = { auto: 'System theme', light: 'Light theme', dark: 'Dark theme' };

function themeFor(pref) {
  const dark = pref === 'dark' || (pref !== 'light' && !matchMedia('(prefers-color-scheme: light)').matches);
  return dark ? 'dark' : 'light';
}

function nextTheme(pref) {
  const order = Object.keys(THEMES);
  return order[(order.indexOf(pref) + 1) % order.length];
}

function applyTheme() {
  const saved = prefs.get('theme', 'auto');
  const pref = saved in THEMES ? saved : 'auto';
  const root = document.documentElement;
  root.dataset.theme = themeFor(pref);
  root.dataset.themePref = pref;  // picks which icon the toggle shows
  const label = `${THEMES[pref]} (click for ${THEMES[nextTheme(pref)].toLowerCase()})`;
  for (const button of document.querySelectorAll('.theme-toggle')) {
    button.title = label;
    button.setAttribute('aria-label', label);
  }
}

function cycleTheme(event) {
  const saved = prefs.get('theme', 'auto');
  const pref = nextTheme(saved in THEMES ? saved : 'auto');
  prefs.set('theme', pref);
  if (themeFor(pref) === document.documentElement.dataset.theme || !document.startViewTransition || still()) {
    applyTheme();
    return;
  }
  // The new colours spread across the page from the button that was pressed.
  const box = event.currentTarget.getBoundingClientRect();
  const x = box.left + box.width / 2;
  const y = box.top + box.height / 2;
  const radius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
  document.startViewTransition(applyTheme).ready.then(() => {
    document.documentElement.animate(
      { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] },
      { duration: 500, easing: 'ease-in-out', pseudoElement: '::view-transition-new(root)' },
    );
  }).catch(applyTheme);
}

// Turns `button` (or a new one) into the sun / moon / screen toggle.
function themeButton(button = h('button', { type: 'button' })) {
  button.classList.add('theme-toggle');
  button.replaceChildren(icon('sun', 'i-light'), icon('moon', 'i-dark'), icon('system', 'i-auto'));
  button.addEventListener('click', cycleTheme);
  return button;
}

// --- setup and sign-in ----------------------------------------------------------------

let minPassword = 10;

// --- the signed-in account --------------------------------------------------------------------------

const RANK = { viewer: 0, operator: 1, admin: 2 };
const ROLE_NAMES = { admin: 'Admin', operator: 'Operator', viewer: 'Viewer' };
const ROLE_HINTS = {
  admin: 'Everything, including settings, KVMs and accounts.',
  operator: 'Sees the wall and runs actions on the machines: keys, text, power, reboot.',
  viewer: 'Sees the wall. Cannot do anything to a machine.',
};
let me = null;        // { id, name, role } of the account signed in here
let ssoOn = false;    // an identity proxy in front of qKVM signs people in: accounts need no password here
let askName = false;  // there are several accounts, so signing in asks which one
let hasRecovery = false;  // a recovery key exists, so a forgotten password can be replaced from the sign-in page

// Is this account at least a `role`? The page only hides what is not allowed; the server is what refuses it.
function can(role) {
  return me != null && RANK[me.role] >= RANK[role];
}

function setMe(user) {
  me = user || null;
  document.documentElement.dataset.role = me ? me.role : '';
  $('#me-toggle').title = me ? `Your account (${me.name})` : 'Your account';
  $('#me-name').textContent = me?.name || '';
  $('#me-role').textContent = me ? (me.token ? 'A screen on the wall' : ROLE_NAMES[me.role]) : '';
  // Signed in by the identity proxy, there is nothing to sign out of here: the next look would sign in again.
  $('#sign-out').hidden = Boolean(me?.sso);
  $('#my-security').hidden = Boolean(me?.token);  // a screen has no password of its own
}

const HERO = {
  welcome: ['Welcome to qKVM.', 'Every KVM on one screen, on your own network. Setting up takes about a minute.'],
  back: ['Welcome back.', 'Sign in to see your KVMs.'],
  plain: ['qKVM', 'Every KVM on one screen, on your own network.'],
};

function hero(kind) {
  const [title, lead] = HERO[kind];
  const feature = (name, heading, text) => h('li', {}, icon(name), h('strong', {}, heading), h('span', {}, text));
  return [
    h('div', { class: 'brand' }, h('img', { src: 'static/favicon.svg', alt: '' }),
      h('span', { class: 'wordmark' }, h('b', {}, 'q'), 'KVM')),
    h('h1', {}, title),
    h('p', { class: 'lead' }, lead),
    // A little wall of screens coming to life; decoration only.
    h('div', { class: 'hero-wall', 'aria-hidden': 'true' }, [1, 2, 3, 4, 5, 6].map(() => h('span', {}, h('i')))),
    kind === 'welcome' && h('ul', { class: 'features' },
      feature('grid', 'See every screen at once', 'Live thumbnails and status for all your KVMs.'),
      feature('power', 'Act from the wall', 'Reboot, power buttons, Ctrl+Alt+Del, Wake-on-LAN.'),
      feature('shield', 'Private by design', 'No cloud. Passwords stay encrypted on this computer.')),
  ].filter(Boolean);
}

// kind picks the greeting next to the form: 'welcome' (first run), 'back' (sign-in) or 'plain'.
function showAuth(kind, ...content) {
  stopWall();
  const auth = $('#auth');
  $('#shell').hidden = true;
  auth.hidden = false;
  if (auth.dataset.kind !== kind) {
    // Only when it changes, so the artwork doesn't restart between wizard steps.
    auth.dataset.kind = kind;
    $('#auth-hero').replaceChildren(...hero(kind));
  }
  $('#auth-card').replaceChildren(themeButton(), ...content.flat().filter(Boolean));
  applyTheme();
}

function steps(current) {
  const names = ['Password', 'Recovery key', 'Network', 'KVMs'];
  return h('ol', { class: 'steps' }, names.map((name, i) =>
    h('li', { 'aria-current': i === current ? 'step' : null }, `${i + 1}. ${name}`)));
}

function showLogin(notice) {
  const name = h('input', { type: 'text', autocomplete: 'username', maxLength: 64, spellcheck: false, autocapitalize: 'none' });
  const nameBox = field('User name', name);
  const { el: passwordBox, input: password } = passwordField('Password', { autocomplete: 'current-password', required: true });
  // Asked for only once the password was right, and only for accounts with two-factor sign-in.
  const code = codeInput();
  // The phone is lost, broken or at home: one of the codes handed out when the second step was set up.
  const noPhone = h('button', {
    type: 'button', class: 'link',
    onclick: () => {
      Object.assign(code, { inputMode: 'text', maxLength: 24, placeholder: 'abcde-12345', value: '' });
      $('span', codeBox).textContent = 'One-time code';
      noPhone.hidden = true;
      code.focus();
    },
  }, 'No phone at hand? Use a one-time code');
  const codeBox = field('Code from your authenticator app', code);
  codeBox.append(noPhone);
  codeBox.hidden = true;
  const remember = h('input', { type: 'checkbox' });
  const error = h('p', { class: 'error', hidden: true });
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Sign in');
  // With a single account its password is all that is asked.
  const askFor = wanted => {
    askName = wanted;
    nameBox.hidden = !wanted;
    name.required = wanted;
  };
  const form = h('form', {
    onsubmit: event => {
      event.preventDefault();
      error.hidden = true;
      busy(submit, async () => {
        try {
          const reply = await api('POST', 'api/v1/login', {
            name: askName ? name.value : '', password: password.value, remember: remember.checked,
            code: codeBox.hidden ? '' : code.value,
          });
          setMe(reply.user);
        } catch (ex) {
          if (ex.code === 'name_required') {  // an account was added since this page was loaded
            askFor(true);
            name.focus();
            return;
          }
          if (ex.code === 'code_required') {
            codeBox.hidden = false;
            code.required = true;
            code.focus();
            return;
          }
          error.textContent = ex.message;
          error.hidden = false;
          (ex.code === 'bad_code' ? code : password).select();
          return;
        }
        startWall();
      });
    },
  },
    h('h2', {}, 'Sign in'),
    notice && h('p', { class: 'muted' }, notice),
    nameBox,
    passwordBox,
    codeBox,
    check(remember, 'Keep this browser signed in for 30 days', 'For a display that should stay on the wall.'),
    error,
    h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'link left', onclick: forgotDialog }, 'Forgot your password?'),
      submit),
  );
  askFor(askName);
  showAuth('back', form);
  (askName ? name : password).focus();
}

function showSetup(session) {
  const first = passwordField('Password', { autocomplete: 'new-password', required: true });
  const second = passwordField('Repeat password', { autocomplete: 'new-password', required: true });
  const [password, again] = [first.input, second.input];
  const coach = passwordCoach(password, again);
  const code = h('input', { type: 'text', autocomplete: 'off', inputMode: 'numeric', required: true });
  const error = h('p', { class: 'error', hidden: true });
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Continue');
  const form = h('form', {
    onsubmit: event => {
      event.preventDefault();
      error.hidden = true;
      const problem = coach.problem();
      if (problem) {
        error.textContent = problem;
        error.hidden = false;
        return;
      }
      busy(submit, async () => {
        let made;
        try {
          made = await api('POST', 'api/v1/setup', { password: password.value, setup_code: code.value });
        } catch (ex) {
          error.textContent = ex.message;
          error.hidden = false;
          return;
        }
        setMe(made.user);
        hasRecovery = Boolean(made.recovery_key);
        if (made.recovery_key) showRecoveryKey(made.recovery_key);
        else setupNetwork();
      });
    },
  },
    steps(0),
    h('h2', {}, 'Create your password'),
    h('p', { class: 'muted' },
      'This is the password of the first account, “admin”. It protects qKVM and encrypts the KVM passwords ',
      'saved on this computer. qKVM does not store it: the recovery key you get next is the only way around a ',
      'forgotten password. More accounts can be added later.'),
    h('input', { type: 'text', autocomplete: 'username', value: 'admin', hidden: true }),
    first.el,
    coach.meter,
    second.el,
    coach.rules,
    session.setup_code_required && field('Setup code', code,
      'This qKVM was started with --setup-code. The code is where it runs: in its terminal, or in its log (journalctl -u qkvm for a service, docker logs qkvm for a container). It proves this copy is yours.'),
    error,
    h('div', { class: 'actions' }, submit),
  );
  showAuth('welcome', form);
  password.focus();
}

// The second step of the first run: the key is shown this once, so make sure it gets kept.
function showRecoveryKey(key) {
  const kept = h('input', { type: 'checkbox' });
  const next = h('button', { type: 'button', class: 'primary', disabled: true, onclick: setupNetwork }, 'Continue');
  kept.addEventListener('change', () => { next.disabled = !kept.checked; });
  showAuth('welcome',
    steps(1),
    h('h2', {}, 'Keep your recovery key'),
    recoveryKeyView(key),
    check(kept, 'I have saved the recovery key'),
    h('div', { class: 'actions' }, next));
}

async function setupNetwork() {
  let settings;
  try {
    settings = await api('GET', 'api/v1/settings');
  } catch (ex) {
    showAuth('welcome', h('p', { class: 'error' }, ex.message));
    return;
  }
  const network = networkForm(settings, false);
  showAuth(
    'welcome',
    steps(2),
    h('h2', {}, 'Where should qKVM be reachable?'),
    settings.overridden && h('div', { class: 'note warn' },
      'qKVM was started with --bind or --port (in a container it always is). Those decide where it listens, ',
      'whatever is chosen here.'),
    network.el,
    h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'primary', onclick: () => setupDevices(settings, network.read()) }, 'Continue')),
  );
}

function setupDevices(settings, wanted) {
  const finish = h('button', { type: 'button', class: 'primary' }, 'Finish');
  finish.addEventListener('click', () => busy(finish, async () => {
    if ($('#auth-card textarea')?.value.trim() && !(await confirmBox({
      title: 'Finish without adding them?',
      message: 'The addresses in the list have not been added yet. “Check and add” adds them; or finish now and add them later from the wall.',
      action: 'Finish anyway',
      danger: false,
    }))) return;
    const changed = ['bind', 'port', 'https'].some(key => String(wanted[key]) !== String(settings[key]));
    try {
      if (changed && await applyNetwork(wanted)) return;
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    startWall();
  }));
  showAuth(
    'welcome',
    steps(3),
    h('h2', {}, 'Add your KVMs'),
    addDevicesForm(() => {}),
    h('div', { class: 'actions' }, finish),
  );
}

// --- network settings (setup wizard and Settings) ------------------------------------------

function networkForm(settings, advanced) {
  const { tailscale, lan } = settings.addresses;
  const has = name => settings.bind.includes(name);
  const local = h('input', { type: 'checkbox', checked: true, disabled: true });
  const ts = h('input', { type: 'checkbox', checked: has('tailscale') });
  const lanBox = h('input', { type: 'checkbox', checked: has('lan') });
  // Said when qKVM was started (--https, or a certificate of its owner's): not something to switch off from here.
  const https = h('input', { type: 'checkbox', checked: settings.https, disabled: settings.https_forced });
  const port = h('input', { type: 'number', min: 1, max: 65535, value: settings.port, required: true });
  const interval = h('input', { type: 'number', min: 0.2, max: 60, step: 0.1, value: settings.interval, required: true });
  // Anything set by hand in the data file ("all", explicit addresses) is kept as it is.
  const other = settings.bind.filter(name => !['local', 'tailscale', 'lan'].includes(name));
  lanBox.addEventListener('change', () => { if (lanBox.checked) https.checked = true; });

  // Its lines, for whoever lays them out: the first run stacks them (`el`), Settings puts them into cards.
  const listen = [
    check(local, 'This computer', 'http://127.0.0.1 — always on, so you can never lock yourself out.'),
    check(ts, tailscale ? `Tailscale — ${tailscale}` : 'Tailscale — not connected on this computer',
      tailscale ? 'Reachable from your other Tailscale devices; Tailscale encrypts the traffic.'
        : 'qKVM starts listening there as soon as Tailscale connects.'),
    check(lanBox, lan ? `Local network — ${lan}` : 'Local network',
      'Anyone on your network can reach the sign-in page.'),
  ];
  const secure = check(https, 'Encrypt connections (HTTPS)', settings.https_forced
    ? 'On because qKVM was started that way. It cannot be switched off from here.'
    : 'Uses a certificate made on this computer; your browser asks you to accept it once. '
      + 'Recommended whenever the local network is enabled.');
  const more = advanced ? [
    field('Port', port, 'The number after the colon in the wall’s address.'),
    field('Tile refresh (seconds)', interval,
      'What a browser starts with. One where a rate was picked in the top bar keeps its own.'),
  ] : [];
  return {
    listen,
    secure,
    more,
    other,
    get el() {
      return h('div', {}, listen, other.length > 0 && h('p', { class: 'muted' }, `Also listening on: ${other.join(', ')}`), secure);
    },
    read: () => ({
      bind: ['local', ...(ts.checked ? ['tailscale'] : []), ...(lanBox.checked ? ['lan'] : []), ...other],
      port: Number(port.value),
      https: https.checked,
      interval: Number(interval.value),
    }),
  };
}

// Saves network settings. Returns true when the page is being taken over by the "restarting" notice.
async function applyNetwork(values) {
  const result = await api('PUT', 'api/v1/settings', values);
  if (!result.restart) return false;
  // The server says where it will be; a --port given on its command line outranks the saved one.
  const { protocol: scheme, port } = new URL(result.urls[0]);
  const here = `${scheme}//${location.hostname}:${port}/`;
  const stillServed = result.urls.includes(here) || location.hostname === 'localhost';
  // Same host and scheme: the session cookie still applies, so the page can simply follow.
  const sameSite = stillServed && scheme === location.protocol;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  showAuth(
    'plain',
    h('h2', {}, 'Network settings saved'),
    h('p', {}, 'qKVM is restarting its listeners. It is now reachable at:'),
    h('ul', {}, result.urls.map(url => h('li', {}, h('a', { href: url }, url)))),
    scheme === 'https:' && location.protocol !== 'https:' && h('div', { class: 'note warn' },
      'Your browser will warn that the certificate is self-signed. Before accepting, check that it shows this SHA-256 fingerprint:',
      h('code', { class: 'fingerprint' }, result.cert_fingerprint || '')),
    !sameSite && h('p', { class: 'muted' }, 'You will need to sign in again at the new address.'),
  );
  if (sameSite && here === `${location.origin}/`) {
    // Same address: follow along as soon as the new listeners answer.
    await sleep(1000);
    for (let attempt = 0; attempt < 40; attempt++) {
      try {
        await api('GET', 'api/v1/session');
        break;
      } catch {
        await sleep(500);
      }
    }
    location.reload();
  } else if (sameSite) {
    // Another port: the page is not allowed to probe it, so give the restart time to finish.
    await sleep(5000);
    location.assign(here);
  }
  return true;
}

// --- adding and editing devices ---------------------------------------------------------------

function addDevicesForm(onAdded) {
  const addresses = h('textarea', { rows: 4, required: true, spellcheck: false, placeholder: '192.168.1.20\n192.168.1.21' });
  const username = h('input', { type: 'text', value: 'admin', autocomplete: 'off', required: true });
  // new-password: stops the browser from filling in the wall's own password here.
  const { el: passwordBox, input: password } = passwordField('Password', { autocomplete: 'new-password' },
    'Leave empty only for a JetKVM that has no password.');
  const groupName = groupInput('');
  const results = h('ul', { class: 'results' });
  const submit = h('button', { type: 'submit', class: 'primary' }, 'Check and add');

  // Looking for KVMs on this computer's own network and among its Tailscale peers.
  const found = h('div', { class: 'found', hidden: true });
  const find = h('button', { type: 'button' }, icon('search'), 'Find KVMs on my network');
  find.addEventListener('click', () => busy(find, async () => {
    let result;
    try {
      result = await api('POST', 'api/v1/discover');
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    const fresh = result.found.filter(entry => !entry.known);
    // On the wall, and not where the wall has it any more: found by its certificate at another address.
    const moved = result.found.filter(entry => entry.moved_from).map(entry => {
      const row = h('li', {}, h('span', {},
        `${entry.known_as} is on the wall at ${entry.moved_from}, where it no longer answers. It answers at ${entry.address}.`));
      row.append(h('button', { type: 'button', onclick: () => relocate(entry, row) }, 'Use this address'));
      return row;
    });
    const picks = fresh.map(entry => {
      const box = h('input', { type: 'checkbox', checked: true });
      const row = check(box, entry.name ? `${entry.address} · ${entry.name}` : entry.address, KINDS[entry.kind]);
      // One KVM that answered at two addresses (on the network, and over the VPN) is one line, with a
      // choice of which address the wall is to use for it. The nearer one comes first.
      const others = entry.also || [];
      const where = others.length > 0 && h('select', { 'aria-label': `Address to use for ${entry.address}` },
        [entry, ...others].map(one => h('option', { value: one.url }, one.address)));
      return { entry, box, where, row: where ? h('div', { class: 'pick-twice' }, row, h('span', { class: 'muted' }, 'use'), where) : row };
    });
    const twice = picks.some(pick => pick.where);
    const use = h('button', { type: 'button', class: 'primary' }, 'Put the ticked ones in the list');
    use.addEventListener('click', () => {
      const list = new Set(addresses.value.split(/[\s,;]+/).filter(Boolean));
      for (const pick of picks) if (pick.box.checked) list.add(pick.where ? pick.where.value : pick.entry.url);
      addresses.value = [...list].join('\n');
      found.hidden = true;
      password.focus();
    });
    const where = result.networks.join(' and ') || 'no network';
    const already = result.found.length - fresh.length - moved.length;
    found.replaceChildren(
      h('p', { class: 'muted' }, `Asked ${result.scanned} addresses on ${where}. `,
        fresh.length ? `${fresh.length} KVM${fresh.length === 1 ? '' : 's'} not on the wall yet:` : 'No KVM was found that is not on the wall already.',
        already ? ` (${already} already on the wall.)` : ''),
      fresh.length > 0 && h('div', { class: 'picklist' }, picks.map(pick => pick.row)),
      moved.length > 0 && h('ul', { class: 'results' }, moved),
      twice && h('p', { class: 'muted' }, 'A KVM that answered at two addresses, on your network and on Tailscale, is listed once. Choose which address the wall uses for it.'),
      result.container && h('p', { class: 'muted' },
        'qKVM runs in a container, and what it can look through is the network the container is on, which is usually not yours. ',
        'Type the addresses above instead, or start the container on the network of its host (--network host, on Linux).'),
      fresh.length > 0 && h('div', { class: 'actions' }, use));
    found.hidden = false;
  }));

  // A KVM the search found somewhere else than the wall has it: its tile is given the new address, and
  // nothing else about it changes. The password saved for it is used; none is typed.
  async function relocate(entry, row) {
    const text = $('span', row);
    for (const button of row.querySelectorAll('button')) button.remove();
    text.textContent = `${entry.known_as}: checking ${entry.address}…`;
    try {
      const there = tiles.get(entry.known_id)?.device || (await api('GET', 'api/v1/wall')).devices.find(device => device.id === entry.known_id);
      if (!there) throw new ApiError(`${entry.known_as} is no longer on the wall`, 'not_found', 404);
      await api('PUT', `api/v1/devices/${there.id}`, {
        name: there.name, url: entry.url, username: there.username || 'admin', password: '',
        open_url: there.custom_open_url || '', tls: there.tls, group: there.group || '',
      });
      row.className = 'ok';
      text.textContent = `${entry.known_as} now uses ${entry.address}`;
      onAdded();
    } catch (ex) {
      row.className = 'bad';
      text.textContent = `${entry.known_as}: ${ex.message}`;
      row.append(h('button', { type: 'button', onclick: () => relocate(entry, row) }, 'Try again'));
    }
  }

  // "Use this address instead": the tile that is there already is given the address just typed.
  async function moveTo(twin, url, row) {
    const text = $('span', row);
    for (const button of row.querySelectorAll('button')) button.remove();
    text.textContent = `${url} — checking…`;
    try {
      // What is saved for that tile now, so that only its address changes. Asked for where no wall is drawn
      // (the first-run steps): guessing "none" there would take its group and its console link away.
      const there = tiles.get(twin.id)?.device || (await api('GET', 'api/v1/wall')).devices.find(device => device.id === twin.id);
      if (!there) throw new ApiError(`${twin.name} is no longer on the wall`, 'not_found', 404);
      await api('PUT', `api/v1/devices/${twin.id}`, {
        url, username: username.value, password: password.value,
        group: there.group || '', open_url: there.custom_open_url || '',
      });
      row.className = 'ok';
      text.textContent = `${twin.name} now uses ${url}`;
      onAdded();
    } catch (ex) {
      row.className = 'bad';
      text.textContent = `${url} — ${ex.message}`;
    }
  }

  async function add(url, row, force, keepBoth = false) {
    const text = $('span', row);
    row.className = '';
    text.textContent = `${url} — checking…`;
    for (const button of row.querySelectorAll('button')) button.remove();
    try {
      const { device, about } = await api('POST', 'api/v1/devices', {
        url, username: username.value, password: password.value, group: groupName.value, force, keep_both: keepBoth,
      });
      const model = [about.model, about.version].filter(Boolean).join(' ');
      row.className = 'ok';
      // Said where it is so: what is typed and seen there, and the device's password, are not encrypted on the way.
      const how = String(device.url || '').startsWith('http://') ? ' · over plain HTTP' : '';
      text.textContent = `${device.name} added${model ? ` — ${model}` : ''}${how}`;
      onAdded();
      return true;
    } catch (ex) {
      const twin = ex.code === 'same_device' && ex.data?.same_as;
      if (twin) {
        // Not a failure: the device is on the wall, under another of its addresses. What is to become of
        // this one is for the person to say, and nothing is done until they have.
        row.className = 'ask';
        text.textContent = `${url} — ${ex.message}.`;
        row.append(
          h('button', { type: 'button', onclick: () => moveTo(twin, url, row) }, 'Use this address instead'),
          h('button', { type: 'button', onclick: () => add(url, row, force, true) }, 'Keep both'));
        return true;
      }
      row.className = 'bad';
      text.textContent = `${url} — ${ex.message}`;
      // Worth saving anyway only when the device simply couldn't be reached right now. (Not where it answers
      // and signs nobody in: an address that is no KVM at all does that, and would be sent the password from then on.)
      if (CANNOT_BE_REACHED.includes(ex.code)) {
        row.append(h('button', { type: 'button', onclick: () => add(url, row, true, keepBoth) }, 'Add anyway'));
      }
      return false;
    }
  }

  return h('form', {
    onsubmit: event => {
      event.preventDefault();
      const list = [...new Set(addresses.value.split(/[\s,;]+/).filter(Boolean))];
      busy(submit, async () => {
        const failed = [];
        for (const url of list) {
          const row = h('li', {}, h('span', {}));
          results.append(row);
          if (!(await add(url, row, false))) failed.push(url);
        }
        addresses.value = failed.join('\n');
        addresses.required = failed.length > 0;
      });
    },
  },
    field('Addresses', addresses,
      'One per line: IP address or name of each KVM, or of a server\'s management controller (BMC). GL.iNet Comet, PiKVM, JetKVM and Redfish controllers are told apart automatically. They are all added with the login below; you can rename them later.'),
    h('div', { class: 'actions left' }, find),
    found,
    h('div', { class: 'row' },
      field('User name', username, 'A JetKVM has none; it is ignored there.'),
      passwordBox),
    field('Group', groupName, 'Optional: a rack, a room, a customer. The wall can show one group at a time.'),
    h('p', { class: 'muted' },
      'Each one is contacted to check the login. Its certificate is remembered, so qKVM will refuse to send the password to anything else at that address.'),
    h('div', { class: 'actions' }, submit),
    results,
  );
}

function addDevicesDialog() {
  openDialog('Add KVMs', body => body.append(addDevicesForm(reloadWall)));
}

const KINDS = { kvmd: 'GL.iNet Comet / PiKVM', jetkvm: 'JetKVM', redfish: 'Server (Redfish)' };

// A text box for a KVM's group that suggests the groups already in use.
function groupInput(value) {
  const input = h('input', { type: 'text', value, maxLength: 40, autocomplete: 'off', placeholder: 'None' });
  const names = h('datalist', { id: `groups-${Math.random().toString(36).slice(2, 8)}` },
    groupNames().map(name => h('option', { value: name })));
  input.setAttribute('list', names.id);
  queueMicrotask(() => input.after(names));  // next to the box, once the box has been put into its form
  return input;
}

function editDeviceDialog(device, onDone) {
  openDialog(`Edit ${device.name}`, (body, close) => {
    const name = h('input', { type: 'text', value: device.name, maxLength: 80, required: true });
    const url = h('input', { type: 'text', value: device.url, required: true, spellcheck: false });
    const username = h('input', { type: 'text', value: device.username, autocomplete: 'off', required: true });
    const { el: passwordBox, input: password } = passwordField('Password', {
      autocomplete: 'new-password', placeholder: device.has_password ? 'Unchanged' : 'Not saved yet',
    }, 'Leave empty to keep the saved one.');
    const openUrl = h('input', { type: 'text', value: device.custom_open_url, spellcheck: false, placeholder: `${device.url}/` });
    const groupName = groupInput(device.group || '');
    const tls = h('select', {},
      h('option', { value: 'pinned' }, 'Remember the certificate (recommended)'),
      h('option', { value: 'system' }, 'Require a certificate from a trusted authority'),
      h('option', { value: 'insecure' }, 'Do not check (unsafe)'));
    tls.value = device.tls;
    const tell = h('input', { type: 'checkbox', checked: device.alerts !== false });
    const error = h('p', { class: 'error', hidden: true });
    const save = h('button', { type: 'submit', class: 'primary' }, 'Save');
    const saveAnyway = h('button', { type: 'button', hidden: true }, 'Save without checking');

    const send = async force => {
      error.hidden = true;
      saveAnyway.hidden = true;  // offered again only for what is refused now
      try {
        await api('PUT', `api/v1/devices/${device.id}`, {
          name: name.value, url: url.value, username: username.value, password: password.value,
          open_url: openUrl.value, tls: tls.value, group: groupName.value, alerts: tell.checked, force,
        });
      } catch (ex) {
        error.textContent = ex.message;
        error.hidden = false;
        // Also where it is there and signs nobody in just now, as long as nothing about how it is signed in to
        // was changed: a tile in that state can still be given another name or group.
        const asItWas = url.value.trim() === device.url && username.value === device.username && !password.value;
        saveAnyway.hidden = !(CANNOT_BE_REACHED.includes(ex.code) || (ex.code === 'no_sign_in' && asItWas));
        return;
      }
      close();
      toast(`${name.value} saved`, 'ok');
      onDone();
    };
    saveAnyway.addEventListener('click', () => busy(saveAnyway, () => send(true)));
    // It is offered for what was refused, as it was sent. Left on show, it saved unchecked whatever was
    // typed after: another address and a password for it, which then went there every five minutes.
    for (const box of [url, username, password, tls]) box.addEventListener('input', () => { saveAnyway.hidden = true; });

    body.append(h('form', { onsubmit: event => { event.preventDefault(); busy(save, () => send(false)); } },
      field('Name', name),
      field('Address', url, `Type: ${KINDS[device.kind] || device.kind}`),
      h('div', { class: 'row' },
        device.kind !== 'jetkvm' && field('User name', username),
        passwordBox),
      field('Group', groupName, 'Optional: a rack, a room, a customer. The wall can show one group at a time.'),
      field('Console link', openUrl,
        'Where "Open console" goes. Set it if you view the wall from somewhere the address above is not reachable.'),
      device.url.startsWith('https') && field('Certificate', tls,
        device.fingerprint ? `Remembered SHA-256: ${device.fingerprint}` : 'No certificate remembered yet.'),
      check(tell, 'Send alerts about this one', 'Off for a machine that is switched on and off all day, or sleeps: its changes are nobody\'s news.'),
      error,
      h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'danger left', onclick: () => removeDevice(device, () => { close(); onDone(); }) }, 'Remove'),
        device.url.startsWith('https') && h('button', { type: 'button', onclick: () => certificateDialog(device, () => { close(); onDone(); }) }, 'Review certificate'),
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        saveAnyway,
        save),
    ));
  });
}

// Two tiles that are one device, reached by two addresses. Whoever looks after the wall says what is to be.
function twinsDialog(device) {
  openDialog('On the wall twice', (body, close) => {
    const all = [device, ...device.same_as.map(twin => tiles.get(twin.id)?.device).filter(Boolean)];
    const done = () => { close(); reloadWall(); };
    const keep = h('button', { type: 'button', class: 'admin-only' }, all.length > 2 ? 'Keep them all' : 'Keep both');
    keep.addEventListener('click', () => busy(keep, async () => {
      try {
        // Said of each of them but the first: the first then has no twin left either.
        for (const one of all.slice(1)) {
          await api('PUT', `api/v1/devices/${one.id}`, {
            name: one.name, url: one.url, username: one.username, open_url: one.custom_open_url, group: one.group,
            keep_both: true, force: true,
          });
        }
      } catch (ex) {
        toast(ex.message, 'error');
        return;
      }
      done();
    }));
    body.append(h('div', {},
      h('p', {}, 'These tiles are one and the same device, reached by different addresses. Each fetches its pictures separately, so the device does the work twice.'),
      h('table', { class: 'rows' }, h('tbody', {}, all.map(one => h('tr', {},
        h('td', { class: 'wrap' }, one.name),
        h('td', { class: 'wrap' }, one.host),
        h('td', {}, h('button', { type: 'button', class: 'danger admin-only', onclick: () => removeDevice(one, done) }, 'Remove')))))),
      h('p', { class: 'muted' }, can('admin')
        ? 'Remove the one you do not need. Or keep both, if you want the device on the wall under each address: it is then not brought up again.'
        : 'An admin can remove one of them, or decide to keep both.'),
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Decide later'), keep)));
  });
}

async function removeDevice(device, onDone) {
  const sure = await confirmBox({
    title: `Remove ${device.name}?`,
    message: 'The KVM disappears from the wall and its saved password is erased. The KVM itself is not touched.',
    action: 'Remove',
  });
  if (!sure) return;
  try {
    await api('DELETE', `api/v1/devices/${device.id}`);
  } catch (ex) {
    toast(ex.message, 'error');
    return;
  }
  toast(`${device.name} removed`, 'ok');
  onDone();
}

async function certificateDialog(device, onDone) {
  let cert;
  try {
    cert = await api('GET', `api/v1/devices/${device.id}/certificate`);
  } catch (ex) {
    toast(`${device.name}: ${ex.message}`, 'error');
    return;
  }
  openDialog(`${device.name} certificate`, (body, close) => {
    const same = cert.saved && cert.saved === cert.presented;
    const trust = h('button', { type: 'button', class: 'danger' }, 'Trust this certificate');
    trust.addEventListener('click', () => busy(trust, async () => {
      try {
        await api('POST', `api/v1/devices/${device.id}/trust`, { fingerprint: cert.presented });
      } catch (ex) {
        toast(ex.message, 'error');
        return;
      }
      close();
      toast(`${device.name}: certificate trusted`, 'ok');
      onDone();
    }));
    body.append(
      h('p', {}, 'Remembered by qKVM:', h('code', { class: 'fingerprint' }, cert.saved || 'none yet')),
      h('p', {}, 'Presented by the device right now:', h('code', { class: 'fingerprint' }, cert.presented)),
      same
        ? h('div', { class: 'note' }, 'They match. qKVM is talking to the same KVM as before.')
        : h('div', { class: 'note bad' },
          'A KVM gets a new certificate after a factory reset or some firmware updates. ',
          'If neither happened, something else may be answering at this address: do not trust it.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, same ? 'Close' : 'Cancel'),
        !same && trust),
    );
  });
}

// --- actions ------------------------------------------------------------------------------------
// One catalogue of things to do, used the same way for a single KVM and for a selection of them.
// A spec says what to send and how to talk about it:
//   { title, body, done, confirm?, danger?, tick?, warning?, question?, detail? }
// (tick: on several machines at once it asks for a tick as well, as everything marked danger does.)

const MODIFIERS = [['ControlLeft', 'Ctrl'], ['AltLeft', 'Alt'], ['ShiftLeft', 'Shift'], ['MetaLeft', 'Win']];
const KEY_LABELS = {
  ControlLeft: 'Ctrl', ControlRight: 'Ctrl', AltLeft: 'Alt', AltRight: 'AltGr', ShiftLeft: 'Shift', ShiftRight: 'Shift',
  MetaLeft: 'Win', MetaRight: 'Win', Escape: 'Esc', Delete: 'Del', Insert: 'Ins', PageUp: 'PgUp', PageDown: 'PgDn',
  ArrowUp: '↑', ArrowDown: '↓', ArrowLeft: '←', ArrowRight: '→', PrintScreen: 'PrtSc',
};
// The keys offered in the picker, as [code, label].
const KEY_CHOICES = [
  ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map(letter => [`Key${letter}`, letter]),
  ...'0123456789'.split('').map(digit => [`Digit${digit}`, digit]),
  ...Array.from({ length: 12 }, (_, i) => [`F${i + 1}`, `F${i + 1}`]),
  ...['Enter', 'Escape', 'Tab', 'Space', 'Backspace', 'Delete', 'Insert', 'Home', 'End', 'PageUp', 'PageDown',
    'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'PrintScreen'].map(code => [code, KEY_LABELS[code] || code]),
];
// Shortcuts worth one click. `confirm` asks first even for a single machine.
const QUICK_KEYS = [
  { icon: 'sun', label: 'Wake screen', keys: 'ShiftLeft' },
  { icon: 'command', label: 'Ctrl+Alt+Del', keys: 'ControlLeft,AltLeft,Delete', confirm: true },
  { icon: 'lock', label: 'Lock screen', keys: 'MetaLeft,KeyL' },
  { icon: 'activity', label: 'Task Manager', keys: 'ControlLeft,ShiftLeft,Escape' },
  { icon: 'grid', label: 'Show desktop', keys: 'MetaLeft,KeyD' },
  { icon: 'enter', label: 'Enter', keys: 'Enter' },
  { icon: 'chevronLeft', label: 'Esc', keys: 'Escape' },
  { icon: 'x', label: 'Close window', keys: 'AltLeft,F4', confirm: true, danger: true },
];

let savedActions = [];  // the user's own actions, from Settings → Actions

// "ControlLeft,AltLeft,Delete" -> "Ctrl+Alt+Del"
function keysLabel(keys) {
  return keys.split(',').map(code => KEY_LABELS[code] || code.replace(/^(Key|Digit)/, '')).join('+');
}

async function loadSavedActions() {
  if (!can('operator')) return savedActions;
  try {
    savedActions = (await api('GET', 'api/v1/actions')).actions;
  } catch { /* keep the list we had */ }
  return savedActions;
}

function keySpec(label, keys, extra = {}) {
  return { title: label, body: { action: 'keys', keys }, done: `${keysLabel(keys)} sent`, ...extra };
}

function savedSpec(action) {
  return {
    title: action.name,
    // With what state of it was shown here: changed by somebody since, it is not run on the strength of an old button.
    body: { action: 'custom', custom_id: action.id, custom_changed: action.changed },
    done: `${action.name} sent`,
    danger: action.danger,
    // Typing text into the wrong window can do anything, so that always asks first.
    confirm: action.danger || action.kind === 'text',
    tick: action.kind === 'text',
  };
}

// Modifier toggles plus one more key. read() gives "ControlLeft,KeyC", or "" when nothing is chosen.
function keyPicker(initial = '') {
  const codes = initial ? initial.split(',') : [];
  const toggles = MODIFIERS.map(([code, label]) => {
    const input = h('input', { type: 'checkbox', checked: codes.includes(code) });
    return { code, input, el: h('label', { class: 'chip-toggle' }, input, h('span', {}, label)) };
  });
  const key = h('select', { 'aria-label': 'Key' },
    h('option', { value: '' }, 'No other key'),
    KEY_CHOICES.map(([code, label]) => h('option', { value: code }, label)));
  key.value = codes.find(code => !MODIFIERS.some(([modifier]) => modifier === code)) || '';
  const preview = h('kbd', {});
  const read = () => [...toggles.filter(toggle => toggle.input.checked).map(toggle => toggle.code), key.value]
    .filter(Boolean).join(',');
  const update = () => { preview.textContent = read() ? keysLabel(read()) : 'Nothing chosen'; };
  for (const toggle of toggles) toggle.input.addEventListener('change', update);
  key.addEventListener('change', update);
  update();
  return { el: h('div', { class: 'keypicker' }, toggles.map(toggle => toggle.el), key, preview), read };
}

// Asks before running `spec` on `targets`. What can lose somebody's work needs a tick as well when it goes
// to several machines: anything marked danger, a power button (a short press shuts a running system down),
// and typed text (which does whatever the window it lands in makes of it).
function confirmRun(targets, spec) {
  const many = targets.length > 1;
  const who = many ? `${targets.length} KVMs` : targets[0].device.name;
  return new Promise(resolve => {
    let answer = false;
    const dialog = openDialog(spec.title, (body, close) => {
      const agree = h('input', { type: 'checkbox' });
      const pace = h('select', { 'aria-label': 'How fast' },
        h('option', { value: '' }, 'A few at a time'),
        h('option', { value: '0' }, 'One after the other'),
        h('option', { value: '10' }, 'One after the other, 10 seconds apart'),
        h('option', { value: '30' }, 'One after the other, 30 seconds apart'),
        h('option', { value: '120' }, 'One after the other, 2 minutes apart'));
      const run = h('button', {
        type: 'button',
        class: spec.danger ? 'danger fill' : 'primary',
        onclick: () => { answer = { gap: pace.value === '' ? undefined : Number(pace.value) }; close(); },
      }, many ? `Run on ${targets.length} KVMs` : spec.title);
      const needsTick = many && (spec.danger || spec.tick);
      run.disabled = needsTick;
      agree.addEventListener('change', () => { run.disabled = !agree.checked; });
      body.append(h('div', {},
        h('p', {}, spec.question ? spec.question(who) : `${spec.title} on ${who}?`),
        spec.detail && h('div', { class: 'note' }, h('code', {}, spec.detail)),
        spec.warning && h('div', { class: 'note warn' }, spec.warning),
        many && h('ul', { class: 'targets' }, targets.map(tile =>
          h('li', { dataset: { state: tile.state } },
            h('span', { class: 'dot' }), tile.device.name, h('span', { class: 'muted' }, tile.device.host),
            h('span', { class: 'muted' }, stateLabel(tile.state, tile.status) || tile.state)))),
        needsTick && check(agree, `Yes, do this on all ${targets.length} machines`),
        many && h('label', { class: 'field' }, h('span', {}, 'In the order shown'), pace),
        h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), run)));
    });
    dialog.addEventListener('close', () => resolve(answer));
  });
}

function afterAction(tile, spec) {
  if (tile.device.picture === false) lookAgainSoon();
  if (spec.body.action !== 'reboot') return;
  Object.assign(tile, { rebootUntil: Date.now() + 180000, wentDown: false });
  render(tile);
}

// What is being done to which machine at this moment: device id -> what it is called. One thing at a time
// per machine. The answer to a power button can take half a minute, and a second press while the first is
// still out does not do it again: it does the opposite.
const acting = new Map();

// What a device is saved in spite of: it could not be reached just now, which says nothing about what was typed.
const CANNOT_BE_REACHED = ['unreachable', 'timeout', 'dropped'];

// No answer is not a refusal: the request may have arrived, and been carried out.
const unanswered = ex => ex.code === 'timeout' || ex.code === 'network';
const ROW_ICONS = { ok: 'check', bad: 'alert', unknown: 'info', skipped: 'x' };

// Runs `spec` on every target, a few at a time, and shows how each one went.
// `gap`: undefined for a few at a time; else one after the other, that many seconds apart (machines that are
// switched on together draw their starting current together, and a storage server wants to be up first).
function runBulk(targets, spec, gap) {
  // Ties this run's entries together in the activity log.
  const batch = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  let running = false;
  let stop = () => {};
  let shown = null;  // the dialog, once there is one to ask whether it is still open
  const dialog = openDialog(`${spec.title} · ${targets.length} KVMs`, (body, close) => {
    const rows = new Map(targets.map(tile => [tile,
      h('li', {}, h('span', { class: 'spinner' }), h('strong', {}, tile.device.name), h('span', { class: 'muted' }, 'Waiting…'))]));
    const summary = h('p', { role: 'status' }, 'Starting…');
    const retry = h('button', { type: 'button', hidden: true }, 'Retry failed');
    const halt = h('button', { type: 'button', class: 'danger' }, 'Stop');
    const done = h('button', { type: 'button', class: 'primary', hidden: true, onclick: close }, 'Close');
    body.append(summary, h('ul', { class: 'progress' }, [...rows.values()]), h('div', { class: 'actions' }, retry, halt, done));

    const mark = (tile, kind, text) => {
      const row = rows.get(tile);
      row.className = kind;
      row.firstChild.replaceWith(ROW_ICONS[kind] ? icon(ROW_ICONS[kind]) : h('span', { class: 'spinner' }));
      row.lastChild.textContent = text;
    };
    const run = async list => {
      for (const button of [retry, done]) button.hidden = true;
      Object.assign(halt, { hidden: false, disabled: false });
      for (const tile of list) mark(tile, '', 'Waiting…');
      const queue = [...list];
      const failed = [];
      const skipped = [];
      let ok = 0;
      let unknown = 0;
      running = true;
      let wake = () => {};  // ends the wait between two machines at once
      // What is on its way cannot be called back. What has not been sent yet is not sent.
      stop = () => {
        for (const tile of queue.splice(0)) {
          mark(tile, 'skipped', 'Not sent');
          skipped.push(tile);
        }
        halt.disabled = true;
        wake();
      };
      halt.onclick = stop;
      // Looked at before every request, and not left to the "close" event alone: nothing more is to go out
      // from a run that nobody can see any longer, whatever the browser does or does not tell the page.
      const next = () => {
        if (shown && !shown.open) stop();
        return queue.shift();
      };
      const worker = async () => {
        for (let tile = next(); tile; tile = next()) {
          if (acting.has(tile.device.id)) {
            // Something sent from a tile, or by a run before this one, is still out to this machine. Nothing is
            // sent on top of it, and its mark is its own to take away. Offered again with what failed.
            mark(tile, 'bad', `"${acting.get(tile.device.id)}" is still under way here`);
            failed.push(tile);
            summary.textContent = `${ok + failed.length + unknown} of ${list.length} done…`;
            continue;
          }
          mark(tile, '', 'Sending…');
          acting.set(tile.device.id, spec.title);
          try {
            const result = await api('POST', `api/v1/devices/${tile.device.id}/actions`, { ...spec.body, batch }, ACTION_PATIENCE);
            mark(tile, 'ok', result?.note || spec.done);  // "already on": left as it was, and that is not a failure
            afterAction(tile, spec);
            ok += 1;
          } catch (ex) {
            if (unanswered(ex)) {
              mark(tile, 'unknown', 'No answer. It may have been done.');
              unknown += 1;
            } else {
              mark(tile, 'bad', ex.message);
              failed.push(tile);
            }
          } finally {
            acting.delete(tile.device.id);
          }
          summary.textContent = `${ok + failed.length + unknown} of ${list.length} done…`;
          if (gap > 0 && queue.length) {
            summary.textContent += ` Next in ${gap} s.`;
            await new Promise(resolve => { wake = resolve; setTimeout(resolve, gap * 1000); });
          }
        }
      };
      await Promise.all(Array.from({ length: gap === undefined ? Math.min(4, list.length) : 1 }, worker));
      running = false;
      const told = ok === list.length
        ? `Done on ${ok === 1 ? 'the KVM' : `all ${ok} KVMs`}.`
        : `${[`${ok} succeeded`, failed.length && `${failed.length} failed`, unknown && `${unknown} without an answer`,
          skipped.length && `${skipped.length} not sent`].filter(Boolean).join(', ')}.`;
      summary.textContent = told;
      halt.hidden = true;
      done.hidden = false;
      // Offered again: what was refused, and what was never sent. Not what got no answer, which may have been
      // carried out: pressing a power button a second time is not a retry.
      const again = [...failed, ...skipped];
      retry.hidden = again.length === 0;
      retry.textContent = !skipped.length ? 'Retry failed' : failed.length ? 'Retry failed, send the rest' : 'Send the rest';
      retry.onclick = () => run(again);
      // Closed while it ran: how it ended is said where it can still be seen.
      if (!dialog.open) toast(`${spec.title}: ${told}`, ok === list.length ? 'ok' : 'error');
    };
    run(targets);
  });
  shown = dialog;
  // Closing it while it runs (the X, Esc) is the fastest way to say "stop": nothing more is sent.
  dialog.addEventListener('close', () => { if (running) stop(); });
}

// The one way anything is done to a machine: ask if needed, then run it on one KVM or on many.
async function perform(ids, spec, onStarted) {
  const targets = ids.map(id => tiles.get(id)).filter(Boolean);
  if (!targets.length) return;
  const many = targets.length > 1;
  if (!many && acting.has(targets[0].device.id)) {  // said before asking "are you sure" about something that will not be sent
    toast(`${targets[0].device.name}: "${acting.get(targets[0].device.id)}" is still under way. Wait for its answer.`, 'info');
    return;
  }
  const go = spec.confirm || many ? await confirmRun(targets, spec) : {};
  if (!go) return;
  if (many) {
    onStarted?.();
    runBulk(targets, spec, go.gap);
    return;
  }
  const [tile] = targets;
  if (acting.has(tile.device.id)) {
    toast(`${tile.device.name}: "${acting.get(tile.device.id)}" is still under way. Wait for its answer.`, 'info');
    return;
  }
  acting.set(tile.device.id, spec.title);
  const finished = working(`${tile.device.name}: ${spec.title}…`);
  let result;
  try {
    result = await api('POST', `api/v1/devices/${tile.device.id}/actions`, spec.body, ACTION_PATIENCE);
  } catch (ex) {
    toast(unanswered(ex)
      ? `${tile.device.name}: no answer to "${spec.title}". It may have been done all the same: look before sending it again.`
      : `${tile.device.name}: ${ex.message}`, 'error');
    if (ex.code === 'changed') {
      for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();  // the list it was clicked in is out of date
      loadSavedActions();
    }
    return;
  } finally {
    acting.delete(tile.device.id);
    finished();
  }
  toast(`${tile.device.name}: ${result?.note || spec.done}`, 'ok');
  afterAction(tile, spec);
  if (spec.body.action === 'reboot') onStarted?.();
}

function typeTextDialog(ids) {
  openDialog('Type text', (body, close) => {
    const text = h('textarea', { rows: 4, required: true, maxLength: 2000, spellcheck: false, placeholder: 'ipconfig /all' });
    const enter = h('input', { type: 'checkbox', checked: true });
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        close();
        perform(ids, {
          title: 'Type text',
          body: { action: 'text', text: text.value, enter: enter.checked },
          done: 'text typed',
          confirm: true,
          tick: true,
          question: who => `Type this on ${who}?`,
          detail: text.value + (enter.checked ? ' ⏎' : ''),
        });
      },
    },
      field('Text', text,
        'Typed on the connected computer as if on its keyboard (US layout). It is not saved, and its content is not written to the activity log.'),
      check(enter, 'Press Enter afterwards'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        h('button', { type: 'submit', class: 'primary' }, 'Continue'))));
    text.focus();
  });
}

function sendKeysDialog(ids) {
  openDialog('Send keys', (body, close) => {
    const picker = keyPicker();
    const error = h('p', { class: 'error', hidden: true }, 'Choose at least one key.');
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        const keys = picker.read();
        error.hidden = Boolean(keys);
        if (!keys) return;
        close();
        perform(ids, keySpec(`Send ${keysLabel(keys)}`, keys, { confirm: true }));
      },
    },
      h('p', { class: 'muted' }, 'Pressed together on the connected computer, then released.'),
      picker.el,
      error,
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        h('button', { type: 'submit', class: 'primary' }, 'Continue'))));
  });
}

// "Open console" on a server whose controller hands out a pass for it: straight into the console, signed
// in, instead of to the controller's sign-in page. Anywhere else, and for an account that may only look,
// the click is left to do what a link does.
let enteringConsole = false;
// Where "Open console" goes for a device; '' where no link is offered. None is offered to a page on the host
// name this wall is looked at under (another port of one name, say: a router that forwards two ports, a
// tunnel to localhost). A browser keeps what signs it in by host name and not by port: it would hand the
// sign-in to this wall to the device's own page, and a device is not trusted with that.
function consoleLink(device) {
  if (!/^https?:\/\//i.test(device.open_url)) return '';
  return sharesOurName(device) ? '' : device.open_url;
}

function sharesOurName(device) {
  try {
    return new URL(device.open_url).hostname === location.hostname;
  } catch {
    return false;
  }
}

async function openSignedIn(event, tile) {
  if (!tile?.status?.console || !can('operator')) return;
  event.preventDefault();
  if (enteringConsole) return;  // a second click while the first is being answered would have a second pass made out
  enteringConsole = true;
  let url;
  try {
    ({ url } = await api('POST', `api/v1/devices/${tile.device.id}/console`));
  } catch (ex) {
    toast(`${tile.device.name}: ${ex.message}`, 'error');
    return;
  } finally {
    enteringConsole = false;
  }
  // The answer came within moments of the click, which a browser still counts as the person's own doing.
  // One that does not (or that was told to open nothing by itself) gets a link to click instead: that always works.
  const tab = window.open(url, '_blank');
  if (tab) {
    try { tab.opener = null; } catch { /* already cut off from this page, which is the point */ }
    return;
  }
  openDialog(`Console of ${tile.device.name}`, (body, close) => {
    body.append(h('div', {},
      h('p', {}, 'The console is ready. It opens in a new tab, signed in.'),
      h('p', { class: 'muted' }, 'The link works once. If it is not used, nothing needs to be undone.'),
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        h('a', { class: 'btn primary', href: url, target: '_blank', rel: 'noopener noreferrer', onclick: () => setTimeout(close, 0) },
          icon('external'), h('span', {}, 'Open console')))));
  });
}

// The action menu for one KVM (an id) or for several (an array of ids).
function actionsDialog(target) {
  const ids = (Array.isArray(target) ? target : [target]).filter(id => tiles.has(id));
  if (!ids.length) return;
  const picked = ids.map(id => tiles.get(id));
  const single = picked.length === 1 ? picked[0] : null;
  openDialog(single ? single.device.name : `${ids.length} KVMs selected`, (body, close) => {
    // While one of its buttons is being answered the menu holds still: a second click, or a key held down,
    // is not a second request.
    const go = async spec => {
      body.inert = true;
      try {
        await perform(ids, spec, close);
      } finally {
        body.inert = false;
      }
    };
    const quick = (name, label, spec, hint) => h('button', {
      type: 'button', class: spec.danger ? 'danger' : '', onclick: () => go(spec),
    }, icon(name), h('span', {}, label), hint && h('kbd', {}, hint));
    const power = (name, label, action, done, warning, danger) => quick(name, label, {
      title: label, body: { action }, done, warning, danger, tick: true, confirm: true,
    });

    const saved = h('div', { class: 'action-grid' });
    const fillSaved = () => saved.replaceChildren(...[
      ...savedActions.map(action => quick(action.kind === 'text' ? 'type' : 'star', action.name, savedSpec(action),
        action.kind === 'keys' ? keysLabel(action.keys) : null)),
      h('button', { type: 'button', class: 'admin-only', onclick: () => { close(); settingsDialog('actions'); } },
        icon('plus'), h('span', {}, savedActions.length ? 'Manage…' : 'Add your own…')),
      !savedActions.length && !can('admin') && h('p', { class: 'muted' }, 'None yet. An admin can add some under Settings → Actions.'),
    ].filter(Boolean));
    fillSaved();
    loadSavedActions().then(fillSaved);

    const hasAtx = picked.some(tile => tile.status?.atx?.enabled);
    // A server's management controller has a power button and no keyboard. With nothing but servers
    // picked, what only a KVM can do is left out; in a mixed pick each machine answers for itself.
    const servers = picked.every(tile => tile.device.picture === false);
    const anyServer = picked.some(tile => tile.device.picture === false);
    const kvmAtx = picked.some(tile => tile.device.picture !== false && tile.status?.atx?.enabled);
    const serverOn = single && servers ? single.status?.atx?.power : null;
    const itself = servers ? 'controller' : 'KVM';
    const lights = picked.filter(tile => tile.status?.server?.locator != null);  // the machines that have a light to find them by
    const ports = single?.status?.ports;
    const wol = h('div', { class: 'action-grid' });
    const head = [];
    if (single) {
      const { device, status, view } = single;
      const [state, message] = stateOf(status, view);
      const certProblem = [view.error?.code, status?.error?.code].some(code => code === 'cert_mismatch' || (code === 'cert_invalid' && device.tls === 'pinned'));
      head.push(
        h('p', { class: 'muted' }, [device.host, status?.about?.model, status?.about?.version].filter(Boolean).join(' · ')),
        state !== 'online' && h('div', { class: 'note warn' }, message || stateLabel(state, status)),
        device.kind === 'jetkvm' && h('p', { class: 'muted' },
          'A JetKVM shows its picture to one viewer at a time. Opening its console takes the picture from this wall until you choose Show here on the tile. Text is typed with a US keyboard layout.'),
        sharesOurName(device) && h('div', { class: 'note warn' },
          `No link to its console is offered here: its page is at ${location.hostname}, the same name qKVM is looked at under, and a browser would hand that page your sign-in to qKVM. Look at one of the two under another name or address.`),
        h('div', { class: 'action-grid' },
          consoleLink(device) && h('a', {
            class: 'btn', href: consoleLink(device), target: '_blank', rel: 'noopener noreferrer',
            onclick: event => openSignedIn(event, single),
          }, icon('external'), h('span', {}, 'Open console'), status?.console && can('operator') && h('kbd', {}, 'signed in')),
          h('button', { type: 'button', onclick: () => { close(); openFocus(device.id); } }, icon('maximize'), h('span', {}, 'Enlarge')),
          h('button', { type: 'button', class: 'admin-only', onclick: () => { close(); editDeviceDialog(device, reloadWall); } }, icon('edit'), h('span', {}, 'Edit…')),
          certProblem && h('button', {
            type: 'button', class: 'danger admin-only', onclick: () => certificateDialog(device, () => { close(); reloadWall(); }),
          }, icon('shield'), h('span', {}, 'Review certificate'))));
      if (!servers) api('GET', `api/v1/devices/${device.id}/wol`).then(({ targets }) => {
        wol.replaceChildren(...targets.map(entry => quick('activity', `Wake ${entry.name || entry.mac}`, {
          title: `Wake ${entry.name || entry.mac}`, body: { action: 'wol', mac: entry.mac }, done: 'Wake-on-LAN sent', confirm: true,
        })));
      }).catch(() => {});
    } else {
      head.push(h('p', { class: 'muted' }, 'The action you choose runs on every selected KVM. You are asked to confirm first.'));
    }

    body.append(h('div', {},
      head,
      ports && [
        h('h3', {}, 'Computer on screen'),
        h('div', { class: 'action-grid' }, ports.list.map((port, index) => h('button', {
          type: 'button', disabled: ports.active === index,
          onclick: () => { close(); switchPort(single, index); },
        }, icon('system'), h('span', {}, portName(port, index)),
          // (Its number, where it has a name of its own. One without a name is called by its number already.)
          h('kbd', {}, ports.active === index ? 'on screen' : port.signal === false ? 'empty' : port.name ? `port ${index + 1}` : 'switch')))),
        h('p', { class: 'muted' }, 'This KVM shows one computer at a time. Switching takes a few seconds and also changes a monitor plugged into the KVM. Keys and text go to the computer on screen.'),
      ],
      !servers && [
        h('h3', {}, 'Keyboard'),
        h('div', { class: 'action-grid' },
          // The keys are shown next to the name, unless the name already is the keys.
          QUICK_KEYS.map(key => quick(key.icon, key.label, keySpec(key.label, key.keys, { confirm: key.confirm, danger: key.danger }),
            keysLabel(key.keys) === key.label ? null : keysLabel(key.keys))),
          h('button', { type: 'button', onclick: () => { close(); sendKeysDialog(ids); } }, icon('command'), h('span', {}, 'Send keys…')),
          h('button', { type: 'button', onclick: () => { close(); typeTextDialog(ids); } }, icon('type'), h('span', {}, 'Type text…'))),
        h('h3', {}, 'Your actions'),
        saved,
      ],
      h('h3', {}, 'Power'),
      h('div', { class: 'action-grid' },
        !servers && [
          quick('coffee', 'Keep awake', { title: 'Keep awake', body: { action: 'jiggler_on' }, done: 'mouse jiggler on' }),
          quick('moon', 'Allow sleep', { title: 'Allow sleep', body: { action: 'jiggler_off' }, done: 'mouse jiggler off' }),
        ],
        hasAtx && [
          // A server's controller knows whether the server is on: it is asked for what is wanted, and leaves
          // alone a server that is there already. One server is offered the one that applies.
          anyServer && serverOn !== true && power('power', servers ? 'Power on' : 'Power on (servers)', 'power_on', 'switched on',
            'Switches on what is off. A server that is on already is left as it is.'),
          anyServer && serverOn !== false && power('moon', servers ? 'Shut down' : 'Shut down (servers)', 'power_off', 'asked to shut down',
            'Asks the operating system to shut down. A server that is off already is left as it is.'),
          // A KVM presses a button, and what that does depends on whether the computer is on, which it cannot vouch for.
          kvmAtx && power('power', 'Press power button', 'atx_power', 'power button pressed',
            'A short press turns the computer on, or asks a running system to shut down.'),
          power('power', 'Hold power button', 'atx_power_long', 'power button held',
            'A long press cuts the power. Unsaved work is lost.', true),
          power('rotate', 'Press reset button', 'atx_reset', 'reset button pressed',
            'A hard reset. Unsaved work is lost.', true),
        ]),
      !hasAtx && h('p', { class: 'muted' }, single
        ? 'Power and reset buttons appear here when the KVM has an ATX power board.'
        : 'None of the selected KVMs has an ATX power board, so there are no power buttons.'),
      wol,
      lights.length > 0 && [
        h('h3', {}, 'Find it in the rack'),
        h('div', { class: 'action-grid' },
          // One machine is offered the one that applies; a selection may hold some of each.
          (!single || single.status.server.locator === false) && quick('sun', 'Locator light on',
            { title: 'Locator light on', body: { action: 'locate_on' }, done: 'locator light on' }),
          (!single || single.status.server.locator === true) && quick('moon', 'Locator light off',
            { title: 'Locator light off', body: { action: 'locate_off' }, done: 'locator light off' })),
        h('p', { class: 'muted' }, 'The light on the machine itself, front and back, for whoever is standing in front of the rack.'),
      ],
      h('h3', {}, single ? `This ${itself}` : `The ${itself}s themselves`),
      h('div', { class: 'action-grid' },
        quick('rotate', servers ? 'Restart controller' : 'Reboot KVM', {
          title: servers ? 'Restart controller' : 'Reboot KVM',
          body: { action: 'reboot' },
          done: servers ? 'restarting' : 'rebooting',
          danger: true,
          confirm: true,
          question: who => (servers ? `Restart the management controller of ${who}?` : `Reboot ${who}?`),
          warning: servers
            ? 'This restarts the management controller, not the server, which keeps running. The controller is away for a minute or two.'
            : 'This restarts the KVM itself, not the computer. Anyone using its console is disconnected for about a minute.',
        }))));
  }, { size: 'wide' });
}

// --- the recovery key, and a forgotten password ------------------------------------------------------

// Shows a recovery key with ways to keep it. The key exists only here: the server keeps a locked copy.
function recoveryKeyView(key) {
  const box = h('input', {
    type: 'text', readOnly: true, value: key, class: 'mono', spellcheck: false, 'aria-label': 'Recovery key',
    onfocus: event => event.target.select(),
  });
  const copy = h('button', { type: 'button' }, 'Copy');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(key);
      toast('Recovery key copied', 'ok');
    } catch {  // no clipboard access on a plain http address
      box.focus();
      box.select();
      toast('Press Ctrl+C to copy it', 'info');
    }
  });
  const save = h('button', { type: 'button' }, icon('download'), 'Save as a file');
  save.addEventListener('click', () => {
    const text = `qKVM recovery key\n\n${key}\n\nWith this key the password of any qKVM account can be replaced.\n`
      + 'Keep it somewhere safe that is not the computer qKVM runs on.\n';
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const link = h('a', { href: url, download: 'qkvm-recovery-key.txt' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  return h('div', { class: 'recovery' },
    h('p', {}, 'If a password is ever forgotten, this key sets a new one without losing the saved KVM passwords.'),
    box,
    h('div', { class: 'actions left' }, copy, save),
    h('p', { class: 'muted' }, 'It is shown only now. Keep it in a password manager or on paper, not on this computer. ',
      'Whoever has it can take over any account, so treat it like a password.'));
}

function newRecoveryKey(onDone) {
  askPassword('Recovery key', 'A new recovery key replaces the one made before, which stops working.', 'Create the key',
    async (password, body, close) => {
      const made = await api('POST', 'api/v1/recovery', { password });
      hasRecovery = true;
      body.replaceChildren(recoveryKeyView(made.recovery_key), h('div', { class: 'actions' },
        h('button', { type: 'button', class: 'primary', onclick: () => { close(); onDone(); } }, 'I have saved it')));
    });
}

// From the sign-in page: every way back in, from the gentlest to the last resort.
function forgotDialog() {
  openDialog('Forgot your password?', (body, close) => {
    const name = h('input', { type: 'text', autocomplete: 'username', maxLength: 64, spellcheck: false, required: askName });
    const key = h('input', {
      type: 'text', class: 'mono', spellcheck: false, autocomplete: 'off', required: true, maxLength: 80,
      placeholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
    });
    const nameBox = field('User name', name);
    nameBox.hidden = !askName;
    const first = passwordField('New password', { autocomplete: 'new-password', required: true });
    const second = passwordField('Repeat new password', { autocomplete: 'new-password', required: true });
    const coach = passwordCoach(first.input, second.input);
    const error = h('p', { class: 'error', hidden: true });
    const go = h('button', { type: 'submit', class: 'primary' }, 'Set the new password');
    const withKey = h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        const problem = coach.problem();
        if (problem) {
          error.textContent = problem;
          error.hidden = false;
          return;
        }
        busy(go, async () => {
          try {
            await api('POST', 'api/v1/recover', {
              name: nameBox.hidden ? '' : name.value, recovery_key: key.value, new_password: first.input.value,
            });
          } catch (ex) {
            if (ex.code === 'name_required') {  // an account was added since this page was loaded
              askName = true;
              nameBox.hidden = false;
              name.required = true;
              name.focus();
              return;
            }
            error.textContent = ex.message;
            error.hidden = false;
            return;
          }
          close();
          toast('Password changed. Sign in with the new one.', 'ok');
        });
      },
    },
      nameBox,
      field('Recovery key', key, 'The key shown when qKVM was set up, or made later under Settings → Security.'),
      first.el,
      coach.meter,
      second.el,
      coach.rules,
      error,
      h('div', { class: 'actions' }, go));

    body.append(h('div', { class: 'ways' },
      h('h3', {}, 'With the recovery key'),
      hasRecovery ? withKey : h('p', { class: 'muted' }, 'No recovery key has been made for this copy of qKVM.'),
      askName && h('h3', {}, 'With the help of an admin'),
      askName && h('p', {}, 'Any admin can set a new password for you under Settings → Accounts.'),
      h('h3', {}, 'Starting over'),
      h('p', {}, 'If neither is possible, run this on the computer qKVM runs on, with qKVM stopped:'),
      h('p', {}, h('code', {}, 'qkvm --reset-password')),
      h('p', { class: 'muted' }, 'It removes every account and the saved KVM passwords. The list of KVMs and the other settings stay. ',
        'Opening qKVM then starts with choosing a password, and the KVM passwords have to be entered again.'),
      h('h3', {}, 'Lost the phone with your authenticator app?'),
      h('p', { class: 'muted' }, 'An admin can switch two-factor sign-in off for your account under Settings → Accounts, or run ',
        h('code', {}, 'qkvm --disable-2fa NAME'), ' on that computer.')));
    (hasRecovery ? (askName ? name : key) : body).focus?.();
  });
}

// --- two-factor sign-in ----------------------------------------------------------------------------

function codeInput() {
  return h('input', {
    type: 'text', inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 7, spellcheck: false, placeholder: '123 456',
  });
}

// Asks for the account's own password, then hands it to `then`, which may throw to show a message.
function askPassword(title, explanation, action, then) {
  openDialog(title, (body, close) => {
    const { el: passwordBox, input: password } = passwordField('Your password', { autocomplete: 'current-password', required: true });
    const error = h('p', { class: 'error', hidden: true });
    const go = h('button', { type: 'submit', class: 'primary' }, action);
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        busy(go, async () => {
          try {
            await then(password.value, body, close);
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            password.select();
          }
        });
      },
    }, h('p', {}, explanation), passwordBox, error,
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), go)));
    password.focus();
  });
}

// Draws a QR code from its rows of "1" (dark) and "0", with the quiet margin readers need.
function qrPicture(rows, label) {
  const margin = 4;
  const size = rows.length + 2 * margin;
  let path = '';
  rows.forEach((row, r) => {
    for (let c = 0; c < row.length; c++) {
      if (row[c] === '1') path += `M${c + margin} ${r + margin}h1v1h-1z`;
    }
  });
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('class', 'qr');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', label);
  svg.setAttribute('shape-rendering', 'crispEdges');
  const paper = document.createElementNS(SVG_NS, 'rect');
  paper.setAttribute('width', size);
  paper.setAttribute('height', size);
  paper.setAttribute('fill', '#fff');
  const ink = document.createElementNS(SVG_NS, 'path');
  ink.setAttribute('d', path);
  ink.setAttribute('fill', '#000');
  svg.append(paper, ink);
  return svg;
}

function twoFactorSetup(onDone) {
  askPassword('Two-factor sign-in',
    'Signing in will ask for your password and for a 6-digit code from an authenticator app on your phone.',
    'Continue',
    async (password, body, close) => {
      const setup = await api('POST', 'api/v1/totp/begin', { password });
      const code = codeInput();
      code.required = true;
      const problem = h('p', { class: 'error', hidden: true });
      const turnOn = h('button', { type: 'submit', class: 'primary' }, 'Turn on');
      body.replaceChildren(h('form', {
        onsubmit: event => {
          event.preventDefault();
          problem.hidden = true;
          busy(turnOn, async () => {
            let reply;
            try {
              reply = await api('POST', 'api/v1/totp/enable', { code: code.value });
            } catch (ex) {
              problem.textContent = ex.message;
              problem.hidden = false;
              code.select();
              return;
            }
            setMe(reply.user);
            toast('Two-factor sign-in is on', 'ok');
            body.replaceChildren(oneTimeCodes(reply.recovery_codes || [], () => { close(); onDone(); }));
          });
        },
      },
        h('p', {}, h('strong', {}, '1. '), 'In an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis…) ',
          'add an account and scan this code.'),
        qrPicture(setup.qr, 'QR code to scan with an authenticator app'),
        field('Or type the setup key', h('input', {
          type: 'text', readOnly: true, value: setup.secret, class: 'mono', spellcheck: false, onfocus: event => event.target.select(),
        }), 'Time based. Name the account whatever you like, for example qKVM.'),
        h('p', { class: 'muted' }, 'Reading this on the phone itself? ', h('a', { href: setup.uri }, 'Open it in the app'), '.'),
        h('p', {}, h('strong', {}, '2. '), 'Enter the code the app shows now.'),
        field('Code', code),
        problem,
        h('p', { class: 'muted' }, 'Next you are given ten one-time codes for when the phone is not at hand. Beyond those, an admin ',
          'can take the second step off an account under Accounts, or run ', h('code', {}, 'qkvm --disable-2fa NAME'),
          ' on the computer qKVM runs on.'),
        h('div', { class: 'actions' }, turnOn)));
      code.focus();
    });
}

// The codes that each stand in once for the phone. Shown when they are made, and never again.
function oneTimeCodes(codes, done) {
  const text = codes.join('\n');
  const copy = h('button', { type: 'button' }, 'Copy');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      toast('Codes copied', 'ok');
    } catch {  // no clipboard access on a plain http address
      toast('Select them and press Ctrl+C to copy', 'info');
    }
  });
  const save = h('button', { type: 'button' }, icon('download'), 'Save as a file');
  save.addEventListener('click', () => {
    const url = URL.createObjectURL(new Blob([
      `qKVM one-time codes for ${me?.name || 'your account'}\n\n${text}\n\nEach signs you in once, in place of a code from the authenticator app.\n`,
    ], { type: 'text/plain' }));
    const link = h('a', { href: url, download: 'qkvm-one-time-codes.txt' });
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });
  return h('div', {},
    h('p', {}, h('strong', {}, 'Keep these where the phone is not. '),
      'Each one signs you in once, in place of a code from the app: for a phone that is lost, broken or at home. They are not shown again.'),
    h('pre', { class: 'codes mono', tabIndex: 0 }, text),
    h('div', { class: 'actions' }, copy, save, h('button', { type: 'button', class: 'primary', onclick: done }, 'I have kept them')));
}

function newOneTimeCodes(onDone) {
  askPassword('New one-time codes', 'Ten new codes are made. The ones that are left of the old stop working.', 'Make new codes',
    async (password, body, close) => {
      const reply = await api('POST', 'api/v1/totp/codes', { password });
      setMe(reply.user);
      body.replaceChildren(oneTimeCodes(reply.recovery_codes, () => { close(); onDone(); }));
    });
}

// Signed in by password alone where two-factor sign-in is required: nothing is shown or done until it is set up.
let enrolling = false;  // the page that says so is up

function mustEnroll() {
  if (enrolling) return;
  enrolling = true;
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  const again = async () => {
    enrolling = false;
    // Who this is now was answered when the second step was switched on. It is asked once more, and an answer
    // that does not come (qKVM busy at that moment, a cable out) is no reason to stay on this page: nothing
    // on it leads anywhere any more.
    try {
      setMe((await api('GET', 'api/v1/session')).user);
    } catch { /* as it was answered a moment ago */ }
    startWall();
  };
  showAuth('plain', h('div', {},
    h('h2', {}, 'One more step'),
    h('p', {}, 'Two-factor sign-in is required for your account. Set it up now: it takes a minute and an authenticator app on your phone.'),
    h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'left', onclick: async () => { await api('POST', 'api/v1/logout', { scope: 'this' }).catch(() => {}); location.reload(); } }, 'Sign out'),
      h('button', { type: 'button', class: 'primary', onclick: () => twoFactorSetup(again) }, 'Set it up'))));
}

function twoFactorOff(onDone) {
  askPassword('Switch off two-factor sign-in?', 'After this your password alone signs you in.', 'Switch off',
    async (password, body, close) => {
      setMe((await api('POST', 'api/v1/totp/disable', { password })).user);
      close();
      toast('Two-factor sign-in is off', 'ok');
      onDone();
    });
}

// --- tokens: for a script, and for a screen on the wall ------------------------------------------

// Something that is shown once and has to be taken away: a token, a link.
function shownOnce(value, label) {
  const box = h('input', {
    type: 'text', readOnly: true, value, class: 'mono', spellcheck: false, 'aria-label': label, onfocus: event => event.target.select(),
  });
  const copy = h('button', { type: 'button' }, 'Copy');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast('Copied', 'ok');
    } catch {  // no clipboard access on a plain http address
      box.focus();
      box.select();
      toast('Press Ctrl+C to copy it', 'info');
    }
  });
  return h('div', { class: 'once' }, box, copy);
}

async function tokensTab(refresh, does) {
  const [{ tokens }, { devices }] = await Promise.all([api('GET', 'api/v1/tokens'), api('GET', 'api/v1/wall')]);
  does.append(
    h('button', { type: 'button', onclick: () => tokenDialog('display', devices, refresh) }, icon('tv'), 'Link for a wall screen'),
    h('button', { type: 'button', class: 'primary', onclick: () => tokenDialog('api', devices, refresh) }, icon('plus'), 'Token for a script'));
  const names = new Map(devices.map(device => [device.id, device.name]));
  const day = at => new Date(at * 1000).toLocaleDateString();
  const sees = token => (token.devices === null ? 'All KVMs'
    : [...(token.groups || []).map(group => `everything in ${group}`), ...token.devices.filter(id => names.has(id)).map(id => names.get(id))]
      .join(', ').replace(/^e/, 'E') || 'No KVMs');
  const takeBack = async token => {
    const sure = await confirmBox({
      title: `Take back "${token.name}"?`,
      message: token.kind === 'display'
        ? 'The screen that is showing with this link goes back to the sign-in page at once, and the link opens nothing any more.'
        : 'Whatever uses this token is refused from now on.',
      action: 'Take it back',
    });
    if (!sure) return;
    try {
      await api('DELETE', `api/v1/tokens/${token.id}`);
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    toast(`${token.name} taken back`, 'ok');
    refresh();
  };
  return [
    h('p', { class: 'intro' },
      'For using qKVM without a person signing in. A token lets a script look at the wall or act on machines; a link keeps ',
      'a screen on the wall showing, and brings it back by itself after a restart. Each has the machines it is for, neither can ',
      'change settings or accounts, and both are shown once when they are made.'),
    listed(tokens.length > 0 && h('table', { class: 'rows' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'For'), h('th', {}, 'Can use'), h('th', {}, 'Ends'), h('th', {}))),
      h('tbody', {}, tokens.map(token => h('tr', {},
        h('td', { class: 'wrap' }, token.name,
          h('div', { class: 'muted' }, token.used ? `Last used ${ago(Date.now() / 1000 - token.used)}` : 'Not used yet')),
        h('td', {}, token.kind === 'display' ? 'A wall screen' : `A script · ${ROLE_NAMES[token.role]}`),
        h('td', { class: 'wrap' }, sees(token)),
        h('td', {}, token.expires ? (token.expires * 1000 < Date.now() ? 'Run out' : day(token.expires)) : 'When taken back'),
        h('td', {}, h('button', { type: 'button', class: 'danger', onclick: () => takeBack(token) }, 'Take back')))))),
      'None yet.'),
  ];
}

function tokenDialog(kind, devices, onDone) {
  const display = kind === 'display';
  openDialog(display ? 'Link for a wall screen' : 'Token for a script', (body, close) => {
    const name = h('input', { type: 'text', required: true, maxLength: 60, placeholder: display ? 'Screen in the hall' : 'Nightly reboot of the build machines' });
    const role = h('select', {},
      h('option', { value: 'viewer' }, 'Viewer: look at the wall and the pictures'),
      h('option', { value: 'operator' }, 'Operator: look, and act on the machines'));
    const days = h('select', {}, [['', 'Until it is taken back'], ['30', '30 days'], ['90', '90 days'], ['365', 'A year']]
      .map(([value, label]) => h('option', { value }, label)));
    const machines = machinePicker(devices, null);
    const error = h('p', { class: 'error', hidden: true });
    const make = h('button', { type: 'submit', class: 'primary' }, display ? 'Make the link' : 'Make the token');
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        busy(make, async () => {
          let made;
          try {
            made = await api('POST', 'api/v1/tokens', {
              name: name.value, kind, role: display ? 'viewer' : role.value, days: days.value ? Number(days.value) : null,
              ...machines.read(),
            });
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            return;
          }
          const here = `${location.origin}${location.pathname}`;
          body.replaceChildren(h('div', {}, display
            ? [
              h('p', {}, h('strong', {}, 'Open this address once in the browser of that screen. '),
                'It then shows the wall as a display, and comes back by itself after qKVM was restarted. It is not shown again.'),
              shownOnce(`${here}#display&key=${made.token}`, 'Display link'),
              h('p', { class: 'muted' }, 'Whoever has the address can look at these machines, and no more than look. Take it back under Tokens if a screen is given away.'),
            ]
            : [
              h('p', {}, h('strong', {}, 'Give this to the script. '), 'It is not shown again.'),
              shownOnce(made.token, 'Token'),
              h('p', { class: 'muted' }, 'Sent with every request, for example:'),
              h('pre', { class: 'mono wrap' }, `curl -H "Authorization: Bearer ${made.token}" ${here}api/v1/status`),
            ],
          h('div', { class: 'actions' }, h('button', { type: 'button', class: 'primary', onclick: () => { close(); onDone(); } }, 'I have it'))));
        });
      },
    },
      field('Name', name, 'What it is for. Shown here and in the activity log.'),
      !display && field('May', role),
      machines.el,
      field('Works', days),
      error,
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), make)));
    name.focus();
  });
}

// --- alerts ----------------------------------------------------------------------------------------

// Numbers for a monitoring system (Prometheus and what reads its format), behind a token of their own.
// The parts of a wall that a file can hold, as the page names them.
const FILE_PARTS = { devices: 'KVMs and servers', actions: 'Saved actions', alerts: 'Alert settings', wall: 'Wall settings' };

// Hand a file to the browser to save: `text` under `name`.
function saveAs(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = h('a', { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportDialog() {
  openDialog('Export to a file', (body, close) => {
    const parts = Object.entries(FILE_PARTS).map(([key, label]) => {
      const box = h('input', { type: 'checkbox', checked: true });
      return { key, box, row: check(box, label) };
    });
    // (Not 'new-password': beside the box for one's own password, a password manager takes the two for a
    // change of the wall's password, and offers to keep the file's passphrase as that.)
    const passphrase = passwordField('Passphrase for the file', { autocomplete: 'off', maxLength: 256 },
      'With a passphrase the file is encrypted, and holds the passwords of the devices, the saved texts and the address alerts go to. Left empty, it is a plain file with none of those in it.');
    const own = passwordField('Your password', { autocomplete: 'current-password', required: true, maxLength: 256 });
    const error = h('p', { class: 'error', hidden: true });
    const make = h('button', { type: 'submit', class: 'primary' }, icon('download'), 'Download');
    const send = async () => {
      error.hidden = true;
      const wanted = parts.filter(part => part.box.checked).map(part => part.key);
      const fail = message => { error.textContent = message; error.hidden = false; };
      if (!wanted.length) return fail('Choose what the file is to hold.');
      const typed = passphrase.input.value;
      if (typed && typed.length < 10) return fail('The passphrase needs 10 characters or more. Leave it empty for a file without passwords.');
      let reply;
      try {
        reply = await fetch('api/v1/export', {
          method: 'POST', cache: 'no-store', signal: AbortSignal.timeout(60000),
          headers: { 'X-QKVM': '1', 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: own.input.value, passphrase: typed, parts: wanted }),
        });
      } catch {
        return fail('qKVM is not responding');
      }
      if (!reply.ok) {
        let said = null;
        try { said = await reply.json(); } catch { /* not JSON */ }
        if (reply.status === 401 && said?.code === 'unauthorized') sessionExpired();
        return fail(said?.message || `The file could not be made (HTTP ${reply.status})`);
      }
      const named = /filename="([A-Za-z0-9._-]+)"/.exec(reply.headers.get('content-disposition') || '');
      // A saved password or text that does not open any more (saved before the wall's password was reset,
      // or damaged in the settings file) is not in the file: said, since the file is kept for what is in it.
      const without = Number(reply.headers.get('x-qkvm-not-opened')) || 0;
      saveAs(await reply.text(), named ? named[1] : (typed ? 'qkvm-export.qkvm' : 'qkvm-export.json'));
      close();
      if (without) {
        toast(`Exported, without ${without === 1 ? 'one saved password or text that does' : `${without} saved passwords or texts that do`} not open any more. `
          + `qKVM's log says which. Give ${without === 1 ? 'it' : 'them'} again on the wall, then export once more.`, 'error');
      } else {
        toast(typed ? 'Exported. The file opens with its passphrase only: keep the two apart.' : 'Exported, without passwords', 'ok');
      }
    };
    body.append(h('form', { onsubmit: event => { event.preventDefault(); busy(make, send); } },
      h('div', {}, parts.map(part => part.row)),
      passphrase.el,
      own.el,
      h('p', { class: 'muted' }, 'Accounts, tokens and two-factor keys are not in the file: each belongs to the qKVM it was made on.'),
      error,
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        make)));
  });
}

function importDialog(onDone) {
  openDialog('Import from a file', (body, close) => {
    let text = '';
    const file = h('input', { type: 'file', accept: '.qkvm,.json,application/json' });
    const passphrase = passwordField('Passphrase of the file', { autocomplete: 'off', maxLength: 256 });
    passphrase.el.hidden = true;
    const error = h('p', { class: 'error', hidden: true });
    const found = h('div', {});
    const read = h('button', { type: 'submit', class: 'primary' }, 'Read the file');
    const take = h('button', { type: 'button', class: 'primary', hidden: true }, icon('upload'), 'Take in');
    const fail = message => { error.textContent = message; error.hidden = false; };
    let boxes = [];
    // What is read, shown and taken belongs to one choice of file and passphrase. Another file chosen while
    // the first was still being read by the server left the first one's summary on show, with a "Take in"
    // that took the second: somebody approved a list and got another. A newer choice outdates whatever is
    // still on its way (`turn`), and what is taken is what the summary on show was made from (`shown`).
    let turn = 0;
    let shown = null;
    const again = () => { turn += 1; shown = null; found.replaceChildren(); take.hidden = true; read.hidden = false; error.hidden = true; boxes = []; };
    file.addEventListener('change', async () => {
      again();
      const mine = turn;
      text = '';
      passphrase.el.hidden = true;
      const chosen = file.files[0];
      if (!chosen) return;
      // (The server writes a plain file of up to four million characters, and a sealed one a third larger: it
      // has the last word on what is too large. This only keeps a film or a disk image from being read in.)
      if (chosen.size > 8000000) return fail('The file is larger than anything qKVM writes.');
      const read = await chosen.text();
      if (mine !== turn) return;  // another file was chosen while this one was being read
      text = read;
      // An encrypted file says so in the open: only then is there a passphrase to ask for.
      try { passphrase.el.hidden = !('sealed' in JSON.parse(text)); } catch { passphrase.el.hidden = true; }
      if (!passphrase.el.hidden) passphrase.input.focus();
    });
    const sent = () => ({ file: text, passphrase: passphrase.el.hidden ? '' : passphrase.input.value });
    const look = async () => {
      error.hidden = true;
      if (!text) return fail('Choose a file first.');
      const mine = turn;
      const asked = sent();
      let there;
      try {
        there = await api('POST', 'api/v1/import/read', asked, 60000);
      } catch (ex) {
        if (mine !== turn) return;
        if (ex.code === 'passphrase_needed') passphrase.el.hidden = false;
        return fail(ex.message);
      }
      if (mine !== turn) return;  // the answer is about a file that is no longer the one chosen
      shown = asked;
      const row = (key, label, hint, on) => {
        const box = h('input', { type: 'checkbox', checked: on, disabled: !on });
        boxes.push({ key, box });
        return check(box, label, hint);
      };
      // Everything that is about to be taken is said, each device and each action by itself: a file may come
      // from somebody else, with names one knows on addresses, console links and texts that are the writer's.
      const listed = lines => h('div', { class: 'picklist' }, lines);
      const hostOf = address => { try { return new URL(address).host; } catch { return address; } };
      const ofDevice = device => h('div', {}, h('strong', {}, device.name), ` · ${device.host}`,
        [device.tls === 'insecure' && 'its certificate is not checked', device.tls === 'system' && 'its certificate is checked against the public list',
          !device.password && 'no password', device.open_url && `console link to ${hostOf(device.open_url)}`, device.group && `group ${device.group}`,
        ].filter(Boolean).map(note => ` · ${note}`).join(''));
      const ofAction = action => {
        const typed = h('code', { hidden: true }, action.text);
        const show = h('button', { type: 'button', class: 'link' }, 'show what it types');
        show.addEventListener('click', () => { typed.hidden = !typed.hidden; show.textContent = typed.hidden ? 'show what it types' : 'hide it'; });
        return h('div', {}, h('strong', {}, action.name), action.kind === 'keys' ? ` · presses ${keysLabel(action.keys)}` : ' · types a text',
          action.enter && ', then Enter', action.danger && ' · asks before it runs', action.kind === 'text' && ' · ', action.kind === 'text' && show, typed);
      };
      const rows = [];
      if (there.devices) {
        const fresh = there.devices.filter(device => device.new);
        const twins = there.devices.filter(device => device.same_as);
        const here = there.devices.length - fresh.length - twins.length;
        rows.push(row('devices', `KVMs and servers: ${fresh.length} to add`,
          [here ? `${here} are on this wall already and stay as they are.` : '',
            twins.length ? `${twins.length} are left out as the same device as one that is here or earlier in the file (${twins.slice(0, 3).map(device => `${device.name}: ${device.same_as}`).join('; ')}${twins.length > 3 ? '; …' : ''}).` : '',
          ].filter(Boolean).join(' '), fresh.length > 0));
        if (fresh.length) rows.push(listed(fresh.map(ofDevice)));
      }
      if (there.actions) {
        const fresh = there.actions.filter(action => action.new);
        rows.push(row('actions', `Saved actions: ${fresh.length} to add`,
          there.actions.length > fresh.length ? `${there.actions.length - fresh.length} are left out: an action of that name is here already.` : '', fresh.length > 0));
        if (fresh.length) rows.push(listed(fresh.map(ofAction)));
      }
      if (there.alerts) {
        const KINDS_TOLD = { offline: 'went offline', no_signal: 'lost its picture', problem: 'has a problem', recovered: 'is over' };
        const about = there.alerts.kinds.map(kind => KINDS_TOLD[kind] || kind).join(', ') || 'nothing';
        rows.push(row('alerts', 'Alert settings',
          `Replaces what is set here: alerts ${there.alerts.enabled ? 'on' : 'off'}, told about: ${about}. ${there.alerts.address ? `They will go to ${there.alerts.host}, the address in the file.` : 'The address this wall sends them to is kept.'}`, true));
        boxes[boxes.length - 1].box.checked = false;  // what replaces something is asked for, not assumed
      }
      if (there.wall && Object.keys(there.wall).length) {
        rows.push(row('wall', 'Wall settings', `Replaces what is set here: ${[
          there.wall.interval && `a picture every ${there.wall.interval} s`,
          there.wall.update_check !== undefined && (there.wall.update_check ? 'asks once a day whether there is a newer version' : 'does not ask for newer versions'),
        ].filter(Boolean).join(', ')}.`, true));
        boxes[boxes.length - 1].box.checked = false;
      }
      // (Only what is there: handed a `false`, the browser writes the word.)
      found.replaceChildren(...[
        h('p', { class: 'muted' }, [
          there.encrypted ? 'An encrypted file' : 'A plain file',
          there.program && `made by qKVM ${there.program}`,
          there.made ? `on ${new Date(there.made * 1000).toLocaleDateString()}` : '',
        ].filter(Boolean).join(', ') + '.'),
        !there.encrypted && there.secrets && h('div', { class: 'note warn' }, 'This file holds passwords in plain text. Whoever wrote it chose to; delete it once it is taken in.'),
        h('div', {}, rows),
        there.left_out.length > 0 && h('div', { class: 'note warn' },
          `${there.left_out.length} ${there.left_out.length === 1 ? 'entry was' : 'entries were'} left out: `, there.left_out.slice(0, 5).join('; '), there.left_out.length > 5 ? '…' : ''),
        !rows.length && h('p', {}, 'There is nothing in this file to take in.'),
      ].filter(Boolean));
      read.hidden = true;
      take.hidden = !boxes.some(part => !part.box.disabled);
    };
    take.addEventListener('click', () => busy(take, async () => {
      error.hidden = true;
      const wanted = boxes.filter(part => part.box.checked).map(part => part.key);
      if (!wanted.length) return fail('Tick what is to be taken in.');
      if (!shown) return fail('Read the file first.');
      let done;
      try {
        done = await api('POST', 'api/v1/import', { ...shown, take: wanted }, 120000);
      } catch (ex) {
        return fail(ex.message);
      }
      close();
      toast([`${done.devices} ${done.devices === 1 ? 'device' : 'devices'} added`, done.actions ? `${done.actions} saved actions` : '',
        done.alerts ? 'alert settings replaced' : '', done.wall ? 'wall settings replaced' : ''].filter(Boolean).join(', '), 'ok');
      onDone();
    }));
    passphrase.input.addEventListener('input', () => { if (!read.hidden) return; again(); });
    body.append(h('form', { onsubmit: event => { event.preventDefault(); if (!read.hidden) busy(read, look); } },
      field('File', file, 'A .qkvm or .json file that qKVM exported.'),
      passphrase.el,
      found,
      error,
      h('div', { class: 'actions' },
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        read,
        take)));
  });
}

async function filesTab(refresh, does) {
  const toFile = h('button', { type: 'button' }, icon('download'), 'Export…');
  toFile.addEventListener('click', exportDialog);
  const fromFile = h('button', { type: 'button', class: 'primary' }, icon('upload'), 'Import…');
  fromFile.addEventListener('click', () => importDialog(() => { refresh(); reloadWall(); }));
  does.append(toFile, fromFile);
  return [
    h('p', { class: 'intro' }, 'The KVMs and servers on this wall, the saved actions and the alert settings can be written to a file, and a file can be taken in here or on another qKVM.'),
    block('A file is one of two kinds',
      setting('Encrypted (.qkvm)', 'Made with a passphrase you choose. It holds the passwords of the devices, the saved texts and the address alerts go to, and opens with that passphrase only.'),
      setting('Plain (.json)', 'Made without a passphrase. The same, with every password and saved text left out: its devices ask for their password where they are taken in.')),
    block('Taking a file in',
      setting('Adds what is not here yet', 'Nothing on this wall is changed or removed by it. The alert and wall settings are replaced only where you tick them.')),
    h('p', { class: 'footnote' }, 'Accounts, tokens, two-factor keys and the recovery key are in no such file: each belongs to the qKVM it was made on. To keep a whole qKVM, accounts and all, keep a copy of its data folder.'),
  ];
}

async function metricsTab(refresh, does) {
  const state = await api('GET', 'api/v1/metrics');
  const address = new URL('metrics', document.baseURI).href;
  const shown = h('div', { class: 'made' });  // the token, for as long as this section stays open after it was made
  const make = h('button', { type: 'button', class: 'primary' }, state.enabled ? 'Make a new token' : 'Switch on and make a token');
  make.addEventListener('click', () => busy(make, async () => {
    if (state.enabled && !(await confirmBox({
      title: 'Make a new token?',
      message: 'The token in use now stops working at once. Whatever collects the metrics has to be given the new one.',
      action: 'Make a new token',
    }))) return;
    let made;
    try {
      made = await api('POST', 'api/v1/metrics/token');
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    state.enabled = true;
    make.textContent = 'Make a new token';
    off.hidden = false;
    how.textContent = 'On. The token was made just now.';
    const once = shownOnce(made.token, 'Metrics token');
    shown.replaceChildren(
      h('div', { class: 'note' }, h('strong', {}, 'This token is shown once.'), ' qKVM keeps only what it needs to recognise it.'),
      once,
      h('p', { class: 'muted' }, 'For Prometheus, in the job that collects from qKVM:'),
      h('pre', { class: 'notes' }, `metrics_path: /metrics\nauthorization:\n  credentials: ${made.token}\nstatic_configs:\n  - targets: ['${location.host}']`));
    $('input', once).focus();
  }));
  const off = h('button', { type: 'button', class: 'danger', hidden: !state.enabled }, 'Switch off');
  off.addEventListener('click', () => busy(off, async () => {
    try {
      await api('DELETE', 'api/v1/metrics/token');
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    toast('Metrics are off', 'ok');
    refresh();
  }));
  does.append(off, make);
  const how = h('small', {}, state.enabled ? `On. The token was made ${ago(Date.now() / 1000 - state.created)}.` : 'Off: the address answers nobody.');
  return [
    h('p', { class: 'intro' }, 'A monitoring system can collect the state of the wall from qKVM: how many machines are online, and for each one '
      + 'whether it answers, whether it has a picture, when it was last heard from and how warm it is.'),
    shown,
    block(null,
      h('div', { class: 'setting' }, h('div', { class: 'what' }, h('strong', {}, 'Collected from'), how), h('div', { class: 'does' }, h('code', {}, address)))),
    h('p', { class: 'footnote' }, 'It is given to whoever sends the token, without signing in, so the token is to be kept like a password. '
      + 'It lets its holder read what is listed above and nothing else. While metrics are on, qKVM goes on watching the machines '
      + 'after the last person has signed out, as it does for alerts.'),
  ];
}

async function alertsTab(refresh, does) {
  const state = await api('GET', 'api/v1/alerts');
  const enabled = h('input', { type: 'checkbox', checked: state.enabled });
  const url = h('input', {
    type: 'text', inputMode: 'url', spellcheck: false, autocomplete: 'off',
    placeholder: state.has_webhook ? 'Saved. Enter another address to replace it.' : 'https://ntfy.sh/your-topic',
  });
  const format = h('select', {}, [
    ['auto', 'Work it out from the address'], ['ntfy', 'ntfy'], ['slack', 'Slack'], ['discord', 'Discord'], ['json', 'JSON, for anything else'],
  ].map(([value, label]) => h('option', { value }, label)));
  format.value = state.format;
  const kinds = [
    ['offline', 'A KVM goes offline', 'It stopped answering.'],
    ['no_signal', 'A computer loses its picture', 'Powered off, asleep, or unplugged from the KVM.'],
    ['problem', 'A KVM has a problem', 'Its login is rejected, or its certificate changed.'],
    ['recovered', 'It is over', 'The KVM answers again, or the picture is back.'],
  ].map(([key, label, hint]) => {
    const box = h('input', { type: 'checkbox', checked: state[key] });
    return { key, box, row: check(box, label, hint) };
  });
  const forget = h('input', { type: 'checkbox' });
  // Where an alert leads: this wall, as whoever sets it up reaches it. Offered, not assumed: a phone on the
  // road may need another address than the desk this is typed at.
  const link = h('input', {
    type: 'text', inputMode: 'url', spellcheck: false, autocomplete: 'off', value: state.link || `${location.origin}${location.pathname}`,
  });
  const pause = minutes => async () => {
    try {
      await api('POST', 'api/v1/alerts/pause', { minutes });
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    toast(minutes ? 'Alerts paused' : 'Alerts are sent again', 'ok');
    refresh();
  };
  const test = h('button', { type: 'button', disabled: !state.has_webhook }, 'Send a test alert');
  test.addEventListener('click', () => busy(test, async () => {
    try {
      await api('POST', 'api/v1/alerts/test');
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    toast('Test alert sent', 'ok');
  }));
  const form = h('form', {
    id: 'alerts-form',
    onsubmit: event => {
      event.preventDefault();
      busy(save, async () => {
        const body = { enabled: enabled.checked, webhook: url.value, forget_webhook: forget.checked, format: format.value, link: link.value };
        for (const kind of kinds) body[kind.key] = kind.box.checked;
        try {
          await api('PUT', 'api/v1/alerts', body);
        } catch (ex) {
          toast(ex.message, 'error');
          return;
        }
        toast('Alerts saved', 'ok');
        refresh();
      });
    },
  },
    block(null,
      check(enabled, 'Watch the KVMs and send alerts', 'A change counts once it has lasted about half a minute, so one hiccup stays quiet.'),
      !state.last_error && state.last_sent && setting('Last alert', null,
        h('span', { class: 'value' }, `Delivered ${ago(Date.now() / 1000 - state.last_sent)}`))),
    block('Send them to',
      field('Address', url, 'A webhook address: an ntfy topic, a Slack or Discord incoming webhook, or any address that takes a POST. '
        + 'It is stored encrypted and never shown again.'),
      field('Service', format, 'How the alert is written, for whoever receives it.'),
      state.has_webhook && check(forget, 'Forget the saved address', 'Alerts then go nowhere until another address is given.'),
      field('Link in alerts', link, 'The address of this wall. An alert then leads to the tile it is about. Leave empty for alerts without a link.')),
    block('Tell me when', kinds.map(kind => kind.row)));
  const save = saves(form);
  does.append(test, save);
  const until = state.paused_until && new Date(state.paused_until * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return [
    state.last_error && h('div', { class: 'note bad' }, `The last alert could not be delivered: ${state.last_error}`),
    form,
    block('Maintenance', state.paused_until
      ? setting(`Paused until ${until}`, 'Nothing is sent meanwhile. What is not as it was by then is told then.',
        h('button', { type: 'button', onclick: pause(0) }, 'Send alerts again'))
      : setting('Pause alerts', 'While machines are worked on. What is still wrong when the time is over is told then.',
        h('button', { type: 'button', onclick: pause(60) }, 'For an hour'),
        h('button', { type: 'button', onclick: pause(240) }, 'For four hours'))),
    h('p', { class: 'footnote' },
      'A single machine that is not to be heard about at all: Settings → KVMs → Edit. ',
      'Without an address, changes are still written to the activity log. While alerts are on, qKVM keeps watching after ',
      'everyone has signed out, which means the saved KVM passwords stay unlocked in its memory until it is restarted. ',
      'After a restart, watching begins when someone signs in. A JetKVM that is not on screen is only checked for answering, ',
      'not for its picture.'),
  ];
}

// --- about ---------------------------------------------------------------------------------------

const SITE = 'https://qkvm.com';
const REPO = 'https://github.com/qkvm/qkvm';
const DOCS = 'https://docs.qkvm.com';
const PYPV = 'https://pypv.com';
const COPYRIGHT = '© 2026 qKVM';
const LICENCE = 'https://www.gnu.org/licenses/agpl-3.0.html';

async function aboutTab() {
  const version = $('meta[name="qkvm-version"]').content;
  let running = {};
  try {
    running = await api('GET', 'api/v1/about');
  } catch { /* said without it: the page knows its own version */ }
  const outside = (href, text) => h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);
  const place = (href, hint) => h('a', { class: 'setting', href, target: '_blank', rel: 'noopener noreferrer' },
    h('div', { class: 'what' }, h('strong', {}, href.replace('https://', '')), h('small', {}, hint)),
    h('div', { class: 'does' }, icon('external')));
  return [
    h('div', { class: 'about-lead' },
      h('div', { class: 'brand' }, h('img', { src: 'static/favicon.svg', alt: '' }),
        h('span', { class: 'wordmark' }, h('b', {}, 'q'), 'KVM'),
        h('span', { class: 'muted' }, `Version ${running.version || version}`)),
      h('p', {}, 'A self-hosted screen wall and command center for IP KVMs and servers. Nothing goes through anyone’s cloud: ',
        'qKVM talks to each KVM directly, over your network or VPN.')),
    block('Where to find it',
      place(SITE, 'Website'),
      place(DOCS, 'Documentation'),
      place(REPO, 'Source code, releases and the place to report a problem')),
    h('section', { class: 'block text' },
      h('h3', {}, 'Licence'),
      h('p', {}, 'qKVM is free software under the ', outside(LICENCE, 'GNU Affero General Public License, version 3'),
        ` (${running.licence || 'AGPL-3.0-only'}). You may use it, study it, change it and share it.`),
      h('p', { class: 'muted' }, 'If you pass it on, or run a changed version for other people to use over a network, the licence asks you to offer ',
        'them the source of what you run, under the same licence. It comes with no warranty. The licence itself is in the file LICENSE of the source.')),
    // What it stands on, to the version: for those who look after it (an admin is told; nobody else is).
    running.libraries && h('section', { class: 'block' },
      h('h3', {}, 'Runs on'),
      h('p', { class: 'intro' }, `Python ${running.python} on ${running.system}, and these libraries, each under its own licence:`),
      h('div', { class: 'lines' }, h('table', { class: 'rows libraries' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Library'), h('th', {}, 'Version'), h('th', {}, 'Licence'))),
        h('tbody', {}, running.libraries.map(library => h('tr', {},
          h('td', {}, library.name), h('td', {}, library.version), h('td', { class: 'wrap' }, library.licence))))))),
    h('p', { class: 'footnote' }, COPYRIGHT, '. qKVM is part of ', h('strong', {}, outside(PYPV, 'PyPV, Python Platform Ventures')), '. ',
      'qKVM is not affiliated with GL.iNet, PiKVM or JetKVM, or with the makers of the servers it talks to; those names belong to their owners.'),
  ];
}

// --- settings ------------------------------------------------------------------------------------

const EVENTS = {
  setup: 'qKVM set up', login: 'Signed in', login_failed: 'Wrong password', logout: 'Signed out',
  password_changed: 'Password changed', device_added: 'KVM added', device_changed: 'KVM changed',
  device_moved: 'KVM followed to its other address',
  device_removed: 'KVM removed', certificate_trusted: 'Certificate trusted', action: 'Action',
  action_failed: 'Action failed', console_opened: 'Console opened', settings_changed: 'Network settings changed',
  saved_action_added: 'Action saved', saved_action_changed: 'Saved action changed', saved_action_removed: 'Saved action removed',
  update_installed: 'Update installed', update_failed: 'Update failed',
  user_added: 'Account added', user_changed: 'Account changed', user_removed: 'Account removed',
  totp_enabled: 'Two-factor switched on', totp_disabled: 'Two-factor switched off', alert: 'Alert',
  password_recovered: 'Password replaced with the recovery key', recovery_failed: 'Wrong recovery key',
  recovery_key_created: 'Recovery key created',
  metrics_token_created: 'Metrics token created', metrics_switched_off: 'Metrics switched off',
  unlocked_at_start: 'Carried on by itself after a restart', unlock_at_start_on: 'Carries on by itself after a restart from now on',
  unlock_at_start_off: 'No longer carries on by itself after a restart',
  settings_restored: 'Settings file unreadable: read from its second copy',
  export_made: 'The wall exported to a file', import_done: 'A file taken in',
  login_code_asked: 'Password right, second step asked for',
  log_gap: 'Entries are missing from this log: it could not be written',
  alerts_paused: 'Alerts paused', alerts_resumed: 'Alerts sent again',
  totp_codes_created: 'New one-time codes made', security_changed: 'Two-factor rule changed',
  token_created: 'Token made', token_removed: 'Token taken back', display_opened: 'Wall screen opened with its link',
  wall_arranged: 'Order of the tiles set',
  user_suspended: 'Account suspended', user_resumed: 'Account no longer suspended', user_signed_out: 'Account signed out everywhere',
};
const ACTION_NAMES = {
  reboot: 'Reboot KVM', ctrl_alt_del: 'Ctrl+Alt+Del', atx_power: 'Power button', power_on: 'Power on', power_off: 'Shut down',
  atx_power_long: 'Power button held', atx_reset: 'Reset button', wol: 'Wake-on-LAN',
  keys: 'Keys', text: 'Typed text', custom: 'Saved action', jiggler_on: 'Keep awake', jiggler_off: 'Allow sleep',
  port: 'Port switched', resume: 'Picture taken back',
};

const TAB_ICONS = {
  devices: 'grid', actions: 'zap', users: 'users', network: 'globe', security: 'shield', updates: 'download', activity: 'list',
  about: 'info', alerts: 'bell', metrics: 'activity', tokens: 'code', files: 'archive',
};

// The sections of the settings, in the groups they are listed under: [key, name, what is in it, what draws it].
// A row of tabs did for five of them. With eleven it had come to wrap, and nothing said which belonged together.
const SETTINGS = [
  ['The wall', [
    ['devices', 'KVMs', 'The KVMs and servers on the wall: add, change, remove.', devicesTab],
    ['actions', 'Actions', 'Key combinations and text of your own, to run on any machine.', actionsTab],
    ['alerts', 'Alerts', 'Who is told when a machine changes, and how.', alertsTab],
    ['files', 'Export and import', 'The wall as a file: to keep, or to take to another qKVM.', filesTab],
  ]],
  ['People', [
    ['users', 'Accounts', 'Who may sign in, as what, and to which machines.', usersTab],
    ['tokens', 'Tokens', 'For scripts, and for screens on the wall.', tokensTab],
    ['security', 'Security', 'Your own password, second step and sessions.', securityTab],
  ]],
  ['This qKVM', [
    ['network', 'Network', 'Where it listens, and how.', networkTab],
    ['metrics', 'Metrics', 'Numbers for a monitoring system to collect.', metricsTab],
    ['activity', 'Activity', 'Who signed in, changed what, and did what to which machine.', activityTab],
    ['updates', 'Updates', 'The version that is running, and newer ones.', updatesTab],
    ['about', 'About', 'What this is, whose it is, and under which licence.', aboutTab],
  ]],
];

function settingsDialog(first) {
  openDialog('Settings', body => {
    // Someone who is not an admin can still change their own password and sign out elsewhere; a screen on the
    // wall has not even that.
    const mine = key => can('admin') || key === 'about' || (key === 'security' && !me?.token);
    const groups = SETTINGS.map(([group, sections]) => [group, sections.filter(([key]) => mine(key))]).filter(([, sections]) => sections.length);
    const all = new Map(groups.flatMap(([, sections]) => sections.map(section => [section[0], section])));
    const pane = h('div', { class: 'section', role: 'tabpanel' });
    const nav = h('nav', { class: 'sections', role: 'tablist', 'aria-orientation': 'vertical', 'aria-label': 'Settings' });
    const buttons = new Map();
    let current = null;
    let loads = 0;
    const show = async key => {
      current = key;
      prefs.set('settings', key);  // opened next time where it was left
      const turn = ++loads;  // a section that loads slowly must not replace the one chosen after it
      const [, label, about, draw] = all.get(key);
      for (const [name, button] of buttons) {
        button.setAttribute('aria-selected', String(name === key));
        button.tabIndex = name === key ? 0 : -1;
      }
      buttons.get(key).scrollIntoView({ block: 'nearest', inline: 'nearest' });
      // What the section is, at the left; what one does in it ("Add", "New"), at the right of the same line,
      // where it is looked for. The section puts its own buttons there.
      const does = h('div', { class: 'section-does' });
      const head = h('header', { class: 'section-head' },
        h('div', { class: 'section-what' }, h('strong', {}, label), h('span', { class: 'muted' }, about)), does);
      pane.replaceChildren(head, h('p', { class: 'loading' }, h('span', { class: 'spinner' }), 'Loading…'));
      pane.scrollTop = 0;
      let content;
      try {
        // A section asks to be drawn again after a change; by then another one may be showing.
        content = [await draw(() => { if (current === key) show(key); }, does)].flat().filter(Boolean);
      } catch (ex) {
        does.replaceChildren();
        content = [h('p', { class: 'error' }, ex.message)];
      }
      if (turn === loads) pane.replaceChildren(head, ...content);
    };
    for (const [group, sections] of groups) {
      if (groups.length > 1) nav.append(h('span', { class: 'group' }, group));
      for (const [key, label] of sections) {
        const button = h('button', { type: 'button', role: 'tab', dataset: { tab: key }, onclick: () => show(key) }, icon(TAB_ICONS[key]), label);
        buttons.set(key, button);
        nav.append(button);
      }
    }
    // Up and down (or left and right, where they lie in a row) go from one section to the next, as in any list of tabs.
    nav.addEventListener('keydown', event => {
      const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[event.key];
      if (!step) return;
      event.preventDefault();
      const keys = [...buttons.keys()];
      const next = keys[(keys.indexOf(current) + step + keys.length) % keys.length];
      buttons.get(next).focus();
      show(next);
    });
    body.append(nav, pane);
    const wanted = first || prefs.get('settings', '');
    show(all.has(wanted) ? wanted : all.keys().next().value);
  }, { size: 'settings' });
}

// Who may sign in, as what, and which KVMs they see.
async function usersTab(refresh, does) {
  const [{ users }, { devices }, rule] = await Promise.all([api('GET', 'api/v1/users'), api('GET', 'api/v1/wall'), api('GET', 'api/v1/security')]);
  does.append(h('button', { type: 'button', class: 'primary', onclick: () => editUserDialog(null, devices, refresh) }, icon('plus'), 'Add account'));
  const required = h('select', {}, [
    ['', 'Nobody: each account decides for itself'], ['admin', 'Admins'], ['operator', 'Admins and operators'], ['viewer', 'Everybody'],
  ].map(([value, label]) => h('option', { value }, label)));
  required.value = rule.require_totp;
  required.addEventListener('change', async () => {
    try {
      await api('PUT', 'api/v1/security', { require_totp: required.value });
    } catch (ex) {
      toast(ex.message, 'error');
      required.value = rule.require_totp;
      return;
    }
    toast('Saved', 'ok');
    refresh();
  });
  const names = new Map(devices.map(device => [device.id, device.name]));
  const sees = user => {
    if (user.role === 'admin' || user.devices === null) return 'All KVMs';
    const known = [...(user.groups || []).map(group => `everything in ${group}`), ...user.devices.filter(id => names.has(id)).map(id => names.get(id))];
    return known.length ? known.join(', ').replace(/^e/, 'E') : 'No KVMs';
  };
  return [
    h('p', { class: 'intro' },
      'Admins manage everything. Operators see the wall and run actions on the machines. Viewers only see the wall. ',
      'An operator or a viewer can be limited to some of the KVMs.'),
    listed(h('table', { class: 'rows' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Role'), h('th', {}, 'Can see'), h('th', {}))),
      h('tbody', {}, users.map(user => h('tr', {},
        h('td', { class: 'wrap' }, user.name, user.you && h('span', { class: 'muted' }, ' (you)'),
          user.suspended && h('div', { class: 'muted' }, 'Suspended'),
          user.totp && h('div', { class: 'muted' }, 'Two-factor sign-in on'),
          user.must_enroll && h('div', { class: 'muted' }, 'Has to set up two-factor sign-in'),
          user.sessions > 0 && !user.you && h('div', { class: 'muted' }, 'Signed in now')),
        h('td', {}, ROLE_NAMES[user.role]),
        h('td', { class: 'wrap' }, sees(user)),
        h('td', {},
          h('button', { type: 'button', onclick: () => editUserDialog(user, devices, refresh) }, 'Edit'),
          !user.you && h('button', { type: 'button', class: 'danger', onclick: () => removeUser(user, refresh) }, 'Remove'))))))),
    block('Two-factor sign-in',
      field('Required of', required, rule.without.length
        ? `Still to set it up: ${rule.without.join(', ')}. They can sign in with their password, and do nothing but set it up.`
        : 'An account it is required of signs in with its password once more, to set it up, and to nothing else until that is done.')),
  ];
}

// "Which machines": all of them, or whole groups (with whatever is added to them later) and single machines.
// read() gives { devices, groups } as the server takes them.
function machinePicker(devices, chosen) {
  const all = h('input', { type: 'checkbox', checked: !chosen || chosen.devices === null });
  const named = [...new Set(devices.map(device => device.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const has = group => (chosen?.groups || []).some(name => name.toLowerCase() === group.toLowerCase());
  const groups = named.map(group => {
    const box = h('input', { type: 'checkbox', checked: has(group) });
    return { group, box, row: check(box, `Everything in ${group}`, 'Also what is added to it later.') };
  });
  const picks = devices.map(device => {
    const box = h('input', { type: 'checkbox', checked: Boolean(chosen?.devices?.includes(device.id)) });
    return { id: device.id, box, row: check(box, device.name, device.group ? `${device.host} · ${device.group}` : device.host) };
  });
  const list = h('div', { class: 'picklist' }, groups.map(pick => pick.row), picks.map(pick => pick.row),
    !devices.length && h('p', { class: 'muted' }, 'There are no KVMs yet.'));
  const sync = () => { list.hidden = all.checked; };
  all.addEventListener('change', sync);
  sync();
  return {
    el: h('div', {}, h('h3', {}, 'KVMs'), check(all, 'All KVMs', 'Including the ones added later.'), list),
    read: () => (all.checked ? { devices: null, groups: [] } : {
      devices: picks.filter(pick => pick.box.checked).map(pick => pick.id),
      groups: groups.filter(pick => pick.box.checked).map(pick => pick.group),
    }),
  };
}

function editUserDialog(user, devices, onDone) {
  openDialog(user ? `Edit ${user.name}` : 'Add account', (body, close) => {
    const name = h('input', {
      type: 'text', value: user?.name || '', required: true, maxLength: 64, autocomplete: 'off', spellcheck: false,
      pattern: '[A-Za-z0-9][A-Za-z0-9._@+\\-]{0,63}', title: 'Letters, digits, dot, dash, underscore, @ and +',
    });
    const role = h('select', {}, Object.entries(ROLE_NAMES).map(([value, label]) => h('option', { value }, label)));
    role.value = user?.role || 'viewer';
    role.disabled = Boolean(user?.you);  // nobody changes their own role: that is how the last admin gets lost
    const roleHint = h('p', { class: 'muted' });
    const { el: passwordBox, input: password } = passwordField(user ? 'New password' : 'Password', {
      autocomplete: 'new-password', required: !user && !ssoOn, minLength: minPassword, placeholder: user ? 'Unchanged' : '',
    }, user
      ? 'Leave empty to keep the current one. A new one signs the account out everywhere.'
      : ssoOn
        ? `Leave empty for somebody your identity provider signs in: the name above is then what it calls them. Otherwise at least ${minPassword} characters.`
        : `At least ${minPassword} characters. They can change it after signing in.`);
    const totpOff = h('input', { type: 'checkbox' });
    const machines = machinePicker(devices, user);
    const access = machines.el;
    const onHold = h('input', { type: 'checkbox', checked: Boolean(user?.suspended) });
    const sync = () => {
      roleHint.textContent = ROLE_HINTS[role.value] + (user?.you ? ' You cannot change your own role.' : '');
      access.hidden = role.value === 'admin';
    };
    role.addEventListener('change', sync);
    sync();
    const error = h('p', { class: 'error', hidden: true });
    const save = h('button', { type: 'submit', class: 'primary' }, user ? 'Save' : 'Add account');

    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        busy(save, async () => {
          const account = {
            name: name.value.trim(), role: role.value, password: user?.you ? '' : password.value, totp_off: totpOff.checked,
            ...(role.value === 'admin' ? { devices: null, groups: [] } : machines.read()),
            suspended: onHold.checked,
          };
          try {
            if (user) await api('PUT', `api/v1/users/${user.id}`, account);
            else await api('POST', 'api/v1/users', account);
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            return;
          }
          if (user?.you) setMe({ ...me, name: account.name });
          close();
          toast(user ? `${account.name} saved` : `${account.name} added`, 'ok');
          onDone();
        });
      },
    },
      h('div', { class: 'row' }, field('User name', name), field('Role', role)),
      roleHint,
      user?.you ? h('p', { class: 'muted' }, 'Your own password and second step are changed under Security, where your current password is asked for.') : passwordBox,
      user?.totp && !user.you && check(totpOff, 'Switch off their two-factor sign-in',
        'For a lost phone. Their password alone signs them in until they set it up again.'),
      access,
      user && !user.you && check(onHold, 'Suspended', 'Cannot sign in until this is lifted, and is signed out now. Password, role and limits are kept.'),
      error,
      h('div', { class: 'actions' },
        user && !user.you && user.sessions > 0 && h('button', {
          type: 'button', class: 'left',
          onclick: async event => {
            try {
              const { ended } = await api('POST', `api/v1/users/${user.id}/logout`);
              toast(`${user.name} signed out of ${ended} browser${ended === 1 ? '' : 's'}`, 'ok');
              event.target.remove();
              onDone();
            } catch (ex) {
              toast(ex.message, 'error');
            }
          },
        }, 'Sign out everywhere'),
        h('button', { type: 'button', onclick: close }, 'Cancel'),
        save)));
    name.focus();
  });
}

async function removeUser(user, onDone) {
  const sure = await confirmBox({
    title: `Remove ${user.name}?`,
    message: 'The account is signed out everywhere and can no longer sign in.',
    action: 'Remove',
  });
  if (!sure) return;
  try {
    await api('DELETE', `api/v1/users/${user.id}`);
  } catch (ex) {
    toast(ex.message, 'error');
    return;
  }
  toast(`${user.name} removed`, 'ok');
  onDone();
}

async function devicesTab(refresh, does) {
  const { devices } = await api('GET', 'api/v1/wall');
  const changed = () => { refresh(); reloadWall(); };
  const modes = { pinned: 'Certificate remembered', system: 'Public certificate', insecure: 'Not checked' };
  does.append(h('button', {
    type: 'button',
    class: 'primary',
    onclick: () => openDialog('Add KVMs', body => body.append(addDevicesForm(changed))),
  }, icon('plus'), 'Add KVMs'));
  return [
    listed(devices.length > 0 && h('table', { class: 'rows' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Address'), h('th', {}, 'Connection'), h('th', {}))),
      h('tbody', {}, devices.map(device => h('tr', {},
        h('td', { class: 'wrap' }, device.name,
          device.same_as?.length > 0 && h('div', { class: 'error' }, `Same device as ${device.same_as.map(twin => twin.name).join(', ')}`)),
        h('td', { class: 'wrap' }, device.host, h('div', { class: 'muted' }, KINDS[device.kind] || device.kind)),
        h('td', {}, device.url.startsWith('https') ? modes[device.tls] : 'Unencrypted (http)',
          !device.has_password && device.kind !== 'jetkvm' && h('div', { class: 'error' }, 'No password saved')),
        h('td', {},
          h('button', { type: 'button', onclick: () => editDeviceDialog(device, changed) }, 'Edit'),
          h('button', { type: 'button', class: 'danger', onclick: () => removeDevice(device, changed) }, 'Remove')))))),
      'No KVMs yet. Add the first one with the button above.'),
  ];
}

// The user's own actions: key combinations and text to type, offered in every action menu.
async function actionsTab(refresh, does) {
  const actions = await loadSavedActions();
  does.append(h('button', { type: 'button', class: 'primary', onclick: () => editActionDialog(null, refresh) }, icon('plus'), 'New action'));
  const remove = async action => {
    const sure = await confirmBox({
      title: `Remove “${action.name}”?`,
      message: 'It disappears from the action menu of every KVM.',
      action: 'Remove',
    });
    if (!sure) return;
    try {
      await api('DELETE', `api/v1/actions/${action.id}`);
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    refresh();
  };
  return [
    h('p', { class: 'intro' },
      'Save the key combinations and commands you use often. They appear in the action menu of every KVM, ',
      'and can be run on many KVMs at once.'),
    listed(actions.length > 0 && h('table', { class: 'rows' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Does'), h('th', {}))),
      h('tbody', {}, actions.map(action => h('tr', {},
        h('td', { class: 'wrap' }, action.name, action.danger && h('span', { class: 'muted' }, ' · asks twice')),
        h('td', {}, action.kind === 'keys'
          ? h('kbd', {}, keysLabel(action.keys))
          : `Types saved text${action.enter ? ', then Enter' : ''}`),
        h('td', {},
          h('button', { type: 'button', onclick: () => editActionDialog(action, refresh) }, 'Edit'),
          h('button', { type: 'button', class: 'danger', onclick: () => remove(action) }, 'Remove')))))),
      'None yet.'),
  ];
}

// Create (action = null) or change one of the user's own actions.
function editActionDialog(action, onDone) {
  openDialog(action ? `Edit “${action.name}”` : 'New action', (body, close) => {
    const name = h('input', { type: 'text', value: action?.name || '', maxLength: 60, required: true, placeholder: 'Restart print spooler' });
    const kinds = ['keys', 'text'].map(kind => h('input', { type: 'radio', name: 'kind', value: kind, checked: (action?.kind || 'keys') === kind }));
    const picker = keyPicker(action?.kind === 'keys' ? action.keys : '');
    const keepsText = action?.kind === 'text';
    const text = h('textarea', {
      rows: 4, maxLength: 2000, spellcheck: false,
      placeholder: keepsText ? 'Leave empty to keep the saved text' : 'net stop spooler && net start spooler',
    });
    const enter = h('input', { type: 'checkbox', checked: action ? action.enter : true });
    const danger = h('input', { type: 'checkbox', checked: Boolean(action?.danger) });
    const keysPane = h('div', {}, h('p', { class: 'muted' }, 'Pressed together on the connected computer, then released.'), picker.el);
    const textPane = h('div', {},
      field('Text to type', text,
        'Typed as if on the computer’s keyboard (US layout). Stored encrypted; it is never shown again or written to the activity log.'),
      check(enter, 'Press Enter afterwards'));
    const error = h('p', { class: 'error', hidden: true });
    const save = h('button', { type: 'submit', class: 'primary' }, 'Save');
    const kind = () => kinds.find(input => input.checked).value;
    const show = () => { keysPane.hidden = kind() !== 'keys'; textPane.hidden = kind() !== 'text'; };
    for (const input of kinds) input.addEventListener('change', show);
    show();

    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        busy(save, async () => {
          const payload = {
            name: name.value, kind: kind(), keys: picker.read(), text: text.value,
            enter: enter.checked, danger: danger.checked,
          };
          try {
            await api(action ? 'PUT' : 'POST', action ? `api/v1/actions/${action.id}` : 'api/v1/actions', payload);
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            return;
          }
          close();
          toast(`${name.value} saved`, 'ok');
          onDone();
        });
      },
    },
      field('Name', name),
      h('div', { class: 'row' },
        check(kinds[0], 'Key combination', 'Such as Win+L or Ctrl+Shift+Esc.'),
        check(kinds[1], 'Type text', 'A command, a path, a login.')),
      keysPane,
      textPane,
      check(danger, 'Ask for extra confirmation', 'For anything that restarts, deletes or logs out.'),
      error,
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), save)));
    name.focus();
  });
}

async function networkTab(refresh, does) {
  const settings = await api('GET', 'api/v1/settings');
  const network = networkForm(settings, true);
  const form = h('form', {
    id: 'network-form',
    onsubmit: event => {
      event.preventDefault();
      busy(save, async () => {
        try {
          if (!(await applyNetwork(network.read()))) toast('Settings saved', 'ok');
        } catch (ex) {
          toast(ex.message, 'error');
        }
      });
    },
  },
    block('Reachable from',
      network.listen,
      network.other.length > 0 && setting('Also listening on', 'Written into the settings file by hand, and kept as it is.',
        h('span', { class: 'value' }, network.other.join(', ')))),
    block('Connection', network.secure, network.more));
  const save = saves(form);
  does.append(save);
  return [
    settings.bind_error && h('div', { class: 'note bad' },
      `The last change could not be applied and was undone: ${settings.bind_error}`),
    settings.overridden && h('div', { class: 'note warn' },
      'qKVM was started with --bind or --port, which take priority over what is saved here.'),
    form,
    block('As it runs now',
      setting('Listening on', null, h('span', { class: 'value' }, settings.listening.join('  ') || 'unknown')),
      settings.cert_fingerprint && setting('Certificate', 'Its SHA-256 fingerprint, to compare with what a browser shows.',
        h('code', {}, settings.cert_fingerprint)),
      setting('Version', null, h('span', { class: 'value' }, `qKVM ${settings.version}, started ${ago(settings.uptime)}`))),
  ];
}

// --- updates ------------------------------------------------------------------------------------------

// Shows the "Update available" button in the top bar when there is something newer.
async function refreshUpdateBadge() {
  if (!can('admin')) return;
  let status;
  try {
    status = await api('GET', 'api/v1/update');
  } catch {
    return;
  }
  const badge = $('#update-badge');
  badge.hidden = !status.available;
  if (status.available) badge.title = `Version ${status.latest.version} is available`;
}

// After an update the wall restarts by itself; wait for the new version to answer, then load its page.
async function followRestart(version) {
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  showAuth('plain',
    h('h2', {}, `Updating to ${version}`),
    h('p', { class: 'loading' }, h('span', { class: 'spinner' }), 'qKVM is restarting. This page reloads by itself.'));
  for (let attempt = 0; attempt < 120; attempt++) {
    await sleep(1000);
    try {
      const health = await (await fetch('healthz', { cache: 'no-store', signal: AbortSignal.timeout(4000) })).json();
      if (health.version === version) {
        location.reload();
        return;
      }
    } catch { /* still restarting */ }
  }
  showAuth('plain',
    h('h2', {}, 'qKVM did not come back'),
    h('p', {}, `Version ${version} was installed, but it is not answering. If the new version could not start, `
      + 'the previous one is started again automatically; check its window or qkvm.log.'),
    h('div', { class: 'actions' }, h('button', { type: 'button', class: 'primary', onclick: () => location.reload() }, 'Reload')));
}

// Installing new code asks for the password again, like changing it does.
function installUpdateDialog(status, onDone) {
  const version = status.latest.version;
  openDialog(`Install version ${version}`, (body, close) => {
    const { el, input } = passwordField('Your password', { autocomplete: 'current-password', required: true });
    const error = h('p', { class: 'error', hidden: true });
    const install = h('button', { type: 'submit', class: 'primary' }, 'Install');
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        busy(install, async () => {
          let result;
          try {
            // The download is part of this request. Given up on after half a minute, the page would say
            // "took too long" while the new version is installed and started under it all the same.
            result = await api('POST', 'api/v1/update/install', { password: input.value }, ACTION_PATIENCE);
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            return;
          }
          close();
          if (result.restarting) {
            followRestart(version);
          } else {
            toast(`Version ${version} is installed. Restart qKVM to start using it.`, 'ok');
            refreshUpdateBadge();
            onDone();
          }
        });
      },
    },
      h('p', {}, status.supervised
        ? 'The new version is downloaded, checked, and installed next to the current one. qKVM then restarts by itself; everyone has to sign in again.'
        : 'The new version is downloaded, checked, and installed next to the current one. It takes effect the next time qKVM is started.'),
      h('p', { class: 'muted' }, 'If the new version cannot start, qKVM goes back to this one by itself.'),
      h('input', { type: 'text', autocomplete: 'username', value: me?.name || 'admin', hidden: true }),
      el,
      error,
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), install)));
    input.focus();
  });
}

async function updatesTab(refresh, does) {
  const status = await api('GET', 'api/v1/update');
  const latest = status.latest;
  const checkNow = h('button', { type: 'button', disabled: !status.repo }, icon('rotate'), 'Check for updates');
  checkNow.addEventListener('click', () => busy(checkNow, async () => {
    try {
      await api('POST', 'api/v1/update/check');
    } catch (ex) {
      toast(ex.message, 'error');
    }
    refreshUpdateBadge();
    refresh();
  }));
  const auto = h('input', { type: 'checkbox', checked: status.auto_check, disabled: !status.repo });
  auto.addEventListener('change', async () => {
    try {
      await api('PUT', 'api/v1/update', { auto_check: auto.checked });
    } catch (ex) {
      toast(ex.message, 'error');
    }
  });

  // What is so, in a sentence under the version; what needs doing something about, as a notice above it
  // (and then not said a second time under the version).
  let state = null;
  let notice = null;
  if (!status.repo) {
    notice = h('div', { class: 'note warn' },
      'Updates are not set up. This copy does not know which GitHub repository its releases are published in; ',
      'see “Publishing releases” in the README.');
  } else if (status.installed && !status.supervised) {
    notice = h('div', { class: 'note' }, `Version ${status.installed} is installed. Restart qKVM to start using it.`);
  } else if (status.available) {
    state = 'A newer version is available.';
  } else if (status.checked_ago == null) {
    state = 'Not checked for updates yet.';
  } else {
    state = `You have the newest version. Checked ${ago(status.checked_ago)}.`;
  }
  does.append(checkNow);
  if (status.available && !status.container && status.installable) {
    does.append(h('button', { type: 'button', class: 'primary', onclick: () => installUpdateDialog(status, refresh) },
      icon('download'), `Install ${latest.version}`));
  }

  return [
    notice,
    status.error && h('div', { class: 'note bad' }, status.error),
    status.available && status.container && h('div', { class: 'note' },
      'This copy runs in a container. To update it, get the new image and start the container from it:',
      h('code', {}, 'docker compose pull && docker compose up -d')),
    status.available && !status.container && !status.installable && h('div', { class: 'note' },
      'This copy has no release key built in, so it cannot tell who published an update and does not install one by itself. ',
      'Install the new version by hand, or start qKVM with ', h('code', {}, '--allow-unsigned-updates'), '.'),
    block(null,
      setting('This copy', state || 'The version that is running.', h('span', { class: 'value' }, `qKVM ${status.current}`)),
      status.available && setting(`Version ${latest.version}`,
        latest.published ? `Released ${new Date(latest.published).toLocaleDateString()}.` : null,
        /^https:\/\/github\.com\//.test(latest.url) && h('a', {
          class: 'btn', href: latest.url, target: '_blank', rel: 'noopener noreferrer',
        }, icon('external'), 'Release page'))),
    status.available && latest.notes && h('pre', { class: 'notes' }, latest.notes),
    block('How updates work',
      check(auto, 'Check automatically once a day',
        'Asks GitHub whether a newer release exists. Nothing about your KVMs is sent. Installing is always your decision.')),
    status.repo && h('p', { class: 'footnote' },
      `Releases come from github.com/${status.repo}. `,
      status.signed
        ? 'A release is installed only if it carries a valid signature from the publisher.'
        : status.installable
          ? 'qKVM was started with --allow-unsigned-updates: a download is only checked against the checksum published with it.'
          : 'This copy tells you about new versions and leaves installing them to you.'),
  ];
}

// One's own password, changed: asked for with the one it replaces, as everything is that changes who gets in.
function changePasswordDialog() {
  openDialog('Change password', (body, close) => {
    const boxes = [
      passwordField('Current password', { autocomplete: 'current-password', required: true }),
      passwordField('New password', { autocomplete: 'new-password', required: true }),
      passwordField('Repeat new password', { autocomplete: 'new-password', required: true }),
    ];
    const [current, next, again] = boxes.map(box => box.input);
    const coach = passwordCoach(next, again);
    const error = h('p', { class: 'error', hidden: true });
    const save = h('button', { type: 'submit', class: 'primary' }, 'Change password');
    body.append(h('form', {
      onsubmit: event => {
        event.preventDefault();
        error.hidden = true;
        const problem = coach.problem();
        if (problem) {
          error.textContent = problem;
          error.hidden = false;
          return;
        }
        busy(save, async () => {
          try {
            await api('POST', 'api/v1/password', { current: current.value, new: next.value });
          } catch (ex) {
            error.textContent = ex.message;
            error.hidden = false;
            current.select();
            return;
          }
          close();
          toast('Password changed. Other browsers were signed out.', 'ok');
        });
      },
    },
      h('input', { type: 'text', autocomplete: 'username', value: me?.name || 'admin', hidden: true }),
      boxes[0].el,
      boxes[1].el,
      coach.meter,
      boxes[2].el,
      coach.rules,
      error,
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), save)));
    current.focus();
  });
}

async function securityTab(refresh) {
  const asked = await api('GET', 'api/v1/session');
  const session = can('admin') ? asked : null;  // only admins deal with the recovery key
  const unattended = asked.unlocks_at_start;
  const signOut = scope => async () => {
    try {
      await api('POST', 'api/v1/logout', { scope });
    } catch (ex) {
      toast(ex.message, 'error');
      if (ex.code !== 'not_saved') return;
      if (scope === 'others') return;
      await sleep(8000);  // signed out all the same: time to read why a restart might undo it, then the page shows it
      location.reload();
      return;
    }
    if (scope === 'others') toast('Other browsers signed out', 'ok');
    else location.reload();
  };
  const does = (label, work, danger) => {
    const button = h('button', { type: 'button', class: danger ? 'danger' : '' }, label);
    button.addEventListener('click', () => busy(button, async () => work()));
    return button;
  };
  return [
    block('Sessions',
      setting('This browser', `Signed in as ${me?.name || 'you'}.`, does('Sign out', signOut('this'))),
      setting('Other browsers', 'Every other browser signed in as you has to enter the password again.',
        does('Sign out my other browsers', signOut('others')))),
    session && block('Recovery key',
      setting('Recovery key',
        session.recovery
          ? `The way back in when a password is forgotten. The current key is from ${new Date(session.recovery_created * 1000).toLocaleDateString()}; a new one replaces it.`
          : 'The way back in when a password is forgotten. None has been made yet.',
        does(session.recovery ? 'Create a new recovery key' : 'Create a recovery key', () => newRecoveryKey(refresh)))),
    block('Two-factor sign-in', me?.totp
      ? [
        setting('Second step', 'On: signing in asks for a code from your authenticator app.', does('Switch off…', () => twoFactorOff(refresh), true)),
        setting('One-time codes', `${me.recovery_codes} left. For signing in when the phone is not at hand; each works once.`,
          does('Make ten new ones…', () => newOneTimeCodes(refresh))),
      ]
      : setting('Second step', 'Off. With it, signing in also asks for a 6-digit code from an authenticator app on your phone.',
        does('Add a second step', () => twoFactorSetup(refresh)))),
    block('Password',
      setting('Password', 'Asked for with the one it replaces. Changing it signs your other browsers out.',
        does('Change password…', changePasswordDialog))),
    h('p', { class: 'footnote' },
      'KVM passwords are stored encrypted, and each account’s password can unlock them for the running program. ',
      unattended
        ? 'This qKVM opens them itself after a restart and carries on watching: the key for that is kept in its data folder, or where --unlock-file says. Whoever has that key and the data folder has the KVM passwords. Started with --locked-start, it keeps no such key.'
        : 'After a restart this qKVM cannot reach the KVMs until someone signs in: it was started with --locked-start, or nobody has signed in yet since it was told otherwise.'),
  ];
}

function eventLabel(entry) {
  if (entry.event === 'login_failed' && entry.step === 'code') return 'Wrong two-factor code';
  if (entry.event === 'settings_changed' && 'alerts' in entry) return entry.alerts ? 'Alerts saved (on)' : 'Alerts saved (off)';
  if (entry.event === 'settings_changed' && 'update_check' in entry) {
    return entry.update_check ? 'Daily update check switched on' : 'Daily update check switched off';
  }
  return EVENTS[entry.event] || entry.event;
}

async function activityTab(refresh, does) {
  const detail = entry => [
    entry.device, entry.account, ROLE_NAMES[entry.role], entry.name || ACTION_NAMES[entry.action] || entry.action,
    entry.event === 'alert' && `${LABELS[entry.was] || entry.was} → ${LABELS[entry.state] || entry.state}`,
    entry.held && 'not sent: alerts were paused', entry.minutes && `${entry.minutes} minutes`,
    entry.recovery_code && `with a one-time code (${entry.codes_left} left)`,
    entry.event === 'login_failed' && entry.suspended && 'the account is suspended',
    entry.event === 'login_failed' && entry.no_second_step && 'the key of its second step does not open',
    entry.no_such_account && 'no account of the name that was typed',
    entry.event === 'export_made' && (entry.encrypted ? 'encrypted, with the passwords' : 'plain, without passwords'),
    entry.event === 'export_made' && entry.not_opened && `${entry.not_opened} saved ${entry.not_opened === 1 ? 'secret' : 'secrets'} did not open and ${entry.not_opened === 1 ? 'is' : 'are'} not in it`,
    (entry.event === 'export_made' || entry.event === 'import_done') && Array.isArray(entry.parts) && entry.parts.map(part => FILE_PARTS[part] || part).join(', '),
    entry.event === 'import_done' && `${entry.devices} ${entry.devices === 1 ? 'device' : 'devices'} and ${entry.actions} saved ${entry.actions === 1 ? 'action' : 'actions'} added`,
    entry.event === 'log_gap' && `${entry.count} since ${new Date(entry.since * 1000).toLocaleString()} (${entry.why})`,
    entry.event === 'settings_restored' && entry.damaged && `the file is kept as ${entry.damaged}`,
    entry.event === 'settings_restored' && entry.why && `what was wrong with it: ${entry.why}`,
    entry.event === 'login' && entry.sso && 'by the identity provider', entry.sessions != null && `${entry.sessions} browsers`,
    entry.require_totp && `required of: ${{ admin: 'admins', operator: 'admins and operators', viewer: 'everybody' }[entry.require_totp] || 'nobody'}`,
    entry.action === 'port' && entry.port && `port ${entry.port}`,
    entry.keys && keysLabel(entry.keys), entry.chars && `${entry.chars} characters`, entry.mac,
    entry.batch && 'bulk run', entry.version && `version ${entry.version}`, entry.note, entry.error, entry.url,
  ].filter(Boolean).join(' · ');
  const line = entry => h('tr', {},
    h('td', { class: 'when' }, new Date(entry.time * 1000).toLocaleString()),
    h('td', {}, entry.user || ''),
    h('td', {}, eventLabel(entry)),
    h('td', { class: 'wrap' }, detail(entry)),
    h('td', {}, entry.ip));
  const find = h('input', {
    type: 'search', placeholder: 'A name, a machine, an address…', 'aria-label': 'Find in the activity log', spellcheck: false, autocomplete: 'off',
  });
  const kind = h('select', { 'aria-label': 'What kind' }, [
    ['', 'Everything'], ['signin', 'Signing in'], ['action', 'Actions on machines'], ['change', 'Changes'], ['alert', 'Alerts'],
  ].map(([value, label]) => h('option', { value }, label)));
  const rows = h('tbody', {});
  const none = h('p', { class: 'nothing', hidden: true }, 'Nothing found.');
  // A log that could not be written for a while has a hole in it, and says so: what was done then was done all the same.
  const hole = h('div', { class: 'note bad', hidden: true });
  const older = h('button', { type: 'button', class: 'link' }, 'Show older');
  const foot = h('div', { class: 'lines-foot', hidden: true }, older);  // the list's last line, while there is more of it
  const asked = () => {
    const typed = find.value.trim();
    const lower = typed.toLowerCase();
    // What is shown here ("Keep awake", "Wrong password") is not what the log is written with (jiggler_on,
    // login_failed). Somebody looks for what they see: it is asked for under both names.
    const also = typed.length < 3 ? [] : Object.entries({ ...EVENTS, ...ACTION_NAMES, ...LABELS })
      .filter(([, label]) => label.toLowerCase().includes(lower)).map(([key]) => key).slice(0, 15);
    return [...new Set([typed, ...also])].filter(Boolean).map(word => `q=${encodeURIComponent(word)}`).join('&') + `&kind=${kind.value}`;
  };
  let last = null;  // the time of the oldest entry shown: what comes next is older than that
  let turn = 0;
  const load = async more => {
    const mine = ++turn;  // an answer that comes after a newer question was asked is not shown
    let found;
    try {
      found = await api('GET', `api/v1/audit?limit=200&${asked()}${more && last ? `&before=${last}` : ''}`);
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    if (mine !== turn) return;
    if (!more) rows.replaceChildren();
    rows.append(...found.entries.map(line));
    if (found.entries.length) last = found.entries[found.entries.length - 1].time;
    foot.hidden = !found.more;
    none.hidden = rows.childElementCount > 0;
    const lost = found.missing;
    hole.hidden = !lost;
    if (lost) {
      hole.textContent = `${lost.count} ${lost.count === 1 ? 'entry is' : 'entries are'} missing from this log since `
        + `${new Date(lost.since * 1000).toLocaleString()}: it could not be written (${lost.why}). What was done in that time was done all the same.`;
    }
  };
  let typing = null;
  find.addEventListener('input', () => {
    clearTimeout(typing);
    typing = setTimeout(() => load(false), 300);
  });
  kind.addEventListener('change', () => load(false));
  older.addEventListener('click', () => busy(older, () => load(true)));
  // What is shown, or all of it when nothing is being looked for, as a file to keep or to hand on.
  const take = format => async () => {
    try {
      const reply = await fetch(`api/v1/audit/export?format=${format}&${asked()}`, { headers: { 'X-QKVM': '1' } });
      if (!reply.ok) throw new Error(`The log could not be fetched (HTTP ${reply.status})`);
      const url = URL.createObjectURL(await reply.blob());
      const link = h('a', { href: url, download: `qkvm-activity.${format}` });
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (ex) {
      toast(ex.message, 'error');
    }
  };
  const csvButton = h('button', { type: 'button' }, icon('download'), 'Download CSV');
  csvButton.addEventListener('click', () => busy(csvButton, take('csv')));
  const linesButton = h('button', { type: 'button' }, icon('download'), 'JSON lines');
  linesButton.addEventListener('click', () => busy(linesButton, take('jsonl')));
  does.append(csvButton, linesButton);
  await load(false);
  return [
    hole,
    h('div', { class: 'toolbar' }, find, kind),
    h('section', { class: 'block' }, h('div', { class: 'lines' },
      h('table', { class: 'rows' },
        h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Who'), h('th', {}, 'What'), h('th', {}, 'Details'), h('th', {}, 'From'))),
        rows),
      none,
      foot)),
  ];
}

// --- the wall --------------------------------------------------------------------------------------

const LABELS = {
  connecting: 'Connecting…', online: 'Online', no_signal: 'No signal',
  offline: 'Offline', auth: 'Login failed', error: 'Problem', busy: 'In use elsewhere',
};
// A server that is switched off is not a computer without a picture: it is called what it is.
function stateLabel(state, status) {
  return state === 'no_signal' && status?.picture === false ? 'Powered off' : LABELS[state];
}

// Snapshot error code -> tile state.
const FEED_STATES = {
  unreachable: 'offline', timeout: 'offline', dropped: 'offline',
  auth_failed: 'auth', no_password: 'auth', no_stream: 'connecting', in_use: 'busy',
};
// Tile state -> the filter it is counted under ("connecting" tiles only show under All).
const GROUPS = { online: 'online', no_signal: 'no_signal', offline: 'attention', auth: 'attention', error: 'attention', busy: 'attention' };
const FILTERS = [['all', 'All', null], ['online', 'Online', 'online'], ['no_signal', 'No signal', 'no_signal'], ['attention', 'Attention', 'offline']];
const VEIL_ICONS = { no_signal: 'system', offline: 'wifiOff', auth: 'lock', error: 'alert', busy: 'eye' };
const FOCUS_PERIOD = 250;  // ms; the enlarged view refreshes faster than the tiles
const RETRY_PERIOD = 3000; // ms between attempts while a device is failing

let period = 1000;  // ms between tile refreshes, 0 = paused
let wallDown = false;
let wallRun = 0;    // bumped whenever the wall is torn down, so old loops notice and stop
let focus = null;   // { id, feed, view } while a tile is enlarged
let filter = 'all'; // which group of tiles is shown
let query = '';     // text typed into the search box
let selecting = false;       // picking KVMs for a bulk action
const selected = new Set();  // ids of the KVMs picked
const tiles = new Map();

// The size of an element in real screen pixels, kept current by the browser. With display
// scaling (125%, 135%, 150%...) this is the only number that lets a picture be drawn 1:1.
const boxPixels = new WeakMap();
const pixelWatcher = new ResizeObserver(entries => {
  for (const entry of entries) {
    const exact = entry.devicePixelContentBoxSize?.[0];
    const ratio = window.devicePixelRatio || 1;
    boxPixels.set(entry.target, exact
      ? { w: exact.inlineSize, h: exact.blockSize }
      : { w: Math.round(entry.contentRect.width * ratio), h: Math.round(entry.contentRect.height * ratio) });
    entry.target.dispatchEvent(new Event('pixelsize'));
  }
});

function watchPixels(box) {
  try {
    pixelWatcher.observe(box, { box: 'device-pixel-content-box' });
  } catch {
    pixelWatcher.observe(box);  // a browser without exact sizes: rounding is the best there is
  }
}

function pixelsOf(box) {
  const ratio = window.devicePixelRatio || 1;
  return boxPixels.get(box) || { w: Math.round(box.clientWidth * ratio), h: Math.round(box.clientHeight * ratio) };
}

// Draws a frame into `canvas` so that every canvas pixel is one screen pixel: the frame is
// resampled exactly once, with the browser's best filter, straight to the size it is shown at.
// Letting the browser stretch an <img> instead resamples a second time, which is what blurs.
async function paintSharp(canvas, box, blob, stillWanted) {
  const { w: boxW, h: boxH } = pixelsOf(box);
  if (boxW < 2 || boxH < 2) return;  // not on screen right now
  const frame = await createImageBitmap(blob);
  let sized = frame;
  try {
    const scale = Math.min(boxW / frame.width, boxH / frame.height);
    const w = Math.max(1, Math.round(frame.width * scale));
    const h = Math.max(1, Math.round(frame.height * scale));
    if (scale < 1) sized = await createImageBitmap(frame, { resizeWidth: w, resizeHeight: h, resizeQuality: 'high' });
    if (stillWanted()) {
      if (canvas.width !== boxW || canvas.height !== boxH) {
        canvas.width = boxW;
        canvas.height = boxH;
      }
      const context = canvas.getContext('2d');
      context.fillStyle = '#000';
      context.fillRect(0, 0, boxW, boxH);
      context.imageSmoothingQuality = 'high';
      context.drawImage(sized, Math.floor((boxW - w) / 2), Math.floor((boxH - h) / 2), w, h);
    }
  } finally {
    // Whatever happened above: a decoded picture is memory the browser does not take back by itself in time.
    frame.close();
    if (sized !== frame) sized.close();
  }
}

// Turns to make a request, for those who must not make too many at once.
class Slots {
  constructor(count) {
    this.free = count;
    this.waiting = [];
  }
  take() {
    if (this.free > 0) {
      this.free -= 1;
      return Promise.resolve();
    }
    return new Promise(resolve => this.waiting.push(resolve));
  }
  release() {
    const next = this.waiting.shift();
    if (next) next();
    else this.free += 1;
  }
}

// A browser makes six requests at a time to one address and keeps the rest waiting. The tiles share
// four of them, so that a click (an action, the settings, the enlarged view) never waits behind pictures.
const tileSlots = new Slots(4);

// Polls one snapshot URL and paints it. getUrl is asked every time, because the size wanted changes with the layout.
// `slots`: the turns its requests are made in, for feeds that are many.
class Feed {
  constructor(canvas, box, getUrl, getPeriod, isActive, onResult, slots = null) {
    Object.assign(this, {
      canvas, box, getUrl, getPeriod, isActive, onResult, slots,
      running: false, failing: false, waking: false, blob: null, paints: 0, sent: 0,
    });
  }
  // Draws the newest frame again, for instance when the tile has changed size.
  async paint() {
    if (!this.blob) return;
    const turn = ++this.paints;
    await paintSharp(this.canvas, this.box, this.blob, () => turn === this.paints);
  }
  start() {
    if (this.running) return;
    this.running = true;
    this.run();
  }
  stop() {
    this.running = false;
    this.paints += 1;  // whatever is still being decoded is no longer wanted
  }
  async run() {
    while (this.running) {
      const period = this.getPeriod();
      if (!period || !this.isActive()) {
        // Paused, hidden or scrolled away: look again soon, so the picture is fresh right after returning.
        await sleep(400);
        continue;
      }
      this.sent = performance.now();
      await this.tick();
      // Decided after the attempt: a device that is down is asked less often than one delivering
      // frames, and a stream that is being woken up is checked again soon even on a slow refresh.
      let wait = period;
      if (this.failing) wait = Math.max(period, RETRY_PERIOD);
      else if (this.waking) wait = Math.min(period, 1000);
      // Counted from when the request went out. From when it began to wait for its turn, two requests
      // could follow each other closely enough for the second to be handed the picture of the first.
      await sleep(Math.max(80, wait - (performance.now() - this.sent)));
    }
  }
  fail(code, message) {
    // An idle stream is being woken up and will have frames within a second.
    this.waking = code === 'no_stream';
    this.failing = !this.waking;
    this.onResult({ error: { code, message } });
  }
  async tick() {
    let res, blob;
    await this.slots?.take();
    try {
      if (!this.running || !this.isActive()) return;  // no longer wanted by the time its turn came
      this.sent = performance.now();
      res = await fetch(this.getUrl(), { cache: 'no-store', signal: AbortSignal.timeout(12000) });
      if (res.ok) blob = await res.blob();
    } catch {
      if (this.running) this.fail('wall', 'qKVM is not responding');
      return;
    } finally {
      this.slots?.release();
    }
    if (!this.running) return;
    if (!blob) {
      let error = {};
      try { error = await res.json(); } catch { /* not JSON */ }
      if (res.status === 401 && error.code === 'unauthorized') {
        sessionExpired();
        return;
      }
      this.fail(error.code || 'error', error.message || `HTTP ${res.status}`);
      return;
    }
    this.blob = blob;
    try {
      await this.paint();
    } catch {
      this.blob = null;
      this.fail('error', 'The KVM sent a picture that could not be shown');
      return;
    }
    this.failing = this.waking = false;
    this.onResult({ signal: res.headers.get('X-KVM-Signal') !== '0' });
  }
}

// How wide a frame to ask for: twice the screen pixels a 16:9 picture fitted in `box` covers.
// The spare detail is what makes the scaled-down result crisp; for a normal tile this means
// the KVM's full frame, for the tiny tiles of a big wall a smaller one.
function sharpWidth(box) {
  const { w, h } = pixelsOf(box);
  const fitted = Math.min(w, h * 16 / 9) || w || 640;
  return Math.max(480, Math.ceil(fitted * 2));
}

// `shared`: ms between refreshes of a view that can do with a picture another browser fetched a
// moment ago. Several people on one wall then cost each KVM little more than one of them would.
function snapshotUrl(id, box, shared = 0) {
  const age = shared ? `&age=${(shared * 0.8 / 1000).toFixed(2)}` : '';
  return `api/v1/devices/${encodeURIComponent(id)}/snapshot?w=${sharpWidth(box)}${age}`;
}

// A view is what one feed knows about a device: { hasFrame, frameAt, signal, error }.
function newView() {
  return { hasFrame: false, frameAt: 0, signal: true, error: null };
}

// How long a picture stays up while its KVM says "ask again": a KVM that is slow with its pictures
// keeps showing the last one, rather than "Connecting…" between every two of them.
const PICTURE_KEPT = 8000;  // ms

function applyResult(view, result) {
  if (result.error) {
    const slow = result.error.code === 'no_stream' && view.hasFrame && !view.error
      && performance.now() - view.frameAt < PICTURE_KEPT;
    if (!slow) view.error = result.error;
  } else {
    Object.assign(view, { error: null, hasFrame: true, frameAt: performance.now(), signal: result.signal });
  }
}

// A server is seen through its management controller. Where that has a console qKVM reads (the status says
// so), the server's screen is taken from it and shown as a KVM's is; where not, the tile says how the server is.
function showsScreen(device, status) {
  return device.picture !== false || status?.screen === true;
}

// A server whose screen is on the tile right now (and not the panel that says how it is): there is a picture
// of it, and the server is running. A fault does not cover the screen of a server that runs: the tile's edge
// says the rest. Switched off, what its controller says of it is what there is to see, and not "no signal:
// not plugged into the KVM", which is a KVM's story.
function pictured(device, view, state) {
  return device.picture === false && view.hasFrame && !view.error && (state === 'online' || state === 'error');
}

function stateOf(status, view) {
  // What a server's controller says of it decides its state: its picture comes and goes with whoever looks.
  if (status?.picture === false) return [status.state, status.error?.message];
  const live = !view.error && performance.now() - view.frameAt < 3000;
  // The status poll lags a few seconds; frames that are arriving right now win over it.
  if (status && status.state !== 'online' && status.state !== 'no_signal' && !live) {
    return [status.state, status.error?.message];
  }
  if (view.error) return [FEED_STATES[view.error.code] || 'error', view.error.message];
  if (!view.hasFrame) return ['connecting', null];
  if (!view.signal || status?.state === 'no_signal') return ['no_signal', null];
  return ['online', null];
}

function metaText(status) {
  if (!status || !status.video) return '';
  if (status.picture === false) {
    // A server's panel already says whether it is on and how warm: its footer says which machine it is.
    if (!status.video.width) return status.about?.model || '';
    // With its screen on the tile, the footer says what the panel would have.
    const health = status.server?.health;
    return [`${status.video.width}×${status.video.height}`, health && health !== 'OK' ? health : null,
      status.health?.temp != null ? `${Math.round(status.health.temp)}°C` : null].filter(Boolean).join(' · ');
  }
  const parts = [];
  const shown = status.ports?.list[status.ports.active];
  if (shown) parts.push(portName(shown, status.ports.active));
  if (status.video.width) parts.push(`${status.video.width}×${status.video.height}`);
  if (status.atx?.enabled) {
    // A computer that sends a picture is on. A power light that says otherwise is not wired up, and
    // "Power off" under a running machine is worse than saying nothing.
    if (status.atx.power) parts.push('Power on');
    else if (status.atx.power === false && !status.video.signal) parts.push('Power off');
  }
  if (status.usb?.keyboard === false) parts.push('USB not connected');
  if (status.health?.temp != null) parts.push(`${Math.round(status.health.temp)}°C`);
  return parts.join(' · ');
}

// --- servers: seen through their management controller, which has no picture to give ---------------

const HEALTH_TONES = { OK: 'ok', Warning: 'warn', Critical: 'bad' };

// Fills what a server's tile shows where a KVM's shows the screen: power, health, heat, fans, and what
// the machine is. `full`: with every temperature, for the enlarged view. Returns whether there is anything to show.
function fillPanel(panel, status, full = false) {
  const server = status?.server;
  const key = server ? JSON.stringify([server, status.health?.temp, full]) : '';
  if (panel.dataset.key === key) return Boolean(server);  // unchanged: leave the DOM alone
  panel.dataset.key = key;
  if (!server) {
    panel.replaceChildren();
    return false;
  }
  const on = status.atx?.power !== false;
  const reading = (label, value, tone) => h('div', { class: 'reading', dataset: tone ? { tone } : {} },
    h('span', {}, label), h('b', {}, value));
  const temp = status.health?.temp;
  const running = server.fans.filter(fan => fan.reading > 0).length;
  const failing = server.fans.filter(fan => !fan.ok).length;
  const hardware = [
    server.processor && `${server.processors > 1 ? `${server.processors} × ` : ''}${server.processor}`,
    server.memory_gib != null && `${server.memory_gib} GiB`,
  ].filter(Boolean).join(' · ');
  panel.dataset.power = on ? 'on' : 'off';
  panel.dataset.tone = HEALTH_TONES[server.health] || '';
  panel.replaceChildren(...[
    h('div', { class: 'panel-power' }, h('span', { class: 'led' }), h('strong', {}, on ? 'On' : 'Off'),
      // Somebody is looking for this machine: the tile says so as plainly as the light on it does.
      server.locator ? h('span', { class: 'locating' }, h('i', {}), 'Locator light on') : h('span', {}, 'Server')),
    h('div', { class: 'readings' },
      reading('Health', server.health || 'Not reported', HEALTH_TONES[server.health]),
      temp != null && reading('Temp', `${Math.round(temp)} °C`),
      server.fans.length > 0 && reading(failing ? `Fans · ${failing} not well` : 'Fans', `${running} running`, failing ? 'warn' : null)),
    hardware && h('p', { class: 'panel-hardware' }, hardware),
    full && server.unwell.length > 0 && h('p', { class: 'panel-unwell' }, `Not well: ${server.unwell.join(', ')}`),
    full && server.no_screen && h('p', { class: 'panel-hardware' }, `Its screen is not shown: ${server.no_screen}`),
    full && server.temperatures.length + server.fans.length > 0 && h('div', { class: 'sensors' },
      server.temperatures.map(sensor => h('div', { dataset: sensor.ok ? {} : { tone: 'warn' } },
        h('span', {}, sensor.name), h('b', {}, `${Math.round(sensor.celsius)} °C`))),
      server.fans.map(fan => h('div', { dataset: fan.ok ? {} : { tone: 'warn' } },
        h('span', {}, fan.name), h('b', {}, fan.reading == null ? '–' : `${Math.round(fan.reading)} ${fan.unit}`)))),
  ].filter(Boolean));
  return true;
}

// --- multi-port KVMs: one KVM, several computers, one of them on screen ----------------------------

function portName(port, index) {
  return port.name || `Port ${index + 1}`;
}

async function switchPort(tile, index) {
  const ports = tile.status?.ports;
  if (!ports || ports.active === index || tile.switching != null) return;
  tile.switching = index;
  render(tile);
  renderFocus();
  try {
    await api('POST', `api/v1/devices/${tile.device.id}/actions`, { action: 'port', port: index }, ACTION_PATIENCE);
    if (tile.status?.ports) tile.status.ports.active = index;  // a status poll may have replaced it meanwhile
    toast(`${tile.device.name}: showing ${portName(ports.list[index], index)}`, 'ok');
  } catch (ex) {
    toast(`${tile.device.name}: ${ex.message}`, 'error');
  }
  tile.switching = null;
  render(tile);
  renderFocus();
}

// One button per input. The lit one is on screen; a dimmed one has nothing plugged in.
function fillPorts(strip, tile) {
  const ports = tile.status?.ports;
  strip.hidden = !ports;
  const key = ports ? JSON.stringify([tile.device.id, ports, tile.switching]) : '';
  if (strip.dataset.key === key) return;  // unchanged: leave the DOM (and any hover) alone
  strip.dataset.key = key;
  strip.replaceChildren(...(ports ? ports.list : []).map((port, index) => {
    const name = portName(port, index);
    const note = ports.active === index ? 'on screen now' : port.signal === false ? 'nothing connected'
      : can('operator') ? 'show this computer' : 'not on screen';
    return h('button', {
      type: 'button',
      disabled: !can('operator') && ports.active !== index,  // a viewer sees which one is shown, and cannot switch
      class: port.signal === false ? 'empty' : '',
      'aria-pressed': String(ports.active === index),
      'aria-busy': String(tile.switching === index),
      'aria-label': `${name} of ${tile.device.name}: ${note}`,
      title: `${name} · ${note}`,
      onclick: () => switchPort(tile, index),
    }, String(index + 1));
  }));
}

// A JetKVM serves one viewer. When its own console was opened the wall stepped aside; this takes the picture back.
async function showHere(device) {
  const sure = await confirmBox({
    title: `Show ${device.name} here?`,
    message: 'Whoever has its console open is disconnected from it.',
    action: 'Show here',
    danger: false,
  });
  if (!sure) return;
  try {
    await api('POST', `api/v1/devices/${device.id}/actions`, { action: 'resume' }, ACTION_PATIENCE);
  } catch (ex) {
    toast(`${device.name}: ${ex.message}`, 'error');
    return;
  }
  const tile = tiles.get(device.id);
  if (tile?.status) {
    // Say "connecting" until the first new picture arrives, rather than "in use" for another few seconds.
    tile.status = { ...tile.status, state: 'connecting', error: null };
    tile.view.error = null;
    if (focus?.id === device.id) focus.view.error = null;
    render(tile);
    renderFocus();
  }
}

// --- groups, and display mode ------------------------------------------------------------------------

let group = prefs.get('group', '');  // which group of KVMs is shown; '' means all of them
let displayMode = false;             // the screens and nothing else, for a monitor on the wall
let rotateTimer = 0;
let awakeTimer = 0;
const ROTATE_EVERY = 20000;          // ms each group stays up while rotating

function groupNames() {
  const names = new Set([...tiles.values()].map(tile => tile.device.group).filter(Boolean));
  return [...names].sort((a, b) => a.localeCompare(b));
}

function renderGroups() {
  const names = groupNames();
  if (group && !names.includes(group)) group = '';
  const select = $('#group');
  select.replaceChildren(h('option', { value: '' }, 'All groups'), ...names.map(name => h('option', { value: name }, name)));
  select.value = group;
  $('#group-pick').hidden = names.length === 0;
  $('#display-group').textContent = group || 'All groups';
  $('#display-rotate-box').hidden = names.length < 2;
}

function setGroup(name, animated = true, remember = true) {
  group = name;
  if (remember) prefs.set('group', name);
  renderGroups();
  applyFilter(animated);
}

function syncRotation() {
  clearInterval(rotateTimer);
  const on = prefs.get('rotate', '0') === '1';
  $('#display-rotate').checked = on;
  if (!displayMode || !on) return;
  rotateTimer = setInterval(() => {
    const names = groupNames();
    if (names.length > 1 && !focus && !$('dialog[open]')) setGroup(names[(names.indexOf(group) + 1) % names.length], true, false);
  }, ROTATE_EVERY);
}

// The address keeps "#display", so a browser on a wall screen can simply be pointed at it.
function setDisplay(on) {
  displayMode = on;
  if (on) setSelecting(false);
  $('#shell').classList.toggle('display', on);
  $('#display-bar').hidden = !on;
  if ((location.hash === '#display') !== on) history.replaceState(null, '', on ? '#display' : location.pathname + location.search);
  syncRotation();
  layout();
  if (on) wakeDisplayBar();
}

// The little bar in display mode shows for a moment when the mouse moves, then gets out of the way.
function wakeDisplayBar() {
  if (!displayMode) return;
  $('#shell').classList.add('awake');
  clearTimeout(awakeTimer);
  awakeTimer = setTimeout(() => $('#shell').classList.remove('awake'), 3000);
}

// What a tile says when it has no live picture: a heading, a line of detail, and sometimes a way out.
function veilContent(device, status, view, state, message) {
  const code = view.error?.code || status?.error?.code;
  const content = { title: LABELS[state], text: message, action: null, owner: device.id };
  // The button stays while what it says stays, which can be longer than the details it was made with: the
  // device is looked up when the button is pressed, so that an edit starts from what is saved now.
  const now = () => tiles.get(device.id)?.device || device;
  if (message === 'Rebooting…') {
    Object.assign(content, { title: 'Rebooting…', text: device.picture === false ? 'Back in a minute or two.' : 'Back in about a minute.' });
  } else if (state === 'no_signal') {
    content.text = 'The computer is off, asleep or not plugged into the KVM.';
  } else if (state === 'offline' && status?.last_seen_ago != null) {
    content.text = `${message || 'Device is unreachable'} · last seen ${ago(status.last_seen_ago)}`;
  } else if (state === 'auth') {
    content.action = ['Update login', () => editDeviceDialog(now(), reloadWall)];
  } else if (state === 'busy') {
    content.text = 'Someone has this JetKVM\'s own console open. It shows its picture to one viewer at a time.';
    content.action = ['Show here', () => showHere(now())];
  }
  // (A certificate that is another one than was remembered, or one that was remembered and cannot be read.)
  const certificate = code === 'cert_mismatch' || (code === 'cert_invalid' && device.tls === 'pinned');
  if (certificate) content.action = ['Review certificate', () => certificateDialog(now(), reloadWall)];
  // Taking the picture back is an action on the machine; the other two change how the KVM is saved.
  if (content.action && !can(state === 'busy' && !certificate ? 'operator' : 'admin')) content.action = null;
  return content;
}

function fillVeil(veil, state, { title, text, action, owner }) {
  const key = [owner, state, title, text, action?.[0]].join('|');
  if (veil.dataset.key === key) return;  // unchanged: leave the DOM (and any hover) alone
  veil.dataset.key = key;
  veil.replaceChildren(...[
    h('span', { class: 'veil-icon' },
      state === 'connecting' ? h('span', { class: 'spinner' }) : icon(VEIL_ICONS[state] || 'alert')),
    h('strong', {}, title),
    text && h('span', {}, text),
    action && h('button', { type: 'button', onclick: action[1] }, action[0]),
  ].filter(Boolean));
}

function makeTile(device, index) {
  const canvas = h('canvas', { role: 'img', 'aria-label': `${device.name} screen` });
  const veil = h('div', { class: 'veil' });
  const panel = h('div', { class: 'panel', role: 'group', 'aria-label': `How ${device.name} is doing` });
  const tick = h('button', {
    type: 'button', class: 'tile-check', role: 'checkbox', 'aria-checked': 'false',
    title: 'Select for a bulk action', 'aria-label': `Select ${device.name}`,
    onclick: () => toggleSelected(device.id),
  }, icon('check'));
  const ports = h('div', { class: 'ports', role: 'group', 'aria-label': `Ports of ${device.name}`, hidden: true });
  const screen = h('div', { class: 'screen' },
    canvas,
    panel,
    veil,
    tick,
    ports,
    h('div', { class: 'tile-tools' },
      consoleLink(device) && h('a', {
        class: 'tool', href: consoleLink(device), target: '_blank', rel: 'noopener noreferrer',
        title: 'Open console', 'aria-label': `Open the console of ${device.name}`,
        onclick: event => openSignedIn(event, tiles.get(device.id)),
      }, icon('external')),
      h('button', {
        type: 'button', class: 'tool operator-only', title: 'Actions', 'aria-label': `Actions for ${device.name}`,
        onclick: () => actionsDialog(device.id),
      }, icon('zap'))));
  const el = h('article', {
    class: 'tile', tabIndex: 0, dataset: { id: device.id, state: 'connecting' },
    'aria-label': `${device.name}. Press Enter to enlarge.`,
  },
    screen,
    h('footer', {},
      h('span', { class: 'dot' }),
      h('span', { class: 'name' }, device.name),
      device.same_as?.length > 0 && h('button', {
        type: 'button', class: 'twin', title: `The same device as ${device.same_as.map(twin => twin.name).join(', ')}`,
        onclick: () => twinsDialog(device),
      }, 'twice'),
      h('span', { class: 'host' }, device.host),
      h('span', { class: 'meta' })),
  );
  el.style.setProperty('--i', Math.min(index, 24));  // staggers the entrance
  const tile = {
    device, el, canvas, screen, veil, panel, tick, ports,
    status: null, view: newView(), visible: true, state: 'connecting', rebootUntil: 0, wentDown: false, switching: null,
  };
  watchPixels(screen);
  // A window being dragged, or the columns changed, gives every tile a new size many times over. The picture
  // is decoded and drawn again once the size has held still for a moment, and not at all for a tile that is
  // scrolled out of sight: that one is drawn when it comes back (see `seen`).
  let settled = 0;
  screen.addEventListener('pixelsize', () => {
    clearTimeout(settled);
    settled = setTimeout(() => {
      if (tile.visible) tile.feed.paint().catch(() => {});
      else tile.redraw = true;
    }, 120);
  });
  tile.feed = new Feed(
    canvas,
    screen,
    () => snapshotUrl(device.id, screen, period),
    () => period,
    () => showsScreen(device, tile.status) && !document.hidden && tile.visible && !focus,
    result => { applyResult(tile.view, result); render(tile); },
    tileSlots,
  );
  el.addEventListener('click', event => {
    if (arranging || event.target.closest('a, button')) return;
    // While picking, a click ticks the tile; otherwise it enlarges it.
    if (selecting) toggleSelected(device.id);
    else openFocus(device.id);
  });
  el.addEventListener('keydown', event => {
    if ((event.key === 'Enter' || event.key === ' ') && event.target === el && !arranging) {
      event.preventDefault();
      if (selecting) toggleSelected(device.id);
      else openFocus(device.id);
    }
  });
  return tile;
}

function render(tile) {
  let [state, message] = stateOf(tile.status, tile.view);
  if (tile.rebootUntil) {
    // After "Reboot KVM": call the outage what it is until the KVM is back (or clearly isn't coming).
    if (Date.now() > tile.rebootUntil) {
      tile.rebootUntil = 0;
    } else if (state !== 'online') {
      tile.wentDown = true;
      state = 'connecting';
      message = 'Rebooting…';
    } else if (tile.wentDown) {
      tile.rebootUntil = 0;
    }
  }
  tile.el.dataset.state = state;
  const screen = pictured(tile.device, tile.view, state);
  tile.el.classList.toggle('has-frame', tile.view.hasFrame);
  tile.el.classList.toggle('has-panel', tile.device.picture === false && !screen && state !== 'connecting' && fillPanel(tile.panel, tile.status));
  tile.el.classList.toggle('pictured', screen);
  if (state !== 'online') fillVeil(tile.veil, state, veilContent(tile.device, tile.status, tile.view, state, message));
  $('.meta', tile.el).textContent = metaText(tile.status);
  fillPorts(tile.ports, tile);
  if (state !== tile.state) {
    tile.state = state;
    tallySoon();
  }
}

// When a switch goes away, or qKVM itself, every tile changes state within the same moment. The counts on
// the filters and the grid are then brought up to date once for all of them, not once for each: each time
// is a pass over every tile and a new layout.
let tallyDue = false;
function tallySoon() {
  if (tallyDue) return;
  tallyDue = true;
  setTimeout(() => {
    tallyDue = false;
    renderFilters();
    if (filter !== 'all') applyFilter();
    if (order === 'state') reorder();
  }, 0);
}

// --- picking KVMs for a bulk action ---------------------------------------------------------------

function renderSelection() {
  for (const id of [...selected]) {
    if (!tiles.has(id)) selected.delete(id);
  }
  $('#shell').classList.toggle('selecting', selecting);
  $('#select-toggle').setAttribute('aria-pressed', String(selecting));
  for (const tile of tiles.values()) {
    const on = selected.has(tile.device.id);
    tile.el.classList.toggle('selected', on);
    tile.tick.setAttribute('aria-checked', String(on));
  }
  $('#bulkbar').hidden = !selecting;
  $('#bulk-count').textContent = `${selected.size} selected`;
  $('#bulk-run').disabled = selected.size === 0;
  $('#bulk-none').disabled = selected.size === 0;
}

function setSelecting(on) {
  selecting = on;
  if (!on) selected.clear();
  renderSelection();
}

function toggleSelected(id) {
  if (!selecting) return;  // tiles are only picked in select mode
  if (selected.has(id)) selected.delete(id);
  else selected.add(id);
  renderSelection();
}

// "Select all" means all that are shown, so a filter or a search narrows it.
function selectShown() {
  for (const tile of tiles.values()) {
    if (!tile.el.hidden) selected.add(tile.device.id);
  }
  renderSelection();
}

// --- filtering and layout ------------------------------------------------------------------------

function renderFilters() {
  const tally = { all: tiles.size, online: 0, no_signal: 0, attention: 0 };
  for (const tile of tiles.values()) {
    const group = GROUPS[tile.state];
    if (group) tally[group] += 1;
  }
  const box = $('#filters');
  if (!box.children.length) {
    for (const [key, label, dot] of FILTERS) {
      box.append(h('button', {
        type: 'button', dataset: { filter: key, ...(dot ? { state: dot } : {}) },
        onclick: () => { filter = filter === key ? 'all' : key; renderFilters(); applyFilter(); },
      }, dot && h('span', { class: 'dot' }), label, h('b', {})));
    }
  }
  for (const button of box.children) {
    const key = button.dataset.filter;
    const count = $('b', button);
    if (count.textContent !== String(tally[key])) {
      count.textContent = tally[key];
      count.classList.remove('bump');
      void count.offsetWidth;  // restarts the little "number changed" animation
      count.classList.add('bump');
    }
    // Empty groups stay out of the way, unless one is the current choice.
    button.hidden = !tally[key] && filter !== key && key !== 'all' && key !== 'online';
    button.setAttribute('aria-pressed', String(filter === key));
  }
}

function namedTiles() {
  return [...tiles.values()].map(tile => [tile.el, `tile-${tile.device.id}`]);
}

// Shows the tiles that match the chosen group and the search text, and re-fits the grid.
function applyFilter(animated = true) {
  const words = query.trim().toLowerCase();
  const change = () => {
    let shown = 0;
    for (const tile of tiles.values()) {
      const text = `${tile.device.name} ${tile.device.host} ${tile.device.group}`.toLowerCase();
      const visible = (!words || text.includes(words)) && (filter === 'all' || GROUPS[tile.state] === filter)
        && (!group || tile.device.group === group);
      tile.el.hidden = !visible;
      if (visible) shown += 1;
    }
    const none = $('#no-match');
    if (none) none.hidden = shown > 0 || tiles.size === 0;
    layout();
  };
  if (animated) glide(change, namedTiles());
  else change();
}

function layout() {
  const wall = $('#wall');
  const count = [...tiles.values()].filter(tile => !tile.el.hidden).length;
  if (!count) return;
  const style = getComputedStyle(wall);
  const gap = parseFloat(style.columnGap) || 12;
  const width = wall.clientWidth - 2 * (parseFloat(style.paddingLeft) || 0);
  const height = wall.clientHeight - 2 * (parseFloat(style.paddingTop) || 0);
  const chrome = (parseFloat(style.getPropertyValue('--bar-h')) || 38) + 2;  // tile footer + borders
  const choice = displayMode ? 'auto' : $('#cols').value;  // a wall screen shows everything, as large as fits

  // A chosen number is a maximum: a narrow window gets fewer columns rather than unreadable tiles.
  let cols = Math.max(1, Math.min(Number(choice), Math.floor((width + gap) / (240 + gap))));
  let tileWidth = '1fr';
  if (choice === 'auto') {
    // Largest 16:9 tile such that every screen fits without scrolling.
    let best = 0;
    for (let c = 1; c <= count; c++) {
      const rows = Math.ceil(count / c);
      const byWidth = (width - gap * (c - 1)) / c;
      const byHeight = ((height - gap * (rows - 1)) / rows - chrome) * 16 / 9;
      const size = Math.min(byWidth, byHeight);
      if (size > best) { best = size; cols = c; }
    }
    if (best >= 260) {
      tileWidth = `${Math.floor(best)}px`;
    } else {
      // Too many screens for this window: fall back to readable tiles and scroll.
      cols = Math.max(1, Math.floor((width + gap) / (300 + gap)));
    }
  }
  wall.style.setProperty('--cols', cols);
  wall.style.setProperty('--tile-w', tileWidth);
}

// --- enlarged view ----------------------------------------------------------------------------------

// Runs `update` so that the picture appears to grow out of `from` into `to` (or shrink back).
function zoom(from, to, update) {
  if (!document.startViewTransition || still() || document.hidden) {
    update();
    return;
  }
  const layer = $('#focus');
  from.style.viewTransitionName = 'zoom';
  layer.style.viewTransitionName = 'focus-layer';
  const clear = () => { for (const el of [from, to, layer]) el.style.viewTransitionName = ''; };
  moving(() => {
    from.style.viewTransitionName = '';
    to.style.viewTransitionName = 'zoom';
    update();
  }).finished.then(clear, clear);
}

function openFocus(id) {
  const tile = tiles.get(id);
  if (!tile) return;
  const show = () => {
    focus?.feed.stop();
    const canvas = $('#focus-canvas');
    const box = $('#focus-screen');
    const view = newView();
    const feed = new Feed(
      canvas,
      box,
      () => snapshotUrl(id, box),
      () => (period ? Math.min(period, FOCUS_PERIOD) : 0),
      () => !document.hidden && showsScreen(tile.device, tile.status),
      result => { applyResult(view, result); renderFocus(); },
    );
    // Show what the tile already has right away; fresher frames replace it as they arrive.
    if (tile.view.hasFrame && tile.feed.blob) {
      feed.blob = tile.feed.blob;
      Object.assign(view, tile.view);
    } else {
      canvas.width = canvas.height = 1;  // clears the previous KVM's picture
    }
    const opening = !focus;
    focus = { id, feed, view };
    $('#focus').hidden = false;
    behindFocus(true);
    renderFocus();
    if (opening) $('#focus-close').focus({ preventScroll: true });
    feed.paint().catch(() => {});
    feed.start();
  };
  // Switching between KVMs while enlarged is a plain swap; opening grows out of the tile.
  if (focus) show();
  else zoom(tile.screen, $('#focus-screen'), show);
}

// While a screen is enlarged it covers the wall; the wall's controls are then out of reach of Tab and screen readers.
function behindFocus(covered) {
  for (const part of [$('.top'), $('#wall'), $('#bulkbar'), $('#banner')]) part.inert = covered;
}

function closeFocus(instant = false) {
  if (!focus) return;
  const tile = tiles.get(focus.id);
  const hide = () => {
    focus?.feed.stop();
    focus = null;
    $('#focus').hidden = true;
    behindFocus(false);
    tile?.el.focus({ preventScroll: true });
  };
  if (instant || !tile || tile.el.hidden) hide();
  else zoom($('#focus-screen'), tile.screen, hide);
}

function stepFocus(delta) {
  if (!focus) return;
  const ids = [...tiles.values()].filter(tile => !tile.el.hidden).map(tile => tile.device.id);
  if (!ids.length) return;
  openFocus(ids[(Math.max(0, ids.indexOf(focus.id)) + delta + ids.length) % ids.length]);
}

function renderFocus() {
  if (!focus) return;
  const tile = tiles.get(focus.id);
  if (!tile) return;
  const [state, message] = stateOf(tile.status, focus.view);
  $('#focus-name').textContent = tile.device.name;
  const open = $('#focus-open');
  if (consoleLink(tile.device)) open.href = consoleLink(tile.device);
  else open.removeAttribute('href');
  $('#focus-bar').dataset.state = state;
  $('#focus').dataset.state = state;
  const screen = pictured(tile.device, focus.view, state);
  $('#focus-screen').classList.toggle('has-frame', focus.view.hasFrame);
  $('#focus').classList.toggle('has-panel', tile.device.picture === false && (!screen || focus.health) && state !== 'connecting'
    && fillPanel($('#focus-panel'), tile.status, true));
  $('#focus').classList.toggle('pictured', screen && !focus.health);
  // With the server's screen up, how the server is (health, every temperature, every fan) is a button away.
  $('#focus-health').hidden = !screen;
  $('#focus-health').setAttribute('aria-pressed', String(Boolean(focus.health)));
  $('#focus-state').textContent = stateLabel(state, tile.status);
  if (state !== 'online') fillVeil($('#focus-veil'), state, veilContent(tile.device, tile.status, focus.view, state, message));
  $('#focus-meta').textContent = [tile.device.host, metaText(tile.status)].filter(Boolean).join(' · ');
  fillPorts($('#focus-ports'), tile);
}

// --- wall lifecycle -----------------------------------------------------------------------------------

// Tiles scrolled out of view (or filtered away) stop asking their KVM for frames.
const seen = new IntersectionObserver(entries => {
  for (const entry of entries) {
    const tile = tiles.get(entry.target.dataset.id);
    if (!tile) continue;
    tile.visible = entry.isIntersecting;
    if (tile.visible && tile.redraw) {  // it changed size while out of sight
      tile.redraw = false;
      tile.feed.paint().catch(() => {});
    }
  }
});

function dropTile(tile) {
  tile.feed.stop();
  seen.unobserve(tile.el);
  pixelWatcher.unobserve(tile.screen);
  tile.el.remove();
  tiles.delete(tile.device.id);
  selected.delete(tile.device.id);
}

function stopWall() {
  wallRun += 1;
  // Whoever was setting the order of the tiles is not any more. Left as it was, the bar for it and the top
  // bar it had switched off were still so on the wall that the next sign-in drew.
  if (arranging) arranging(false);
  closeFocus(true);
  selecting = false;
  selected.clear();
  $('#bulkbar').hidden = true;
  for (const tile of [...tiles.values()]) dropTile(tile);
  $('#wall').replaceChildren();
}

function emptyWall() {
  return h('div', { class: 'empty' },
    h('span', { class: 'empty-icon' }, icon('grid')),
    h('h2', {}, 'Your wall is empty'),
    h('p', {}, can('admin') ? 'Add your KVMs to see their screens here.' : 'No KVMs have been shared with your account yet.'),
    h('button', { type: 'button', class: 'primary admin-only', onclick: addDevicesDialog }, icon('plus'), 'Add KVMs'));
}

// The order the tiles are shown in: as the server lists them (the order they were added in), or one chosen
// here. It is this browser's choice, like the number of columns: a wall screen may want what needs attention
// first, the desk next to it the same machines by name.
let order = prefs.get('order', '');
let asAdded = [];  // the devices as the server listed them last
const byName = (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
const ATTENTION_FIRST = { attention: 0, no_signal: 1, online: 2 };

function inOrder(devices) {
  const rank = device => ATTENTION_FIRST[GROUPS[tiles.get(device.id)?.state]] ?? 3;  // not known yet: after what is
  const compare = {
    name: byName,
    // Machines without a group come after the groups.
    group: (a, b) => (!a.group - !b.group) || byName({ name: a.group }, { name: b.group }) || byName(a, b),
    state: (a, b) => rank(a) - rank(b) || byName(a, b),
  }[order];
  return compare ? [...devices].sort(compare) : devices;
}

// The wall's own order, set by hand: every tile says its place, and is dragged, stepped or numbered to another.
// What comes of it is saved on the server and is everybody's: this is where the screen in the hall gets its
// order from. (Sorting by name or by what needs attention stays each browser's own choice, in the View menu.)
let arranging = null;  // while it is being done: how to leave it

function arrangeTiles() {
  if (arranging || !tiles.size) return;
  if (focus) closeFocus(true);
  setSelecting(false);
  // All of them, in the wall's own order: nobody arranges what is hidden by a search, or sorted some other way.
  const was = { order, filter, query, group };
  order = '';
  filter = 'all';
  query = $('#search').value = '';
  group = '';
  buildTiles(asAdded);
  const wall = $('#wall');
  const shell = $('#shell');
  const placed = () => [...wall.querySelectorAll(':scope > .tile')];
  const number = () => placed().forEach((el, at) => { $('.arrange input', el).value = at + 1; });
  const put = (el, at) => {
    const others = placed().filter(other => other !== el);
    // (Counted where the tile is moved, which with a movement on screen is a moment later: counted right
    // away, every tile kept the number of the place it had been in.)
    glide(() => {
      wall.insertBefore(el, others[Math.max(0, Math.min(at, others.length))] || $('#no-match'));
      number();
    }, namedTiles());
  };
  let dragged = null;
  const marked = () => { for (const el of wall.querySelectorAll('.drop-before, .drop-after')) el.classList.remove('drop-before', 'drop-after'); };
  const cleanups = [];
  for (const tile of tiles.values()) {
    const el = tile.el;
    const at = h('input', { type: 'number', min: 1, max: tiles.size, inputMode: 'numeric', 'aria-label': `Place of ${tile.device.name}` });
    const step = by => h('button', {
      type: 'button', title: by < 0 ? 'One place earlier' : 'One place later', 'aria-label': `${tile.device.name}: ${by < 0 ? 'one place earlier' : 'one place later'}`,
      onclick: () => put(el, placed().indexOf(el) + by),
    }, icon(by < 0 ? 'chevronLeft' : 'chevronRight'));
    at.addEventListener('change', () => put(el, (Number(at.value) || 1) - 1));
    at.addEventListener('focus', () => at.select());
    const layer = h('div', { class: 'arrange' }, h('div', { class: 'where' }, step(-1), at, step(1)), h('span', {}, tile.device.name));
    el.append(layer);
    el.draggable = true;
    const on = (name, handler) => { el.addEventListener(name, handler); cleanups.push(() => el.removeEventListener(name, handler)); };
    on('dragstart', event => {
      dragged = el;
      el.classList.add('dragging');
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', tile.device.id);
    });
    on('dragover', event => {
      if (!dragged || dragged === el) return;
      event.preventDefault();
      const box = el.getBoundingClientRect();
      marked();
      el.classList.add(event.clientX < box.left + box.width / 2 ? 'drop-before' : 'drop-after');
    });
    on('drop', event => {
      if (!dragged || dragged === el) return;
      event.preventDefault();
      const after = el.classList.contains('drop-after');
      marked();
      put(dragged, placed().filter(other => other !== dragged).indexOf(el) + (after ? 1 : 0));
    });
    on('dragend', () => { el.classList.remove('dragging'); marked(); dragged = null; });
    cleanups.push(() => { layer.remove(); el.draggable = false; });
  }
  number();
  shell.classList.add('arranging');
  $('.top').inert = true;
  // `rebuild`: false where the wall itself is going (signed out, a session that ended): nothing is drawn again.
  let left = false;
  const leave = (saved, rebuild = true) => {
    if (left) return;  // once: an order still being saved when the wall went has nothing to leave when it is answered
    left = true;
    for (const cleanup of cleanups) cleanup();
    shell.classList.remove('arranging');
    $('.top').inert = false;
    bar.remove();
    arranging = null;
    ({ filter, query, group } = was);
    order = saved ? '' : was.order;  // an order that was just made is the one to look at
    if (saved) $('#order').value = '';
    $('#search').value = query;
    if (!saved && rebuild) buildTiles(asAdded);
  };
  const save = h('button', { type: 'button', class: 'primary' }, 'Save this order');
  save.addEventListener('click', () => busy(save, async () => {
    try {
      await api('PUT', 'api/v1/wall/order', { ids: placed().map(el => el.dataset.id) });
    } catch (ex) {
      toast(ex.message, 'error');
      return;
    }
    // (Answered after the wall it was done on went, a session that ended meanwhile: saved it is, and what is
    // on the page by now, another arranging perhaps, is not this one's to end.)
    if (left) return;
    leave(true);
    prefs.set('order', '');
    toast('The order is saved, for everybody who looks at this wall', 'ok');
    reloadWall();
  }));
  const bar = h('div', { class: 'bulkbar', role: 'toolbar', 'aria-label': 'Arrange the tiles' },
    h('strong', {}, 'Arrange'), h('span', { class: 'muted' }, 'Drag a tile to its place, or type the place it is to have.'),
    h('button', { type: 'button', onclick: () => leave(false) }, 'Cancel'), save);
  shell.append(bar);
  arranging = (rebuild = true) => leave(false, rebuild);
}

// Put the tiles in the chosen order again, if they are not: a state changed, or another order was chosen.
function reorder() {
  if (arranging) return;  // not under the hands of whoever is setting the order
  const wanted = inOrder(asAdded).map(device => device.id);
  if (wanted.length !== tiles.size || wanted.some((id, at) => id !== [...tiles.keys()][at])) glide(() => buildTiles(asAdded), namedTiles());
}

function buildTiles(devices) {
  asAdded = devices;
  devices = inOrder(devices);
  const wall = $('#wall');
  const wanted = new Set(devices.map(device => device.id));
  if (focus && !wanted.has(focus.id)) closeFocus(true);
  for (const tile of [...tiles.values()]) {
    if (!wanted.has(tile.device.id)) dropTile(tile);
  }
  for (const extra of wall.querySelectorAll('.empty')) extra.remove();
  if (!devices.length) wall.append(emptyWall());

  let fresh = 0;
  let place = wall.firstElementChild;  // where the next tile belongs; what is left in the wall by now is tiles only
  for (const device of devices) {
    let tile = tiles.get(device.id);
    // A tile whose details changed is rebuilt; one that didn't keeps its picture and keeps running.
    if (tile && JSON.stringify(tile.device) !== JSON.stringify(device)) {
      const old = tile;
      const ticked = selected.has(device.id);
      if (place === old.el) place = place.nextElementSibling;
      dropTile(old);
      tile = makeTile(device, 0);
      Object.assign(tile, { status: old.status, rebootUntil: old.rebootUntil, wentDown: old.wentDown });
      if (ticked) selected.add(device.id);  // renamed by somebody else, it is still one of the machines picked here
    } else if (!tile) {
      tile = makeTile(device, fresh++);
    }
    tiles.set(device.id, tile);
    // A tile that is where it belongs is left alone: moved, it would fade in again and lose the keyboard's
    // focus, on every tile of the wall, each time anybody saves anything.
    if (tile.el === place) place = place.nextElementSibling;
    else wall.insertBefore(tile.el, place);
    seen.observe(tile.el);
    render(tile);
    tile.feed.start();
  }
  if (devices.length) {
    wall.append(h('div', { class: 'empty', id: 'no-match', hidden: true },
      h('span', { class: 'empty-icon' }, icon('search')),
      h('h2', {}, 'No KVMs match'),
      h('button', {
        type: 'button',
        onclick: () => { filter = 'all'; query = ''; $('#search').value = ''; renderFilters(); setGroup(''); },
      }, 'Show all')));
  }
  // Keep the map in the wall's order: Previous / Next in the enlarged view walk it.
  const ordered = devices.map(device => [device.id, tiles.get(device.id)]);
  tiles.clear();
  for (const [id, tile] of ordered) tiles.set(id, tile);
  renderFilters();
  renderSelection();
  renderGroups();
  applyFilter(false);  // new tiles bring their own entrance
  if (location.hash === '#display' && !displayMode) setDisplay(true);
  // An alert's link: the wall, opened at the tile it is about. Once; the address is tidied so that a reload stays on the wall.
  const asked = /^#tile=([A-Za-z0-9_-]{1,40})$/.exec(location.hash);
  if (asked) {
    history.replaceState(null, '', location.pathname + location.search);
    if (tiles.has(asked[1])) openFocus(asked[1]);
  }
}

async function reloadWall() {
  if (arranging) return;  // not under the hands of whoever is setting the order: it is fetched again when they are done
  try {
    buildTiles((await api('GET', 'api/v1/wall')).devices);
  } catch (ex) {
    if (ex.code !== 'unauthorized') toast(ex.message, 'error');
  }
}

function setBanner(text) {
  const banner = $('#banner');
  if (!text) {
    banner.hidden = true;
  } else if (banner.hidden || banner.textContent !== text) {
    banner.replaceChildren(h('span', { class: 'spinner' }), text);
    banner.hidden = false;
  }
}

let polls = 0;

function applyStatuses(all) {
  for (const [id, status] of Object.entries(all)) {
    const tile = tiles.get(id);
    if (tile) { tile.status = status; render(tile); }
  }
}

// What was just done to a server (its power button, its locator light) shows on the tile once its
// controller has got round to it and been asked again: five seconds, on a real one. So the wall looks
// again at these moments after, instead of at its usual pace. However many machines it was done to,
// that is one round of looks.
const LOOKS_AFTER = [900, 2200, 3300, 3600];  // ms from one to the next: about 1, 3, 6 and 10 s after
let looksLeft = 0;
async function lookAgainSoon() {
  const underWay = looksLeft > 0;
  looksLeft = LOOKS_AFTER.length;
  if (underWay) return;
  const run = wallRun;
  while (looksLeft > 0 && run === wallRun) {
    await sleep(LOOKS_AFTER[LOOKS_AFTER.length - looksLeft]);
    looksLeft -= 1;
    try {
      const all = await api('GET', 'api/v1/status');
      if (run !== wallRun) break;
      applyStatuses(all);
      renderFocus();
    } catch {
      break;  // the regular look says what is wrong with the wall
    }
  }
  looksLeft = 0;
}

async function pollStatus(run) {
  while (run === wallRun) {
    if (!document.hidden) {
      try {
        const all = await api('GET', 'api/v1/status');
        if (run !== wallRun) return;
        wallDown = false;
        applyStatuses(all);
        // Somebody added or removed a KVM in another browser: this wall follows.
        const ids = Object.keys(all);
        if (ids.length !== tiles.size || ids.some(id => !tiles.has(id))) await reloadWall();
        if (++polls % 15 === 0) {  // about once a minute: has an admin changed what this account may do?
          const account = (await api('GET', 'api/v1/session')).user;
          if (run !== wallRun) return;
          if (account && me && (account.role !== me.role || account.name !== me.name)) {
            setMe(account);
            await reloadWall();
          }
        }
      } catch {
        if (run !== wallRun) return;
        wallDown = true;
      }
      setBanner(wallDown ? 'Lost contact with qKVM. Trying again…' : null);
      renderFocus();
    }
    await sleep(4000);
  }
}

let rateReady = false;
function setupRate(defaultSeconds) {
  if (rateReady) return;
  rateReady = true;
  const select = $('#rate');
  const fallback = String(Math.round(defaultSeconds * 1000));
  const seconds = [...new Set([0.5, 1, 2, 5, 10, defaultSeconds])].sort((a, b) => a - b);
  for (const s of seconds) select.add(new Option(`${s} s`, String(Math.round(s * 1000))));
  select.add(new Option('Paused', '0'));
  // "Paused" is for now. Remembered, the wall would open days later with every tile waiting for a picture
  // that is never asked for, and nothing to say why.
  const wanted = prefs.get('rate', fallback);
  select.value = wanted !== '0' && [...select.options].some(option => option.value === wanted) ? wanted : fallback;
  period = Number(select.value);
  select.addEventListener('change', () => {
    period = Number(select.value);
    if (period) prefs.set('rate', select.value);
  });
}

async function startWall() {
  if (me?.must_enroll) {
    mustEnroll();
    return;
  }
  stopWall();
  const run = wallRun;
  $('#auth').hidden = true;
  $('#auth-card').replaceChildren();  // with it go the password and code that were typed there
  $('#shell').hidden = false;
  setBanner(null);
  applyTheme();
  let info;
  try {
    info = await api('GET', 'api/v1/wall');
  } catch (ex) {
    if (ex.code !== 'unauthorized') {
      $('#wall').replaceChildren(h('div', { class: 'empty' },
        h('span', { class: 'empty-icon' }, icon('alert')),
        h('h2', {}, 'The wall could not be loaded'),
        h('p', {}, ex.message),
        h('button', { type: 'button', class: 'primary', onclick: startWall }, 'Try again')));
    }
    return;
  }
  if (run !== wallRun) return;
  setupRate(info.interval);
  buildTiles(info.devices);
  loadSavedActions();
  refreshUpdateBadge();
  if (can('admin') && !hasRecovery && prefs.get('recovery-hint', '') !== 'shown') {
    // Said once per browser: a copy set up before recovery keys existed has none.
    prefs.set('recovery-hint', 'shown');
    toast('There is no recovery key yet. Create one under Settings → Security, so a forgotten password can be replaced.', 'info');
  }
  pollStatus(run);
}

let reopening = false;  // a display link is being handed in again

function sessionExpired() {
  if (!$('#auth').hidden || reopening) return;  // already back at the sign-in page, or on the way back in
  if (prefs.get('display-key', '')) {
    // A screen on the wall: nobody is standing there with a keyboard. Its link is what it comes back in with.
    reopening = true;
    openDisplay().then(opened => {
      reopening = false;
      if (opened) startWall();
      else sessionExpired();
    });
    reloadIfOutdated();
    return;
  }
  if (ssoOn) {
    // The identity proxy has them signed in still, most likely: asked, qKVM signs them in again by that.
    reopening = true;
    api('GET', 'api/v1/session').then(session => {
      reopening = false;
      if (session.authenticated) {
        if (me && session.user.id !== me.id) {
          // The proxy names somebody else now. What the one before had open (the accounts, the activity
          // log) is not left on the screen for them: the page is fetched anew, as that account.
          location.reload();
          return;
        }
        setMe(session.user);
        startWall();
      } else {
        ssoOn = false;  // not this time: the sign-in page, like anybody
        sessionExpired();
        ssoOn = Boolean(session.sso?.on);
      }
    }).catch(() => { reopening = false; });
    reloadIfOutdated();
    return;
  }
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  showLogin('Your session ended. Sign in again to continue.');
  reloadIfOutdated();  // sessions end when the program restarts, which is also when it may have become a newer one
}

// A display link (…#display&key=…) opened in this browser: the key is kept here and taken out of the address,
// where it would be on show for whoever walks past the screen.
function takeDisplayKey() {
  const given = /[#&]key=(qkvm_[A-Za-z0-9_-]{20,80})/.exec(location.hash);
  if (!given) return '';
  history.replaceState(null, '', `${location.pathname}${location.search}#display`);
  return given[1];
}

// Hand the kept display link in for a session. False: there is none, or it is not valid any more.
async function openDisplay() {
  const key = prefs.get('display-key', '');
  if (!key) return false;
  for (;;) {
    try {
      setMe((await api('POST', 'api/v1/display', { key })).user);
      return true;
    } catch (ex) {
      if (ex.code !== 'network' && ex.code !== 'timeout') {
        prefs.set('display-key', '');  // taken back, or run out: a person has to sign in, or bring a new link
        return false;
      }
      await sleep(5000);  // qKVM is on its way back up: this screen waits for it
    }
  }
}

// A page belongs to one version of the program. Where an update was installed from another browser, or the
// program restarted as a newer one, a page that stayed open is the old page: its script asks for what the
// new program may no longer answer. It fetches itself again, once.
async function reloadIfOutdated() {
  const version = $('meta[name="qkvm-version"]')?.content || '';
  if (!version || version.includes('{{')) return;
  // The version, and the mark of the page's own files: the same version with other files is another page.
  const mine = `${version} ${$('meta[name="qkvm-page"]')?.content || ''}`;
  let theirs;
  try {
    const said = await (await fetch('healthz', { cache: 'no-store', signal: AbortSignal.timeout(5000) })).json();
    theirs = said.version && `${said.version} ${said.page || ''}`;
  } catch {
    return;  // not answering: there is nothing to compare with yet
  }
  if (!theirs || theirs === mine) return;
  try {
    // Once per version. If the page that comes back is still the old one, something in between keeps it,
    // and fetching it again and again would only keep the sign-in form from ever staying put.
    if (sessionStorage.getItem('qkvm.fetched-again-for') === theirs) return;
    sessionStorage.setItem('qkvm.fetched-again-for', theirs);
  } catch {
    return;  // nowhere to note that it was tried
  }
  location.reload();
}

async function signOut() {
  const sure = await confirmBox({
    title: 'Sign out?',
    message: 'qKVM keeps running. You need your password to get back in.',
    action: 'Sign out',
    danger: false,
  });
  if (!sure) return;
  try {
    await api('POST', 'api/v1/logout', { scope: 'this' });
  } catch (ex) {
    toast(ex.message, 'error');
    if (ex.code !== 'not_saved') return;
    await sleep(8000);  // signed out all the same: time to read why a restart might undo it, then the page shows it
  }
  prefs.set('display-key', '');  // signed out by hand, a wall screen stays out
  location.reload();
}

function toggleFullscreen() {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen?.().catch(() => {});
}

// Puts the icons on the buttons that live in index.html.
function decorate() {
  $('#add-device').prepend(icon('plus'));
  $('#update-badge').prepend(icon('download'));
  $('#select-toggle').prepend(icon('checkSquare'));
  $('#sign-out').prepend(icon('logOut'));
  $('#my-security').prepend(icon('shield'));
  $('#arrange').prepend(icon('grid'));
  $('#me-toggle').append(icon('users'));
  $('#view-toggle').prepend(icon('columns'));
  $('#view-toggle').append(icon('chevronDown', 'chevron'));
  $('#bulk-run').prepend(icon('zap'));
  $('#bulk-done').append(icon('x'));
  $('#open-settings').append(icon('sliders'));
  $('#fullscreen').append(icon('maximize', 'i-enter'), icon('minimize', 'i-exit'));
  themeButton($('#theme-toggle'));
  $('#display').prepend(icon('tv'));
  $('#group-pick').prepend(icon('grid'));
  $('#group-pick').append(icon('chevronDown', 'chevron'));
  $('#search-box').prepend(icon('search'));
  $('#order-pick').prepend(icon('list'));
  $('#order-pick').append(icon('chevronDown', 'chevron'));
  $('#cols-pick').prepend(icon('columns'));
  $('#cols-pick').append(icon('chevronDown', 'chevron'));
  $('#rate-pick').prepend(icon('clock'));
  $('#rate-pick').append(icon('chevronDown', 'chevron'));
  $('#focus-prev').append(icon('chevronLeft'));
  $('#focus-next').append(icon('chevronRight'));
  $('#focus-actions').prepend(icon('zap'));
  $('#focus-health').prepend(icon('activity'));
  $('#focus-open').prepend(icon('external'));
  $('#focus-open').addEventListener('click', event => openSignedIn(event, focus && tiles.get(focus.id)));
  $('#focus-close').append(icon('x'));
}

// A small panel that drops from a button in the top bar: for what is set now and then, and need not stand in
// the bar all day. One at a time; a click anywhere else, Esc, or what was chosen in it, closes it.
const dropped = [];

function closeDrops(except) {
  for (const [button, panel] of dropped) {
    if (panel === except || panel.hidden) continue;
    panel.hidden = true;
    button.setAttribute('aria-expanded', 'false');
  }
}

function drop(button, panel) {
  dropped.push([button, panel]);
  button.addEventListener('click', () => {
    closeDrops(panel);
    panel.hidden = !panel.hidden;
    button.setAttribute('aria-expanded', String(!panel.hidden));
  });
  // A choice that leads somewhere (a dialog, display mode) leaves no menu hanging behind it.
  panel.addEventListener('click', event => { if (event.target.closest('.menu-row')) closeDrops(); });
}

document.addEventListener('pointerdown', event => {
  if (!event.target.closest?.('.drop')) closeDrops();
});
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  const open = dropped.find(([, panel]) => !panel.hidden);
  if (!open) return;
  closeDrops();
  open[0].focus();
});

async function boot() {
  applyTheme();
  decorate();
  // The page states which version of the program it belongs to. A server from before that
  // existed sends the page with the placeholder still in it: the files were updated, but the
  // old program is still running and does not know the newer page's requests.
  const pageVersion = $('meta[name="qkvm-version"]')?.content || '';
  $('#stale').hidden = !pageVersion.includes('{{');
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyTheme);
  document.addEventListener('fullscreenchange', () => {
    document.documentElement.classList.toggle('is-fullscreen', Boolean(document.fullscreenElement));
  });

  const sorted = $('#order');
  sorted.value = order;
  if (sorted.value !== order) order = sorted.value = '';  // a choice saved by another version, that is not offered here
  sorted.addEventListener('change', () => {
    order = sorted.value;
    prefs.set('order', order);
    reorder();
  });
  const cols = $('#cols');
  const savedCols = prefs.get('cols', 'auto');
  cols.value = [...cols.options].some(option => option.value === savedCols) ? savedCols : 'auto';
  cols.addEventListener('change', () => { prefs.set('cols', cols.value); glide(layout, namedTiles()); });
  new ResizeObserver(layout).observe($('#wall'));

  const search = $('#search');
  search.addEventListener('input', () => { query = search.value; applyFilter(); });
  search.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    search.value = query = '';
    applyFilter();
    search.blur();
  });

  $('#add-device').addEventListener('click', addDevicesDialog);
  $('#select-toggle').addEventListener('click', () => setSelecting(!selecting));
  $('#bulk-all').addEventListener('click', selectShown);
  $('#bulk-none').addEventListener('click', () => { selected.clear(); renderSelection(); });
  $('#bulk-done').addEventListener('click', () => setSelecting(false));
  $('#bulk-run').addEventListener('click', () => actionsDialog([...selected]));
  $('#sign-out').addEventListener('click', signOut);
  $('#my-security').addEventListener('click', () => settingsDialog('security'));
  $('#arrange').addEventListener('click', arrangeTiles);
  drop($('#view-toggle'), $('#view-panel'));
  drop($('#me-toggle'), $('#me-panel'));
  $('#about').addEventListener('click', () => settingsDialog('about'));
  $('#group').addEventListener('change', event => setGroup(event.target.value));
  $('#display').addEventListener('click', () => setDisplay(true));
  $('#display-exit').addEventListener('click', () => setDisplay(false));
  $('#display-rotate').addEventListener('change', event => {
    prefs.set('rotate', event.target.checked ? '1' : '0');
    syncRotation();
  });
  for (const sign of ['pointermove', 'pointerdown', 'keydown']) document.addEventListener(sign, wakeDisplayBar);
  $('#update-badge').addEventListener('click', () => settingsDialog('updates'));
  // The server looks for a new release shortly after it starts and then once a day; ask it now and then.
  setInterval(() => { if (!$('#shell').hidden && !document.hidden) refreshUpdateBadge(); }, 10 * 60 * 1000);
  setTimeout(refreshUpdateBadge, 45 * 1000);
  // The enlarged view repaints when its size changes, like the tiles do.
  watchPixels($('#focus-screen'));
  $('#focus-screen').addEventListener('pixelsize', () => focus?.feed.paint().catch(() => {}));
  $('#open-settings').addEventListener('click', () => settingsDialog());
  $('#fullscreen').addEventListener('click', toggleFullscreen);
  $('#focus-close').addEventListener('click', () => closeFocus());
  $('#focus-prev').addEventListener('click', () => stepFocus(-1));
  $('#focus-next').addEventListener('click', () => stepFocus(1));
  $('#focus-actions').addEventListener('click', () => focus && actionsDialog(focus.id));
  $('#focus-health').addEventListener('click', () => {
    if (!focus) return;
    focus.health = !focus.health;
    renderFocus();
  });
  document.addEventListener('keydown', event => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if ($('dialog[open]') || $('#shell').hidden) return;
    if (arranging) {
      // The wall's own keys rest while its order is being set. Esc leaves it, also from the box a place is typed in.
      if (event.key === 'Escape') arranging();
      return;
    }
    if (event.target.matches?.('select, input, textarea')) return;
    if (event.key === 'f' || event.key === 'F') {
      toggleFullscreen();
    } else if (event.key === '/' && !focus) {
      event.preventDefault();
      search.focus();
    } else if ((event.key === 's' || event.key === 'S') && !focus && can('operator')) {
      setSelecting(!selecting);
    } else if ((event.key === 'd' || event.key === 'D') && !focus) {
      setDisplay(!displayMode);
    } else if (event.key === 'Escape' && !focus && selecting) {
      setSelecting(false);
    } else if (event.key === 'Escape' && !focus && displayMode) {
      setDisplay(false);
    } else if (focus && event.key === 'Escape') {
      closeFocus();
    } else if (focus && event.key === 'ArrowLeft') {
      stepFocus(-1);
    } else if (focus && event.key === 'ArrowRight') {
      stepFocus(1);
    }
  });

  const clock = $('#clock');
  const tick = () => { clock.textContent = new Date().toLocaleTimeString(); };
  tick();
  setInterval(tick, 1000);

  // Before anything is waited for: a display link's key does not stay in the address for a moment longer than it takes to read it.
  const offered = takeDisplayKey();
  let session;
  try {
    session = await api('GET', 'api/v1/session');
  } catch (ex) {
    showAuth('plain', h('p', { class: 'error' }, ex.message),
      h('div', { class: 'actions' }, h('button', { type: 'button', onclick: () => location.reload() }, 'Try again')));
    return;
  }
  minPassword = session.min_password;
  askName = session.ask_name;
  hasRecovery = session.recovery;
  ssoOn = Boolean(session.sso?.on);
  setMe(session.user);
  // Kept by a browser that nobody is signed in to: the screen it was made for. Where a person is signed in, it
  // is not: when their session ended, the browser would sign itself in again as the screen, for whoever sits down next.
  if (offered && !session.authenticated) prefs.set('display-key', offered);
  if (!session.initialized) showSetup(session);
  else if (session.authenticated) startWall();
  else if (await openDisplay()) startWall();
  else {
    // Signed in where the company signs in, and unknown here: said, so that nobody wonders which password is wanted.
    const stranger = session.sso?.name && !session.sso.known;
    showLogin(stranger ? `You are signed in as ${session.sso.name}, and there is no qKVM account of that name. An admin can make one.` : undefined);
  }
}

boot();
