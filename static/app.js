/* KESTREL // Cyber Threat Observatory — front end
 * Vanilla JS + MapLibre GL (2D) + SortableJS. All feed text is untrusted: everything goes through esc().
 */
'use strict';

/* ------------------------------------------------------------------ utils */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = u => (/^https?:\/\//i.test(u || '') ? u : null);
const fmtN = n => n == null ? '—' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(0) + 'k' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const IP_RX = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i;
const CVE_RX = /^CVE-\d{4}-\d{4,7}$/i;
// Phones get a single scrolling page (see the max-width: 760px block in style.css)
const PHONE_MQ = matchMedia('(max-width: 760px)');
const isPhone = () => PHONE_MQ.matches;
function ago(iso) {
  if (!iso) return '—';
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (isNaN(s)) return '—';
  if (s < 0) return 'soon';
  if (s < 60) return Math.floor(s) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
const fmtTime = iso => iso ? new Date(iso).toISOString().replace('T', ' ').slice(0, 16) + 'Z' : '—';
const cc = c => c ? `<span class="cc">${esc(c)}</span>` : '';
const loc = g => g ? [g.city, g.country].filter(Boolean).join(', ') + (g.approx ? ' (approx.)' : '') : 'locating…';
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 2600); }

/* --------------------------------------------------------------- settings */
// Three screens share this code: the map "face" (port 8787), "analytics" (port 8788, no map)
// and "mitre" (port 8789, MITRE ATT&CK only). Every panel exists on all of them; each screen just shows a different set by default.
// The page buttons in the top bar are presets ("views"). Map, Analytics and MITRE are the three screens; the other
// presets are panel sets shown on the analytics screen (#ransom, #vulns, ...) and switch in place without a reload.
const SCREEN = ['analytics', 'mitre'].includes(document.body.dataset.screen) ? document.body.dataset.screen : 'face';
const FACE_PANELS = ['pressure', 'livefeed', 'stream', 'ransomware', 'kev'];
const CHART_PANELS = ['tline', 'vulnboard', 'actorgraph', 'sectorheat', 'industries', 'scope', 'kevtrend', 'spider', 'cvetimeline', 'ransomtimeline', 'porttrend', 'outagegantt', 'cwe'];
const OTHER_PANELS = ['cves', 'attackers', 'ports', 'hotspots', 'c2', 'phishing', 'outages', 'news', 'investigate'];
const KEYED_PANELS = ['threatfox', 'urlhaus'];
const MITRE_PANELS = ['attackmx', 'mtactics', 'mttop', 'mttrend', 'mtactors', 'mtkev', 'mtfeed'];
const ALL_PANELS = [...FACE_PANELS, ...OTHER_PANELS, ...KEYED_PANELS, ...CHART_PANELS, 'saas', ...MITRE_PANELS];
// analytics: the threat radar and the industry panels lead, everything else follows
const ANALYTICS_TOP = ['scope', 'industries', 'sectorheat'];
const ANALYTICS_PANELS = [...ANALYTICS_TOP, 'saas', ...CHART_PANELS.filter(id => !ANALYTICS_TOP.includes(id)), ...OTHER_PANELS];
const ICON = {
  face: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
  analytics: '<path d="M4 19V9M10 19V5M16 19v-7M22 19H2"/>',
  mitre: '<path d="M3 4h5v5H3zM10 4h5v5h-5zM17 4h4v5h-4zM3 11h5v4H3zM10 11h5v4h-5zM3 17h5v3H3z"/>',
  ransom: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3M12 15v2"/>',
  vulns: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M12 8v5M12 16v.5"/>',
  network: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 11l10-5M7 13l10 5M19 7v10"/>',
  outages: '<path d="M2 12h4l2.5-6 4 12 2.5-6H22"/>',
  cycle: '<path d="M4 12a8 8 0 0 1 14-5.3M20 12a8 8 0 0 1-14 5.3M18 3v4h-4M6 21v-4h4"/>',
};
const VIEWS = [
  { id: 'face', label: 'Map', screen: 'face', title: 'Live map, Threat Pressure Index and live threat feed' },
  { id: 'analytics', label: 'Analytics', screen: 'analytics', title: 'Threat radar, industry targeting and every chart' },
  { id: 'mitre', label: 'MITRE', screen: 'mitre', title: 'MITRE ATT&CK matrix, kill chain and trending techniques' },
  { id: 'ransom', label: 'Ransomware', screen: 'analytics', cols: 3, title: 'Leak-site claims, who is being hit and the groups behind it',
    panels: ['ransomtimeline', 'ransomware', 'sectorheat', 'industries', 'actorgraph', 'news'], wide: ['ransomtimeline', 'sectorheat', 'actorgraph'] },
  { id: 'vulns', label: 'Vulnerabilities', screen: 'analytics', cols: 3, title: 'Exploited and newly published vulnerabilities',
    panels: ['vulnboard', 'kev', 'kevtrend', 'cvetimeline', 'cwe', 'cves', 'mtkev'], wide: ['vulnboard', 'cves'] },
  { id: 'network', label: 'Network', screen: 'analytics', cols: 3, title: 'Hostile infrastructure: scanners, C2, phishing and targeted ports',
    panels: ['scope', 'hotspots', 'porttrend', 'ports', 'attackers', 'c2', 'phishing', 'spider'], wide: ['scope', 'porttrend'] },
  { id: 'outages', label: 'Outages', screen: 'analytics', cols: 2, title: 'Cloud and SaaS provider outages and internet outages',
    panels: ['saas', 'outagegantt', 'outages', 'stream'], wide: ['saas', 'outagegantt'] },
];
const VIEW_BY = Object.fromEntries(VIEWS.map(v => [v.id, v]));
// a preset in the address bar (#ransom) only counts on the screen that hosts it
const hashView = () => { const v = VIEW_BY[decodeURIComponent(location.hash.slice(1))]; return v && v.screen === SCREEN ? v.id : SCREEN; };
let VIEW, PANEL_IDS, SHOWN, DEFAULTS, LS_KEY;
function viewConfig(view) {
  VIEW = view;
  const V = VIEW_BY[view];
  SHOWN = V.panels || (SCREEN === 'face' ? FACE_PANELS : SCREEN === 'mitre' ? MITRE_PANELS : ANALYTICS_PANELS);
  PANEL_IDS = [...SHOWN, ...ALL_PANELS.filter(id => !SHOWN.includes(id))];
  DEFAULTS = {
    layout: 'right', cols: V.cols || (SCREEN === 'face' ? 2 : SCREEN === 'mitre' ? 3 : 4), dockW: 620, dockH: 340, ticker: true, rail: true, compact: false, theme: 'obsidian', pings: true,
    base: 'satellite', labels: true, refresh: 5, layerCollapsed: false, kpiCollapsed: false, railMin: false,
    order: PANEL_IDS.slice(),
    hidden: Object.fromEntries(PANEL_IDS.filter(id => !SHOWN.includes(id)).map(id => [id, true])),
    collapsed: {},
    wide: V.wide ? Object.fromEntries(V.wide.map(id => [id, true]))
      : SCREEN === 'face' ? { pressure: true, livefeed: true, stream: true, news: true, cves: true }
      : SCREEN === 'mitre' ? { attackmx: true, mttrend: true, mtfeed: true }
      : { saas: true, tline: true, vulnboard: true, actorgraph: true, sectorheat: true, industries: true, attackmx: true, scope: true, kevtrend: true, cvetimeline: true, porttrend: true, news: true, cves: true },
    layers: { ransomware: true, c2: true, attackers: true, compromised: true, phishing: true, tor: false, threatfox: true, urlhaus: true, outages: true, heat: false, cables: true, paths: true, trails: true, night: true },
    pstate: {},
    split1: true, split2: true, split3: true,
  };
  // each preset keeps its own saved layout; the three screens keep the key they always had
  LS_KEY = 'kestrel.settings.v2' + (V.panels ? '.' + view : '');
}
viewConfig(hashView());
let S = loadSettings();
function loadSettings() {
  try {
    const raw = JSON.parse(localStorage.getItem(LS_KEY) || 'null');
    if (!raw) return structuredClone(DEFAULTS);
    const m = Object.assign(structuredClone(DEFAULTS), raw);
    for (const k of ['hidden', 'collapsed', 'wide', 'layers', 'pstate']) m[k] = Object.assign({}, DEFAULTS[k], raw[k] || {});
    if (SCREEN === 'face' && !raw.split1) { for (const id of PANEL_IDS) if (!FACE_PANELS.includes(id)) m.hidden[id] = true; m.split1 = true; }
    // 2026-11: the ATT&CK panels moved to their own MITRE screen; the new outage panel joins analytics
    if (!raw.split2) { if (SCREEN !== 'mitre') for (const id of MITRE_PANELS) m.hidden[id] = true; if (SCREEN === 'analytics') { m.hidden.saas = false; m.wide.saas = true; } m.split2 = true; }
    // undo the brief dense-mode experiment: restore the layout saved before it
    if (raw.density === 'dense' && raw.comfyPrefs) { Object.assign(m, raw.comfyPrefs); delete m.density; delete m.densePrefs; delete m.comfyPrefs; }
    m.order = (raw.order || []).filter(id => PANEL_IDS.includes(id));
    PANEL_IDS.forEach((id, i) => { if (!m.order.includes(id)) m.order.splice(Math.min(i, m.order.length), 0, id); });
    // 2026-11: analytics leads with the threat radar and the industry panels
    if (VIEW === 'analytics' && !raw.split3) { for (const id of ANALYTICS_TOP) { m.hidden[id] = false; m.wide[id] = true; } m.order = [...ANALYTICS_TOP, ...m.order.filter(id => !ANALYTICS_TOP.includes(id))]; m.split3 = true; }
    return m;
  } catch { return structuredClone(DEFAULTS); }
}
function save() { try { localStorage.setItem(LS_KEY, JSON.stringify(S)); } catch { /* private mode */ } }
const ps = id => (S.pstate[id] = S.pstate[id] || {});

/* ------------------------------------------------------------ page presets */
// The top-bar buttons. Links to another screen keep that screen's own tab (two-monitor walls);
// presets on this screen switch in place, without a reload.
const SCREEN_BASE = {};
for (const a of $$('#views a[data-to]')) SCREEN_BASE[a.dataset.to] = { href: a.getAttribute('href'), target: a.getAttribute('target') || '' };
SCREEN_BASE[SCREEN] = { href: location.pathname + location.search, target: '' };
const CYCLE_KEY = 'kestrel.cycle';
const CYCLE_VIEWS = VIEWS.filter(v => v.screen === 'analytics').map(v => v.id);
let CYC = { min: 0 }, cycleAt = Date.now(), lastInput = 0;
try { CYC = Object.assign(CYC, JSON.parse(localStorage.getItem(CYCLE_KEY) || '{}')); } catch { /* private mode */ }
const svgI = k => `<svg viewBox="0 0 24 24">${ICON[k]}</svg>`;
function viewHref(v) { const b = SCREEN_BASE[v.screen]; return b ? b.href + (v.panels ? '#' + v.id : '') : null; }
function renderViewNav() {
  const nav = $('#views');
  if (!nav) return;
  nav.innerHTML = VIEWS.filter(v => SCREEN_BASE[v.screen]).map(v => {
    const b = SCREEN_BASE[v.screen], here = v.screen === SCREEN;
    return `<a class="vw ${v.id === VIEW ? 'on' : ''} ${v.panels ? 'pre' : ''}" data-view="${v.id}" href="${esc(viewHref(v))}" ${!here && b.target ? `target="${esc(b.target)}"` : ''} title="${esc(v.label + ' · ' + v.title)}">${svgI(v.id)}<span>${esc(v.label)}</span></a>`;
  }).join('') + (SCREEN === 'analytics' ? `<button class="vw vw-cycle ${CYC.min ? 'on' : ''}" id="viewCycle" title="${CYC.min ? `Cycling the analytics presets every ${CYC.min} min (waits while you use the screen). Click to stop.` : 'Cycle through the analytics presets on this screen (interval under Customise)'}">${svgI('cycle')}<span>${CYC.min ? CYC.min + 'm' : 'Cycle'}</span><i></i></button>` : '');
  // phones scroll the button row sideways: keep the current page's button in view
  const on = $('.vw.on', nav);
  if (on && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = on.offsetLeft - nav.clientWidth / 2 + on.offsetWidth / 2;
  const V = VIEW_BY[VIEW];
  const sub = $('.brand .sub');
  if (sub) sub.textContent = SCREEN === 'face' ? 'Threat Observatory' : SCREEN === 'mitre' ? 'MITRE ATT&CK' : V.label;
  document.title = SCREEN === 'face' ? 'KESTREL · Cyber Threat Observatory' : `KESTREL · ${SCREEN === 'mitre' ? 'MITRE ATT&CK' : V.label}`;
}
function switchView(view) {
  if (view === VIEW) return;
  save();
  viewConfig(view);
  S = loadSettings();
  document.body.dataset.view = VIEW;
  applyLook(); buildDock(); buildDrawer(); renderViewNav();
  $('#dock').scrollTop = 0;
  window.scrollTo(0, 0);
  cycleAt = Date.now();
}
function goView(id) {
  const v = VIEW_BY[id];
  if (!v || v.screen !== SCREEN) return false;
  if (v.panels) { if (location.hash !== '#' + id) location.hash = id; else switchView(id); }
  else { history.pushState(null, '', location.pathname + location.search); switchView(SCREEN); }
  return true;
}
function setCycle(min) {
  CYC.min = +min || 0;
  if (CYC.min) CYC.last = CYC.min;
  try { localStorage.setItem(CYCLE_KEY, JSON.stringify(CYC)); } catch { /* private mode */ }
  cycleAt = Date.now();
  renderViewNav();
  const sel = $('#selCycle'); if (sel) sel.value = String(CYC.min);
}
addEventListener('hashchange', () => switchView(hashView()));
addEventListener('popstate', () => switchView(hashView()));
for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) addEventListener(ev, () => { lastInput = Date.now(); }, { passive: true });
// Cycle: step to the next analytics preset; waits while someone is using the screen or the Customise drawer is open
setInterval(() => {
  const bar = $('#viewCycle i');
  if (SCREEN !== 'analytics' || !CYC.min) { if (bar) bar.style.width = '0'; return; }
  const per = CYC.min * 60000;
  if (Date.now() - lastInput < 45000 || $('#drawer')?.classList.contains('open')) cycleAt = Math.max(cycleAt, Date.now() - per + 15000);
  const f = Math.min(1, (Date.now() - cycleAt) / per);
  if (bar) bar.style.width = (f * 100).toFixed(1) + '%';
  if (f >= 1) { const i = CYCLE_VIEWS.indexOf(VIEW); goView(CYCLE_VIEWS[(i + 1) % CYCLE_VIEWS.length]); }
}, 1000);

/* ------------------------------------------------------------------- data */
const FEEDS = ['cloudstatus', 'kev', 'ransomware', 'attackers', 'c2', 'outages', 'news', 'cves', 'phishing', 'tor', 'threatfox', 'urlhaus', 'home', 'porthist', 'epss'];
const GEO_FEEDS = ['c2', 'attackers', 'phishing', 'tor', 'threatfox', 'urlhaus'];
const D = {}, META = {};
let STATUS = null, INV = null;

async function loadFeed(name, quiet) {
  try {
    const r = await fetch('/api/' + name);
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || r.statusText);
    D[name] = j.data;
    META[name] = { updated: j.updated, stale: j.stale, source: j.source };
  } catch (e) {
    META[name] = Object.assign({}, META[name], { error: e.message });
  }
  onData(name, quiet);
}
async function loadStatus() {
  try { STATUS = await (await fetch('/api/status')).json(); } catch { STATUS = null; }
  renderHealth();
  const pend = STATUS?.geo?.pending || 0;
  const note = $('#geoNote');
  if (STATUS?.ports) {
    let changed = false;
    for (const [scr, port] of Object.entries(STATUS.ports)) {
      if (!port || scr === SCREEN || !SCREEN_BASE[scr]) continue;
      const href = `${location.protocol}//${location.hostname}:${port}/`;
      if (SCREEN_BASE[scr].href !== href) { SCREEN_BASE[scr].href = href; changed = true; }
    }
    if (changed) renderViewNav();
  }
  if (pend > 0) { note.innerHTML = `Geolocating <b>${pend}</b> IPs via ip-api… map fills in as they resolve`; note.classList.remove('hidden'); }
  else note.classList.add('hidden');
  return pend;
}
async function refreshAll() {
  const btn = $('#btnRefresh'); btn.classList.add('spin');
  await Promise.all(FEEDS.map(f => loadFeed(f)));
  btn.classList.remove('spin');
  await loadStatus();
}
// While the background geolocator is working, re-pull IP feeds so markers appear progressively
async function geoPoll() {
  const pend = await loadStatus();
  if (pend > 0) { await Promise.all(GEO_FEEDS.filter(f => D[f] && !D[f].needsKey).map(f => loadFeed(f, true))); setTimeout(geoPoll, 15000); }
  else if (geoPoll.wasPending) { await Promise.all(GEO_FEEDS.map(f => loadFeed(f, true))); }
  geoPoll.wasPending = pend > 0;
}

function onData(name, quiet) {
  for (const p of PANELS) if (p.deps.includes(name)) renderPanel(p.id);
  for (const L of LAYERS) if (L.feed === name || (L.id === 'heat' && GEO_FEEDS.includes(name))) updateLayer(L.id);
  if (name === 'attackers' || name === 'home' || name === 'ransomware') buildArcs();
  renderKPIs();
  lfIngest();
  if (name === 'news' || name === 'ransomware' || name === 'kev') renderTicker();
  if (name === 'cloudstatus') renderOutageAlert();
  if (!quiet) bootLog(`${name} ✓`);
}

/* ------------------------------------------------- cloud & SaaS outage alert */
// A provider outage (from /api/cloudstatus) raises a steady red banner on every screen (no flashing).
// The wall runs unattended, so each outage shows for OUTAGE_SHOW_MS after this screen first sees it and then
// clears by itself (the Cloud & SaaS panel keeps listing it). Dismiss clears it early. A new outage shows again.
const OUTAGE_SHOW_MS = 30 * 1000;
const SEEN_KEY = 'kestrel.outage.seen', ACK_KEY = 'kestrel.outage.ack';
let OUTAGE_TEST = null;
const lsGet = k => { try { return JSON.parse(localStorage.getItem(k) || '{}') || {}; } catch { return {}; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } };
const OUTAGE_SEEN = lsGet(SEEN_KEY);
function outageAlerts() {
  const live = (D.cloudstatus?.alerts || []).slice();
  if (OUTAGE_TEST && Date.now() < OUTAGE_TEST.until) live.unshift(OUTAGE_TEST.alert);
  return live;
}
// alerts still inside their 30-second window and not dismissed
function activeOutages() {
  const now = Date.now(), acks = lsGet(ACK_KEY);
  let dirty = false;
  for (const a of outageAlerts()) if (!OUTAGE_SEEN[a.key]) { OUTAGE_SEEN[a.key] = now; dirty = true; }
  for (const [k, v] of Object.entries(OUTAGE_SEEN)) if (now - v > 14 * 864e5) { delete OUTAGE_SEEN[k]; dirty = true; }
  if (dirty) lsSet(SEEN_KEY, OUTAGE_SEEN);
  return outageAlerts().filter(a => !acks[a.key] && now - OUTAGE_SEEN[a.key] < OUTAGE_SHOW_MS);
}
function renderOutageAlert() {
  let el = $('#outageAlert');
  if (!el) {
    el = document.createElement('div'); el.id = 'outageAlert'; el.setAttribute('role', 'alert');
    document.body.prepend(el);
    el.addEventListener('click', e => {
      if (e.target.closest('[data-ack]')) {
        const acks = lsGet(ACK_KEY), now = Date.now();
        for (const a of outageAlerts()) acks[a.key] = now;
        for (const [k, v] of Object.entries(acks)) if (now - v > 14 * 864e5) delete acks[k];
        lsSet(ACK_KEY, acks);
        renderOutageAlert();
      } else if (e.target.closest('[data-goto-saas]')) gotoPanel('saas');
    });
  }
  const alerts = activeOutages();
  const wasOn = document.body.classList.contains('outage-on');
  document.body.classList.toggle('outage-on', alerts.length > 0);
  if (wasOn !== alerts.length > 0) setTimeout(() => map?.resize(), 50);
  if (!alerts.length) { el.innerHTML = ''; return; }
  const left = Math.max(0, Math.ceil(Math.max(...alerts.map(a => OUTAGE_SEEN[a.key] + OUTAGE_SHOW_MS - Date.now())) / 1000));
  const svcs = [...new Set(alerts.map(a => a.service))];
  const line = a => `<span class="oa-item"><b>${esc(a.service)}</b> ${esc(a.title)}${a.started ? ` <i>· started ${ago(a.started)} ago</i>` : ''}</span>`;
  el.innerHTML = `<div class="oa-icon">!</div>
    <div class="oa-main"><div class="oa-head">Outage <span>${esc(svcs.join(' · '))}</span></div>
    <div class="oa-list">${alerts.slice(0, 3).map(line).join('')}${alerts.length > 3 ? `<span class="oa-item">+${alerts.length - 3} more</span>` : ''}</div></div>
    <div class="oa-act"><span class="oa-left" title="The banner clears itself; the Cloud &amp; SaaS panel keeps the details">clears in ${left}s</span><button data-ack title="Clear the banner now on this screen">Dismiss</button><button data-goto-saas>Details</button></div>`;
}
setInterval(() => { if (document.body.classList.contains('outage-on')) renderOutageAlert(); }, 1000);
function testOutageAlert() {
  OUTAGE_TEST = { until: Date.now() + 30000, alert: { key: 'test|' + Date.now(), service: 'TEST', title: 'This is a test of the outage alert. It clears itself in 30 seconds.', started: new Date().toISOString(), level: 'major' } };
  renderOutageAlert();
  setTimeout(renderOutageAlert, 30500);
}
document.addEventListener('click', e => { if (e.target.closest('[data-outage-test]')) testOutageAlert(); });
if (new URLSearchParams(location.search).has('outage-test')) setTimeout(testOutageAlert, 1500);

/* ------------------------------------------------------- threat pressure */
const INFOCON_LVL = { green: 0, yellow: 1, orange: 2, red: 3 };
function pressure() {
  const comps = [
    { k: 'KEV additions · 7d', v: D.kev?.added7, max: 12, w: 20 },
    { k: 'Critical CVEs · 72h', v: D.cves?.severity?.CRITICAL, max: 220, w: 20 },
    { k: 'Ransomware victims · 24h', v: D.ransomware?.last24h, max: 40, w: 25 },
    { k: 'Active botnet C2', v: D.c2?.online, max: 25, w: 10 },
    { k: 'Internet outages · live', v: D.outages?.ongoing, max: 12, w: 10 },
    { k: 'SANS ISC INFOCON', v: INFOCON_LVL[D.attackers?.infocon], max: 3, w: 15, disp: D.attackers?.infocon },
  ];
  let sc = 0, wt = 0;
  for (const c of comps) { if (c.v == null) continue; c.f = Math.min(c.v / c.max, 1); sc += c.f * c.w; wt += c.w; }
  const score = wt ? Math.round(sc / wt * 100) : null;
  const lvl = score == null ? ['—', '#4d6378'] : score < 20 ? ['LOW', '#5ee08a'] : score < 40 ? ['GUARDED', '#39b8ff'] : score < 60 ? ['ELEVATED', '#ffd166'] : score < 80 ? ['HIGH', '#ff8a3d'] : ['SEVERE', '#ff2d55'];
  return { score, lvl, comps };
}

/* ------------------------------------------------------------------- KPIs */
function renderKPIs() {
  const p = pressure();
  const k = [
    ['Pressure', p.score ?? '—', p.lvl[0], 'pressure', p.score >= 60 ? 'alert' : p.score >= 40 ? 'warn' : ''],
    ['INFOCON', (D.attackers?.infocon || '—').toUpperCase(), '', 'attackers', D.attackers?.infocon && D.attackers.infocon !== 'green' ? 'warn' : ''],
    ['Ransom 24h', D.ransomware?.last24h, 'victims', 'ransomware', D.ransomware?.last24h > 20 ? 'alert' : ''],
    ['KEV 7d', D.kev?.added7 != null ? '+' + D.kev.added7 : null, 'exploited', 'kev', D.kev?.added7 > 8 ? 'warn' : ''],
    ['Critical CVE', D.cves?.severity?.CRITICAL, '72h', 'cves', ''],
    ['C2 online', D.c2?.online, 'feodo', 'c2', ''],
    ['Outages', D.outages?.ongoing, 'live', 'outages', D.outages?.ongoing > 5 ? 'warn' : ''],
    ['Phish', D.phishing?.total, 'urls', 'phishing', ''],
  ];
  const pill = $('#levelPill');
  pill.querySelector('.lv-dot').style.background = p.lvl[1];
  pill.querySelector('.lv-txt').innerHTML = p.score == null ? '<span class="lv-pre">Threat level </span>—' : `<span class="lv-pre">Threat level · </span>${esc(p.lvl[0])}`;
  pill.querySelector('.lv-num').textContent = p.score == null ? '' : p.score + '/100';
  $('#kpis').innerHTML = k.map(([lbl, v, sub, pid, cls]) =>
    `<div class="kpi ${cls}" data-goto="${pid}" title="Show ${esc(pid)} panel"><div class="k">${esc(lbl)}</div><div class="v">${esc(v ?? '—')}<small>${esc(sub)}</small></div></div>`).join('');
}

/* ----------------------------------------------------------------- ticker */
function renderTicker() {
  const items = [];
  for (const n of (D.news?.items || []).slice(0, 30)) if (safeUrl(n.link)) items.push(`<a href="${esc(n.link)}" target="_blank" rel="noopener noreferrer"><b>${esc(n.source)}</b><i>${ago(n.published)}</i>${esc(n.title)}</a>`);
  for (const r of (D.ransomware?.items || []).slice(0, 8)) items.splice(Math.floor(Math.random() * items.length), 0, `<a><b style="color:var(--ransom)">RANSOMWARE</b><i>${ago(r.discovered)}</i>${esc(r.group)} claims ${esc(r.victim)}${r.cc ? ' (' + esc(r.cc) + ')' : ''}</a>`);
  if (!items.length) return;
  const el = $('#tickerInner');
  el.innerHTML = items.join('') + items.join('');
  el.style.animationDuration = Math.max(60, items.length * 7) + 's';
}

/* ---------------------------------------------------------------- helpers */
function barsHTML(pairs, opt = {}) {
  if (!pairs?.length) return '<div class="loading">no data</div>';
  const max = opt.max || Math.max(...pairs.map(p => p[1]), 1);
  return `<div class="bars">${pairs.map(([l, v, attrs = '', color]) => `<div class="bar ${attrs ? 'click' : ''}" ${attrs}><span class="lbl" title="${esc(l)}">${esc(l)}</span><span class="trk"><span class="fill" style="width:${(v / max * 100).toFixed(1)}%;${color ? `background:${color};box-shadow:0 0 8px ${color}` : ''}"></span></span><span class="val">${fmtN(v)}</span></div>`).join('')}</div>`;
}
const flyAttr = g => g ? `data-fly="${g.lon},${g.lat}"` : '';
const ccFly = code => { const c = COUNTRY_CENTER[code]; return c ? `data-fly="${c[1]},${c[0]},3.2"` : ''; };
function chips(pid, key, opts, cur) {
  return `<div class="chips">${opts.map(([v, l]) => `<button class="chip ${String(cur) === String(v) ? 'on' : ''}" data-chip="${pid}|${key}|${esc(v)}">${esc(l)}</button>`).join('')}</div>`;
}
const sevOf = s => s == null ? 'UNSCORED' : s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MEDIUM' : s > 0 ? 'LOW' : 'NONE';
const nvd = id => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
const needsKey = (feed) => `<div class="keynote">This feed needs a free API key.<br>Add <code>${esc(D[feed]?.needsKey)}</code> to <code>config.json</code> (or set it as an environment variable) and restart KESTREL. See the README for where to get one.</div>`;
const COUNTRY_CENTER = {};

/* ----------------------------------------------------------------- panels */
const PANELS = [
  {
    id: 'pressure', title: 'Threat Pressure Index', deps: ['kev', 'cves', 'ransomware', 'c2', 'outages', 'attackers'],
    src: () => 'composite of 6 feeds',
    render() {
      const p = pressure();
      const C = 2 * Math.PI * 54, arc = C * 0.75, val = p.score == null ? 0 : arc * p.score / 100;
      const ticks = Array.from({ length: 21 }, (_, i) => { const a = (135 + i * 13.5) * Math.PI / 180; const r1 = 62, r2 = i % 5 ? 65 : 69; return `<line x1="${70 + r1 * Math.cos(a)}" y1="${70 + r1 * Math.sin(a)}" x2="${70 + r2 * Math.cos(a)}" y2="${70 + r2 * Math.sin(a)}" stroke="rgba(255,255,255,${i % 5 ? .12 : .3})"/>`; }).join('');
      return `<div class="gauge-wrap">
        <svg class="gauge" viewBox="0 0 140 130" width="150">
          <circle cx="70" cy="70" r="54" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="9" stroke-dasharray="${arc} ${C}" transform="rotate(135 70 70)"/>
          <circle cx="70" cy="70" r="54" fill="none" stroke="${p.lvl[1]}" stroke-width="9" stroke-dasharray="${val} ${C}" transform="rotate(135 70 70)" stroke-linecap="round" style="transition:stroke-dasharray 1s"/>
          ${ticks}
          <text x="70" y="76" text-anchor="middle" fill="${p.lvl[1]}" font-size="32" font-weight="600">${p.score ?? '—'}</text>
          <text x="70" y="96" text-anchor="middle" style="fill:var(--dim)" font-size="10" letter-spacing="2">${p.lvl[0]}</text>
        </svg>
        <div>${p.comps.map(c => `<div class="comp"><span class="lbl">${esc(c.k)}</span><span class="trk"><span class="fill" style="width:${((c.f || 0) * 100).toFixed(0)}%;background:${c.f > .66 ? 'var(--crit)' : c.f > .33 ? 'var(--high)' : 'var(--acc)'}"></span></span><span>${esc(c.disp ?? (c.v ?? '…'))}</span></div>`).join('')}
        <div class="disclaim">Heuristic 0–100 composite of live feed volumes, weighted and capped. A situational-awareness signal, not a forecast.</div></div>
      </div>`;
    },
  },
  {
    id: 'livefeed', title: 'Live Threat Feed', deps: [], live: true,
    badge: () => LF.paused ? 'paused' : `${LF.rate} / min`,
    src: () => 'streams every item in the loaded feeds · NEW = arrived since you opened KESTREL',
    render() {
      const st = ps('livefeed'), f = st.kind || 'all', sp = st.speed || '1400';
      const opt = (v, l, cur) => `<option value="${v}" ${String(cur) === v ? 'selected' : ''}>${l}</option>`;
      return `<div class="lf-bar">
        <select data-pset="livefeed|kind" title="Filter by type">${[['all', 'All types'], ['ransom', 'Ransomware'], ['attack', 'Attackers'], ['c2', 'C2 servers'], ['phish', 'Phishing'], ['comp', 'Compromised'], ['outage', 'Outages'], ['vuln', 'Vulnerabilities'], ['ioc', 'IOCs']].map(([v, l]) => opt(v, l, f)).join('')}</select>
        <select data-pset="livefeed|speed" title="Stream speed">${[['2600', 'Slow'], ['1400', 'Normal'], ['650', 'Fast']].map(([v, l]) => opt(v, l, sp)).join('')}</select>
        <button class="lf-pause ${LF.paused ? 'on' : ''}" data-lf="pause" title="Pause / resume (P)">${LF.paused ? '▶' : '❚❚'}</button></div>
        <div class="rows lf" id="lfList">${LF.list.filter(e => f === 'all' || e.kind === f).slice(0, 60).map(lfRow).join('') || '<div class="loading">waiting for the first events</div>'}</div>`;
    },
  },
  {
    id: 'stream', title: 'Latest Events', deps: ['ransomware', 'kev', 'cves', 'news', 'outages'],
    src: () => 'merged · newest first',
    render() {
      const ev = [];
      for (const r of D.ransomware?.items || []) ev.push({ t: r.discovered, c: 'var(--ransom)', tag: ['RANSOM', 'red'], title: `${r.group} → ${r.victim}`, sub: [r.sector, r.cc].filter(Boolean).join(' · '), fly: r.geo });
      for (const k of (D.kev?.items || []).slice(0, 25)) ev.push({ t: k.added + 'T12:00:00Z', c: 'var(--high)', tag: ['KEV', 'org'], title: `${k.cve} · ${k.vendor} ${k.product}`, sub: k.name, url: nvd(k.cve) });
      for (const c of (D.cves?.items || []).filter(c => c.score >= 9).slice(0, 25)) ev.push({ t: c.published, c: 'var(--crit)', tag: ['CVE ' + c.score, 'red'], title: c.id, sub: c.desc.slice(0, 110), url: nvd(c.id) });
      for (const o of (D.outages?.items || []).filter(o => o.ongoing)) ev.push({ t: o.startIso, c: 'var(--outage)', tag: ['OUTAGE', 'ylw'], title: `${o.name} internet disruption`, sub: o.sources.join(', '), fly: o.geo });
      for (const n of (D.news?.items || []).slice(0, 30)) ev.push({ t: n.published, c: 'var(--acc)', tag: [n.source.split(' ')[0].toUpperCase(), ''], title: n.title, url: n.link });
      ev.sort((a, b) => (b.t || '').localeCompare(a.t || ''));
      return `<div class="rows">${ev.slice(0, 60).map(e => {
        const a = e.fly ? flyAttr(e.fly) : e.url && safeUrl(e.url) ? `data-open="${esc(e.url)}"` : '';
        return `<div class="r ${a ? 'click' : ''}" ${a}><span class="typebar" style="background:${e.c}"></span><div><div class="t"><span class="tag ${e.tag[1]}">${esc(e.tag[0])}</span>${esc(e.title)}</div>${e.sub ? `<div class="s">${esc(e.sub)}</div>` : ''}</div><span class="m">${ago(e.t)}</span></div>`;
      }).join('')}</div>`;
    },
  },
  {
    id: 'ransomware', title: 'Ransomware Leak Sites', deps: ['ransomware'], feed: 'ransomware',
    badge: () => D.ransomware ? `${D.ransomware.last24h} / 24h` : '',
    render() {
      const d = D.ransomware, st = ps('ransomware'), tab = st.tab || 'victims';
      let body;
      if (tab === 'groups') body = barsHTML(d.groups.map(([g, n]) => [g, n, '', 'var(--ransom)']));
      else if (tab === 'targets') body = `<div class="sub-h">Countries</div>${barsHTML(d.countries.map(([c, n]) => [`${c} ${COUNTRY_NAME[c] || ''}`, n, ccFly(c)]))}<div class="sub-h">Sectors</div>${barsHTML(d.sectors.map(([s, n]) => [s, n]))}`;
      else body = `<div class="rows">${d.items.map(v => `<div class="r ${v.geo ? 'click' : ''}" ${flyAttr(v.geo)}><span class="dotS" style="background:var(--ransom);box-shadow:0 0 6px var(--ransom)"></span><div><div class="t">${esc(v.victim)}</div><div class="s"><span class="tag red">${esc(v.group)}</span>${cc(v.cc)}${esc(v.sector || '')}</div></div><span class="m">${ago(v.discovered)}${v.url ? `<br><a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer">src ↗</a>` : ''}</span></div>`).join('')}</div>`;
      return chips('ransomware', 'tab', [['victims', 'Victims'], ['groups', 'Groups'], ['targets', 'Targets']], tab) + body;
    },
  },
  {
    id: 'kev', title: 'CISA Known Exploited', deps: ['kev'], feed: 'kev',
    badge: () => D.kev ? `+${D.kev.added7} / 7d` : '',
    render() {
      const d = D.kev;
      return `<div class="stats"><div class="stat"><div class="k">Catalog</div><div class="v">${fmtN(d.total)}</div></div><div class="stat"><div class="k">+30 days</div><div class="v">${d.added30}</div></div><div class="stat"><div class="k">Ransomware-linked</div><div class="v" style="color:var(--ransom)">${d.ransomware}</div></div></div>
      <div class="rows">${d.items.slice(0, 50).map(k => `<div class="r click" data-open="${esc(nvd(k.cve))}" title="${esc(k.desc)}"><span class="dotS" style="background:${k.ransomware ? 'var(--ransom)' : 'var(--high)'}"></span><div><div class="t">${esc(k.cve)} <span class="s">${esc(k.vendor)} · ${esc(k.product)}</span></div><div class="s">${esc(k.name)}</div><div>${k.ransomware ? '<span class="tag red">ransomware</span>' : ''}${(k.cwes || []).slice(0, 2).map(c => `<span class="tag">${esc(c)}</span>`).join('')}<span class="tag ylw">due ${esc(k.due)}</span></div></div><span class="m">${esc(k.added)}</span></div>`).join('')}</div>`;
    },
  },
  {
    id: 'cves', title: 'New CVEs · NVD', deps: ['cves'], feed: 'cves',
    badge: () => D.cves ? `${fmtN(D.cves.total)} / 72h` : '',
    render() {
      const d = D.cves, st = ps('cves'), f = st.sev || 'CRITICAL';
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];
      const tot = order.reduce((a, k) => a + (d.severity[k] || 0), 0) || 1;
      const strip = `<div style="display:flex;height:8px;margin-bottom:8px">${order.map(k => `<span title="${k}: ${d.severity[k] || 0}" style="width:${(d.severity[k] || 0) / tot * 100}%;background:var(--${{ CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', UNSCORED: 'mute' }[k]})"></span>`).join('')}</div>`;
      const list = d.items.filter(c => f === 'ALL' || sevOf(c.score) === f).slice(0, 80);
      return chips('cves', 'sev', [['CRITICAL', `Critical ${d.severity.CRITICAL || 0}`], ['HIGH', `High ${d.severity.HIGH || 0}`], ['MEDIUM', `Medium ${d.severity.MEDIUM || 0}`], ['ALL', 'All']], f) + strip +
        `<div class="rows">${list.map(c => `<div class="r click" data-open="${esc(nvd(c.id))}"><span class="sc ${sevOf(c.score)}">${c.score ?? '—'}</span><div><div class="t">${esc(c.id)} ${(c.cwe || []).map(w => `<span class="tag">${esc(w)}</span>`).join('')}</div><div class="s">${esc(c.desc)}</div></div><span class="m">${ago(c.published)}</span></div>`).join('') || '<div class="loading">none in window</div>'}</div>`;
    },
  },
  {
    id: 'attackers', title: 'Top Attacking IPs · DShield', deps: ['attackers'], feed: 'attackers',
    badge: () => D.attackers ? `INFOCON ${D.attackers.infocon.toUpperCase()}` : '',
    render() {
      const d = D.attackers, max = Math.max(...d.items.map(i => i.reports), 1);
      const tr = d.trend.filter(t => t.count != null);
      let spark = '';
      if (tr.length > 2) {
        const m = Math.max(...tr.map(t => t.count)), w = 300, h = 46;
        const pts = tr.map((t, i) => `${(i / (tr.length - 1) * w).toFixed(1)},${(h - 4 - t.count / m * (h - 8)).toFixed(1)}`).join(' ');
        spark = `<div class="sub-h">ISC threat-feed volume · 30d</div><svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polygon points="0,${h} ${pts} ${w},${h}" fill="rgba(var(--acc-rgb),.12)"/><polyline points="${pts}" fill="none" stroke="var(--acc)" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
      }
      return spark + `<div class="sub-h">Most-reported sources</div><div class="rows">${d.items.slice(0, 40).map(a => `<div class="r click" ${a.geo ? flyAttr(a.geo) : ''} data-inv="${esc(a.ip)}"><span class="m" style="text-align:left;min-width:20px">#${a.rank}</span><div><div class="t">${esc(a.ip)} ${cc(a.geo?.cc)}</div><div class="s">${esc(a.geo?.isp || 'locating…')}</div><div class="trk" style="height:3px;background:rgba(255,255,255,.05);margin-top:3px"><div style="height:3px;width:${(a.reports / max * 100).toFixed(1)}%;background:var(--attk)"></div></div></div><span class="m">${fmtN(a.reports)}<br>reports</span></div>`).join('')}</div>`;
    },
  },
  {
    id: 'ports', title: 'Most-Targeted Ports', deps: ['attackers'], feed: 'attackers',
    render() {
      return barsHTML(D.attackers.ports.map(p => [`${p.port}${p.name ? ' · ' + p.name : ''}`, p.records])) +
        '<div class="disclaim">Records reported to SANS ISC DShield sensors worldwide today.</div>';
    },
  },
  {
    id: 'hotspots', title: 'Hostile Infrastructure by Country', deps: GEO_FEEDS,
    src: () => 'C2, attackers, compromised, phishing, Tor, IOCs',
    render() {
      const st = ps('hotspots'), src = st.src || 'all';
      const pools = {
        c2: D.c2?.items, attackers: D.attackers?.items, compromised: D.attackers?.compromised, phishing: D.phishing?.items, tor: D.tor?.items,
        threatfox: D.threatfox?.items, urlhaus: D.urlhaus?.items,
      };
      const cnt = {};
      for (const [k, arr] of Object.entries(pools)) if (src === 'all' || src === k) for (const x of arr || []) if (x.geo?.cc) cnt[x.geo.cc] = (cnt[x.geo.cc] || 0) + 1;
      const top = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 14);
      return chips('hotspots', 'src', [['all', 'All'], ['attackers', 'Attackers'], ['compromised', 'Compromised'], ['phishing', 'Phishing'], ['tor', 'Tor'], ['c2', 'C2']], src) +
        (top.length ? barsHTML(top.map(([c, n]) => [`${c} ${COUNTRY_NAME[c] || ''}`, n, ccFly(c)])) : '<div class="loading">waiting for geolocation</div>');
    },
  },
  {
    id: 'c2', title: 'Botnet C2 Servers · Feodo', deps: ['c2'], feed: 'c2',
    badge: () => D.c2 ? `${D.c2.online} online` : '',
    render() {
      const d = D.c2;
      return `<div class="chips">${d.families.map(([f, n]) => `<span class="tag pur">${esc(f)} ${n}</span>`).join('')}</div><div class="rows">${d.items.map(c => `<div class="r click" ${flyAttr(c.geo)} data-inv="${esc(c.ip)}"><span class="dotS" style="background:${c.status === 'online' ? 'var(--crit)' : 'var(--mute)'};${c.status === 'online' ? 'box-shadow:0 0 6px var(--crit)' : ''}"></span><div><div class="t">${esc(c.ip)}:${esc(c.port)} ${cc(c.cc)}</div><div class="s"><span class="tag pur">${esc(c.malware)}</span>${esc(c.asName || '')}</div></div><span class="m">${esc(c.status)}<br>${esc(c.lastOnline || '')}</span></div>`).join('') || '<div class="loading">Feodo tracker currently lists no C2s</div>'}</div>
      <div class="disclaim">Feodo Tracker covers banking-trojan/loader botnets (Emotet, QakBot, Dridex…). Small numbers here usually mean takedowns worked.</div>`;
    },
  },
  {
    id: 'phishing', title: 'Active Phishing · OpenPhish', deps: ['phishing'], feed: 'phishing',
    badge: () => D.phishing ? `${D.phishing.total} urls` : '',
    render() {
      const d = D.phishing, st = ps('phishing'), tab = st.tab || 'urls';
      if (tab === 'hosting') return chips('phishing', 'tab', [['urls', 'URLs'], ['hosting', 'Hosting platforms']], tab) + `<div class="sub-h">Abused domains / platforms</div>${barsHTML(d.platforms.map(([p, n]) => [p, n]))}<div class="sub-h">TLDs</div>${barsHTML(d.tlds.map(([p, n]) => ['.' + p, n]))}`;
      return chips('phishing', 'tab', [['urls', 'URLs'], ['hosting', 'Hosting platforms']], tab) +
        `<div class="rows">${d.items.slice(0, 120).map(p => `<div class="r ${p.geo ? 'click' : ''}" ${flyAttr(p.geo)}><span class="dotS" style="background:var(--phish)"></span><div><div class="t" style="font-size:10.5px">${esc(p.url)}</div><div class="s">${cc(p.geo?.cc)}${esc(p.ip || 'resolving…')} ${esc(p.geo?.isp || '')}</div></div><span class="m"></span></div>`).join('')}</div><div class="disclaim">URLs are defanged (hxxp, [.]) and never linked. Do not visit them.</div>`;
    },
  },
  {
    id: 'outages', title: 'Internet Outages · IODA', deps: ['outages'], feed: 'outages',
    badge: () => D.outages ? `${D.outages.ongoing} live` : '',
    render() {
      const d = D.outages;
      return `<div class="rows">${d.items.map(o => `<div class="r click" ${flyAttr(o.geo)}><span class="dotS" style="background:${o.ongoing ? 'var(--outage)' : 'var(--mute)'};${o.ongoing ? 'box-shadow:0 0 6px var(--outage)' : ''}"></span><div><div class="t">${cc(o.cc)}${esc(o.name)} ${o.ongoing ? '<span class="tag red">ongoing</span>' : ''}</div><div class="s">${o.sources.map(s => `<span class="tag">${esc(s)}</span>`).join('')} ${o.durationH}h</div></div><span class="m">${ago(o.startIso)} ago<br>score ${fmtN(Math.round(o.score))}</span></div>`).join('') || '<div class="loading">no outages detected</div>'}</div>
      <div class="disclaim">Country-level connectivity drops detected by BGP, active probing and telescope signals over the last 48h.</div>`;
    },
  },
  {
    id: 'news', title: 'Intel Wire', deps: ['news'], feed: 'news',
    render() {
      const d = D.news, st = ps('news'), src = st.src || 'all', q = (st.q || '').toLowerCase();
      const items = d.items.filter(n => (src === 'all' || n.source === src) && (!q || (n.title + ' ' + n.summary).toLowerCase().includes(q)));
      return chips('news', 'src', [['all', 'All'], ...d.sources.map(s => [s, s])], src) + (q ? `<div class="chips"><button class="chip on" data-chip="news|q|">filter: "${esc(q)}" ✕</button></div>` : '') +
        `<div class="rows">${items.slice(0, 60).map(n => `<div class="r click" data-open="${esc(safeUrl(n.link) || '')}"><span class="typebar" style="background:var(--acc)"></span><div><div class="t">${esc(n.title)}</div><div class="s">${esc(n.summary.slice(0, 180))}</div><div><span class="tag grn">${esc(n.source)}</span>${n.tags.map(t => `<span class="tag ${t === 'ransomware' || t === 'zero-day' ? 'red' : t === 'apt' ? 'pur' : ''}">${esc(t)}</span>`).join('')}${n.cves.map(c => `<span class="tag org">${esc(c)}</span>`).join('')}</div></div><span class="m">${ago(n.published)}</span></div>`).join('') || '<div class="loading">no matches</div>'}</div>`;
    },
  },
  {
    id: 'investigate', title: 'IP Investigation', deps: [],
    src: () => 'GreyNoise community · feeds · CINS · Spamhaus DROP',
    render() {
      const st = ps('investigate');
      let out = `<form class="inv-form" data-invform><input name="ip" placeholder="e.g. 45.83.66.22" value="${esc(st.q || '')}" spellcheck="false"><button class="btn">Scan</button></form>`;
      if (INV === 'loading') return out + '<div class="loading">querying sources</div>';
      if (!INV) return out + '<div class="keynote">Enter an IP, or click <b>Investigate</b> on any map marker or IP row. KESTREL checks it against every loaded feed, the CINS Army list, Spamhaus DROP and GreyNoise.</div>';
      if (INV.error) return out + `<div class="err">${esc(INV.error)}</div>`;
      const gn = INV.greynoise || {};
      const label = { listed: 'LISTED · HOSTILE', noise: 'INTERNET SCANNER', clean: 'NO HITS' }[INV.verdict];
      out += `<div class="verdict ${INV.verdict}"><span>${esc(INV.ip)}</span><span>${label}</span></div>`;
      out += `<table class="kv"><tr><td>Location</td><td>${esc(loc(INV.geo))}</td></tr><tr><td>Network</td><td>${esc(INV.geo?.as || '—')}</td></tr><tr><td>ISP</td><td>${esc(INV.geo?.isp || '—')}</td></tr><tr><td>rDNS</td><td>${esc(INV.rdns || '—')}</td></tr>
        <tr><td>GreyNoise</td><td>${gn.error ? esc(gn.error) : `${gn.noise ? '<span class="tag org">noise</span>' : ''}${gn.riot ? '<span class="tag grn">benign service</span>' : ''}${gn.classification ? `<span class="tag ${gn.classification === 'malicious' ? 'red' : ''}">${esc(gn.classification)}</span>` : ''} ${esc(gn.name && gn.name !== 'unknown' ? gn.name : '')} <span class="s">${esc(gn.message || '')}</span>`}</td></tr></table>`;
      out += `<div class="sub-h">Feed matches (${INV.hits.length})</div>` + (INV.hits.length ? `<div class="rows">${INV.hits.map(h => `<div class="r"><span class="dotS" style="background:var(--crit)"></span><div><div class="t">${esc(h.feed)}</div><div class="s">${esc(Object.entries(h.detail).filter(([, v]) => v != null && v !== '' && typeof v !== 'object').slice(0, 5).map(([k, v]) => `${k}: ${v}`).join(' · '))}</div></div><span></span></div>`).join('')}</div>` : '<div class="s" style="color:var(--dim)">Not present in any loaded feed or blocklist.</div>');
      return out;
    },
  },
  {
    id: 'threatfox', title: 'ThreatFox IOCs · 24h', deps: ['threatfox'], feed: 'threatfox', keyed: true,
    badge: () => D.threatfox?.items?.length ? `${D.threatfox.items.length} iocs` : '',
    render() {
      const d = D.threatfox;
      if (d.needsKey) return needsKey('threatfox');
      return `<div class="chips">${d.families.map(([f, n]) => `<span class="tag pur">${esc(f)} ${n}</span>`).join('')}</div><div class="rows">${d.items.slice(0, 100).map(x => `<div class="r ${x.geo ? 'click' : ''}" ${flyAttr(x.geo)}><span class="dotS" style="background:var(--tfox)"></span><div><div class="t" style="font-size:10.5px">${esc(x.ioc)}</div><div class="s"><span class="tag">${esc(x.type)}</span><span class="tag pur">${esc(x.malware)}</span>${esc(x.threat)} · conf ${esc(x.confidence)}%</div></div><span class="m">${ago(x.firstSeen)}</span></div>`).join('')}</div>`;
    },
  },
  {
    id: 'urlhaus', title: 'URLhaus Malware URLs', deps: ['urlhaus'], feed: 'urlhaus', keyed: true,
    badge: () => D.urlhaus?.items?.length ? `${D.urlhaus.online} online` : '',
    render() {
      const d = D.urlhaus;
      if (d.needsKey) return needsKey('urlhaus');
      return `<div class="rows">${d.items.slice(0, 100).map(x => `<div class="r ${x.geo ? 'click' : ''}" ${flyAttr(x.geo)}><span class="dotS" style="background:${x.status === 'online' ? 'var(--uh)' : 'var(--mute)'}"></span><div><div class="t" style="font-size:10.5px">${esc(x.url)}</div><div class="s">${cc(x.geo?.cc)}${esc(x.threat || '')} ${(x.tags || []).slice(0, 4).map(t => `<span class="tag">${esc(t)}</span>`).join('')}</div></div><span class="m">${ago(x.added)}</span></div>`).join('')}</div>`;
    },
  },
];
PANELS.push(...(window.EXTRA_PANELS || []));
const PANEL = Object.fromEntries(PANELS.map(p => [p.id, p]));

function panelShell(p) {
  const el = document.createElement('section');
  el.className = 'panel';
  el.dataset.id = p.id;
  el.innerHTML = `<header class="ph"><span class="grip" title="Drag to reorder">⋮⋮</span><h3 data-act="collapse">${esc(p.title)}</h3><span class="badge ${p.live ? 'live' : ''}"></span>
    <div class="pa"><button data-act="wide" title="Toggle full width">⇔</button><button data-act="collapse" title="Collapse">▾</button><button data-act="hide" title="Hide panel">✕</button></div></header>
    <div class="pb"><div class="loading">awaiting feed</div></div><footer class="pf"><span class="src"></span><span class="upd"></span></footer>`;
  return el;
}
function buildDock() {
  const dock = $('#dock');
  dock.innerHTML = '';
  for (const id of S.order) {
    const p = PANEL[id];
    if (!p || S.hidden[id]) continue;
    const el = panelShell(p);
    el.classList.toggle('wide', !!S.wide[id]);
    el.classList.toggle('collapsed', !!S.collapsed[id]);
    dock.appendChild(el);
    renderPanel(id);
  }
}
function renderPanel(id) {
  const p = PANEL[id];
  const el = $(`.panel[data-id="${id}"]`);
  if (!p || !el) return;
  const body = $('.pb', el);
  const feed = p.feed;
  const missing = feed ? !D[feed] : p.deps.length && p.deps.every(f => !D[f]);
  if (feed && META[feed]?.error && !D[feed]) body.innerHTML = `<div class="err">Feed unavailable: ${esc(META[feed].error)}</div>`;
  else if (missing) body.innerHTML = '<div class="loading">awaiting feed</div>';
  else {
    const top = body.scrollTop;
    try { body.innerHTML = p.render(); } catch (e) { console.error(id, e); body.innerHTML = `<div class="err">render error: ${esc(e.message)}</div>`; }
    body.scrollTop = top;
  }
  $('.badge', el).textContent = p.badge && !missing ? p.badge() : '';
  $('.badge', el).style.display = $('.badge', el).textContent ? '' : 'none';
  const m = feed && META[feed];
  $('.src', el).textContent = p.src ? p.src() : m?.source || '';
  $('.upd', el).innerHTML = m?.updated ? `${m.stale ? '<span class="stale">stale · </span>' : ''}updated ${ago(m.updated)} ago` : '';
}
function gotoPanel(id) {
  if (S.hidden[id]) { S.hidden[id] = false; save(); buildDock(); buildDrawer(); }
  if (S.layout === 'map') setLayout('right');
  const el = $(`.panel[data-id="${id}"]`);
  if (!el) return;
  if (S.collapsed[id]) { S.collapsed[id] = false; el.classList.remove('collapsed'); save(); }
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash');
}

/* ------------------------------------------------------- live threat feed */
// Streams items from every loaded feed one at a time into the Live Threat Feed panel, pinging each on the map.
// Items that appear in a feed after KESTREL has loaded jump the queue and are tagged NEW.
const LF = { list: [], pool: [], fresh: [], seen: new Set(), primed: false, idx: 0, paused: false, rate: 0, stamps: [] };
const LF_KINDS = {
  ransom: { label: 'Ransomware', color: 'var(--ransom)', tag: 'red' },
  c2: { label: 'C2', color: 'var(--c2)', tag: 'pur' },
  attack: { label: 'Attacker', color: 'var(--attk)', tag: 'org' },
  comp: { label: 'Compromised', color: 'var(--comp)', tag: 'ylw' },
  phish: { label: 'Phishing', color: 'var(--phish)', tag: 'grn' },
  outage: { label: 'Outage', color: 'var(--outage)', tag: 'red' },
  vuln: { label: 'Vuln', color: 'var(--high)', tag: 'org' },
  ioc: { label: 'IOC', color: 'var(--tfox)', tag: 'grn' },
};
function lfHarvest() {
  const ev = [];
  const isp = g => g?.isp ? ' · ' + g.isp : '';
  const add = (id, kind, title, sub, geo, t, extra) => ev.push(Object.assign({ id, kind, title, sub, geo, t }, extra));
  for (const r of D.ransomware?.items || []) add('r:' + r.group + '|' + r.victim, 'ransom', `${r.group} claims ${r.victim}`, [r.sector, COUNTRY_NAME[r.cc] || r.cc].filter(Boolean).join(' · '), r.geo, r.discovered);
  for (const c of D.c2?.items || []) add('c:' + c.ip, 'c2', `${c.malware} C2 ${c.status === 'online' ? 'online' : 'listed'} · ${c.ip}:${c.port}`, loc(c.geo) + (c.asName ? ' · ' + c.asName : ''), c.geo, null, { ip: c.ip });
  for (const a of D.attackers?.items || []) add('a:' + a.ip, 'attack', `Scanning source ${a.ip} · ${fmtN(a.reports)} reports`, loc(a.geo) + isp(a.geo), a.geo, null, { ip: a.ip });
  for (const x of D.attackers?.compromised || []) add('e:' + x.ip, 'comp', `Compromised host ${x.ip}`, loc(x.geo) + isp(x.geo), x.geo, null, { ip: x.ip });
  for (const p of D.phishing?.items || []) add('p:' + p.url, 'phish', `Phishing site on ${p.host}`, loc(p.geo) + isp(p.geo), p.geo, null, { ip: p.ip });
  for (const o of (D.outages?.items || []).filter(o => o.ongoing)) add('o:' + o.cc + o.start, 'outage', `Internet disruption · ${o.name}`, o.sources.join(', '), o.geo, o.startIso);
  for (const k of (D.kev?.items || []).slice(0, 30)) add('k:' + k.cve, 'vuln', `${k.cve} added to CISA KEV`, `${k.vendor} ${k.product} · ${k.name}`, null, k.added + 'T12:00:00Z', { url: nvd(k.cve) });
  for (const c of (D.cves?.items || []).filter(c => c.score >= 9).slice(0, 40)) add('v:' + c.id, 'vuln', `${c.id} · CVSS ${c.score}`, c.desc.slice(0, 110), null, c.published, { url: nvd(c.id) });
  if (!D.threatfox?.needsKey) for (const x of (D.threatfox?.items || []).slice(0, 150)) add('t:' + x.ioc, 'ioc', `${x.malware} IOC · ${x.type}`, x.ioc, x.geo, x.firstSeen, { ip: x.ip });
  if (!D.urlhaus?.needsKey) for (const x of (D.urlhaus?.items || []).slice(0, 150)) add('u:' + x.url, 'ioc', `Malware URL${x.threat ? ' · ' + x.threat : ''}`, x.url, x.geo, x.added, { ip: x.ip });
  return ev;
}
function lfIngest() {
  const byKind = {};
  for (const e of lfHarvest()) {
    if (LF.primed && !LF.seen.has(e.id) && LF.fresh.length < 40) LF.fresh.push(Object.assign(e, { isNew: true }));
    LF.seen.add(e.id);
    (byKind[e.kind] = byKind[e.kind] || []).push(e);
  }
  // newest first within each kind, then round-robin across kinds so the stream stays varied
  const lists = Object.values(byKind);
  for (const a of lists) a.sort((x, y) => (y.t || '').localeCompare(x.t || ''));
  const pool = [];
  for (let i = 0; lists.some(a => a.length > i); i++) for (const a of lists) if (a[i]) pool.push(a[i]);
  LF.pool = pool;
}
function lfRow(e) {
  const K = LF_KINDS[e.kind];
  const a = e.geo ? flyAttr(e.geo) : e.url && safeUrl(e.url) ? `data-open="${esc(e.url)}"` : '';
  return `<div class="r lf-row ${a ? 'click' : ''} ${e.isNew ? 'is-new' : ''}" ${a}><span class="typebar" style="background:${K.color}"></span><div><div class="t"><span class="tag ${K.tag}">${K.label}</span>${e.isNew ? '<span class="tag red">NEW</span>' : ''}${esc(e.title)}</div><div class="s">${esc(e.sub || '')}</div></div><span class="m">${new Date(e.at).toISOString().slice(11, 19)}<br>${e.t ? ago(e.t) + ' ago' : 'in feed'}</span></div>`;
}
function lfTick() {
  if (LF.paused || document.hidden || (!LF.pool.length && !LF.fresh.length)) return;
  const src = LF.fresh.shift() || LF.pool[LF.idx++ % LF.pool.length];
  const e = Object.assign({}, src, { at: Date.now() });
  LF.list.unshift(e);
  if (LF.list.length > 120) LF.list.pop();
  const now = Date.now();
  LF.stamps.push(now);
  while (LF.stamps[0] < now - 60000) LF.stamps.shift();
  LF.rate = LF.stamps.length;
  const list = $('#lfList'), f = ps('livefeed').kind || 'all';
  if (list && (f === 'all' || e.kind === f)) {
    list.querySelector('.loading')?.remove();
    list.insertAdjacentHTML('afterbegin', lfRow(e));
    list.firstElementChild.classList.add('lf-enter');
    while (list.children.length > 60) list.lastElementChild.remove();
  }
  const badge = $('.panel[data-id="livefeed"] .badge');
  if (badge) { badge.textContent = `${LF.rate} / min`; badge.style.display = ''; }
  if (e.geo && S.pings) { ping(e); arcShot(e); }
}
let lfTimer;
function lfSchedule() {
  clearInterval(lfTimer);
  lfTimer = setInterval(lfTick, +(ps('livefeed').speed || 1400));
}
// Ripple + callout on the map for each streamed event
let pingCount = 0;
function ping(e) {
  if (!mapReady || pingCount > 5) return;
  const K = LF_KINDS[e.kind];
  const el = document.createElement('div');
  el.className = 'ping' + (e.isNew ? ' new' : '');
  el.style.setProperty('--pc', K.color);
  el.innerHTML = `<i></i><i></i><b></b><span>${esc(K.label)} · ${esc(e.title.length > 52 ? e.title.slice(0, 50) + '…' : e.title)}</span>`;
  const m = new maplibregl.Marker({ element: el, anchor: 'center' }).setLngLat([e.geo.lon, e.geo.lat]).addTo(map);
  pingCount++;
  setTimeout(() => { m.remove(); pingCount--; }, 3400);
}

/* ---------------------------------------------------------------- map */
const COLORS = {};
const FEAT = {}, LAYER_FC = {};
const pointSize = (L, base) => ['interpolate', ['linear'], ['zoom'], 1, ['*', ['get', 'sz'], base], 5, ['*', ['get', 'sz'], base * 2], 10, ['*', ['get', 'sz'], base * 3]];
const LAYERS = [
  { id: 'night', name: 'Day / night terminator', kind: 'overlay', shape: 'half', color: '--dim' },
  { id: 'cables', name: 'Submarine cables', kind: 'line', color: '--cable' },
  { id: 'heat', name: 'Threat density heatmap', kind: 'heat', color: '--high' },
  { id: 'outages', name: 'Internet outages', feed: 'outages', kind: 'ring', color: '--outage', items: d => d.items, size: o => Math.max(1, Math.min(4, Math.log10(o.score + 10) - 1.5)), fresh: o => o.ongoing, label: o => `Outage · ${o.name}` },
  { id: 'tor', name: 'Tor exit nodes', feed: 'tor', color: '--tor', base: 1.6, items: d => d.items, label: x => `Tor exit · ${x.ip}` },
  { id: 'compromised', name: 'Compromised hosts (ET)', feed: 'attackers', color: '--comp', base: 2, items: d => d.compromised, label: x => `Compromised · ${x.ip}` },
  { id: 'phishing', name: 'Phishing hosting', feed: 'phishing', color: '--phish', base: 2.3, items: d => d.items, label: x => `Phish · ${x.host}` },
  { id: 'urlhaus', name: 'Malware URLs (URLhaus)', feed: 'urlhaus', color: '--uh', base: 2.3, key: true, items: d => d.items, label: x => `URLhaus · ${x.host}` },
  { id: 'threatfox', name: 'IOCs (ThreatFox)', feed: 'threatfox', color: '--tfox', base: 2.3, key: true, items: d => d.items, label: x => `${x.malware} · ${x.type}` },
  { id: 'attackers', name: 'Top attackers (DShield)', feed: 'attackers', color: '--attk', base: 2.4, items: d => d.items, size: a => 1 + Math.min(2.2, a.reports / 120000), label: x => `Attacker #${x.rank} · ${x.ip}` },
  { id: 'c2', name: 'Botnet C2 servers', feed: 'c2', color: '--c2', base: 3.2, items: d => d.items, fresh: c => c.status === 'online', label: x => `${x.malware} C2 · ${x.ip}` },
  { id: 'ransomware', name: 'Ransomware victims', feed: 'ransomware', color: '--ransom', base: 3, items: d => d.items, fresh: r => Date.now() - Date.parse(r.discovered) < 86400e3, label: x => `${x.group} → ${x.victim}` },
  { id: 'trails', name: 'Ransomware campaign trails', kind: 'overlay', shape: 'line', color: '--ransom' },
  { id: 'paths', name: 'Live attack paths', kind: 'overlay', shape: 'line', color: '--attk' },
];
const LAYER = Object.fromEntries(LAYERS.map(l => [l.id, l]));
const BASE_PAINT = {
  // greyscale: fully desaturated so the coloured threat layers and attack paths stand out
  satellite: { 'raster-saturation': -1, 'raster-brightness-max': 0.78, 'raster-contrast': 0.12 },
  muted: { 'raster-saturation': -1, 'raster-brightness-max': 0.48, 'raster-contrast': 0.18 },
};
const ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services/';
let map, hoverPop, invMarker, mapReady = false;

function initMap() {
  for (const L of LAYERS) COLORS[L.id] = css(L.color);
  map = new maplibregl.Map({
    container: 'map', center: isPhone() ? [15, 22] : [12, 24], zoom: isPhone() ? 0.3 : 1.6, minZoom: isPhone() ? 0 : 0.6, maxPitch: 0, pitchWithRotate: false, dragRotate: false, touchPitch: false,
    renderWorldCopies: true, attributionControl: false, fadeDuration: 0,
    style: {
      version: 8,
      sources: {
        sat: { type: 'raster', tiles: [ESRI + 'World_Imagery/MapServer/tile/{z}/{y}/{x}'], tileSize: 256, maxzoom: 19, attribution: 'Imagery © Esri, Maxar, Earthstar Geographics, GIS User Community' },
        dark: { type: 'raster', tiles: [ESRI + 'Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}'], tileSize: 256, maxzoom: 16, attribution: '© Esri' },
        ref: { type: 'raster', tiles: [ESRI + 'Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}'], tileSize: 256, maxzoom: 19 },
      },
      layers: [
        { id: 'bg', type: 'background', paint: { 'background-color': '#050506' } },
        { id: 'sat', type: 'raster', source: 'sat' },
        { id: 'dark', type: 'raster', source: 'dark', layout: { visibility: 'none' }, paint: { 'raster-saturation': -1 } },
        { id: 'ref', type: 'raster', source: 'ref', paint: { 'raster-opacity': 0.75, 'raster-saturation': -1 } },
      ],
    },
  });
  map.addControl(new maplibregl.AttributionControl({ compact: true, customAttribution: 'Cables: TeleGeography · Feeds: see README' }), 'bottom-right');
  map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'bottom-right');
  map.addControl(new maplibregl.ScaleControl({ maxWidth: 110 }), 'bottom-right');
  map.touchZoomRotate.disableRotation();
  // phones: start with the map attribution folded away (tap the (i) to read it)
  if (isPhone()) map.once('load', () => $('.maplibregl-ctrl-attrib')?.classList.remove('maplibregl-compact-show'));
  hoverPop = new maplibregl.Popup({ closeButton: false, closeOnClick: false, className: 'hover-tip', offset: 10 });

  map.on('load', () => {
    mapReady = true;
    fitWorld(0);
    applyBase();
    const empty = { type: 'FeatureCollection', features: [] };
    addNight();
    for (const L of LAYERS) {
      if (L.kind === 'overlay') continue;
      map.addSource(L.id, { type: 'geojson', data: empty });
      const vis = S.layers[L.id] ? 'visible' : 'none';
      const c = COLORS[L.id];
      if (L.kind === 'line') {
        map.addLayer({ id: 'cables', type: 'line', source: 'cables', layout: { visibility: vis, 'line-cap': 'round' }, paint: { 'line-color': c, 'line-opacity': 0.5, 'line-width': ['interpolate', ['linear'], ['zoom'], 1, 0.6, 6, 1.8] } });
      } else if (L.kind === 'heat') {
        map.addLayer({ id: 'heat', type: 'heatmap', source: 'heat', layout: { visibility: vis }, paint: {
          'heatmap-weight': ['get', 'w'], 'heatmap-intensity': ['interpolate', ['linear'], ['zoom'], 0, 0.8, 6, 2],
          'heatmap-radius': ['interpolate', ['linear'], ['zoom'], 0, 14, 6, 36], 'heatmap-opacity': 0.7,
          'heatmap-color': ['interpolate', ['linear'], ['heatmap-density'], 0, 'rgba(0,0,0,0)', 0.15, 'rgba(60,20,120,.5)', 0.4, '#a01a7d', 0.65, '#ec3c3c', 0.85, '#ff9a3c', 1, '#fff3b0'] } });
      } else if (L.kind === 'ring') {
        const r = ['interpolate', ['linear'], ['zoom'], 1, ['*', ['get', 'sz'], 5], 5, ['*', ['get', 'sz'], 16]];
        map.addLayer({ id: L.id, type: 'circle', source: L.id, layout: { visibility: vis }, paint: { 'circle-radius': r, 'circle-color': c, 'circle-opacity': 0.1, 'circle-stroke-color': c, 'circle-stroke-width': 1.2, 'circle-stroke-opacity': 0.85, 'circle-pitch-alignment': 'map' } });
        map.addLayer({ id: L.id + '-pulse', type: 'circle', source: L.id, filter: ['==', ['get', 'fresh'], 1], layout: { visibility: vis }, paint: { 'circle-radius': r, 'circle-color': 'rgba(0,0,0,0)', 'circle-stroke-color': c, 'circle-stroke-width': 1.5, 'circle-stroke-opacity': 0.6, 'circle-pitch-alignment': 'map' } });
      } else {
        const b = L.base || 2.5;
        map.addLayer({ id: L.id + '-glow', type: 'circle', source: L.id, layout: { visibility: vis }, paint: { 'circle-radius': pointSize(L, b * 2.4), 'circle-color': c, 'circle-opacity': 0.14, 'circle-blur': 0.9 } });
        map.addLayer({ id: L.id, type: 'circle', source: L.id, layout: { visibility: vis }, paint: { 'circle-radius': pointSize(L, b), 'circle-color': c, 'circle-stroke-color': 'rgba(8,8,10,.85)', 'circle-stroke-width': 0.8, 'circle-opacity': 0.95 } });
        if (L.fresh) map.addLayer({ id: L.id + '-pulse', type: 'circle', source: L.id, filter: ['==', ['get', 'fresh'], 1], layout: { visibility: vis }, paint: { 'circle-radius': pointSize(L, b), 'circle-color': 'rgba(0,0,0,0)', 'circle-stroke-color': c, 'circle-stroke-width': 1.4, 'circle-stroke-opacity': 0.8 } });
      }
      if (L.kind !== 'line' && L.kind !== 'heat') {
        map.on('click', L.id, e => openPopup(L.id, e));
        map.on('mouseenter', L.id, e => { map.getCanvas().style.cursor = 'pointer'; const f = e.features[0]; hoverPop.setLngLat(e.lngLat).setHTML(esc(f.properties.label)).addTo(map); });
        map.on('mousemove', L.id, e => hoverPop.setLngLat(e.lngLat));
        map.on('mouseleave', L.id, () => { map.getCanvas().style.cursor = ''; hoverPop.remove(); });
      }
    }
    map.on('mouseenter', 'cables', e => { map.getCanvas().style.cursor = 'crosshair'; hoverPop.setLngLat(e.lngLat).setHTML('Cable · ' + esc(e.features[0].properties.name)).addTo(map); });
    map.on('mousemove', 'cables', e => hoverPop.setLngLat(e.lngLat).setHTML('Cable · ' + esc(e.features[0].properties.name)));
    map.on('mouseleave', 'cables', () => { map.getCanvas().style.cursor = ''; hoverPop.remove(); });
    addArcLayers();
    for (const L of LAYERS) if (L.feed && D[L.feed]) updateLayer(L.id);
    updateLayer('heat');
    loadCables();
    buildArcs();
    requestAnimationFrame(pulse);
    requestAnimationFrame(arcLoop);
  });
  map.on('mousemove', e => { $('#hudCoords').textContent = `${e.lngLat.lat.toFixed(3)}°, ${e.lngLat.lng.toFixed(3)}°`; });
}

async function loadCables() {
  try {
    const j = await (await fetch('/api/cables')).json();
    map.getSource('cables')?.setData(j.data);
    LAYER.cables.count = j.data.features.length;
    renderLayerList();
  } catch (e) { console.warn('cables', e); }
}

function updateLayer(id) {
  if (!map || !map.getSource(id)) { renderLayerList(); return; }
  const L = LAYER[id];
  if (id === 'heat') {
    const feats = [];
    const w = { c2: 1, attackers: 1, compromised: 0.7, phishing: 0.6, tor: 0.25, threatfox: 0.8, urlhaus: 0.6 };
    for (const lid of Object.keys(w)) for (const f of LAYER_FC[lid]?.features || []) feats.push({ type: 'Feature', geometry: f.geometry, properties: { w: w[lid] } });
    map.getSource('heat').setData({ type: 'FeatureCollection', features: feats });
    L.count = feats.length;
    renderLayerList();
    return;
  }
  if (!L.feed || !D[L.feed]) return;
  if (D[L.feed].needsKey) { L.locked = true; renderLayerList(); return; }
  const items = L.items(D[L.feed]) || [];
  const feats = [];
  FEAT[id] = [];
  for (const it of items) {
    const g = it.geo;
    if (!g || g.lat == null) continue;
    const i = FEAT[id].push(it) - 1;
    feats.push({ type: 'Feature', geometry: { type: 'Point', coordinates: [g.lon, g.lat] }, properties: { i, sz: L.size ? L.size(it) : 1, fresh: L.fresh && L.fresh(it) ? 1 : 0, label: L.label(it) } });
  }
  const fc = { type: 'FeatureCollection', features: feats };
  map.getSource(id).setData(fc);
  LAYER_FC[id] = fc; // kept for the heatmap merge
  L.count = feats.length;
  if (['c2', 'attackers', 'compromised', 'phishing', 'tor', 'threatfox', 'urlhaus'].includes(id)) { clearTimeout(updateLayer._h); updateLayer._h = setTimeout(() => updateLayer('heat'), 300); }
  renderLayerList();
}

function renderLayerList() {
  const el = $('#layerList');
  if (!el) return;
  el.innerHTML = [...LAYERS].reverse().map(L => {
    const shape = L.shape || (L.kind === 'line' ? 'line' : L.kind === 'ring' ? 'ring' : '');
    const locked = L.key && D[L.feed]?.needsKey;
    return `<div class="lyr ${S.layers[L.id] && !locked ? '' : 'off'} ${locked ? 'locked' : ''}" data-layer="${L.id}"><span class="sw ${shape}" style="color:${css(L.color)}"></span><span class="nm">${esc(L.name)}</span><span class="ct">${L.count != null ? fmtN(L.count) : ''}</span></div>`;
  }).join('');
}
function setLayerVis(id, on) {
  S.layers[id] = on; save();
  if (!map) return;
  const vis = on ? 'visible' : 'none';
  for (const suf of ['', '-glow', '-pulse', '-edge']) if (map.getLayer(id + suf)) map.setLayoutProperty(id + suf, 'visibility', vis);
  if (id === 'paths' || id === 'trails') buildArcs();
  renderLayerList();
}

// Animated pulse rings for fresh events (ransomware <24h, online C2, ongoing outages)
function pulse(t) {
  if (mapReady && !document.hidden) {
    const ph = (t % 2200) / 2200;
    LAYERS.forEach((L, i) => {
      if (map.getLayer(L.id + '-glow') && S.layers[L.id]) map.setPaintProperty(L.id + '-glow', 'circle-opacity', 0.07 + 0.13 * (0.5 + 0.5 * Math.sin(t / 650 + i * 1.3)));
    });
    for (const L of LAYERS) {
      const id = L.id + '-pulse';
      if (!map.getLayer(id) || !S.layers[L.id]) continue;
      const k = L.kind === 'ring' ? 1 + ph * 0.8 : 1 + ph * 5;
      const base = L.kind === 'ring' ? null : L.base || 2.5;
      const r = L.kind === 'ring'
        ? ['interpolate', ['linear'], ['zoom'], 1, ['*', ['get', 'sz'], 5 * k], 5, ['*', ['get', 'sz'], 16 * k]]
        : pointSize(L, base * k);
      map.setPaintProperty(id, 'circle-radius', r);
      map.setPaintProperty(id, 'circle-stroke-opacity', (1 - ph) * 0.85);
    }
  }
  setTimeout(() => requestAnimationFrame(pulse), 50);
}

/* ---------------------------------------------- attack paths & live overlays */
// Every arc comes from real feed data, nothing is invented:
//  paths  - DShield's most-reported scanning sources -> your location (the "home" feed), plus a one-shot arc for each
//           geolocated event the Live Threat Feed streams (threat origin -> you; ransomware arcs run from the same
//           group's previous victim to the new one instead)
//  trails - each ransomware group's victims in the order they were posted over the last 72h (its campaign path)
//  night  - the real-time day/night terminator
const ARC_MAX_PATHS = 36, ARC_TRAIL_HOURS = 72, ARC_MAX_TRAILS = 60, ARC_MAX_SHOTS = 14;
const ARC = { paths: [], trails: [], shots: [], victims: {} };
const REDUCED_MOTION = matchMedia('(prefers-reduced-motion: reduce)').matches;
let homeMarker;

// Curved arc between two [lon, lat] points on the flat map, taking the short way round and bowing toward the pole
function arcCoords(a, b, n = 40) {
  const [x1, y1] = a;
  let [x2, y2] = b;
  if (x2 - x1 > 180) x2 -= 360; else if (x2 - x1 < -180) x2 += 360;
  const dx = x2 - x1, dy = y2 - y1, d = Math.hypot(dx, dy);
  if (d < 1.2) return null;
  const s = dx >= 0 ? 1 : -1, bend = Math.min(d * 0.24, 28);
  const cx = (x1 + x2) / 2 - dy / d * bend * s, cy = Math.max(-80, Math.min(80, (y1 + y2) / 2 + dx / d * bend * s));
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n, u = 1 - t;
    pts.push([u * u * x1 + 2 * u * t * cx + t * t * x2, Math.max(-84, Math.min(84, u * u * y1 + 2 * u * t * cy + t * t * y2))]);
  }
  return pts;
}
function arcAt(c, f) {
  const n = c.length - 1, x = Math.max(0, Math.min(1, f)) * n, i = Math.min(Math.floor(x), n - 1), k = x - i;
  return [c[i][0] + (c[i + 1][0] - c[i][0]) * k, c[i][1] + (c[i + 1][1] - c[i][1]) * k];
}
function arcSlice(c, f0, f1) {
  f0 = Math.max(0, f0); f1 = Math.min(1, f1);
  if (f1 - f0 < 0.002) return null;
  const n = c.length - 1, out = [arcAt(c, f0)];
  for (let i = Math.ceil(f0 * n); i < f1 * n; i++) if (i / n > f0) out.push(c[i]);
  out.push(arcAt(c, f1));
  return out;
}
const kindColor = k => css((LF_KINDS[k]?.color || 'var(--acc)').slice(4, -1));
const homeLL = () => D.home && D.home.lat != null ? [D.home.lon, D.home.lat] : null;

function buildArcs() {
  if (!mapReady || !map.getSource('arc-base')) return;
  const home = homeLL();
  // scanners -> you
  ARC.paths = [];
  if (home && S.layers.paths) {
    const top = (D.attackers?.items || []).filter(a => a.geo && a.geo.lat != null).slice(0, ARC_MAX_PATHS);
    const maxR = Math.max(...top.map(a => a.reports), 1);
    for (const a of top) {
      const c = arcCoords([a.geo.lon, a.geo.lat], home);
      if (!c) continue;
      ARC.paths.push({ c, col: COLORS.attackers || css('--attk'), w: 1 + 1.4 * Math.sqrt(a.reports / maxR), dur: 2600 + Math.random() * 2600, off: Math.random(),
        label: `Scanner ${a.ip}${a.geo.cc ? ' (' + a.geo.cc + ')' : ''} · ${fmtN(a.reports)} reports → ${D.home.name || 'you'}` });
    }
  }
  // ransomware campaign trails: victim -> next victim, per group, in posting order
  ARC.trails = []; ARC.victims = {};
  const since = Date.now() - ARC_TRAIL_HOURS * 3600e3;
  for (const v of D.ransomware?.items || []) {
    if (!v.geo || v.geo.lat == null || !(Date.parse(v.discovered) > since)) continue;
    (ARC.victims[v.group] = ARC.victims[v.group] || []).push(v);
  }
  const legs = [];
  for (const [g, list] of Object.entries(ARC.victims)) {
    list.sort((x, y) => Date.parse(x.discovered) - Date.parse(y.discovered));
    for (let i = 1; i < list.length; i++) {
      const p = list[i - 1], q = list[i];
      if (p.cc && p.cc === q.cc) continue;
      legs.push({ g, p, q, t: Date.parse(q.discovered) });
    }
  }
  legs.sort((x, y) => y.t - x.t);
  if (S.layers.trails) for (const L of legs.slice(0, ARC_MAX_TRAILS)) {
    const c = arcCoords([L.p.geo.lon, L.p.geo.lat], [L.q.geo.lon, L.q.geo.lat]);
    if (c) ARC.trails.push({ c, col: COLORS.ransomware || css('--ransom'), w: 1.3, dur: 3400 + Math.random() * 2400, off: Math.random(), ring: true,
      label: `${L.g}: ${L.p.victim} (${L.p.cc || '?'}) → ${L.q.victim} (${L.q.cc || '?'})` });
  }
  LAYER.paths.count = home ? ARC.paths.length : null;
  LAYER.trails.count = ARC.trails.length;
  const feats = [...ARC.paths, ...ARC.trails].map(a => ({ type: 'Feature', geometry: { type: 'LineString', coordinates: a.c }, properties: { c: a.col, w: a.w, label: a.label } }));
  map.getSource('arc-base').setData({ type: 'FeatureCollection', features: feats });
  updateHome();
  renderLayerList();
}

// Pulsing beacon at your location: the end point of every inbound path
function updateHome() {
  const home = homeLL();
  if (!home || !S.layers.paths) { homeMarker?.remove(); homeMarker = null; return; }
  if (!homeMarker) {
    const el = document.createElement('div');
    el.className = 'home-beacon';
    el.innerHTML = '<i></i><i></i><i></i><b></b><span></span>';
    homeMarker = new maplibregl.Marker({ element: el, anchor: 'center' });
  }
  homeMarker.getElement().querySelector('span').textContent = 'YOU · ' + (D.home.name || 'observer');
  homeMarker.setLngLat(home).addTo(map);
}

// One-shot arc for a streamed Live Threat Feed event
function arcShot(e) {
  if (!mapReady || !S.layers.paths || REDUCED_MOTION || !e.geo || e.geo.lat == null) return;
  let from, to;
  if (e.kind === 'ransom') {
    const [grp, victim] = e.id.slice(2).split('|');
    const list = ARC.victims[grp] || [];
    const i = list.findIndex(v => v.victim === victim);
    if (i < 1 || !list[i - 1].geo) return;
    from = [list[i - 1].geo.lon, list[i - 1].geo.lat]; to = [e.geo.lon, e.geo.lat];
  } else if (['attack', 'c2', 'comp', 'phish', 'ioc'].includes(e.kind)) {
    to = homeLL(); from = [e.geo.lon, e.geo.lat];
    if (!to) return;
  } else return;
  const c = arcCoords(from, to);
  if (!c) return;
  if (ARC.shots.length >= ARC_MAX_SHOTS) ARC.shots.shift();
  ARC.shots.push({ c, col: kindColor(e.kind), w: 2.2, start: performance.now(), dur: 1500 + Math.min(1500, Math.hypot(to[0] - from[0], to[1] - from[1]) * 9) });
}

function addArcLayers() {
  const empty = { type: 'FeatureCollection', features: [] };
  map.addSource('arc-base', { type: 'geojson', data: empty });
  map.addSource('arc-trail', { type: 'geojson', data: empty });
  map.addSource('arc-head', { type: 'geojson', data: empty });
  map.addLayer({ id: 'arc-base', type: 'line', source: 'arc-base', layout: { 'line-cap': 'round' }, paint: { 'line-color': ['get', 'c'], 'line-opacity': 0.16, 'line-width': ['get', 'w'], 'line-dasharray': [1, 2.5] } });
  map.addLayer({ id: 'arc-glow', type: 'line', source: 'arc-trail', layout: { 'line-cap': 'round' }, paint: { 'line-color': ['get', 'c'], 'line-opacity': ['*', ['get', 'o'], 0.35], 'line-width': ['*', ['get', 'w'], 4], 'line-blur': 4 } });
  map.addLayer({ id: 'arc-trail', type: 'line', source: 'arc-trail', layout: { 'line-cap': 'round' }, paint: { 'line-color': ['get', 'c'], 'line-opacity': ['get', 'o'], 'line-width': ['get', 'w'] } });
  map.addLayer({ id: 'arc-ring', type: 'circle', source: 'arc-head', filter: ['==', ['get', 'k'], 'ring'], paint: { 'circle-radius': ['get', 'r'], 'circle-color': 'rgba(0,0,0,0)', 'circle-stroke-color': ['get', 'c'], 'circle-stroke-width': 1.4, 'circle-stroke-opacity': ['get', 'o'] } });
  map.addLayer({ id: 'arc-headglow', type: 'circle', source: 'arc-head', filter: ['==', ['get', 'k'], 'head'], paint: { 'circle-radius': ['*', ['get', 'w'], 4.5], 'circle-color': ['get', 'c'], 'circle-opacity': 0.35, 'circle-blur': 1 } });
  map.addLayer({ id: 'arc-head', type: 'circle', source: 'arc-head', filter: ['==', ['get', 'k'], 'head'], paint: { 'circle-radius': ['*', ['get', 'w'], 1.3], 'circle-color': '#ffffff', 'circle-stroke-color': ['get', 'c'], 'circle-stroke-width': 1.2 } });
  map.on('mouseenter', 'arc-base', e => { map.getCanvas().style.cursor = 'crosshair'; hoverPop.setLngLat(e.lngLat).setHTML(esc(e.features[0].properties.label)).addTo(map); });
  map.on('mousemove', 'arc-base', e => hoverPop.setLngLat(e.lngLat).setHTML(esc(e.features[0].properties.label)));
  map.on('mouseleave', 'arc-base', () => { map.getCanvas().style.cursor = ''; hoverPop.remove(); });
}

// Comet heads with fading tails travel along each path; trails ring the victim on arrival
const TAIL = 0.2, TAIL_STEPS = [0.12, 0.3, 0.55, 1];
function cometFeats(a, f, trail, head, ring) {
  for (let i = 0; i < TAIL_STEPS.length; i++) {
    const seg = arcSlice(a.c, f - TAIL + TAIL * i / TAIL_STEPS.length, f - TAIL + TAIL * (i + 1) / TAIL_STEPS.length);
    if (seg) trail.push({ type: 'Feature', geometry: { type: 'LineString', coordinates: seg }, properties: { c: a.col, w: a.w, o: TAIL_STEPS[i] } });
  }
  if (f >= 0 && f <= 1) head.push({ type: 'Feature', geometry: { type: 'Point', coordinates: arcAt(a.c, f) }, properties: { k: 'head', c: a.col, w: a.w } });
  if (ring != null) head.push({ type: 'Feature', geometry: { type: 'Point', coordinates: a.c[a.c.length - 1] }, properties: { k: 'ring', c: a.col, r: 3 + ring * 22, o: (1 - ring) * 0.9 } });
}
function arcLoop(now) {
  if (mapReady && !document.hidden && !REDUCED_MOTION && map.getSource('arc-trail')) {
    const trail = [], head = [];
    for (const a of [...ARC.paths, ...ARC.trails]) {
      const f = ((now / a.dur) + a.off) % 1 * 1.25; // 1..1.25 = pause at the target while the tail drains
      const r = a.ring && f > 1 ? (f - 1) / 0.25 : null;
      cometFeats(a, f, trail, head, r);
    }
    ARC.shots = ARC.shots.filter(s => (now - s.start) / s.dur < 1.5);
    for (const s of ARC.shots) {
      const f = (now - s.start) / s.dur;
      cometFeats(s, f, trail, head, f > 1 ? (f - 1) / 0.5 : null);
    }
    map.getSource('arc-trail').setData({ type: 'FeatureCollection', features: trail });
    map.getSource('arc-head').setData({ type: 'FeatureCollection', features: head });
  }
  setTimeout(() => requestAnimationFrame(arcLoop), 33);
}

// Real-time day/night terminator (solar declination + subsolar longitude from the current UTC time)
function nightPolygon(date = new Date()) {
  const rad = Math.PI / 180;
  const start = Date.UTC(date.getUTCFullYear(), 0, 0), doy = (date - start) / 864e5;
  const g = 2 * Math.PI / 365 * (doy - 1);
  const eot = 229.18 * (0.000075 + 0.001868 * Math.cos(g) - 0.032077 * Math.sin(g) - 0.014615 * Math.cos(2 * g) - 0.040849 * Math.sin(2 * g));
  let dec = -23.44 * Math.cos(2 * Math.PI / 365 * (doy + 10));
  if (Math.abs(dec) < 0.2) dec = dec < 0 ? -0.2 : 0.2;
  const utcMin = date.getUTCHours() * 60 + date.getUTCMinutes() + date.getUTCSeconds() / 60;
  const sunLon = -(utcMin + eot - 720) / 4;
  const line = [];
  for (let lon = -180; lon <= 180; lon += 2) line.push([lon, Math.atan(-Math.cos((lon - sunLon) * rad) / Math.tan(dec * rad)) / rad]);
  const pole = dec > 0 ? -85 : 85;
  return {
    night: { type: 'Feature', geometry: { type: 'Polygon', coordinates: [[...line, [180, pole], [-180, pole], line[0]]] }, properties: {} },
    edge: { type: 'Feature', geometry: { type: 'LineString', coordinates: line }, properties: {} },
  };
}
function addNight() {
  const { night, edge } = nightPolygon();
  const vis = S.layers.night ? 'visible' : 'none';
  map.addSource('night', { type: 'geojson', data: night });
  map.addSource('night-edge', { type: 'geojson', data: edge });
  map.addLayer({ id: 'night', type: 'fill', source: 'night', layout: { visibility: vis }, paint: { 'fill-color': '#000000', 'fill-opacity': 0.34, 'fill-antialias': false } });
  map.addLayer({ id: 'night-edge', type: 'line', source: 'night-edge', layout: { visibility: vis }, paint: { 'line-color': css('--acc'), 'line-opacity': 0.22, 'line-width': 6, 'line-blur': 6 } });
  setInterval(() => {
    if (document.hidden || !map.getSource('night')) return;
    const p = nightPolygon();
    map.getSource('night').setData(p.night);
    map.getSource('night-edge').setData(p.edge);
  }, 60000);
}

function popupHTML(layerId, x) {
  const row = (k, v) => v == null || v === '' ? '' : `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`;
  const head = (title, color) => `<div class="pop-h"><span class="dot" style="color:${color}"></span>${esc(title)}</div>`;
  const inv = ip => ip ? `<button class="btn" data-inv="${esc(ip)}">Investigate</button>` : '';
  const link = (u, l) => safeUrl(u) ? `<a class="btn" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(l)} ↗</a>` : '';
  const c = COLORS[layerId];
  const g = x.geo || {};
  switch (layerId) {
    case 'ransomware': return head('Ransomware claim', c) + `<div class="pop-b"><table>${row('Victim', x.victim)}${row('Group', x.group)}${row('Sector', x.sector)}${row('Country', (COUNTRY_NAME[x.cc] || x.cc) + ' (approx.)')}${row('Domain', x.domain)}${row('Discovered', fmtTime(x.discovered))}</table><div class="act">${link(x.url, 'ransomware.live')}</div></div>`;
    case 'c2': return head(`${x.malware} botnet C2`, c) + `<div class="pop-b"><table>${row('Endpoint', `${x.ip}:${x.port}`)}${row('Status', x.status)}${row('Network', x.asName)}${row('Location', loc(x.geo))}${row('First seen', fmtTime(x.firstSeen))}${row('Last online', x.lastOnline)}</table><div class="act">${inv(x.ip)}${link('https://feodotracker.abuse.ch/browse/host/' + encodeURIComponent(x.ip) + '/', 'Feodo')}</div></div>`;
    case 'attackers': return head(`Top attacker #${x.rank}`, c) + `<div class="pop-b"><table>${row('IP', x.ip)}${row('Reports', fmtN(x.reports))}${row('Targets', x.targets)}${row('ISP', g.isp)}${row('AS', g.as)}${row('Location', loc(x.geo))}</table><div class="act">${inv(x.ip)}${link('https://isc.sans.edu/ipinfo/' + encodeURIComponent(x.ip), 'SANS ISC')}</div></div>`;
    case 'compromised': return head('Compromised host', c) + `<div class="pop-b"><table>${row('IP', x.ip)}${row('ISP', g.isp)}${row('Location', loc(x.geo))}${row('Source', 'Emerging Threats compromised-IP list')}</table><div class="act">${inv(x.ip)}</div></div>`;
    case 'tor': return head('Tor exit node', c) + `<div class="pop-b"><table>${row('IP', x.ip)}${row('ISP', g.isp)}${row('Location', loc(x.geo))}</table><div class="act">${inv(x.ip)}${link('https://metrics.torproject.org/rs.html#search/' + encodeURIComponent(x.ip), 'Relay search')}</div></div>`;
    case 'phishing': return head('Phishing site', c) + `<div class="pop-b"><table>${row('URL', x.url)}${row('Host', x.host)}${row('IP', x.ip)}${row('Hosting', g.isp)}${row('Location', loc(x.geo))}</table><div class="act">${inv(x.ip)}</div></div>`;
    case 'threatfox': return head(`${x.malware} IOC`, c) + `<div class="pop-b"><table>${row('IOC', x.ioc)}${row('Type', x.type)}${row('Threat', x.threat)}${row('Confidence', x.confidence + '%')}${row('Location', loc(x.geo))}${row('First seen', fmtTime(x.firstSeen))}</table><div class="act">${inv(x.ip)}</div></div>`;
    case 'urlhaus': return head('Malware distribution URL', c) + `<div class="pop-b"><table>${row('URL', x.url)}${row('Status', x.status)}${row('Threat', x.threat)}${row('Tags', (x.tags || []).join(', '))}${row('Location', loc(x.geo))}</table><div class="act">${inv(x.ip)}</div></div>`;
    case 'outages': return head(`Internet outage · ${x.name}`, c) + `<div class="pop-b"><table>${row('Status', x.ongoing ? 'ONGOING' : 'recovered')}${row('Started', fmtTime(x.startIso))}${row('Duration', x.durationH + ' h')}${row('Signals', x.sources.join(', '))}${row('Severity score', fmtN(Math.round(x.score)))}</table><div class="act">${link('https://ioda.inetintel.cc.gatech.edu/country/' + encodeURIComponent(x.cc), 'IODA')}</div></div>`;
  }
  return '';
}
function openPopup(layerId, e) {
  const f = e.features[0];
  const x = FEAT[layerId]?.[f.properties.i];
  if (!x) return;
  hoverPop.remove();
  new maplibregl.Popup({ offset: 12, maxWidth: '340px' }).setLngLat(f.geometry.coordinates).setHTML(popupHTML(layerId, x)).addTo(map);
}

function flyTo(lon, lat, zoom = 4.2) {
  if (!map) return;
  map.flyTo({ center: [lon, lat], zoom: Math.max(map.getZoom(), zoom), speed: 1.4, curve: 1.4, essential: true });
}
function fitWorld(duration = 800) {
  if (!map) return;
  map.fitBounds([[-168, -56], [178, 76]], { padding: 12, duration });
}
function applyBase() {
  if (!map?.getLayer('sat')) return;
  const dark = S.base === 'dark';
  map.setLayoutProperty('sat', 'visibility', dark ? 'none' : 'visible');
  map.setLayoutProperty('dark', 'visibility', dark ? 'visible' : 'none');
  if (!dark) for (const [k, v] of Object.entries(BASE_PAINT[S.base] || BASE_PAINT.satellite)) map.setPaintProperty('sat', k, v);
  map.setLayoutProperty('ref', 'visibility', S.labels ? 'visible' : 'none');
}

/* ------------------------------------------------------------ investigate */
async function investigate(ip) {
  ip = (ip || '').trim();
  if (!ip) return;
  ps('investigate').q = ip; save();
  gotoPanel('investigate');
  INV = 'loading'; renderPanel('investigate');
  try { INV = await (await fetch('/api/lookup?ip=' + encodeURIComponent(ip))).json(); } catch (e) { INV = { error: e.message }; }
  renderPanel('investigate');
  if (INV.geo && map) {
    invMarker?.remove();
    const el = document.createElement('div');
    el.style.cssText = `width:18px;height:18px;border:2px solid var(--acc);border-radius:50%;box-shadow:0 0 12px var(--acc),inset 0 0 8px var(--acc);`;
    invMarker = new maplibregl.Marker({ element: el }).setLngLat([INV.geo.lon, INV.geo.lat]).addTo(map);
    flyTo(INV.geo.lon, INV.geo.lat, 5);
  }
}

/* ------------------------------------------------------- layout & drawer */
function setLayout(v) {
  S.layout = v; save();
  document.body.classList.remove('layout-right', 'layout-left', 'layout-bottom', 'layout-map');
  document.body.classList.add('layout-' + v);
  syncSegs();
  setTimeout(() => map?.resize(), 50);
}
function applyLook() {
  const b = document.body;
  b.classList.remove('theme-obsidian', 'theme-carbon', 'theme-midnight', 'theme-moss');
  b.classList.add('theme-' + S.theme);
  b.classList.toggle('no-ticker', !S.ticker);
  b.classList.toggle('no-rail', !S.rail);
  b.classList.toggle('compact', !!S.compact);
  b.classList.toggle('rail-min', !!S.railMin);
  document.documentElement.style.setProperty('--dock-w', S.dockW + 'px');
  document.documentElement.style.setProperty('--dock-h', S.dockH + 'px');
  document.documentElement.style.setProperty('--cols', S.cols);
  setLayout(S.layout);
}
function syncSegs() {
  const set = (sel, v) => $$(sel + ' button').forEach(b => b.classList.toggle('on', b.dataset.v === v));
  set('#segLayout', S.layout); set('#segTheme', S.theme); set('#segBase', S.base);
  $('#selCols').value = S.cols; $('#selRefresh').value = S.refresh;
  $('#chkTicker').checked = S.ticker; $('#chkRail').checked = S.rail; $('#chkCompact').checked = !!S.compact; $('#chkLabels').checked = S.labels;
  $('#btnFocus').classList.toggle('on', S.layout === 'map');
}
function buildDrawer() {
  $('#panelToggles').innerHTML = S.order.filter(id => PANEL[id]).map(id => {
    const p = PANEL[id];
    return `<label class="ptog"><input type="checkbox" data-ptog="${id}" ${S.hidden[id] ? '' : 'checked'}><span class="nm">${esc(p.title)}</span>${p.keyed ? '<small>needs key</small>' : ''}</label>`;
  }).join('');
  syncSegs();
}
function renderHealth() {
  if (!STATUS) { $('#feedHealth').innerHTML = '<div class="err">server unreachable</div>'; return; }
  const rows = Object.entries(STATUS.feeds).map(([k, f]) => {
    const keyed = D[k]?.needsKey;
    const col = f.error ? 'var(--crit)' : keyed ? 'var(--mute)' : f.updated ? 'var(--low)' : 'var(--med)';
    return `<div class="fh" title="${esc(f.error?.error || '')}"><span class="dotS" style="background:${col};margin:0"></span><span>${esc(f.source)}</span><span class="s">${keyed ? 'no key' : f.error ? 'error' : f.updated ? ago(f.updated) + ' ago' : '…'}</span></div>`;
  });
  rows.push(`<div class="fh"><span class="dotS" style="background:${STATUS.geo.error ? 'var(--crit)' : 'var(--low)'};margin:0"></span><span>ip-api geolocation</span><span class="s">${fmtN(STATUS.geo.known)} cached · ${STATUS.geo.pending} queued</span></div>`);
  $('#feedHealth').innerHTML = rows.join('');
}
function openDrawer(open) {
  const d = $('#drawer');
  const o = open ?? !d.classList.contains('open');
  d.classList.toggle('open', o);
  d.setAttribute('aria-hidden', String(!o));
  if (o) { buildDrawer(); loadStatus(); }
}

/* ------------------------------------------------------------------ events */
function wire() {
  document.addEventListener('click', e => {
    const t = e.target;
    const act = t.closest('[data-act]');
    if (act && act.closest('.panel')) {
      const id = act.closest('.panel').dataset.id, a = act.dataset.act;
      if (a === 'hide') { S.hidden[id] = true; act.closest('.panel').remove(); buildDrawer(); toast(`${PANEL[id].title} hidden. Restore it from Customise.`); }
      if (a === 'collapse') { S.collapsed[id] = !S.collapsed[id]; act.closest('.panel').classList.toggle('collapsed', S.collapsed[id]); }
      if (a === 'wide') { S.wide[id] = !S.wide[id]; act.closest('.panel').classList.toggle('wide', S.wide[id]); }
      save(); return;
    }
    const chip = t.closest('[data-chip]');
    if (chip) { const [pid, key, val] = chip.dataset.chip.split('|'); ps(pid)[key] = val; save(); renderPanel(pid); if (pid === 'livefeed' && key === 'speed') lfSchedule(); return; }
    if (t.closest('[data-lf="pause"]')) { LF.paused = !LF.paused; renderPanel('livefeed'); return; }
    const inv = t.closest('[data-inv]');
    if (inv && !t.closest('a')) { if (inv.dataset.inv && inv.dataset.inv !== 'null') investigate(inv.dataset.inv); return; }
    const fly = t.closest('[data-fly]');
    if (fly && !t.closest('a')) { const [lon, lat, z] = fly.dataset.fly.split(',').map(Number); flyTo(lon, lat, z || 4.2); return; }
    const open = t.closest('[data-open]');
    if (open && !t.closest('a')) { const u = safeUrl(open.dataset.open); if (u) window.open(u, '_blank', 'noopener,noreferrer'); return; }
    const vw = t.closest('a[data-view]');
    if (vw) { if (!e.ctrlKey && !e.metaKey && !e.shiftKey && (vw.dataset.view === VIEW || goView(vw.dataset.view))) e.preventDefault(); return; }
    if (t.closest('#viewCycle')) { setCycle(CYC.min ? 0 : (CYC.last || 2)); return; }
    const go = t.closest('[data-goto]');
    if (go) { gotoPanel(go.dataset.goto); return; }
    const lyr = t.closest('[data-layer]');
    if (lyr) {
      const L = LAYER[lyr.dataset.layer];
      if (L.key && D[L.feed]?.needsKey) { toast('Add an API key in config.json to enable this layer (see README).'); return; }
      setLayerVis(L.id, !S.layers[L.id]); return;
    }
  });
  document.addEventListener('change', e => {
    const sel = e.target.closest('[data-pset]');
    if (!sel) return;
    const [pid, key] = sel.dataset.pset.split('|');
    ps(pid)[key] = sel.value; save(); renderPanel(pid);
    if (pid === 'livefeed' && key === 'speed') lfSchedule();
  });
  document.addEventListener('submit', e => {
    if (e.target.matches('[data-invform]')) { e.preventDefault(); investigate(e.target.ip.value); }
  });
  $('#searchForm').addEventListener('submit', e => {
    e.preventDefault();
    const q = $('#search').value.trim();
    if (!q) return;
    if (IP_RX.test(q)) investigate(q);
    else if (CVE_RX.test(q)) {
      const id = q.toUpperCase();
      const k = D.kev?.items.find(x => x.cve === id);
      toast(k ? `${id} is on CISA KEV (added ${k.added})` : `Opening ${id} on NVD`);
      window.open(nvd(id), '_blank', 'noopener,noreferrer');
    } else { ps('news').q = q; ps('news').src = 'all'; save(); renderPanel('news'); gotoPanel('news'); }
    $('#search').blur();
  });
  $('#btnRefresh').onclick = () => refreshAll();
  $('#btnSettings').onclick = () => openDrawer();
  $('#drClose').onclick = () => openDrawer(false);
  $('#btnFocus').onclick = () => setLayout(S.layout === 'map' ? (S.prevLayout || 'right') : (S.prevLayout = S.layout, 'map'));
  $('#lcToggle').onclick = () => { S.layerCollapsed = !S.layerCollapsed; $('#layerCtl').classList.toggle('collapsed', S.layerCollapsed); $('#lcToggle').textContent = S.layerCollapsed ? '+' : '–'; save(); };
  $('#kpiToggle').onclick = () => { S.kpiCollapsed = !S.kpiCollapsed; $('#kpiCtl').classList.toggle('collapsed', S.kpiCollapsed); $('#kpiToggle').textContent = S.kpiCollapsed ? '+' : '–'; save(); };
  // On a phone the sidebar is a slide-in sheet; this doesn't touch the saved desktop layout
  const scrim = document.createElement('div'); scrim.id = 'railScrim'; document.body.appendChild(scrim);
  const railSheet = open => document.body.classList.toggle('rail-open', open);
  scrim.onclick = () => railSheet(false);
  PHONE_MQ.addEventListener('change', () => { railSheet(false); map?.resize(); });
  $('#railToggle').onclick = () => { if (isPhone()) return railSheet(!document.body.classList.contains('rail-open')); if (!S.rail) { S.rail = true; S.railMin = false; } else S.railMin = !S.railMin; save(); applyLook(); syncSegs(); };
  $('#btnHome').onclick = () => fitWorld();
  const syncPings = () => { $('#btnPings').classList.toggle('on', S.pings); $('#btnPings').textContent = S.pings ? 'Live pings on' : 'Live pings off'; };
  $('#btnPings').onclick = () => { S.pings = !S.pings; save(); syncPings(); };
  syncPings();

  const seg = (sel, fn) => $(sel).addEventListener('click', e => { const b = e.target.closest('button'); if (b) fn(b.dataset.v); });
  seg('#segLayout', v => setLayout(v));
  seg('#segTheme', v => { S.theme = v; save(); applyLook(); renderLayerList(); });
  seg('#segBase', v => { S.base = v; save(); applyBase(); syncSegs(); });
  $('#selCols').onchange = e => { S.cols = +e.target.value; save(); applyLook(); };
  $('#selRefresh').onchange = e => { S.refresh = +e.target.value; save(); schedule(); };
  $('#rowCycle')?.classList.toggle('hidden', SCREEN !== 'analytics');
  if ($('#selCycle')) { $('#selCycle').value = String(CYC.min); $('#selCycle').onchange = e => setCycle(e.target.value); }
  $('#chkTicker').onchange = e => { S.ticker = e.target.checked; save(); applyLook(); };
  $('#chkRail').onchange = e => { S.rail = e.target.checked; save(); applyLook(); };
  $('#chkCompact').onchange = e => { S.compact = e.target.checked; save(); applyLook(); };
  $('#chkLabels').onchange = e => { S.labels = e.target.checked; save(); applyBase(); };
  $('#panelToggles').addEventListener('change', e => {
    const id = e.target.dataset.ptog;
    if (!id) return;
    S.hidden[id] = !e.target.checked; save(); buildDock();
    if (e.target.checked) gotoPanel(id);
  });
  $('#btnReset').onclick = () => { if (confirm('Reset KESTREL layout and preferences?')) { S = structuredClone(DEFAULTS); save(); applyLook(); buildDock(); buildDrawer(); applyBase(); for (const L of LAYERS) setLayerVis(L.id, S.layers[L.id]); } };
  $('#btnExport').onclick = async () => { const txt = JSON.stringify(S); try { await navigator.clipboard.writeText(txt); toast('Layout copied to clipboard'); } catch { prompt('Copy your layout JSON:', txt); } };
  $('#btnImport').onclick = () => {
    const txt = prompt('Paste layout JSON:');
    if (!txt) return;
    try { localStorage.setItem(LS_KEY, JSON.stringify(JSON.parse(txt))); location.reload(); } catch { toast('That is not valid layout JSON'); }
  };

  // Dock resizer
  const rz = $('#dockResizer');
  rz.addEventListener('pointerdown', e => {
    rz.setPointerCapture(e.pointerId); rz.classList.add('drag');
    const move = ev => {
      if (S.layout === 'bottom') S.dockH = Math.max(160, Math.min(innerHeight - 200, innerHeight - (S.ticker ? 28 : 0) - ev.clientY));
      else S.dockW = Math.max(300, Math.min(innerWidth - 320, S.layout === 'left' ? ev.clientX : innerWidth - ev.clientX));
      document.documentElement.style.setProperty('--dock-w', S.dockW + 'px');
      document.documentElement.style.setProperty('--dock-h', S.dockH + 'px');
      map?.resize();
    };
    const up = () => { rz.classList.remove('drag'); rz.removeEventListener('pointermove', move); rz.removeEventListener('pointerup', up); save(); };
    rz.addEventListener('pointermove', move); rz.addEventListener('pointerup', up);
  });

  document.addEventListener('keydown', e => {
    if (e.target.matches('input, select, textarea')) { if (e.key === 'Escape') e.target.blur(); return; }
    const k = e.key.toLowerCase();
    if (e.key === '/') { e.preventDefault(); $('#search').focus(); }
    else if (k === 'r' && !e.ctrlKey && !e.metaKey) refreshAll();
    else if (k === 'f') $('#btnFocus').click();
    else if (k === 's') openDrawer();
    else if (k === 'l') $('#lcToggle').click();
    else if (e.key === '[') $('#railToggle').click();
    else if (k === 'h') fitWorld();
    else if (k === 'p') { LF.paused = !LF.paused; renderPanel('livefeed'); toast(LF.paused ? 'Live feed paused' : 'Live feed resumed'); }
    else if (e.key === 'Escape') { openDrawer(false); document.body.classList.remove('rail-open'); }
  });

  new Sortable($('#dock'), {
    handle: '.grip', animation: 180, ghostClass: 'sortable-ghost', chosenClass: 'sortable-chosen',
    onEnd: () => {
      const vis = $$('#dock .panel').map(p => p.dataset.id);
      const hidden = S.order.filter(id => !vis.includes(id));
      S.order = [...vis, ...hidden]; save();
    },
  });
  setInterval(() => { $('#clock').textContent = new Date().toISOString().slice(11, 19); }, 1000);
  setInterval(() => { for (const p of PANELS) { const el = $(`.panel[data-id="${p.id}"] .upd`); const m = p.feed && META[p.feed]; if (el && m?.updated) el.innerHTML = `${m.stale ? '<span class="stale">stale · </span>' : ''}updated ${ago(m.updated)} ago`; } }, 30000);
}

let pollTimer;
function schedule() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => { await Promise.all(FEEDS.map(f => loadFeed(f, true))); loadStatus(); }, S.refresh * 60000);
}
// provider outages are checked every minute whatever the poll interval, so the alert is never late
setInterval(() => loadFeed('cloudstatus', true), 60000);

function bootLog(msg) { const el = $('#bootLog'); if (el) el.textContent = msg; }

/* ------------------------------------------------------------------- boot */
const COUNTRY_NAME = {};
async function boot() {
  try {
    const c = await (await fetch('/countries.json')).json();
    for (const [k, v] of Object.entries(c)) { COUNTRY_NAME[k] = v[2]; COUNTRY_CENTER[k] = v; }
  } catch { /* names optional */ }
  document.body.dataset.view = VIEW;
  renderViewNav();
  applyLook();
  $('#layerCtl').classList.toggle('collapsed', S.layerCollapsed);
  $('#lcToggle').textContent = S.layerCollapsed ? '+' : '–';
  $('#kpiCtl').classList.toggle('collapsed', S.kpiCollapsed);
  $('#kpiToggle').textContent = S.kpiCollapsed ? '+' : '–';
  buildDock();
  buildDrawer();
  renderKPIs();
  wire();
  if ($('#map')) try { initMap(); } catch (e) { console.error(e); $('#map').innerHTML = `<div class="err" style="padding:20px">Map failed to load: ${esc(e.message)}. Check your connection to unpkg.com and server.arcgisonline.com.</div>`; }
  renderLayerList();
  bootLog('linking feeds…');
  const first = ['cloudstatus', 'kev', 'ransomware', 'attackers', 'c2', 'outages', 'news'];
  await Promise.race([Promise.all(first.map(f => loadFeed(f))), new Promise(r => setTimeout(r, 8000))]);
  $('#boot').classList.add('done');
  await Promise.all(FEEDS.filter(f => !first.includes(f)).map(f => loadFeed(f, true)));
  lfIngest();
  LF.primed = true;
  lfSchedule();
  geoPoll();
  schedule();
}
boot();
