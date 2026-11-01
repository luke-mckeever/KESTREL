/* KESTREL // analytics chart panels (screen 2, also available on screen 1 via Customise).
 * Loaded before app.js; render functions run later and use app.js globals (D, esc, fmtN, ago, COUNTRY_NAME…).
 * Every chart is drawn from live feed data — nothing here is simulated.
 */
'use strict';

const CONTINENT = {};
Object.entries({
  'N. America': 'US CA MX GT BZ SV HN NI CR PA CU JM HT DO BS BB TT PR GL BM KY AG DM GD KN LC VC AW CW VG VI GP MQ',
  'S. America': 'BR AR CL CO PE VE EC BO PY UY GY SR GF',
  Europe: 'GB IE FR DE NL BE LU CH AT IT ES PT DK NO SE FI IS EE LV LT PL CZ SK HU SI HR BA RS ME MK AL GR BG RO MD UA BY RU MT CY XK AD MC SM VA LI FO GI IM JE GG',
  Africa: 'DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY MG MW ML MR MU YT MA MZ NA NE NG RE RW ST SN SC SL SO ZA SS SD TZ TG TN UG EH ZM ZW',
  Asia: 'AF AM AZ BH BD BT BN KH CN GE HK IN ID IR IQ IL JP JO KZ KW KG LA LB MO MY MV MN MM NP KP OM PK PS PH QA SA SG KR LK SY TW TJ TH TL TR TM AE UZ VN YE',
  Oceania: 'AU NZ FJ PG SB VU NC PF WS TO KI NR TV FM MH PW GU MP AS',
}).forEach(([k, v]) => v.split(' ').forEach(c => { CONTINENT[c] = k; }));
const REGIONS = ['N. America', 'Europe', 'Asia', 'Oceania', 'Africa', 'S. America'];

const CWE_NAMES = {
  'CWE-79': 'Cross-site scripting', 'CWE-89': 'SQL injection', 'CWE-22': 'Path traversal', 'CWE-78': 'OS command injection',
  'CWE-77': 'Command injection', 'CWE-94': 'Code injection', 'CWE-352': 'CSRF', 'CWE-787': 'Out-of-bounds write',
  'CWE-125': 'Out-of-bounds read', 'CWE-416': 'Use after free', 'CWE-20': 'Improper input validation',
  'CWE-862': 'Missing authorization', 'CWE-863': 'Incorrect authorization', 'CWE-287': 'Improper authentication',
  'CWE-306': 'Missing auth for critical function', 'CWE-434': 'Unrestricted file upload', 'CWE-502': 'Unsafe deserialization',
  'CWE-918': 'SSRF', 'CWE-200': 'Information exposure', 'CWE-476': 'NULL pointer dereference', 'CWE-120': 'Buffer overflow',
  'CWE-121': 'Stack buffer overflow', 'CWE-122': 'Heap buffer overflow', 'CWE-400': 'Resource exhaustion',
  'CWE-639': 'IDOR', 'CWE-798': 'Hard-coded credentials', 'CWE-269': 'Privilege management', 'CWE-284': 'Access control',
  'CWE-601': 'Open redirect', 'CWE-611': 'XXE', 'CWE-190': 'Integer overflow', 'CWE-74': 'Injection',
  'CWE-532': 'Sensitive data in logs', 'CWE-770': 'Unlimited allocation', 'CWE-285': 'Improper authorization',
};

const shortDate = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }); };
const shortHour = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toISOString().slice(5, 13).replace('T', ' ') + 'h'; };
const tip = s => `data-tip="${esc(s)}"`;
const noData = msg => `<div class="loading">${esc(msg || 'waiting for data')}</div>`;

// polyline/area path through values scaled into a box
function pathFor(vals, w, h, max, pad = 4) {
  const n = vals.length;
  return vals.map((v, i) => `${i ? 'L' : 'M'}${(n === 1 ? w / 2 : i / (n - 1) * w).toFixed(1)},${(h - pad - (v / max) * (h - pad * 2)).toFixed(1)}`).join('');
}

/* ------------------------------------------------------------- radar scope */
function geoMath(home, g) {
  const R = Math.PI / 180, f1 = home.lat * R, f2 = g.lat * R, dl = (g.lon - home.lon) * R;
  const y = Math.sin(dl) * Math.cos(f2), x = Math.cos(f1) * Math.sin(f2) - Math.sin(f1) * Math.cos(f2) * Math.cos(dl);
  const brg = (Math.atan2(y, x) / R + 360) % 360;
  const a = Math.sin((f2 - f1) / 2) ** 2 + Math.cos(f1) * Math.cos(f2) * Math.sin(dl / 2) ** 2;
  return { brg, km: 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)) };
}
const COMPASS = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
const SCOPE_TYPES = [
  ['c2', 'C2 server', 'var(--c2)', () => D.c2?.items],
  ['attack', 'Top attacker', 'var(--attk)', () => D.attackers?.items],
  ['comp', 'Compromised', 'var(--comp)', () => D.attackers?.compromised],
  ['phish', 'Phishing host', 'var(--phish)', () => D.phishing?.items],
  ['ioc', 'ThreatFox IOC', 'var(--tfox)', () => D.threatfox?.needsKey ? [] : D.threatfox?.items],
];

window.EXTRA_PANELS = [
  {
    id: 'scope', title: 'Threat Radar · distance from you', deps: ['home', 'c2', 'attackers', 'phishing', 'threatfox'],
    feed: 'home', badge: () => D.home ? D.home.name : '',
    src: () => 'bearing and great-circle distance of every geolocated hostile host',
    render() {
      const home = D.home;
      const st = ps('scope'), show = st.show || 'all';
      const S2 = 300, C = S2 / 2, RMAX = 138, PERIOD = 6;
      const rOf = km => Math.sqrt(Math.min(km, 20015) / 20015) * RMAX;
      const blips = [];
      for (const [k, label, color, get] of SCOPE_TYPES) {
        if (show !== 'all' && show !== k) continue;
        for (const x of get() || []) {
          if (!x.geo || x.geo.lat == null) continue;
          const m = geoMath(home, x.geo);
          blips.push({ k, label, color, ip: x.ip || x.host, geo: x.geo, ...m });
        }
      }
      const rings = [1000, 3000, 6000, 10000, 20000];
      const within = km => blips.filter(b => b.km <= km).length;
      const svgBlips = blips.map(b => {
        const r = rOf(b.km), a = b.brg * Math.PI / 180;
        const delay = -(PERIOD - b.brg / 360 * PERIOD);
        return `<circle class="blip" cx="${(C + r * Math.sin(a)).toFixed(1)}" cy="${(C - r * Math.cos(a)).toFixed(1)}" r="2.6" fill="${b.color}" style="animation-delay:${delay.toFixed(2)}s" ${tip(`${b.label} · ${b.ip}\n${loc(b.geo)}\n${fmtN(Math.round(b.km))} km · ${COMPASS[Math.round(b.brg / 22.5) % 16]}`)}/>`;
      }).join('');
      const nearest = blips.slice().sort((a, b) => a.km - b.km).slice(0, 6);
      return chips('scope', 'show', [['all', 'All'], ...SCOPE_TYPES.filter(t => (t[3]() || []).length).map(t => [t[0], t[1]])], show) +
        `<div class="scope-wrap"><svg class="scope" viewBox="0 0 ${S2} ${S2}">
          <defs><radialGradient id="scopeBg"><stop offset="0" stop-color="rgba(var(--acc-rgb),.10)"/><stop offset="1" stop-color="rgba(var(--acc-rgb),.02)"/></radialGradient>
          <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="rgba(var(--acc-rgb),0)"/><stop offset="1" stop-color="rgba(var(--acc-rgb),.38)"/></linearGradient></defs>
          <circle cx="${C}" cy="${C}" r="${RMAX}" fill="url(#scopeBg)" stroke="var(--line2)"/>
          ${rings.map(km => `<circle cx="${C}" cy="${C}" r="${rOf(km).toFixed(1)}" fill="none" stroke="var(--line2)" stroke-dasharray="2 3"/><text x="${C + 3}" y="${(C - rOf(km) + 10).toFixed(1)}" class="scope-lbl">${km >= 1000 ? km / 1000 + 'k' : km} km</text>`).join('')}
          <line x1="${C - RMAX}" y1="${C}" x2="${C + RMAX}" y2="${C}" stroke="var(--line)"/><line x1="${C}" y1="${C - RMAX}" x2="${C}" y2="${C + RMAX}" stroke="var(--line)"/>
          ${['N', 'E', 'S', 'W'].map((d, i) => `<text class="scope-dir" x="${C + Math.sin(i * Math.PI / 2) * (RMAX + 8)}" y="${C - Math.cos(i * Math.PI / 2) * (RMAX + 8) + 3}">${d}</text>`).join('')}
          <g class="sweep" style="animation-duration:${PERIOD}s"><path d="M${C},${C} L${C + RMAX * Math.sin(-Math.PI / 5)},${C - RMAX * Math.cos(-Math.PI / 5)} A${RMAX},${RMAX} 0 0 1 ${C},${C - RMAX} Z" fill="url(#sweepGrad)"/><line x1="${C}" y1="${C}" x2="${C}" y2="${C - RMAX}" stroke="var(--acc)" stroke-width="1.2"/></g>
          ${svgBlips}
          <circle cx="${C}" cy="${C}" r="3.5" fill="var(--acc)"/>
        </svg>
        <div class="scope-side">
          <div class="sub-h">Within range</div>
          ${rings.slice(0, 4).map(km => `<div class="kvrow"><span>≤ ${fmtN(km)} km</span><b>${within(km)}</b></div>`).join('')}
          <div class="kvrow"><span>Total plotted</span><b>${blips.length}</b></div>
          <div class="sub-h">Closest hostile hosts</div>
          ${nearest.map(b => `<div class="near click" data-inv="${esc(b.ip)}"><i style="background:${b.color}"></i><span>${esc(b.ip)}</span><em>${fmtN(Math.round(b.km))} km ${COMPASS[Math.round(b.brg / 22.5) % 16]}</em></div>`).join('') || '<div class="s">none located yet</div>'}
        </div></div>
        <div class="disclaim">Centred on ${esc(home.name)} (${esc(home.source)}). Radius uses a square-root distance scale; the sweep lights each host as it passes its true bearing. Set <code>home_lat</code>/<code>home_lon</code> in config.json to move the centre.</div>`;
    },
  },
  {
    id: 'spider', title: 'Threat Composition by Region', deps: ['attackers', 'phishing', 'ransomware', 'c2', 'threatfox'],
    src: () => 'share of each threat type located in each region',
    render() {
      const series = [
        ['Scanning & compromised', 'var(--attk)', [...(D.attackers?.items || []), ...(D.attackers?.compromised || [])].map(x => x.geo?.cc)],
        ['Phishing hosting', 'var(--phish)', (D.phishing?.items || []).map(x => x.geo?.cc)],
        ['Ransomware victims', 'var(--ransom)', (D.ransomware?.items || []).map(x => x.cc)],
        ['C2 & IOCs', 'var(--c2)', [...(D.c2?.items || []), ...(D.threatfox?.needsKey ? [] : D.threatfox?.items || [])].map(x => x.geo?.cc)],
      ].map(([name, color, ccs]) => {
        const cnt = Object.fromEntries(REGIONS.map(r => [r, 0]));
        let tot = 0;
        for (const c of ccs) { const r = CONTINENT[c]; if (r) { cnt[r]++; tot++; } }
        return { name, color, cnt, tot };
      }).filter(s => s.tot > 0);
      if (!series.length) return noData('waiting for geolocated data');
      const S2 = 300, C = 150, R = 105, N = REGIONS.length;
      const pt = (i, f) => { const a = -Math.PI / 2 + i * 2 * Math.PI / N; return [C + Math.cos(a) * R * f, C + Math.sin(a) * R * f]; };
      const grid = [0.25, 0.5, 0.75, 1].map(f => `<polygon points="${REGIONS.map((_, i) => pt(i, f).join(',')).join(' ')}" fill="none" stroke="var(--line2)" ${f < 1 ? 'stroke-dasharray="2 3"' : ''}/>`).join('');
      const axes = REGIONS.map((r, i) => { const [x, y] = pt(i, 1), [lx, ly] = pt(i, 1.18); return `<line x1="${C}" y1="${C}" x2="${x}" y2="${y}" stroke="var(--line)"/><text class="spider-lbl" x="${lx}" y="${ly + 3}">${r}</text>`; }).join('');
      const polys = series.map((s, si) => {
        const pts = REGIONS.map((r, i) => pt(i, s.cnt[r] / s.tot));
        return `<g class="spider-s" style="animation-delay:${si * 0.15}s"><polygon points="${pts.map(p => p.join(',')).join(' ')}" fill="${s.color}" fill-opacity=".14" stroke="${s.color}" stroke-width="1.6"/>
          ${pts.map((p, i) => `<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="${s.color}" ${tip(`${s.name} · ${REGIONS[i]}\n${s.cnt[REGIONS[i]]} of ${s.tot} (${Math.round(s.cnt[REGIONS[i]] / s.tot * 100)}%)`)}/>`).join('')}</g>`;
      }).join('');
      return `<svg class="spider" viewBox="0 0 ${S2} ${S2}">${grid}${axes}${polys}</svg>
        <div class="legend">${series.map(s => `<span><i style="background:${s.color}"></i>${esc(s.name)} <em>${s.tot}</em></span>`).join('')}</div>`;
    },
  },
  {
    id: 'kevtrend', title: 'Exploited Vulns Added · 26 weeks', deps: ['kev'], feed: 'kev',
    badge: () => D.kev?.weekly ? `${D.kev.weekly.reduce((a, w) => a + w.all, 0)} total` : '',
    render() {
      const wk = D.kev.weekly || [];
      if (!wk.length) return noData('restart kestrel.py to load weekly data');
      const W = 600, H = 170, max = Math.max(...wk.map(w => w.all), 1);
      const all = pathFor(wk.map(w => w.all), W, H, max), rw = pathFor(wk.map(w => w.ransomware), W, H, max);
      const avg = wk.reduce((a, w) => a + w.all, 0) / wk.length;
      const last4 = wk.slice(-4).reduce((a, w) => a + w.all, 0) / 4;
      const pts = wk.map((w, i) => `<rect x="${(i / (wk.length - 1) * W - W / wk.length / 2).toFixed(1)}" y="0" width="${(W / wk.length).toFixed(1)}" height="${H}" fill="transparent" ${tip(`Week of ${shortDate(w.week)}\n${w.all} added · ${w.ransomware} ransomware-linked`)}/>`).join('');
      return `<div class="stats"><div class="stat"><div class="k">Weekly average</div><div class="v">${avg.toFixed(1)}</div></div><div class="stat"><div class="k">Last 4 weeks</div><div class="v" style="color:${last4 > avg * 1.25 ? 'var(--high)' : 'var(--text)'}">${last4.toFixed(1)}</div></div><div class="stat"><div class="k">Peak week</div><div class="v">${max}</div></div></div>
        <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
          <line x1="0" x2="${W}" y1="${(H - 4 - avg / max * (H - 8)).toFixed(1)}" y2="${(H - 4 - avg / max * (H - 8)).toFixed(1)}" stroke="var(--mute)" stroke-dasharray="4 4" vector-effect="non-scaling-stroke"/>
          <path d="${all}L${W},${H}L0,${H}Z" fill="rgba(var(--acc-rgb),.12)"/>
          <path class="draw" d="${all}" pathLength="1000" fill="none" stroke="var(--acc)" stroke-width="2" vector-effect="non-scaling-stroke"/>
          <path class="draw" d="${rw}" pathLength="1000" fill="none" stroke="var(--ransom)" stroke-width="1.6" stroke-dasharray="1000" vector-effect="non-scaling-stroke"/>
          ${pts}
        </svg>
        <div class="axis"><span>${shortDate(wk[0].week)}</span><span>max ${max}/wk</span><span>this week</span></div>
        <div class="legend"><span><i style="background:var(--acc)"></i>All KEV additions</span><span><i style="background:var(--ransom)"></i>Known ransomware use</span><span><i style="background:var(--mute)"></i>26-week average</span></div>`;
    },
  },
  {
    id: 'cvetimeline', title: 'CVE Publication Rate · 72h', deps: ['cves'], feed: 'cves',
    badge: () => D.cves ? `${fmtN(D.cves.total)} CVEs` : '',
    render() {
      const tl = D.cves.timeline || [];
      if (!tl.length) return noData('restart kestrel.py to load the timeline');
      const keys = [['CRITICAL', 'var(--crit)'], ['HIGH', 'var(--high)'], ['MEDIUM', 'var(--med)'], ['LOW', 'var(--low)'], ['UNSCORED', 'var(--mute)']];
      const W = 600, H = 160, bw = W / tl.length, tot = b => keys.reduce((a, [k]) => a + b[k], 0), max = Math.max(...tl.map(tot), 1);
      const bars = tl.map((b, i) => {
        let y = H;
        const segs = keys.map(([k, c]) => { const h = b[k] / max * (H - 6); y -= h; return h > 0 ? `<rect x="${(i * bw + 1.5).toFixed(1)}" y="${y.toFixed(1)}" width="${(bw - 3).toFixed(1)}" height="${h.toFixed(1)}" fill="${c}"/>` : ''; }).join('');
        return `<g class="grow" style="animation-delay:${i * 25}ms" ${tip(`${shortHour(b.t)} UTC (+3h)\n${tot(b)} published · ${b.CRITICAL} critical · ${b.HIGH} high`)}>${segs}<rect x="${i * bw}" y="0" width="${bw}" height="${H}" fill="transparent"/></g>`;
      }).join('');
      return `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${bars}</svg>
        <div class="axis"><span>${shortDate(tl[0].t)} ${tl[0].t.slice(11, 16)}Z</span><span>peak ${max} per 3h</span><span>now</span></div>
        <div class="legend">${keys.map(([k, c]) => `<span><i style="background:${c}"></i>${k.toLowerCase()} <em>${D.cves.severity[k] || 0}</em></span>`).join('')}</div>`;
    },
  },
  {
    id: 'ransomtimeline', title: 'Ransomware Claims · 4 days', deps: ['ransomware'], feed: 'ransomware',
    render() {
      const tl = D.ransomware.timeline || [];
      if (!tl.length) return noData('restart kestrel.py to load the timeline');
      const W = 600, H = 150, bw = W / tl.length, max = Math.max(...tl.map(b => b.count), 1);
      const bars = tl.map((b, i) => {
        const h = b.count / max * (H - 22);
        return `<g class="grow" style="animation-delay:${i * 40}ms" ${tip(`${shortHour(b.t)} UTC (+6h)\n${b.count} claims${b.top ? '\nmost active: ' + b.top : ''}`)}><rect x="${(i * bw + 3).toFixed(1)}" y="${(H - h).toFixed(1)}" width="${(bw - 6).toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="var(--ransom)" fill-opacity="${0.45 + 0.55 * b.count / max}"/>${b.count ? `<text class="bar-v" x="${(i * bw + bw / 2).toFixed(1)}" y="${(H - h - 5).toFixed(1)}">${b.count}</text>` : ''}<rect x="${i * bw}" y="0" width="${bw}" height="${H}" fill="transparent"/></g>`;
      }).join('');
      const days = tl.filter((_, i) => i % 4 === 0).map(b => `<span>${shortDate(b.t)}</span>`).join('');
      return `<svg class="chart" viewBox="0 0 ${W} ${H}">${bars}</svg><div class="axis">${days}</div>
        <div class="sub-h">Most active groups (latest ${D.ransomware.items.length} claims)</div>${barsHTML(D.ransomware.groups.slice(0, 5).map(([g, n]) => [g, n, '', 'var(--ransom)']))}`;
    },
  },
  {
    id: 'porttrend', title: 'Port Attack Trends · 30 days', deps: ['porthist'], feed: 'porthist',
    src: () => 'SANS ISC DShield daily reports for today\'s most-targeted ports',
    render() {
      const W = 220, H = 46;
      return `<div class="minis">${D.porthist.ports.map(p => {
        const v = p.days.map(d => d.records);
        if (v.length < 2) return '';
        const max = Math.max(...v, 1), last = v[v.length - 1], prev = v.slice(-8, -1), avg = prev.reduce((a, b) => a + b, 0) / (prev.length || 1);
        const ch = avg ? (last - avg) / avg * 100 : 0;
        const path = pathFor(v, W, H, max, 3);
        const hover = p.days.map((d, i) => `<rect x="${(i / (v.length - 1) * W - W / v.length / 2).toFixed(1)}" y="0" width="${(W / v.length).toFixed(1)}" height="${H}" fill="transparent" ${tip(`Port ${p.port} · ${d.date}\n${fmtN(d.records)} reports · ${fmtN(d.sources)} sources`)}/>`).join('');
        return `<div class="mini"><div class="mini-h"><b>${p.port}</b><span>${esc(p.name)}</span><em class="${ch > 15 ? 'up' : ch < -15 ? 'down' : ''}">${ch >= 0 ? '▲' : '▼'} ${Math.abs(ch).toFixed(0)}%</em></div>
          <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><path d="${path}L${W},${H}L0,${H}Z" fill="rgba(var(--acc-rgb),.1)"/><path class="draw" d="${path}" pathLength="1000" fill="none" stroke="var(--acc)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>${hover}</svg>
          <div class="mini-f"><span>${fmtN(last)} yesterday</span><span>vs 7-day avg</span></div></div>`;
      }).join('')}</div>`;
    },
  },
  {
    id: 'outagegantt', title: 'Internet Outage Timeline · 48h', deps: ['outages'], feed: 'outages',
    badge: () => D.outages ? `${D.outages.ongoing} ongoing` : '',
    render() {
      const now = Date.now() / 1000, from = now - 48 * 3600;
      const rows = D.outages.items.filter(o => o.end > from).slice(0, 16);
      if (!rows.length) return noData('no outages in the last 48h');
      const pct = t => Math.max(0, Math.min(100, (t - from) / (now - from) * 100));
      return `<div class="gantt">${rows.map((o, i) => {
        const a = pct(o.start), b = o.ongoing ? 100 : pct(o.end);
        return `<div class="g-row click" ${flyAttr(o.geo)}><span class="g-lbl">${cc(o.cc)}${esc(o.name)}</span><span class="g-trk"><span class="g-bar ${o.ongoing ? 'live' : ''}" style="left:${a}%;width:${Math.max(b - a, 0.8)}%;animation-delay:${i * 40}ms" ${tip(`${o.name}\n${o.ongoing ? 'ongoing' : 'recovered'} · ${o.durationH}h\nsignals: ${o.sources.join(', ')}`)}></span></span></div>`;
      }).join('')}
      <div class="g-row g-axis"><span class="g-lbl"></span><span class="g-trk"><span style="left:0">-48h</span><span style="left:50%">-24h</span><span style="right:0">now</span></span></div></div>`;
    },
  },
  {
    id: 'cwe', title: 'Top Weakness Types · 72h', deps: ['cves'], feed: 'cves',
    render() {
      const c = D.cves.cwes || [];
      if (!c.length) return noData('restart kestrel.py to load weakness data');
      return barsHTML(c.map(([id, n]) => [`${CWE_NAMES[id] || id}`, n, `${tip(id)}`])) + '<div class="disclaim">CWE classes assigned to CVEs published in the last 72 hours.</div>';
    },
  },
];

// shared hover tooltip for any element with data-tip
(() => {
  const el = document.createElement('div');
  el.id = 'chartTip';
  document.addEventListener('DOMContentLoaded', () => document.body.appendChild(el));
  document.addEventListener('mouseover', e => {
    const t = e.target.closest && e.target.closest('[data-tip]');
    if (!t) { el.style.opacity = 0; return; }
    el.textContent = t.getAttribute('data-tip');
    el.style.opacity = 1;
  });
  document.addEventListener('mousemove', e => {
    if (el.style.opacity !== '1') return;
    const x = Math.min(e.clientX + 14, innerWidth - el.offsetWidth - 8);
    el.style.transform = `translate(${x}px, ${e.clientY + 14}px)`;
  });
})();
