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

/* ======================================================================= intel panels
 * Threat timeline, actor & campaign graph, sector heatmap, ATT&CK heatmap, vulnerability pressure board.
 * Built from feeds KESTREL already collects (NVD, CISA KEV, ransomware.live, security news incl. CISA advisories)
 * plus FIRST.org EPSS. Actor / sector / technique extraction from news is keyword matching, and each panel says so.
 */
const newsText = n => `${n.title}. ${n.text || n.summary || ''}`;
const isKevNotice = n => /Adds? .*Known Exploited Vulnerabilit/i.test(n.title);
const hashN = s => { let h = 2166136261; for (const c of String(s)) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967295; };
const rgbaAcc = a => `rgba(var(--acc-rgb),${a.toFixed(3)})`;

/* ---------------------------------------------------------------- sectors */
const SECTORS = [
  ['Healthcare', /health|hospital|medical|clinic|pharma|patient/i],
  ['Financial Services', /financ|\bbank|insurance|insurer|credit union|fintech|payment|crypto(currency)? exchange|brokerage/i],
  ['Government & Defense', /government|ministry|municipal|federal agenc|\bcouncil\b|city of|county|defen[cs]e (contractor|ministry|sector)|military|armed forces|embass/i],
  ['Education', /educat|universit|school|college|student/i],
  ['Manufacturing', /manufactur|factory|automotive|semiconductor|industrial (company|firm|giant)/i],
  ['Technology', /technolog|software|\bsaas\b|cloud provider|it services|managed service|\bmsp\b|developer|open[- ]source|github|\bnpm\b|pypi/i],
  ['Professional Services', /professional services|law firm|legal|accounting|consult|staffing|business services/i],
  ['Energy & Utilities', /energy|utilit|power (grid|plant)|electric|\boil\b|\bgas\b|water|nuclear|pipeline/i],
  ['Transportation & Logistics', /transport|logistic|shipping|maritime|airline|airport|aviation|\brail|freight/i],
  ['Retail & Hospitality', /retail|e-?commerce|hospitality|hotel|restaurant|consumer goods/i],
  ['Telecom & Media', /telecom|\bcarrier|\bisp\b|mobile operator|media|broadcast|entertainment|gaming|publish/i],
  ['Construction & Real Estate', /construct|real estate|property/i],
  ['Agriculture & Food', /agricultur|\bfood|farm|beverage/i],
];
const sectorOf = s => s ? (SECTORS.find(([, rx]) => rx.test(s)) || [null])[0] : null;
const sectorsIn = txt => SECTORS.filter(([, rx]) => rx.test(txt)).map(([n]) => n).slice(0, 2);
const THREAT_TYPES = [
  ['Ransomware', 'var(--ransom)', null],
  ['Breach / leak', 'var(--high)', /breach|leak|exposed (data|records|database)|stolen data|data theft/i],
  ['Exploited vulns', 'var(--med)', /exploit|zero[- ]day|0-day|vulnerabilit|\bRCE\b|remote code/i],
  ['Phishing & fraud', 'var(--phish)', /phish|scam|fraud|business email compromise|\bBEC\b/i],
  ['Espionage / APT', 'var(--tor)', /\bAPT ?\d*\b|espionage|state[- ](sponsored|backed)|nation[- ]state|Typhoon|Blizzard|Lazarus|Kimsuky|Sandworm/i],
  ['Malware', 'var(--c2)', /malware|trojan|botnet|stealer|backdoor|loader|\bRAT\b/i],
  ['DDoS', 'var(--outage)', /\bDDoS\b|denial[- ]of[- ]service/i],
];

/* ---------------------------------------------------------- actors & malware */
const ACTORS = ['Lazarus', 'Kimsuky', 'Andariel', 'BlueNoroff', 'Sandworm', 'Turla', 'Gamaredon', 'MuddyWater', 'OilRig', 'Charming Kitten',
  'Scattered Spider', 'ShinyHunters', 'LAPSUS$', 'Cl0p', 'Clop', 'LockBit', 'ALPHV', 'BlackCat', 'Akira', 'Black Basta', 'Qilin', 'RansomHub', 'Medusa',
  'Rhysida', 'INC Ransom', 'BianLian', '8Base', 'Hunters International', 'DragonForce', 'SafePay', 'Interlock', 'Lynx', 'Cicada3301', 'Embargo',
  'Play ransomware', 'Fog ransomware', 'Warlock', 'Gentlemen', 'Kraken', 'Sinobi', 'Chaos ransomware', 'Crypto24', 'Everest', 'World Leaks', 'Silent Ransom Group',
  'Patchwork', 'SideWinder', 'Transparent Tribe', 'Konni', 'APT-C-60', 'Winnti', 'Volt Typhoon', 'Salt Typhoon', 'Flax Typhoon', 'Silk Typhoon', 'Linen Typhoon',
  'Mustang Panda', 'Cozy Bear', 'Fancy Bear', 'Star Blizzard', 'Midnight Blizzard', 'Forest Blizzard', 'Seashell Blizzard', 'Secret Blizzard', 'Void Blizzard'];
const ACTOR_ALIAS = { clop: 'Cl0p', blackcat: 'ALPHV', 'cozy bear': 'APT29', 'midnight blizzard': 'APT29', 'fancy bear': 'APT28', 'forest blizzard': 'APT28', 'play ransomware': 'Play', 'fog ransomware': 'Fog', 'chaos ransomware': 'Chaos', 'seashell blizzard': 'Sandworm' };
const ACTOR_RX = new RegExp(`\\b(${ACTORS.map(a => a.replace(/[$.]/g, '\\$&')).join('|')}|APT ?\\d{1,3}|UNC\\d{3,5}|TA\\d{3,4}|FIN\\d{1,2}|Storm-\\d{4}|UAC-\\d{4}|Earth [A-Z][a-z]+|[A-Z][a-z]+ (?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Panda|Chollima|Kitten))\\b`, 'g');
const normActor = a => { const k = a.toLowerCase(); return ACTOR_ALIAS[k] || a.replace(/^APT (\d)/, 'APT$1'); };
const MALWARE = ['Emotet', 'QakBot', 'Qbot', 'IcedID', 'Pikabot', 'Lumma', 'LummaC2', 'RedLine', 'Vidar', 'StealC', 'AsyncRAT', 'Remcos', 'njRAT', 'DarkGate',
  'Latrodectus', 'SocGholish', 'Cobalt Strike', 'Sliver', 'Brute Ratel', 'Mirai', 'Gafgyt', 'XWorm', 'Agent Tesla', 'AgentTesla', 'Formbook', 'Rhadamanthys',
  'PlugX', 'ShadowPad', 'BPFDoor', 'Bumblebee', 'SystemBC', 'NetSupport', 'GootLoader', 'SmokeLoader', 'DanaBot', 'Atomic Stealer', 'AMOS', 'Raccoon',
  'Havoc', 'Mythic', 'Gh0st', 'Sality', 'Kinsing', 'XMRig', 'Medusa Stealer', 'Snake Keylogger', 'Grandoreiro', 'Mekotio', 'Anatsa', 'Hook', 'Octo', 'Coyote',
  'BADBOX', 'Aisuru', 'Kimwolf', 'RondoDox', 'Vo1d', 'ValleyRAT', 'Winos', 'Akira_v2', 'Mamona', 'Gremlin', 'Katz Stealer', 'Acreed', 'ClickFix'];
const MAL_ALIAS = { qbot: 'QakBot', lummac2: 'Lumma', agenttesla: 'Agent Tesla', amos: 'Atomic Stealer' };

function graphModel() {
  const nodes = new Map(), edges = new Map();
  const node = (type, name) => { const id = type + ':' + name; if (!nodes.has(id)) nodes.set(id, { id, type, name, w: 0, refs: [] }); return nodes.get(id); };
  const link = (a, b, w, why) => {
    if (a.id === b.id) return;
    const k = a.id < b.id ? a.id + '|' + b.id : b.id + '|' + a.id;
    const e = edges.get(k) || { a: a.id < b.id ? a.id : b.id, b: a.id < b.id ? b.id : a.id, w: 0, why: new Set() };
    e.w += w; if (why && e.why.size < 3) e.why.add(why); edges.set(k, e);
    a.w += w; b.w += w;
  };
  const malSet = new Set(MALWARE);
  for (const c of D.c2?.items || []) if (c.malware) malSet.add(c.malware);
  if (!D.threatfox?.needsKey) for (const x of D.threatfox?.items || []) if (x.malware && x.malware.length > 3 && !/unknown/i.test(x.malware)) malSet.add(x.malware.replace(/^\w+\./, ''));
  const malRx = new RegExp(`\\b(${[...malSet].map(m => m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\b`, 'g');
  const kevSet = new Set((D.kev?.items || []).map(k => k.cve));
  // 1. news co-mentions: who, using what, against which CVEs and sectors
  for (const n of D.news?.items || []) {
    if (isKevNotice(n)) continue;
    const t = newsText(n);
    const actors = [...new Set((t.match(ACTOR_RX) || []).map(normActor))].map(a => node('actor', a));
    const mal = [...new Set((t.match(malRx) || []).map(m => MAL_ALIAS[m.toLowerCase()] || m))].filter(m => !actors.some(a => a.name === m)).map(m => node('malware', m));
    const cves = (n.cves || []).slice(0, 4).map(c => Object.assign(node('cve', c), { kev: kevSet.has(c) }));
    const secs = sectorsIn(t).map(s => node('sector', s));
    for (const x of [...actors, ...mal, ...cves]) if (x.refs.length < 4 && !x.refs.includes(n.title)) x.refs.push(n.title);
    const pairs = [[actors, mal], [actors, cves], [actors, secs], [mal, cves], [mal, secs]];
    for (const [A, B] of pairs) for (const a of A) for (const b of B) link(a, b, 1, n.title);
    if (!actors.length && cves.length && secs.length) for (const c of cves) for (const s of secs) link(c, s, 0.5, n.title);
  }
  // 2. ransomware.live: each of the most active groups -> the sectors of its posted victims
  const groups = (D.ransomware?.groups || []).slice(0, 8).map(([g]) => g);
  for (const v of D.ransomware?.items || []) {
    if (!groups.includes(v.group)) continue;
    const s = sectorOf(v.sector);
    if (!s) continue;
    const a = node('actor', /^[a-z0-9 ]+$/.test(v.group) ? v.group.replace(/\b\w/g, c => c.toUpperCase()) : v.group);
    a.ransom = true;
    link(a, node('sector', s), 1, `${v.group} claimed ${v.victim}`);
  }
  // keep the best-connected nodes
  const keep = new Set([...nodes.values()].filter(n => n.w > 0).sort((x, y) => y.w - x.w).slice(0, 44).map(n => n.id));
  const E = [...edges.values()].filter(e => keep.has(e.a) && keep.has(e.b));
  const deg = new Set(E.flatMap(e => [e.a, e.b]));
  const N = [...nodes.values()].filter(n => deg.has(n.id));
  return { N, E };
}

// Layered layout: actors -> malware -> CVEs -> sectors, left to right. Each column is ordered by the average position
// of its neighbours (barycentre sweeps) to cut down crossings. Deterministic, so re-renders don't jump.
const AG_COL = { actor: 0.1, malware: 0.37, cve: 0.63, sector: 0.9 };
const AG_COLOR = { actor: 'var(--crit)', malware: 'var(--c2)', cve: 'var(--high)', sector: 'var(--phish)' };
function layoutGraph(N, E, W, H) {
  const idx = new Map(N.map((n, i) => [n.id, i]));
  const P = N.map(n => ({ x: AG_COL[n.type] * W, y: 0 }));
  const nb = N.map(() => []);
  for (const e of E) { const a = idx.get(e.a), b = idx.get(e.b); nb[a].push([b, e.w]); nb[b].push([a, e.w]); }
  const cols = Object.keys(AG_COL).map(t => N.map((n, i) => i).filter(i => N[i].type === t));
  const place = col => col.forEach((i, k) => { P[i].y = 20 + (k + 0.5) * (H - 40) / col.length; });
  cols.forEach(col => { col.sort((a, b) => hashN(N[a].id) - hashN(N[b].id)); place(col); });
  const order = [0, 1, 2, 3, 2, 1, 0];
  for (let sweep = 0; sweep < 6; sweep++) for (const c of order) {
    const col = cols[c];
    const bary = new Map(col.map(i => { let s = 0, w = 0; for (const [j, ew] of nb[i]) { s += P[j].y * ew; w += ew; } return [i, w ? s / w : P[i].y]; }));
    col.sort((a, b) => bary.get(a) - bary.get(b)); place(col);
  }
  return P;
}

/* --------------------------------------------------------------- ATT&CK */
const TACTICS = [
  ['Reconnaissance', [['T1595', 'Active Scanning', /mass[- ]scan|scanning for (vulnerable|exposed)|reconnaissance|probing/i], ['T1589', 'Gather Victim Identity Info', /harvest(ed|ing) (e-?mails|credentials|identities)|\bOSINT\b/i], ['T1598', 'Phishing for Information', /phishing for (information|credentials)|credential[- ]harvesting/i]]],
  ['Resource Development', [['T1583', 'Acquire Infrastructure', /bulletproof hosting|typosquat|lookalike domains?|registered (new |malicious )?domains/i], ['T1584', 'Compromise Infrastructure', /compromised (routers|websites?|wordpress|servers|edge devices)|hijacked (domains|sites|accounts)/i], ['T1587', 'Develop Capabilities', /(new|custom|previously undocumented) (malware|backdoor|loader|implant|toolkit)/i], ['T1588', 'Obtain Capabilities', /malware-as-a-service|\bMaaS\b|initial access broker|exploit broker|sold on (a )?(dark ?web|forum)/i], ['T1608', 'Stage Capabilities', /SEO poisoning|staged payloads?|hosted (the )?payloads?/i]]],
  ['Initial Access', [['T1190', 'Exploit Public-Facing Application', /actively exploit|exploited in the wild|mass[- ]exploit|zero[- ]day|0-day|remote code execution|\bRCE\b|exploitation of/i], ['T1566', 'Phishing', /phish/i], ['T1195', 'Supply Chain Compromise', /supply[- ]chain|malicious (npm|pypi|packages?|extensions?|updates?)/i], ['T1078', 'Valid Accounts', /stolen credentials|valid accounts|compromised credentials|leaked credentials|credential stuffing/i], ['T1133', 'External Remote Services', /\bVPN\b|remote desktop|\bRDP\b|Citrix|remote access (service|gateway)/i], ['T1189', 'Drive-by Compromise', /drive-by|watering[- ]hole|malvertising|fake (browser )?updates?/i], ['T1199', 'Trusted Relationship', /third[- ]party (vendor|provider|supplier)|managed service provider|\bMSPs?\b/i]]],
  ['Execution', [['T1059', 'Command & Scripting Interpreter', /PowerShell|command[- ]line|\bbash\b|VBScript|JavaScript payload|cmd\.exe|python script/i], ['T1204', 'User Execution', /ClickFix|fake CAPTCHA|tricked into (running|opening|executing)|malicious (attachment|document|LNK|shortcut)/i], ['T1203', 'Exploitation for Client Execution', /browser (zero-day|exploit)|Chrome zero-day|memory corruption|type confusion/i], ['T1053', 'Scheduled Task/Job', /scheduled tasks?|cron ?jobs?/i], ['T1047', 'WMI', /\bWMI\b|Windows Management Instrumentation/i]]],
  ['Persistence', [['T1505.003', 'Web Shell', /web ?shells?/i], ['T1547', 'Boot/Logon Autostart', /run keys?|autostart|startup folder|persistence mechanism/i], ['T1136', 'Create Account', /creat(ed|ing|es) (new |rogue |backdoor |admin(istrator)? )+accounts?/i], ['T1098', 'Account Manipulation', /OAuth (apps?|tokens?|consent)|added (to|as) (an? )?(admin|global administrator)/i], ['T1542', 'Pre-OS Boot', /bootkit|\bUEFI\b|firmware implant/i], ['T1543', 'Create/Modify System Process', /malicious service|systemd service|launch ?(daemon|agent)/i]]],
  ['Privilege Escalation', [['T1068', 'Exploitation for Privilege Escalation', /privilege escalation|elevat(e|ion) (of )?privileges?|escalate privileges|gain (root|SYSTEM)/i], ['T1548', 'Abuse Elevation Control', /UAC bypass|\bsudo\b/i], ['T1134', 'Access Token Manipulation', /token (theft|manipulation|impersonation)/i], ['T1611', 'Escape to Host', /container escape|(VM|sandbox) escape/i]]],
  ['Defense Evasion', [['T1562', 'Impair Defenses', /disabl(e|ed|es|ing) (security|antivirus|\bAV\b|EDR|Defender)|EDR killer|\bBYOVD\b|vulnerable driver/i], ['T1027', 'Obfuscated Files or Info', /obfuscat|steganograph|encrypted payload/i], ['T1070', 'Indicator Removal', /(delet|clear|wip)(e|ed|es|ing) (event )?logs|anti-forensic/i], ['T1574', 'Hijack Execution Flow', /DLL side-?loading|DLL hijack|search[- ]order hijack/i], ['T1218', 'System Binary Proxy Execution', /\bLOLBins?\b|living[- ]off[- ]the[- ]land|rundll32|mshta|regsvr32|msiexec/i], ['T1036', 'Masquerading', /masquerad|disguised as|posing as (legitimate|a legitimate)|fake (installer|app|software)/i], ['T1553', 'Subvert Trust Controls', /signed (malware|driver)|stolen (code[- ]signing )?certificates?|code[- ]signing certificate/i]]],
  ['Credential Access', [['T1003', 'OS Credential Dumping', /credential dump|LSASS|Mimikatz|\bNTDS\b|SAM database/i], ['T1110', 'Brute Force', /brute[- ]forc|password[- ]spray|credential stuffing/i], ['T1555', 'Credentials from Password Stores', /(browser|saved) (passwords|credentials)|password managers?|keychain/i], ['T1539', 'Steal Web Session Cookie', /session (cookies?|tokens?)|cookie theft|session hijack/i], ['T1111', 'MFA Interception / Bypass', /MFA (bypass|fatigue|interception)|adversary-in-the-middle|\bAiTM\b|one-time (passcode|password)/i], ['T1056', 'Input Capture', /keylog/i], ['T1558', 'Steal/Forge Kerberos Tickets', /Kerberoast|golden ticket|AS-REP/i], ['T1552', 'Unsecured Credentials', /hard-?coded (credentials|keys|passwords)|exposed (API )?keys|secrets? (leaked|exposed)/i]]],
  ['Discovery', [['T1046', 'Network Service Discovery', /port scan|network scan|service discovery/i], ['T1087', 'Account Discovery', /enumerat(e|ed|es|ing) (users|accounts)|BloodHound|AdFind|Active Directory (recon|enumeration)/i], ['T1082', 'System Information Discovery', /system information|fingerprint(s|ed|ing)? (the )?(host|system|device)/i], ['T1018', 'Remote System Discovery', /remote system discovery|network mapping|map(ped)? the network/i]]],
  ['Lateral Movement', [['T1021', 'Remote Services', /lateral(ly)? mov|\bPsExec\b|\bWinRM\b|\bSMB\b|\bSSH\b/i], ['T1210', 'Exploitation of Remote Services', /wormable|EternalBlue|self-propagat/i], ['T1550', 'Use Alternate Auth Material', /pass-the-(hash|ticket)|stolen (session )?tokens? to (access|move)/i], ['T1570', 'Lateral Tool Transfer', /lateral tool transfer|copied (tools|payloads) (to|across)/i]]],
  ['Collection', [['T1005', 'Data from Local System', /(stole|steal|stealing|steals) (sensitive )?(files|data|documents|information)/i], ['T1114', 'Email Collection', /mailbox(es)?|email (accounts|inboxes)|Exchange (server|Online)/i], ['T1530', 'Data from Cloud Storage', /cloud storage|S3 buckets?|SharePoint|OneDrive|Snowflake|Salesforce/i], ['T1560', 'Archive Collected Data', /WinRAR|7-?Zip|archiv(ed|ing) (the )?(data|files)/i], ['T1113', 'Screen Capture', /screenshots?|screen capture/i]]],
  ['Command and Control', [['T1071', 'Application Layer Protocol', /\bC2\b|command[- ]and[- ]control|beacon(s|ing)?\b|Cobalt Strike|Sliver/i], ['T1219', 'Remote Access Software', /\bRMM\b|remote (monitoring|access) (software|tools?)|AnyDesk|ScreenConnect|TeamViewer|NetSupport|SimpleHelp/i], ['T1105', 'Ingress Tool Transfer', /dropper|loader|download(s|ed|ing)? (additional|second-stage|next-stage|further) (payloads?|malware)/i], ['T1572', 'Protocol Tunneling', /tunnel(ing|led)?\b|ngrok|DNS tunnel/i], ['T1090', 'Proxy', /residential prox|proxy (network|botnet)|operational relay box|\bORB\b/i], ['T1102', 'Web Service', /(Telegram|Discord|Google Drive|Dropbox|GitHub|Slack) (as|for) (a )?(C2|command)/i], ['T1568', 'Dynamic Resolution', /\bDGA\b|domain generation|fast[- ]flux/i]]],
  ['Exfiltration', [['T1041', 'Exfiltration Over C2 Channel', /exfiltrat/i], ['T1567', 'Exfiltration to Web Service', /rclone|\bMEGA\b|exfiltrat\w* (to|via) (cloud|Dropbox|Google Drive|Telegram)/i], ['T1048', 'Exfil Over Alternative Protocol', /exfiltrat\w* (over|via) (DNS|FTP|SFTP)/i]]],
  ['Impact', [['T1486', 'Data Encrypted for Impact', /ransomware|encrypt(ed|s|ing) (files|data|systems|servers)/i], ['T1657', 'Financial Theft', /extort|ransom demand|business email compromise|\bBEC\b|crypto(currency)? (theft|heist)|drain(ed|ing)? wallets|stole \$/i], ['T1498', 'Network Denial of Service', /\bDDoS\b|denial[- ]of[- ]service/i], ['T1485', 'Data Destruction', /wiper|data destruction|destroy(ed|s)? data/i], ['T1490', 'Inhibit System Recovery', /shadow cop(y|ies)|vssadmin|backups? (were )?(deleted|destroyed)/i], ['T1496', 'Resource Hijacking', /cryptojack|coin ?miner|crypto(currency)? min(er|ing)|XMRig/i], ['T1491', 'Defacement', /defac/i], ['T1489', 'Service Stop / Disruption', /disrupt(ed|ion of) (operations|services)|took (systems|services) offline|outage caused by/i]]],
];

function attackCounts() {
  const C = {}, ex = {};
  const hit = (id, title) => { C[id] = (C[id] || 0) + 1; if (title && (ex[id] = ex[id] || []).length < 3 && !ex[id].includes(title)) ex[id].push(title); };
  let docs = 0;
  for (const n of D.news?.items || []) {
    if (isKevNotice(n)) continue;
    const t = newsText(n);
    docs++;
    const ids = new Set((t.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || []));
    for (const [, techs] of TACTICS) for (const [id, , rx] of techs) if (rx.test(t) || ids.has(id)) hit(id, n.title);
  }
  // CISA KEV descriptions say how each exploited bug is used
  let kevN = 0;
  for (const k of (D.kev?.items || []).filter(k => Date.now() - Date.parse(k.added) < 30 * 864e5)) {
    kevN++;
    const d = k.desc || '';
    if (/privilege escalation|elevat|escalate privileges/i.test(d)) hit('T1068', `${k.cve} (KEV)`);
    else if (/remote|unauthenticated|network/i.test(d)) hit('T1190', `${k.cve} (KEV)`);
    if (/browser|chrom|webkit|memory corruption|type confusion/i.test(d)) hit('T1203', `${k.cve} (KEV)`);
    if (/hard-?coded/i.test(d)) hit('T1552', `${k.cve} (KEV)`);
  }
  return { C, ex, docs, kevN };
}

/* ----------------------------------------------------- vulnerability board */
function vulnBoard() {
  const M = new Map();
  const get = id => { if (!M.has(id)) M.set(id, { id, chatter: 0, titles: [] }); return M.get(id); };
  const recentKev = (D.kev?.items || []).filter(k => Date.now() - Date.parse(k.added) < 45 * 864e5);
  for (const k of recentKev) Object.assign(get(k.cve), { kev: k.added, kevRansom: k.ransomware, vendor: k.vendor, product: k.product, name: k.name });
  for (const c of D.cves?.items || []) if (c.score >= 9 || M.has(c.id)) Object.assign(get(c.id), { cvss: c.score, sev: c.severity, desc: c.desc, published: c.published });
  for (const n of D.news?.items || []) for (const c of n.cves || []) { const v = get(c); v.chatter++; if (v.titles.length < 3) v.titles.push(n.title); }
  const ep = Object.fromEntries((D.epss?.items || []).map(e => [e.cve, e]));
  const kevAll = Object.fromEntries((D.kev?.items || []).map(k => [k.cve, k]));
  const cveAll = Object.fromEntries((D.cves?.items || []).map(c => [c.id, c]));
  for (const v of M.values()) {
    const e = ep[v.id];
    if (e) Object.assign(v, { epss: e.epss, pct: e.percentile, series: e.series });
    const k = kevAll[v.id]; if (k && !v.kev) Object.assign(v, { kev: k.added, kevRansom: k.ransomware, vendor: k.vendor, product: k.product, name: k.name });
    const c = cveAll[v.id]; if (c && v.cvss == null) Object.assign(v, { cvss: c.score, sev: c.severity, desc: c.desc });
    v.score = 100 * (0.4 * (v.epss || 0) + 0.15 * (v.pct || 0) + 0.2 * (v.kev ? 1 : 0) + 0.05 * (v.kevRansom ? 1 : 0) + 0.12 * Math.min(v.chatter, 3) / 3 + 0.08 * (v.cvss || 0) / 10);
  }
  return [...M.values()].sort((a, b) => b.score - a.score);
}

/* ------------------------------------------------------- threat timeline */
function tlEvents(from) {
  const lanes = [
    { k: 'cve', name: 'CVEs', color: 'var(--high)', ev: [] },
    { k: 'kev', name: 'KEV additions', color: 'var(--crit)', ev: [] },
    { k: 'ransom', name: 'Ransomware victims', color: 'var(--ransom)', ev: [] },
    { k: 'adv', name: 'Advisories', color: 'var(--acc)', ev: [] },
  ];
  const sevC = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)' };
  for (const c of D.cves?.items || []) {
    const t = Date.parse(c.published); if (!(t >= from)) continue;
    lanes[0].ev.push({ t, r: c.score ? 1.4 + c.score / 10 * 2.6 : 1.4, c: sevC[c.severity] || 'var(--mute)', tip: `${c.id} · ${c.score != null ? 'CVSS ' + c.score : 'unscored'}\n${fmtTime(c.published)}\n${(c.desc || '').slice(0, 140)}`, open: nvd(c.id), w: 1 });
  }
  for (const k of D.kev?.items || []) {
    const t = Date.parse(k.added + 'T00:00:00Z'); if (!(t >= from - 864e5)) continue;
    lanes[1].ev.push({ t: Math.max(t, from), r: 4.5, c: k.ransomware ? 'var(--ransom)' : 'var(--crit)', shape: 'd', tip: `${k.cve} added to KEV · ${k.added}\n${k.vendor} ${k.product}\n${k.name}${k.ransomware ? '\nknown ransomware use' : ''}`, open: nvd(k.cve), w: 1 });
  }
  for (const v of D.ransomware?.items || []) {
    const t = Date.parse(v.discovered); if (!(t >= from)) continue;
    lanes[2].ev.push({ t, r: 3.2, c: 'var(--ransom)', tip: `${v.group} claims ${v.victim}\n${[v.sector, COUNTRY_NAME[v.cc] || v.cc].filter(Boolean).join(' · ')}\n${fmtTime(v.discovered)}`, open: v.url, w: 1 });
  }
  for (const n of D.news?.items || []) {
    if (n.source !== 'CISA Advisories' && !/\badvisory\b|security bulletin|patch tuesday/i.test(n.title)) continue;
    const t = Date.parse(n.published); if (!(t >= from)) continue;
    lanes[3].ev.push({ t, r: 3.6, c: n.source === 'CISA Advisories' ? 'var(--acc)' : 'var(--dim)', shape: 's', tip: `${n.source}\n${n.title}\n${fmtTime(n.published)}`, open: safeUrl(n.link), w: 1 });
  }
  return lanes;
}
let tlTimer;

window.EXTRA_PANELS.push(
  {
    id: 'tline', title: 'Threat Timeline', deps: ['cves', 'kev', 'ransomware', 'news'], live: true,
    badge: () => `last ${ps('tline').win || 72}h`,
    src: () => 'NVD · CISA KEV · ransomware.live · CISA and vendor advisories',
    render() {
      clearTimeout(tlTimer); tlTimer = setTimeout(() => renderPanel('tline'), 60000); // keep it scrolling
      const win = +(ps('tline').win || 72), now = Date.now(), from = now - win * 3600e3;
      const lanes = tlEvents(from);
      const W = 1300, LX = 130, LH = 44, TOP = 40, H = TOP + lanes.length * LH + 22;
      const x = t => LX + (t - from) / (now - from) * (W - LX - 12);
      const nb = Math.min(win, 72), bw = (now - from) / nb;
      // hourly bins -> spikes (>= mean + 2 sd and at least 3 events)
      const spikes = [];
      const totals = new Array(nb).fill(0);
      lanes.forEach((L, li) => {
        const bins = new Array(nb).fill(0);
        for (const e of L.ev) { const b = Math.min(nb - 1, Math.floor((e.t - from) / bw)); if (b >= 0) { bins[b]++; totals[b]++; } }
        const mean = bins.reduce((a, b) => a + b, 0) / nb, sd = Math.sqrt(bins.reduce((a, b) => a + (b - mean) ** 2, 0) / nb);
        bins.forEach((c, b) => { if (c >= Math.max(3, mean + 2 * sd)) spikes.push({ li, b, c, x: k => x(from + k * bw), mean }); });
        L.count = L.ev.length;
      });
      const tmax = Math.max(...totals, 1);
      const dens = totals.map((v, i) => `${i ? 'L' : 'M'}${x(from + (i + 0.5) * bw).toFixed(1)},${(TOP - 6 - v / tmax * 26).toFixed(1)}`).join('');
      const grid = [];
      for (let h = 0; h <= win; h += win > 24 ? 12 : 6) {
        const gx = x(now - h * 3600e3);
        grid.push(`<line x1="${gx}" x2="${gx}" y1="${TOP - 4}" y2="${H - 18}" stroke="var(--line)" ${h % 24 ? 'stroke-dasharray="2 4"' : ''}/><text class="tl-ax" x="${gx}" y="${H - 5}">${h ? '-' + h + 'h' : 'now'}</text>`);
      }
      const lanesSvg = lanes.map((L, li) => {
        const y0 = TOP + li * LH, cy = y0 + LH / 2;
        const sp = spikes.filter(s => s.li === li).map(s => `<rect class="tl-spike" x="${s.x(s.b).toFixed(1)}" y="${y0 + 3}" width="${(x(from + bw) - x(from)).toFixed(1)}" height="${LH - 6}" rx="3" fill="${L.color}" ${tip(`Spike: ${s.c} ${L.name.toLowerCase()} in one hour\n(${s.mean.toFixed(1)}/h average in this window)`)}/>`).join('');
        const dots = L.ev.map(e => {
          const ex = x(e.t), ey = cy + (hashN(e.tip) - 0.5) * (LH - 18);
          const attrs = `${tip(e.tip)} ${e.open ? `data-open="${esc(e.open)}"` : ''} class="tl-dot"`;
          if (e.shape === 'd') return `<path d="M${ex},${ey - e.r}L${ex + e.r},${ey}L${ex},${ey + e.r}L${ex - e.r},${ey}Z" fill="${e.c}" ${attrs}/>`;
          if (e.shape === 's') return `<rect x="${ex - e.r}" y="${ey - e.r}" width="${e.r * 2}" height="${e.r * 2}" rx="1" fill="${e.c}" ${attrs}/>`;
          return `<circle cx="${ex.toFixed(1)}" cy="${ey.toFixed(1)}" r="${e.r.toFixed(1)}" fill="${e.c}" fill-opacity=".8" ${attrs}/>`;
        }).join('');
        return `<g><rect x="0" y="${y0}" width="${W}" height="${LH}" fill="${li % 2 ? 'transparent' : 'rgba(255,255,255,.015)'}"/>
          <text class="tl-lane" x="4" y="${cy - 2}">${esc(L.name)}</text><text class="tl-cnt" x="4" y="${cy + 11}" fill="${L.color}">${L.count}</text>${sp}${dots}</g>`;
      }).join('');
      const spikeTxt = spikes.sort((a, b) => b.c - a.c).slice(0, 4).map(s => `<span class="tag ${lanes[s.li].k === 'ransom' || lanes[s.li].k === 'kev' ? 'red' : 'org'}">${esc(lanes[s.li].name)} · ${s.c} at ${new Date(from + s.b * bw).toISOString().slice(5, 13).replace('T', ' ')}h</span>`).join('');
      return chips('tline', 'win', [['24', '24h'], ['48', '48h'], ['72', '72h']], String(win)) +
        `<svg class="tline" viewBox="0 0 ${W} ${H}">
          <path d="${dens}L${x(now)},${TOP - 6}L${LX},${TOP - 6}Z" fill="rgba(var(--acc-rgb),.14)"/><path d="${dens}" fill="none" stroke="var(--acc)" stroke-width="1.2" opacity=".8"/>
          <text class="tl-ax" x="4" y="${TOP - 12}" style="text-anchor:start">activity / hour</text>
          ${grid.join('')}${lanesSvg}
          <line class="tl-now" x1="${x(now)}" x2="${x(now)}" y1="${TOP - 34}" y2="${H - 18}"/>
        </svg>
        <div class="legend">${spikeTxt ? 'Spikes: ' + spikeTxt : '<span>No spikes: activity is steady across this window</span>'}</div>
        <div class="disclaim">Dots are real events. CVE size and colour follow CVSS; ◆ marks KEV additions (CISA dates only, so they sit at midnight UTC); ■ marks advisories. Click any mark to open its source. Shaded blocks are hours at least 2 standard deviations above the lane's average.</div>`;
    },
  },
  {
    id: 'vulnboard', title: 'Vulnerability Pressure Board', deps: ['epss', 'kev', 'cves', 'news'],
    badge: () => D.epss?.items ? `${D.epss.items.length} EPSS scored` : '',
    src: () => 'FIRST.org EPSS · CISA KEV · NVD · security news mentions',
    render() {
      const list = vulnBoard().slice(0, 12);
      if (!list.length) return noData('waiting for vulnerability feeds');
      const noEpss = !D.epss || META.epss?.error;
      const tiles = list.map((v, i) => {
        const lvl = v.score >= 55 ? 'crit' : v.score >= 35 ? 'high' : v.score >= 20 ? 'med' : 'low';
        const ser = v.series && v.series.length > 1 ? (() => { const m = Math.max(...v.series, 0.01); return `<svg class="vb-spark" viewBox="0 0 100 24" preserveAspectRatio="none"><path d="${pathFor(v.series, 100, 24, m, 2)}" fill="none" stroke="var(--${lvl})" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`; })() : '';
        const what = v.vendor ? `${v.vendor} ${v.product}` : (v.desc || v.titles[0] || '').slice(0, 90);
        return `<div class="vb-tile vb-${lvl} click" style="animation-delay:${i * 40}ms" data-open="${esc(nvd(v.id))}" ${tip(`${v.id}\n${v.name || v.desc || ''}`.slice(0, 260) + (v.titles.length ? `\n\nIn the news:\n• ${v.titles.join('\n• ')}` : ''))}>
          <div class="vb-h"><span class="vb-rank">#${i + 1}</span><span class="vb-id">${esc(v.id)}</span><span class="vb-sc">${Math.round(v.score)}</span></div>
          <div class="vb-what">${esc(what)}</div>
          <div class="vb-big"><b>${v.epss != null ? (v.epss * 100).toFixed(v.epss < 0.1 ? 1 : 0) + '%' : '—'}</b><span>EPSS${v.pct != null ? ` · ${Math.round(v.pct * 100)}th pct` : ''}</span></div>
          ${ser}
          <div class="vb-tags">${v.kev ? `<span class="tag red">KEV ${esc(v.kev.slice(5))}</span>` : ''}${v.kevRansom ? '<span class="tag red">ransomware</span>' : ''}${v.cvss != null ? `<span class="tag ${v.cvss >= 9 ? 'red' : 'org'}">CVSS ${v.cvss}</span>` : ''}${v.chatter ? `<span class="tag ylw">${v.chatter} report${v.chatter > 1 ? 's' : ''}</span>` : ''}</div>
          <div class="vb-bar"><span style="width:${Math.min(100, v.score)}%"></span></div>
        </div>`;
      }).join('');
      return `${noEpss ? `<div class="keynote">EPSS scores unavailable${META.epss?.error ? ': ' + esc(META.epss.error) : ''}. Ranking uses KEV, CVSS and news chatter until FIRST.org responds.</div>` : ''}<div class="vb-grid">${tiles}</div>
        <div class="disclaim">Pressure = 40% EPSS probability + 15% EPSS percentile + 20% in CISA KEV + 5% known ransomware use + 12% news chatter (3+ reports = max) + 8% CVSS. EPSS estimates the chance of exploitation in the next 30 days; the sparkline is its 30-day history.</div>`;
    },
  },
  {
    id: 'actorgraph', title: 'Actor & Campaign Graph', deps: ['news', 'ransomware', 'kev', 'c2'],
    badge: () => { const g = graphModel(); return `${g.N.length} nodes`; },
    src: () => 'security news co-mentions + ransomware.live victim sectors',
    render() {
      const { N, E } = graphModel();
      if (N.length < 3) return noData('not enough linked actors in the current news yet');
      const W = 1300, H = Math.max(300, 24 * Math.max(...Object.keys(AG_COL).map(t => N.filter(n => n.type === t).length)) + 40), P = layoutGraph(N, E, W, H);
      const idx = new Map(N.map((n, i) => [n.id, i])), wmax = Math.max(...N.map(n => n.w), 1);
      const edges = E.map(e => { const a = P[idx.get(e.a)], b = P[idx.get(e.b)], mx = (a.x + b.x) / 2; return `<path class="ag-e" data-a="${esc(e.a)}" data-b="${esc(e.b)}" d="M${a.x.toFixed(1)},${a.y.toFixed(1)}C${mx.toFixed(1)},${a.y.toFixed(1)} ${mx.toFixed(1)},${b.y.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}" stroke-width="${(0.6 + Math.min(e.w, 8) * 0.35).toFixed(2)}" ${tip([...e.why].join('\n'))}/>`; }).join('');
      const nodes = N.map((n, i) => {
        const p = P[i], r = 3.5 + Math.sqrt(n.w / wmax) * 9, c = AG_COLOR[n.type];
        const right = n.type === 'sector';
        const label = n.name.length > 26 ? n.name.slice(0, 25) + '…' : n.name;
        const open = n.type === 'cve' ? `data-open="${esc(nvd(n.name))}"` : '';
        const t = `${{ actor: n.ransom ? 'Ransomware group' : 'Threat actor', malware: 'Malware / tool', cve: 'Vulnerability', sector: 'Targeted sector' }[n.type]} · ${n.name}${n.kev ? ' (KEV)' : ''}\nlinks: ${Math.round(n.w)}${n.refs.length ? '\n• ' + n.refs.slice(0, 3).join('\n• ') : ''}`;
        return `<g class="ag-n" data-id="${esc(n.id)}" ${open} ${tip(t)}><circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r.toFixed(1)}" fill="${c}" fill-opacity=".85" stroke="${n.kev ? 'var(--crit)' : 'rgba(0,0,0,.6)'}" stroke-width="${n.kev ? 2 : 1}"/>
          <text x="${(p.x + (right ? -r - 5 : r + 5)).toFixed(1)}" y="${(p.y + 3.5).toFixed(1)}" text-anchor="${right ? 'end' : 'start'}">${esc(label)}</text></g>`;
      }).join('');
      const heads = Object.entries({ actor: 'Actors & groups', malware: 'Malware & tools', cve: 'CVEs', sector: 'Sectors' }).map(([k, l]) => `<text class="ag-h" x="${AG_COL[k] * W}" y="12" fill="${AG_COLOR[k]}">${l}</text>`).join('');
      return `<svg class="agraph" viewBox="0 0 ${W} ${H + 10}"><g transform="translate(0,10)">${heads}${edges}${nodes}</g></svg>
        <div class="disclaim">Links come from the same report naming both ends (security news and CISA advisories), plus each of the 8 most active ransomware groups to the sectors of its posted victims. Names are found by keyword matching, so treat links as leads. Hover a node to isolate it; red-ringed CVEs are in CISA KEV.</div>`;
    },
  },
  {
    id: 'sectorheat', title: 'Sector Heatmap · who is being hit', deps: ['ransomware', 'news'],
    src: () => 'ransomware.live victim sectors + sector mentions in security news',
    render() {
      const M = Object.fromEntries(SECTORS.map(([s]) => [s, THREAT_TYPES.map(() => ({ n: 0, ex: [] }))]));
      for (const v of D.ransomware?.items || []) { const s = sectorOf(v.sector); if (s) { const c = M[s][0]; c.n++; if (c.ex.length < 3) c.ex.push(`${v.group} → ${v.victim}`); } }
      for (const n of D.news?.items || []) {
        if (isKevNotice(n)) continue;
        const t = newsText(n), secs = sectorsIn(t);
        if (!secs.length) continue;
        THREAT_TYPES.forEach(([, , rx], ti) => { if (ti === 0 ? /ransom/i.test(t) : rx.test(t)) for (const s of secs) { const c = M[s][ti]; c.n += ti === 0 ? 0.5 : 1; if (c.ex.length < 3) c.ex.push(n.title); } });
      }
      const colMax = THREAT_TYPES.map((_, ti) => Math.max(...SECTORS.map(([s]) => M[s][ti].n), 1));
      const rows = SECTORS.map(([s]) => ({ s, cells: M[s], tot: M[s].reduce((a, c, ti) => a + c.n / colMax[ti], 0) })).sort((a, b) => b.tot - a.tot);
      const hot = rows[0];
      const head = `<div class="sh-c sh-hd"></div>${THREAT_TYPES.map(([t, c]) => `<div class="sh-c sh-hd" style="--tc:${c}">${esc(t)}</div>`).join('')}`;
      const body = rows.map(r => `<div class="sh-c sh-row">${esc(r.s)}</div>${r.cells.map((c, ti) => {
        const f = c.n / colMax[ti];
        return `<div class="sh-c sh-cell" style="background:${c.n ? `color-mix(in srgb, ${THREAT_TYPES[ti][1]} ${Math.round(12 + f * 78)}%, transparent)` : 'var(--panel2)'}" ${tip(`${r.s} · ${THREAT_TYPES[ti][0]}\n${c.n % 1 ? c.n.toFixed(1) : c.n} ${ti === 0 ? 'victims / mentions' : 'reports'}${c.ex.length ? '\n• ' + c.ex.join('\n• ') : ''}`)}>${c.n ? Math.round(c.n) || '·' : ''}</div>`;
      }).join('')}`).join('');
      return `${hot && hot.tot > 0 ? `<div class="sh-hot">Hardest hit right now: <b>${esc(hot.s)}</b></div>` : ''}<div class="sheat" style="grid-template-columns:minmax(120px,1.4fr) repeat(${THREAT_TYPES.length},1fr)">${head}${body}</div>
        <div class="disclaim">Ransomware column = sectors of posted victims (ransomware.live; news mentions add half a point). Other columns count news and advisory reports that name both a sector and that threat type. Colour is relative within each column, so columns of different size stay comparable.</div>`;
    },
  },
  {
    id: 'attackmx', title: 'ATT&CK Matrix · techniques in recent reports', deps: ['news', 'kev'],
    badge: () => { const { C } = attackCounts(); return `${Object.keys(C).length} techniques seen`; },
    src: () => 'MITRE ATT&CK Enterprise · matched in security news, CISA advisories and KEV',
    render() {
      const { C, ex, docs, kevN } = attackCounts();
      const max = Math.max(...Object.values(C), 1);
      const recent = mxRecent(), prev = mxPrev.C;
      mxPrev.C = C;
      const cols = TACTICS.map(([tac, techs], ti) => {
        const tot = techs.reduce((a, [id]) => a + (C[id] || 0), 0);
        const cells = techs.slice().sort((a, b) => (C[b[0]] || 0) - (C[a[0]] || 0)).map(([id, name]) => {
          const n = C[id] || 0, f = Math.sqrt(n / max);
          const cls = [n ? 'on' : '', recent[id] ? 'recent' : '', prev && n > (prev[id] || 0) ? 'bump' : ''].join(' ');
          return `<div class="mx-cell ${cls}" data-tid="${esc(id)}" style="${n ? `background:${rgbaAcc(0.1 + f * 0.75)};color:${f > 0.55 ? 'var(--acc-ink)' : 'var(--text)'}` : ''}" data-open="https://attack.mitre.org/techniques/${id.replace('.', '/')}/" ${tip(`${id} · ${name}\n${n} report${n === 1 ? '' : 's'}${recent[id] ? `, ${recent[id]} in the last 48 hours` : ''}${ex[id] ? '\n• ' + ex[id].join('\n• ') : ''}`)}><span>${esc(name)}</span><em>${n || ''}</em></div>`;
        }).join('');
        return `<div class="mx-col" data-tac="${ti}"><div class="mx-h ${tot ? 'on' : ''}"><span>${esc(tac)}</span><em>${tot}</em></div>${cells}</div>`;
      }).join('');
      return `<div class="mx-spot" aria-live="off">${mxSpotHTML()}</div><div class="mx-wrap"><div class="mx">${cols}</div></div>
        <div class="disclaim">Scanned ${docs} news and advisory reports plus ${kevN} KEV entries from the last 30 days. Techniques are matched from keywords and explicit ATT&CK IDs, so this shows emphasis, not confirmed attribution. A dot marks techniques reported in the last 48 hours; the spotlight steps through the most-reported techniques. Click a cell to open it on attack.mitre.org.</div>`;
    },
  },
);

// Actor graph: hover a node to isolate its links
document.addEventListener('mouseover', e => {
  const n = e.target.closest && e.target.closest('.ag-n');
  const svg = e.target.closest && e.target.closest('.agraph');
  if (!svg) { document.querySelectorAll('.agraph.focus').forEach(g => g.classList.remove('focus')); return; }
  svg.querySelectorAll('.hl').forEach(x => x.classList.remove('hl'));
  svg.classList.toggle('focus', !!n);
  if (!n) return;
  const id = n.dataset.id;
  n.classList.add('hl');
  svg.querySelectorAll('.ag-e').forEach(el => {
    if (el.dataset.a !== id && el.dataset.b !== id) return;
    el.classList.add('hl');
    const other = el.dataset.a === id ? el.dataset.b : el.dataset.a;
    svg.querySelector(`.ag-n[data-id="${CSS.escape(other)}"]`)?.classList.add('hl');
  });
});

/* ======================================================================= cloud & SaaS status
 * Public status pages of the big cloud, identity and SaaS providers (backend feed "cloudstatus").
 * An outage here also raises the red banner on every screen (renderOutageAlert in app.js).
 */
const CS_LABEL = { ok: 'Operational', minor: 'Degraded', major: 'Outage', unknown: 'No data' };
const CS_TAG = { major: 'red', minor: 'ylw', info: '' };
window.EXTRA_PANELS.push({
  id: 'saas', title: 'Cloud & SaaS Outages', feed: 'cloudstatus', deps: ['cloudstatus'],
  badge: () => { const d = D.cloudstatus; return d.major ? `${d.major} outage${d.major > 1 ? 's' : ''}` : d.minor ? `${d.minor} degraded` : 'all operational'; },
  render() {
    const d = D.cloudstatus;
    const svcs = d.services || [];
    const sum = d.major ? `<b>${d.major}</b> provider${d.major > 1 ? 's' : ''} reporting an outage` : d.minor ? `<b>${d.minor}</b> provider${d.minor > 1 ? 's' : ''} degraded, no outages` : 'All monitored providers operational';
    const tiles = svcs.map(s => {
      const n = s.incidents.filter(i => i.level !== 'info').length;
      return `<div class="cs-tile ${s.state}" data-open="${esc(safeUrl(s.page) || '')}" ${tip(`${s.name} · ${CS_LABEL[s.state]}${s.error ? '\nCould not read the status page: ' + s.error : ''}${s.incidents.length ? '\n• ' + s.incidents.slice(0, 4).map(i => i.title).join('\n• ') : ''}`)}><i></i><b>${esc(s.name)}</b><span>${CS_LABEL[s.state]}${n > 1 ? ` · ${n}` : ''}</span></div>`;
    }).join('');
    const inc = svcs.flatMap(s => s.incidents.map(i => Object.assign({ svc: s.name }, i)))
      .sort((a, b) => ({ major: 0, minor: 1 }[a.level] ?? 2) - ({ major: 0, minor: 1 }[b.level] ?? 2) || String(b.updated || '').localeCompare(String(a.updated || '')));
    const rows = inc.slice(0, 30).map(i => `<div class="r click" data-open="${esc(safeUrl(i.url) || '')}"><span class="dotS" style="background:${i.level === 'major' ? 'var(--crit)' : i.level === 'minor' ? 'var(--med)' : 'var(--mute)'}"></span><div><div class="t"><span class="tag ${CS_TAG[i.level]}">${esc(i.svc)}</span>${esc(i.title)}</div>${i.detail ? `<div class="s">${esc(i.detail.slice(0, 220))}</div>` : ''}<div>${i.level === 'major' ? '<span class="tag red">outage</span>' : i.level === 'minor' ? '<span class="tag ylw">degraded</span>' : '<span class="tag">notice</span>'}${i.longRunning ? '<span class="tag">long-running</span>' : ''}${(i.components || []).slice(0, 4).map(c => `<span class="tag">${esc(c)}</span>`).join('')}</div></div><span class="m">${i.started ? ago(i.started) : ''}</span></div>`).join('');
    return `<div class="cs-sum ${d.major ? 'major' : d.minor ? 'minor' : 'ok'}"><span class="cs-led"></span>${sum}<button class="cs-test" data-outage-test title="Show the outage banner for 30 seconds">Test alert</button></div>
      <div class="cs-grid">${tiles}</div>
      <div class="rows">${rows || '<div class="loading">No open incidents on any monitored status page</div>'}</div>
      <div class="disclaim">Read from each provider's public status page every 2 minutes${d.unknown ? `; ${d.unknown} could not be reached just now` : ''}. A new outage (started in the last 72 hours) shows a red banner on every screen for 30 seconds, then the banner clears itself and the outage stays listed here. Older long-running events are listed here only. Click a tile or incident to open the provider's page.</div>`;
  },
});

/* ======================================================================= MITRE ATT&CK screen
 * Everything here is built from the same keyword / explicit-ID technique matching as the ATT&CK matrix,
 * over security news, CISA advisories and CISA KEV. It shows emphasis in public reporting, not confirmed attribution.
 */
const TECH = {};
TACTICS.forEach(([tac, techs], ti) => techs.forEach(([id, name, rx]) => { TECH[id] = { id, name, rx, tac, ti }; }));
const mitreUrl = id => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
const techChip = (id, extra = '') => `<span class="tag mt-chip" data-open="${mitreUrl(id)}" ${tip(`${id} · ${TECH[id]?.name || ''}\n${TECH[id]?.tac || ''}`)}>${esc(id)}${extra}</span>`;
function kevTechs(k) {
  const d = k.desc || '', out = [];
  if (/privilege escalation|elevat|escalate privileges/i.test(d)) out.push('T1068');
  else if (/remote|unauthenticated|network/i.test(d)) out.push('T1190');
  if (/browser|chrom|webkit|memory corruption|type confusion/i.test(d)) out.push('T1203');
  if (/hard-?coded/i.test(d)) out.push('T1552');
  if (/\bVPN\b|remote access|gateway|Citrix|FortiOS|Pulse|Ivanti Connect/i.test(d + ' ' + k.product)) out.push('T1133');
  if (/authentication bypass|missing authentication|improper authentication/i.test(d)) out.push('T1078');
  return [...new Set(out)];
}
// One pass over the reports: which techniques each one mentions, keyed by day
function mitreModel() {
  if (mitreModel.c && mitreModel.c.n === D.news && mitreModel.c.k === D.kev) return mitreModel.c.m;
  const reports = [];
  for (const n of D.news?.items || []) {
    if (isKevNotice(n)) continue;
    const t = newsText(n);
    const ids = new Set(t.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || []);
    const techs = Object.values(TECH).filter(x => x.rx.test(t) || ids.has(x.id)).map(x => x.id);
    const actors = [...new Set((t.match(ACTOR_RX) || []).map(normActor))];
    reports.push({ n, techs, actors, day: (n.published || '').slice(0, 10) });
  }
  const kev = (D.kev?.items || []).filter(k => Date.now() - Date.parse(k.added) < 30 * 864e5).map(k => ({ k, techs: kevTechs(k) }));
  const count = {};
  for (const r of reports) for (const id of r.techs) count[id] = (count[id] || 0) + 1;
  for (const x of kev) for (const id of x.techs) count[id] = (count[id] || 0) + 1;
  const m = { reports, kev, count };
  mitreModel.c = { n: D.news, k: D.kev, m };
  return m;
}
const lastDays = n => Array.from({ length: n }, (_, i) => new Date(Date.now() - (n - 1 - i) * 864e5).toISOString().slice(0, 10));

window.EXTRA_PANELS.push(
  {
    id: 'mtactics', title: 'ATT&CK Kill Chain · tactic activity', deps: ['news', 'kev'],
    badge: () => { const { count } = mitreModel(); return `${TACTICS.filter(([, t]) => t.some(([id]) => count[id])).length} of ${TACTICS.length} tactics active`; },
    src: () => 'MITRE ATT&CK Enterprise tactics · news, CISA advisories, KEV',
    render() {
      const { reports, kev, count } = mitreModel();
      const rows = TACTICS.map(([tac, techs], ti) => {
        const set = new Set(techs.map(([id]) => id));
        const n = reports.filter(r => r.techs.some(id => set.has(id))).length + kev.filter(x => x.techs.some(id => set.has(id))).length;
        const seen = techs.filter(([id]) => count[id]).length;
        const top = techs.slice().sort((a, b) => (count[b[0]] || 0) - (count[a[0]] || 0))[0];
        return { tac, ti, n, seen, tot: techs.length, top: count[top[0]] ? top : null };
      });
      const max = Math.max(...rows.map(r => r.n), 1);
      return `<div class="kc">${rows.map(r => `<div class="kc-row ${r.n === max && r.n ? 'hot' : ''}" style="--i:${r.ti}" ${tip(`${r.tac}\n${r.n} reports · ${r.seen}/${r.tot} tracked techniques seen${r.top ? `\nMost seen: ${r.top[0]} ${r.top[1]}` : ''}`)}>
          <span class="kc-i">${String(r.ti + 1).padStart(2, '0')}</span><span class="kc-n">${esc(r.tac)}</span>
          <span class="kc-trk"><span style="width:${(r.n / max * 100).toFixed(1)}%"></span></span><span class="kc-v">${r.n}</span>
          <span class="kc-top">${r.top ? techChip(r.top[0]) + `<em>${esc(r.top[1])}</em>` : '<em class="dim">—</em>'}</span></div>`).join('')}</div>
        <div class="disclaim">Reports mentioning at least one technique in each tactic, in kill-chain order. Read across to see where in the attack lifecycle current reporting is concentrated.</div>`;
    },
  },
  {
    id: 'mttop', title: 'Top Techniques · now trending', deps: ['news', 'kev'],
    badge: () => { const { count } = mitreModel(); return `${Object.keys(count).length} techniques`; },
    src: () => 'MITRE ATT&CK · matched in security news, CISA advisories and KEV',
    render() {
      const { reports, count } = mitreModel();
      const days = lastDays(14), recent = new Set(days.slice(7)), prior = new Set(days.slice(0, 7));
      const top = Object.entries(count).sort((a, b) => b[1] - a[1]).slice(0, 15);
      if (!top.length) return noData('no techniques matched yet');
      const max = top[0][1];
      return `<div class="mt-top">${top.map(([id, n], i) => {
        const now = reports.filter(r => recent.has(r.day) && r.techs.includes(id)).length;
        const was = reports.filter(r => prior.has(r.day) && r.techs.includes(id)).length;
        const series = days.map(d => reports.filter(r => r.day === d && r.techs.includes(id)).length);
        const sm = Math.max(...series, 1);
        const delta = now - was;
        return `<div class="mt-row" style="--i:${i}" data-open="${mitreUrl(id)}" ${tip(`${id} · ${TECH[id].name}\n${TECH[id].tac}\n${n} mentions · last 7 days ${now}, 7 days before ${was}`)}>
          <span class="mt-rank">${i + 1}</span>
          <div class="mt-name"><b>${esc(TECH[id].name)}</b><span>${esc(id)} · ${esc(TECH[id].tac)}</span></div>
          <svg class="mt-spark" viewBox="0 0 70 18" preserveAspectRatio="none"><path d="${pathFor(series, 70, 18, sm, 2)}"/></svg>
          <span class="mt-bar"><span style="width:${(n / max * 100).toFixed(1)}%"></span></span>
          <span class="mt-n">${n}</span>
          <span class="mt-d ${delta > 0 ? 'up' : delta < 0 ? 'down' : ''}">${delta > 0 ? '▲' + delta : delta < 0 ? '▼' + -delta : '·'}</span></div>`;
      }).join('')}</div>
        <div class="disclaim">Mentions across all loaded reports and recent KEV entries. Sparkline = daily mentions over 14 days; arrow = last 7 days against the 7 before.</div>`;
    },
  },
  {
    id: 'mttrend', title: 'Technique Activity · last 14 days', deps: ['news'],
    badge: () => `${mitreModel().reports.filter(r => r.techs.length).length} tagged reports`,
    src: () => 'MITRE ATT&CK · daily technique mentions in security news and advisories',
    render() {
      const { reports } = mitreModel();
      const days = lastDays(14);
      const c = {};
      for (const r of reports) if (days.includes(r.day)) for (const id of r.techs) c[id] = (c[id] || 0) + 1;
      const ids = Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 14).map(([id]) => id);
      if (!ids.length) return noData('no technique mentions in the last 14 days');
      const grid = ids.map(id => days.map(d => reports.filter(r => r.day === d && r.techs.includes(id))));
      const max = Math.max(...grid.flat().map(x => x.length), 1);
      const head = `<div class="tt-c"></div>${days.map(d => `<div class="tt-c tt-d">${esc(shortDate(d + 'T12:00:00Z'))}</div>`).join('')}`;
      const body = ids.map((id, ri) => `<div class="tt-c tt-l" data-open="${mitreUrl(id)}"><b>${esc(id)}</b> ${esc(TECH[id].name)}</div>${grid[ri].map((rs, di) => {
        const f = rs.length / max;
        return `<div class="tt-c tt-cell ${di === days.length - 1 ? 'today' : ''}" style="${rs.length ? `background:${rgbaAcc(0.12 + Math.sqrt(f) * 0.8)};color:${f > 0.5 ? 'var(--acc-ink)' : 'var(--text)'}` : ''}" ${tip(`${id} · ${TECH[id].name}\n${days[di]} · ${rs.length} report${rs.length === 1 ? '' : 's'}${rs.length ? '\n• ' + rs.slice(0, 3).map(r => r.n.title).join('\n• ') : ''}`)}>${rs.length || ''}</div>`;
      }).join('')}`).join('');
      return `<div class="tt-wrap"><div class="tt" style="grid-template-columns:minmax(190px,1.6fr) repeat(${days.length},minmax(34px,1fr))">${head}${body}</div></div>
        <div class="disclaim">The 14 most-mentioned techniques of the last two weeks, one column per day (UTC). Hover a cell for the reports behind it.</div>`;
    },
  },
  {
    id: 'mtactors', title: 'Threat Actors · techniques reported', deps: ['news'],
    badge: () => { const a = new Set(mitreModel().reports.filter(r => r.techs.length).flatMap(r => r.actors)); return `${a.size} actors`; },
    src: () => 'Actor names and ATT&CK techniques co-mentioned in the same report',
    render() {
      const { reports } = mitreModel();
      const A = new Map();
      for (const r of reports) {
        if (!r.actors.length || !r.techs.length) continue;
        for (const a of r.actors) {
          const x = A.get(a) || { a, n: 0, t: {}, ex: [] };
          x.n++; for (const id of r.techs) x.t[id] = (x.t[id] || 0) + 1;
          if (x.ex.length < 3) x.ex.push(r.n.title);
          A.set(a, x);
        }
      }
      const list = [...A.values()].sort((a, b) => b.n - a.n || Object.keys(b.t).length - Object.keys(a.t).length).slice(0, 16);
      if (!list.length) return noData('no reports name both an actor and a technique yet');
      return `<div class="rows">${list.map(x => {
        const ids = Object.entries(x.t).sort((a, b) => b[1] - a[1]);
        const tacs = new Set(ids.map(([id]) => TECH[id].ti));
        return `<div class="r" ${tip(x.ex.join('\n'))}><span class="dotS" style="background:var(--crit)"></span><div>
          <div class="t">${esc(x.a)} <span class="s">${x.n} report${x.n === 1 ? '' : 's'} · ${ids.length} technique${ids.length === 1 ? '' : 's'}</span></div>
          <div class="mt-tac">${TACTICS.map(([tac], i) => `<i class="${tacs.has(i) ? 'on' : ''}" title="${esc(tac)}"></i>`).join('')}</div>
          <div>${ids.slice(0, 8).map(([id]) => techChip(id)).join('')}</div></div><span class="m"></span></div>`;
      }).join('')}</div>
        <div class="disclaim">Strip = the 14 ATT&CK tactics in kill-chain order, lit where this actor's reports mention a technique. Co-mention in a report, not confirmed attribution.</div>`;
    },
  },
  {
    id: 'mtkev', title: 'Exploited Vulnerabilities → ATT&CK', deps: ['kev'],
    badge: () => `${mitreModel().kev.length} KEV · 30d`,
    src: () => 'CISA KEV (last 30 days) mapped to ATT&CK from each entry\'s description',
    render() {
      const { kev } = mitreModel();
      if (!kev.length) return noData('no KEV additions in the last 30 days');
      const by = {};
      for (const x of kev) for (const id of x.techs) by[id] = (by[id] || 0) + 1;
      const sum = Object.entries(by).sort((a, b) => b[1] - a[1]).map(([id, n]) => `<div class="mk-s" data-open="${mitreUrl(id)}"><b>${n}</b><span>${esc(id)}</span><em>${esc(TECH[id].name)}</em></div>`).join('');
      return `<div class="mk-sum">${sum}</div><div class="rows">${kev.slice(0, 40).map(({ k, techs }) => `<div class="r click" data-open="https://nvd.nist.gov/vuln/detail/${esc(k.cve)}" title="${esc(k.desc)}"><span class="dotS" style="background:${k.ransomware ? 'var(--ransom)' : 'var(--high)'}"></span><div><div class="t">${esc(k.cve)} <span class="s">${esc(k.vendor)} · ${esc(k.product)}</span></div><div>${techs.map(id => techChip(id, ' ' + esc(TECH[id].name))).join('') || '<span class="tag">unmapped</span>'}${k.ransomware ? '<span class="tag red">ransomware</span>' : ''}</div></div><span class="m">${esc(k.added)}</span></div>`).join('')}</div>
        <div class="disclaim">Each exploited vulnerability is mapped from its CISA description (remote / unauthenticated → T1190, privilege escalation → T1068, browser and memory bugs → T1203, VPN and gateways → T1133, auth bypass → T1078, hard-coded secrets → T1552).</div>`;
    },
  },
  {
    id: 'mtfeed', title: 'ATT&CK-Tagged Reports', deps: ['news'],
    badge: () => `${mitreModel().reports.filter(r => r.techs.length).length} reports`,
    src: () => 'Security news and CISA advisories with matched ATT&CK techniques',
    render() {
      const list = mitreModel().reports.filter(r => r.techs.length).slice(0, 60);
      if (!list.length) return noData('no reports matched a technique yet');
      return `<div class="rows">${list.map(({ n, techs, actors }) => `<div class="r click" data-open="${esc(safeUrl(n.link) || '')}"><span class="typebar" style="background:var(--acc)"></span><div><div class="t">${esc(n.title)}</div><div class="s">${esc((n.summary || '').slice(0, 200))}</div><div><span class="tag grn">${esc(n.source)}</span>${actors.slice(0, 2).map(a => `<span class="tag red">${esc(a)}</span>`).join('')}${techs.slice(0, 8).map(id => techChip(id, ' ' + esc(TECH[id].name))).join('')}</div></div><span class="m">${ago(n.published)}</span></div>`).join('')}</div>`;
    },
  },
);

/* ======================================================================= MITRE screen motion (2026-11)
 * The ATT&CK screen runs unattended on the wall, so it keeps moving: a spotlight steps through the most-reported
 * techniques (highlighting each in the matrix with its latest report), a scan line sweeps the matrix, techniques
 * reported in the last 48 hours pulse, and long lists scroll themselves. Hover anything to hold it still.
 */
const mxPrev = {};
const MX_SPOT = { i: -1, list: [], t: 0 };
const MX_SPOT_MS = 7000;
function mxRecent() {
  const out = {}, cut = Date.now() - 48 * 3600e3;
  for (const r of mitreModel().reports) if (Date.parse(r.n.published) > cut) for (const id of r.techs) out[id] = (out[id] || 0) + 1;
  return out;
}
function mxSpotHTML() {
  const { C } = attackCounts();
  MX_SPOT.list = Object.entries(C).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([id]) => id);
  const L = MX_SPOT.list;
  if (!L.length) return '';
  const i = ((MX_SPOT.i % L.length) + L.length) % L.length, id = L[i], T = TECH[id];
  const rep = mitreModel().reports.find(r => r.techs.includes(id));
  return `<span class="mxs-k">Spotlight <b>${i + 1}</b>/${L.length}</span>
    <span class="mxs-id" data-open="${mitreUrl(id)}">${esc(id)}</span>
    <span class="mxs-n"><b>${esc(T?.name || id)}</b><em>${esc(T?.tac || '')} · ${C[id]} report${C[id] === 1 ? '' : 's'}</em></span>
    <span class="mxs-r">${rep ? `<i>latest</i> ${esc(rep.n.title)} <i>· ${esc(rep.n.source)} · ${ago(rep.n.published)} ago</i>` : ''}</span>
    <span class="mxs-bar"><span style="animation-duration:${MX_SPOT_MS}ms"></span></span>`;
}
function mxSpotStep() {
  const panel = document.querySelector('.panel[data-id="attackmx"]');
  if (!panel || panel.classList.contains('collapsed') || document.hidden) return;
  if (panel.matches(':hover')) return;
  MX_SPOT.i++;
  const strip = panel.querySelector('.mx-spot');
  if (strip) strip.innerHTML = mxSpotHTML();
  const id = MX_SPOT.list[((MX_SPOT.i % MX_SPOT.list.length) + MX_SPOT.list.length) % MX_SPOT.list.length];
  panel.querySelectorAll('.mx-cell.spot, .mx-col.spot').forEach(el => el.classList.remove('spot'));
  const cell = id && panel.querySelector(`.mx-cell[data-tid="${CSS.escape(id)}"]`);
  if (cell) {
    cell.classList.add('spot'); cell.closest('.mx-col')?.classList.add('spot');
    // keep the lit cell in view when the matrix is wider than the panel
    const wrap = panel.querySelector('.mx-wrap');
    if (wrap && wrap.scrollWidth > wrap.clientWidth + 4) {
      const x = cell.offsetLeft - wrap.clientWidth / 2 + cell.offsetWidth / 2;
      wrap.scrollTo({ left: Math.max(0, x), behavior: 'smooth' });
    }
  }
}
const MOTION_OK = !matchMedia('(prefers-reduced-motion: reduce)').matches;
if (MOTION_OK) setInterval(mxSpotStep, MX_SPOT_MS);
setTimeout(() => MOTION_OK && mxSpotStep(), 2500);

// Long lists on the MITRE screen scroll slowly by themselves, pause at the end, then return to the top.
// Any wheel, touch or hover on a list holds it for a while.
const AUTOSCROLL = ['mtfeed', 'mtactors', 'mtkev', 'mttop'];
const AS = new WeakMap();
function autoScrollTick() {
  if (document.body.dataset.screen !== 'mitre' || document.hidden || matchMedia('(max-width: 760px)').matches) return;
  const now = performance.now();
  for (const id of AUTOSCROLL) {
    const pb = document.querySelector(`.panel[data-id="${id}"]:not(.collapsed) .pb`);
    if (!pb) continue;
    const st = AS.get(pb) || { pos: pb.scrollTop, hold: now + 6000 };
    AS.set(pb, st);
    const room = pb.scrollHeight - pb.clientHeight;
    if (room < 12) continue;
    if (pb.matches(':hover') || Math.abs(pb.scrollTop - Math.round(st.pos)) > 2) { st.pos = pb.scrollTop; st.hold = now + 12000; continue; }
    if (now < st.hold) continue;
    if (st.pos >= room - 1) { st.hold = now + 5000; st.pos = 0; pb.scrollTo({ top: 0, behavior: 'smooth' }); st.back = now + 1200; continue; }
    if (st.back && now < st.back) continue;
    st.pos = Math.min(room, st.pos + 0.5);
    pb.scrollTop = Math.round(st.pos);
    if (st.pos >= room - 1) st.hold = now + 5000;
  }
}
if (MOTION_OK) setInterval(autoScrollTick, 40);

/* ======================================================================= industry watch
 * Analytics: the specifics behind the sector heatmap. One card per hard-hit industry with its ransomware
 * victims over 4 days (12-hour bars), the change against the day before, and the groups behind it.
 * Click a card for its latest victims, countries and the security news naming that industry.
 */
function industryModel() {
  const now = Date.now(), H = 3600e3;
  const M = Object.fromEntries(SECTORS.map(([s]) => [s, { s, v: [], news: [] }]));
  let unk = 0;
  for (const v of D.ransomware?.items || []) { const s = sectorOf(v.sector); if (s) M[s].v.push(v); else unk++; }
  for (const n of D.news?.items || []) { if (isKevNotice(n)) continue; for (const s of sectorsIn(newsText(n))) M[s].news.push(n); }
  const age = v => (now - (Date.parse(v.discovered) || 0)) / H;
  const list = Object.values(M).map(x => {
    x.d24 = x.v.filter(v => age(v) < 24).length;
    x.p24 = x.v.filter(v => age(v) >= 24 && age(v) < 48).length;
    x.bins = Array.from({ length: 8 }, (_, i) => x.v.filter(v => { const a = age(v) / 12; return a >= 7 - i && a < 8 - i; }).length);
    const cnt = key => Object.entries(x.v.reduce((o, v) => { const k = v[key]; if (k) o[k] = (o[k] || 0) + 1; return o; }, {})).sort((a, b) => b[1] - a[1]);
    x.groups = cnt('group'); x.ccs = cnt('cc');
    x.score = x.v.length + x.news.length / 1000;
    return x;
  }).filter(x => x.score > 0).sort((a, b) => b.score - a.score || b.d24 - a.d24);
  return { list, unk };
}
window.EXTRA_PANELS.push({
  id: 'industries', title: 'Industry Watch · sector specifics', deps: ['ransomware', 'news'],
  badge: () => { const { list } = industryModel(); const n = list.filter(x => x.d24).length; return n ? `${n} industries hit · 24h` : ''; },
  src: () => 'ransomware.live victim sectors (last 4 days) + industries named in security news',
  render() {
    const { list, unk } = industryModel();
    if (!list.length) return noData('no sector data yet');
    const st = ps('industries');
    const sel = list.find(x => x.s === st.sel) || list[0];
    const cards = list.slice(0, 8).map(x => {
      const bm = Math.max(...x.bins, 1), d = x.d24 - x.p24;
      const bars = x.bins.map((b, i) => `<rect x="${i * 10 + 1}" y="${(22 - (b / bm) * 20).toFixed(1)}" width="8" height="${Math.max(b ? 2 : 1, (b / bm) * 20).toFixed(1)}" rx="1.5" class="${i === 7 ? 'now' : ''} ${b ? '' : 'z'}"/>`).join('');
      return `<div class="iw-card ${x === sel ? 'on' : ''}" data-chip="industries|sel|${esc(x.s)}" ${tip(`${x.s}\n${x.v.length} ransomware victims in 4 days (${x.d24} in the last 24h, ${x.p24} the day before)\n${x.news.length} news reports name this industry`)}>
        <div class="iw-h"><b>${esc(x.s)}</b><span class="iw-d ${d > 0 ? 'up' : d < 0 ? 'down' : ''}">${d > 0 ? '▲' + d : d < 0 ? '▼' + -d : '·'}</span></div>
        <div class="iw-n">${x.v.length}<small>victims</small><em>${x.news.length ? `${x.news.length} news` : ''}</em></div>
        <svg class="iw-spark" viewBox="0 0 80 23" preserveAspectRatio="none">${bars}</svg>
        <div class="iw-g">${x.groups.slice(0, 3).map(([g]) => esc(g)).join(' · ') || '<span class="dim">no claims</span>'}</div></div>`;
    }).join('');
    const vict = sel.v.slice().sort((a, b) => String(b.discovered).localeCompare(String(a.discovered))).slice(0, 7);
    const gmax = sel.groups[0]?.[1] || 1;
    const det = `<div class="iw-det">
      <div><div class="sub-h">Latest victims · ${esc(sel.s)}</div>${vict.map(v => `<div class="iw-row ${v.geo ? 'click' : ''}" ${v.geo ? `data-fly="${v.geo.lon},${v.geo.lat}"` : ''}><span class="tag red">${esc(v.group)}</span><span class="iw-v">${esc(v.victim)}</span>${cc(v.cc)}<span class="m">${ago(v.discovered)}</span></div>`).join('') || '<div class="s">no posted victims in this window</div>'}</div>
      <div><div class="sub-h">Groups behind it</div>${sel.groups.slice(0, 5).map(([g, n]) => `<div class="iw-gb"><span>${esc(g)}</span><span class="trk"><span class="fill" style="width:${(n / gmax * 100).toFixed(0)}%"></span></span><b>${n}</b></div>`).join('') || '<div class="s">—</div>'}
        <div class="sub-h">Countries</div><div>${sel.ccs.slice(0, 8).map(([c, n]) => `<span class="tag">${esc(c)} ${n}</span>`).join('') || '<span class="s">—</span>'}</div></div>
      <div><div class="sub-h">In the news</div>${sel.news.slice(0, 5).map(n => `<div class="iw-news click" data-open="${esc(safeUrl(n.link) || '')}"><span>${esc(n.title)}</span><i>${esc(n.source)} · ${ago(n.published)}</i></div>`).join('') || '<div class="s">no recent reports name this industry</div>'}</div>
    </div>`;
    return `<div class="iw-grid">${cards}</div>${det}
      <div class="disclaim">Victims are ransomware leak-site posts in the last 4 days grouped by the victim's industry${unk ? ` (${unk} posts had no usable industry)` : ''}; bars are 12-hour blocks, newest on the right, and the arrow compares the last 24 hours with the 24 before. News counts reports that name the industry. Click a card for its detail.</div>`;
  },
});
