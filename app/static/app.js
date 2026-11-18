/* Render API values as text because scan output is untrusted. */
(() => {
const $ = (s, r = document) => r.querySelector(s);
const B = document.body.dataset;
const csrf = () => document.querySelector('meta[name=csrf-token]').content;

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
const clear = (el) => { el.replaceChildren(); return el; };
async function api(path, opts = {}) {
  // Keep JSON encoding, CSRF headers, and API error handling in one place.
  const o = { method: opts.method || 'GET', headers: {} };
  if (opts.body !== undefined) { o.body = JSON.stringify(opts.body); o.headers['Content-Type'] = 'application/json'; }
  if (o.method !== 'GET') o.headers['X-CSRF-Token'] = csrf();
  const r = await fetch(path, o);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
const fmt = (t) => t ? new Date(t * 1000).toLocaleString() : '-';
const badge = (cls, txt) => h('span', { class: 'badge ' + cls }, txt);
const stateB = (s) => badge('s-' + s, s);
const table = (head, rows) => h('table', {}, h('thead', {}, h('tr', {}, head.map(x => h('th', {}, x)))), h('tbody', {}, rows.map(r => h('tr', {}, r.map(c => h('td', {}, c))))));
const card = (label, val) => h('div', { class: 'card' }, h('b', {}, val), h('span', {}, label));
const code = (o) => h('pre', { class: 'code' }, typeof o === 'string' ? o : JSON.stringify(o, null, 2));
const scanLink = (s) => h('a', { href: '/scans/' + s.id }, '#' + s.id + ' ' + s.name);

const pages = {
async dashboard() {
  const s = await api('/api/stats');
  const c = clear($('#cards'));
  [['Hosts discovered', s.hosts], ['Open TCP ports', s.open_tcp], ['Open UDP ports', s.open_udp], ['Services identified', s.identified],
   ['Unknown services', s.unknown], ['Suspicious findings', s.suspicious], ['Active scans', s.active]].forEach(([l, v]) => c.append(card(l, v)));
  const bars = [['TCP open', s.open_tcp, 'var(--open)'], ['UDP open', s.open_udp, 'var(--ofilt)'], ['Identified', s.identified, 'var(--info)'], ['Unknown', s.unknown, 'var(--filt)'], ['Suspicious', s.suspicious, 'var(--bad)']];
  const max = Math.max(1, ...bars.map(b => b[1])); const ch = clear($('#chart'));
  bars.forEach(([l, v, col]) => { const i = h('i'); i.style.width = (v / max * 100) + '%'; i.style.background = col; ch.append(h('div', { class: 'hbar' }, h('span', {}, l), i, h('b', {}, ' ' + v))); });
  const r = clear($('#recent'));
  r.append(s.recent.length ? table(['Scan', 'Target', 'Status', 'When'], s.recent.map(x => [scanLink(x), x.target, badge('st-' + x.status, x.status), fmt(x.created)])) : h('p', { class: 'muted' }, 'No scans yet.'));
},

new() {
  const f = $('#scanform');
  const build = () => {
    // Convert form strings and checkbox state into the API's scan/config shape.
    const g = (n) => f.elements[n];
    const num = (n) => g(n).value === '' ? undefined : Number(g(n).value);
    const list = (n) => g(n).value.split(',').map(x => x.trim()).filter(Boolean).map(Number);
    const mods = [...f.querySelectorAll('input[name=m]:checked')].map(x => x.value);
    const cfg = { name: g('name').value, vantage: g('vantage').value, tcp: g('tcp').checked, udp: g('udp').checked, tcp_mode: g('tcp_mode').value,
      tcp_ports: g('tcp_ports').value, udp_ports: g('udp_ports').value, backend: g('backend').value, timing: num('timing'), retries: num('retries'),
      probe_timeout: num('probe_timeout'), max_rate: num('max_rate'), delay_ms: num('delay_ms'), cooldown_s: num('cooldown_s'),
      modules: mods, service_detection: f.querySelector('[name=service_detection]').checked,
      os_detection: f.querySelector('[name=os_detection]').checked,
      http_paths: g('http_paths').value.split(',').map(x => x.trim()).filter(Boolean), vhost: g('vhost').value };
    if (g('knock_seq').value.trim()) cfg.knock = { sequence: list('knock_seq'), protected_port: num('knock_port') };
    if (g('source_ports').value.trim()) cfg.source_ports = list('source_ports');
    return { target: g('target').value, config: cfg };
  };
  $('#review').onclick = () => { const o = $('#reviewout'); o.hidden = false; o.textContent = JSON.stringify(build(), null, 2); $('#start').hidden = false; };
  f.onsubmit = async (e) => { e.preventDefault(); $('#formerr').textContent = '';
    try { const r = await api('/api/scans', { method: 'POST', body: build() }); location.href = '/scans/' + r.id; }
    catch (err) { $('#formerr').textContent = err.message; } };
},

async live() {
  const sid = B.sid; let after = 0; let hostsDone = false;
  const ctl = (action, extra) => async () => { try { await api(`/api/scans/${sid}/control`, { method: 'POST', body: { action, ...extra } }); } catch (e) { alert(e.message); } tick(); };
  async function tick() {
    const s = await api('/api/scans/' + sid);
    $('#sname').textContent = s.name; const sb = $('#sstatus'); sb.textContent = s.status; sb.className = 'badge st-' + s.status;
    $('#stage').textContent = s.stage + (s.error ? ' · ' + s.error : '');
    $('#barfill').style.width = Math.round((s.progress || 0) * 100) + '%';
    const cnt = (st) => s.counts.filter(c => c.state === st).reduce((a, c) => a + c.n, 0);
    clear($('#counters')).append(card('Hosts', s.hosts.filter(x => x.status !== 'unreachable').length), card('Open', cnt('open')), card('Filtered', cnt('filtered')),
      card('open|filtered', cnt('open|filtered')), card('Ports investigated', s.ports_investigated), card('Services identified', s.services_identified));
    const c = clear($('#controls'));
    const btn = (t, fn, cls) => c.append(h('button', { class: 'btn ' + (cls || ''), onclick: fn }, t));
    if (s.status === 'running') { btn('Pause', ctl('pause')); btn('Cancel', ctl('cancel'), 'danger'); }
    if (s.status === 'paused') { btn('Continue', ctl('unpause')); btn('Cancel', ctl('cancel'), 'danger'); }
    if (s.status === 'paused_blocking') {
      c.append(h('p', { class: 'note' }, 'Probing is paused: the scanner suspects temporary blocking. See the warning in the event log for the evidence. Cooldown ends ' + fmt(s.cooldown_until) + '.'));
      btn('Resume after cooldown', ctl('release')); btn('Resume now (override)', ctl('release', { force: true })); btn('Cancel', ctl('cancel'), 'danger'); }
    if (['cancelled', 'interrupted', 'failed'].includes(s.status)) btn('Resume from checkpoint', async () => { try { await api(`/api/scans/${sid}/resume`, { method: 'POST', body: {} }); } catch (e) { alert(e.message); } tick(); });
    clear($('#hosts')).append(table(['Address', 'Status', 'OS'], s.hosts.map(x => [h('a', { href: `/scans/${sid}/hosts/${x.address}` }, x.address + (x.family === 6 ? ' (IPv6)' : '')), x.status, x.os || '-'])));
    const ports = await api(`/api/scans/${sid}/ports`);
    clear($('#ports')).append(table(['Host', 'Port', 'State', 'Service', 'Verdict'], ports.filter(p => p.state !== 'closed').slice(0, 200).map(p =>
      [p.host, h('a', { href: `/scans/${sid}/services/${p.host}/${p.proto}/${p.port}` }, p.proto + '/' + p.port), stateB(p.state), p.product || p.service || '-', p.verdict ? h('span', { class: 'v-' + p.verdict }, p.verdict + ' ' + Math.round((p.confidence || 0) * 100) + '%') : '-'])));
    const ev = await api(`/api/scans/${sid}/events?after=${after}`); const log = $('#events');
    ev.forEach(e => { after = e.id; log.append(h('div', { class: 'lv-' + e.level }, new Date(e.ts * 1000).toLocaleTimeString() + ' [' + e.kind + '] ' + e.message,
      e.data && e.data.indicators ? h('div', { class: 'muted' }, '↳ ' + e.data.indicators.join(' · ')) : null)); });
    if (ev.length) log.scrollTop = log.scrollHeight;
    const f = await api(`/api/scans/${sid}/findings`);
    clear($('#findings')).append(f.length ? table(['Category', 'Severity', 'Where', 'Finding', 'Evidence'], f.map(x => [x.category, h('span', { class: 'sev-' + x.severity }, x.severity), x.host + (x.port ? ' ' + x.proto + '/' + x.port : ''), x.title,
      h('details', {}, h('summary', {}, 'show'), code(x.evidence))])) : h('p', { class: 'muted' }, 'No findings yet.'));
    return !['completed', 'cancelled', 'failed', 'interrupted'].includes(s.status);
  }
  (async function loop() { let again = true; try { again = await tick(); } catch (e) { console.error(e); } setTimeout(loop, again ? 1500 : 5000); })();
},

async history() {
  const scans = await api('/api/scans'); const sel = new Set();
  clear($('#scans')).append(table(['', 'Scan', 'Target', 'Vantage', 'Status', 'When', 'Report'], scans.map(s => [
    h('input', { type: 'checkbox', onchange: (e) => e.target.checked ? sel.add(s.id) : sel.delete(s.id) }), scanLink(s), s.target, s.vantage, badge('st-' + s.status, s.status), fmt(s.created),
    h('span', {}, h('a', { href: '/reports/' + s.id }, 'report'), ' · ', h('a', { href: `/api/scans/${s.id}/report.json` }, 'json'), ' · ', h('a', { href: `/api/scans/${s.id}/report.csv` }, 'csv'), ' · ', h('a', { href: `/api/scans/${s.id}/report.pdf` }, 'pdf'))])));
  $('#cmpbtn').onclick = async () => {
    const ids = [...sel].sort((a, b) => a - b); if (ids.length !== 2) return alert('Select exactly two scans');
    const d = await api(`/api/compare?a=${ids[0]}&b=${ids[1]}`); $('#cmp').hidden = false; const o = clear($('#cmpout'));
    o.append(h('p', {}, `Comparing #${d.a} (older) → #${d.b}: ${d.changes.length} change(s), ${d.unchanged} unchanged, ${d.newly_exposed.length} newly exposed.`));
    d.notes.forEach(n => o.append(h('div', { class: 'note' }, h('div', {}, h('b', {}, 'Observed: '), n.observed), h('div', {}, h('b', {}, 'Probable: '), n.probable), (n.hypotheses || []).map(x => h('div', { class: 'muted' }, 'Unconfirmed hypothesis: ' + x)))));
    o.append(d.changes.length ? table(['Host', 'Port', 'From', 'To', 'Service'], d.changes.map(c => [c.host, c.proto + '/' + c.port, stateB(c.from), stateB(c.to), c.service || '-'])) : h('p', { class: 'muted' }, 'No differences.'));
  };
},

async host() {
  const sid = B.sid, addr = B.address;
  const [scan, ports, finds] = await Promise.all([api('/api/scans/' + sid), api(`/api/scans/${sid}/ports?host=${encodeURIComponent(addr)}`), api(`/api/scans/${sid}/findings`)]);
  const hi = scan.hosts.find(x => x.address === addr) || {};
  clear($('#hostinfo')).append(table(['Address', 'Family', 'Hostname', 'OS estimate', 'Status'], [[addr, 'IPv' + (hi.family || '?'), hi.hostname || '-', hi.os || 'not determined', hi.status || '-']]));
  clear($('#ports')).append(table(['Port', 'State', 'Service', 'Version', 'Verdict', 'Confidence', 'Banner'], ports.map(p => [h('a', { href: `/scans/${sid}/services/${addr}/${p.proto}/${p.port}` }, p.proto + '/' + p.port), stateB(p.state), p.service || '-', ((p.product || '') + ' ' + (p.version || '')).trim() || '-',
    h('span', { class: 'v-' + p.verdict }, p.verdict || '-'), p.confidence != null ? Math.round(p.confidence * 100) + '%' : '-', h('span', { class: 'mono' }, (p.banner || '').slice(0, 60))])));
  const hf = finds.filter(f => f.host === addr);
  if (hf.length) $('#ports').append(h('h2', {}, 'Findings'), table(['Category', 'Severity', 'Finding'], hf.map(f => [f.category, h('span', { class: 'sev-' + f.severity }, f.severity), f.title])));
},

async service() {
  const q = `host=${encodeURIComponent(B.address)}&proto=${B.proto}&port=${B.port}`;
  const d = await api(`/api/scans/${B.sid}/service?${q}`); const p = d.port; const v = (p.fingerprint || {}).verdict || {};
  clear($('#svc')).append(table(['Port', 'State', 'Reason', 'Service', 'Product / version', 'Verdict', 'Confidence'], [[p.proto + '/' + p.port, stateB(p.state), p.reason, p.service || '-', ((p.product || '') + ' ' + (p.version || '')).trim() || '-', h('span', { class: 'v-' + p.verdict }, p.verdict || '-'), Math.round((p.confidence || 0) * 100) + '%']]),
    h('h2', {}, 'Banner'), code(p.banner || '(no server-first banner)'),
    h('h2', {}, 'Evidence'), h('ul', {}, (v.evidence || []).map(e => h('li', {}, e))),
    v.issues && v.issues.length ? h('div', { class: 'note' }, h('b', {}, 'Potential inconsistencies'), h('ul', {}, v.issues.map(e => h('li', {}, e)))) : null,
    p.fingerprint && p.fingerprint.decoy ? h('div', { class: 'note' }, h('b', {}, 'Decoy indicators (hypothesis, not proof)'), h('ul', {}, p.fingerprint.decoy.indicators.map(e => h('li', {}, e)))) : null,
    h('h2', {}, 'Probe observations'), code((p.fingerprint || {}).observation || {}));
  clear($('#svcfind')).append(d.findings.length ? table(['Category', 'Severity', 'Finding'], d.findings.map(f => [f.category, h('span', { class: 'sev-' + f.severity }, f.severity), f.title])) : h('p', { class: 'muted' }, 'None.'));
  clear($('#inv')).append(...d.investigations.map(i => h('details', { open: true }, h('summary', {}, i.investigator), h('p', { class: 'muted' }, 'Why: ' + i.reason), code(i.result))));
},

async report() {
  const r = await api(`/api/scans/${B.sid}/report`); const o = clear($('#report'));
  const sec = (t, ...k) => o.append(h('section', { class: 'panel' }, h('h2', {}, t), ...k));
  sec('Executive summary', h('div', { class: 'cards' }, Object.entries(r.executive_summary).map(([k, v]) => card(k.replace(/_/g, ' '), v))));
  sec('Scope', code(r.scope)); sec('Methodology', h('p', {}, r.methodology.summary), code(r.methodology));
  sec('Discovered hosts', table(['Address', 'Hostname', 'OS', 'Status'], r.hosts.map(x => [x.address, x.hostname || '-', x.os || '-', x.status])));
  sec('Ports and services', table(['Host', 'Port', 'State', 'Service', 'Verdict', 'Conf'], r.ports.filter(p => p.state !== 'closed').map(p => [p.host, p.proto + '/' + p.port, stateB(p.state), p.product || p.service || '-', p.verdict || '-', p.confidence != null ? Math.round(p.confidence * 100) + '%' : '-'])));
  sec('Findings & fingerprinting evidence', r.findings.length ? table(['Category', 'Severity', 'Finding', 'Evidence'], r.findings.map(f => [f.category, f.severity, f.title, h('details', {}, h('summary', {}, 'show'), code(f.evidence))])) : h('p', {}, 'No findings.'));
  sec('Limitations', h('ul', {}, r.limitations.map(x => h('li', {}, x)))); sec('Recommendations', h('ul', {}, r.recommendations.map(x => h('li', {}, x))));
  sec('Raw evidence references', r.raw_evidence.length ? table(['ID', 'Host', 'Label', 'Bytes', ''], r.raw_evidence.map(x => [x.id, x.host, x.label, x.bytes, h('a', { href: `/api/scans/${B.sid}/raw/${x.id}` }, 'download')])) : h('p', {}, 'None (built-in scanner used).'));
}};
if (pages[B.page]) pages[B.page]().catch(e => document.querySelector('main').prepend(h('p', { class: 'err' }, e.message)));
})();
