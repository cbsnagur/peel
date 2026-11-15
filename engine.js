(function (root) {
'use strict';

const MAX_DEPTH = 6;
const enc = new TextEncoder();

/* ---------- small helpers ---------- */
const plural = (n, u) => n + ' ' + u + (n === 1 ? '' : 's');
const pad2 = n => String(n).padStart(2, '0');
const group = n => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');

function rel(ms, now) {
  now = now == null ? Date.now() : now;
  const d = ms - now, a = Math.abs(d);
  if (a < 45e3) return d <= 0 ? 'just now' : 'in a few seconds';
  const U = [['year', 31557600e3], ['month', 2629800e3], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]];
  for (const [name, size] of U) {
    if (a >= size) {
      const v = a / size;
      const n = name === 'year' && v < 10 ? Math.round(v * 10) / 10 : Math.round(v);
      const txt = n + ' ' + name + (n === 1 ? '' : 's');
      return d < 0 ? txt + ' ago' : 'in ' + txt;
    }
  }
  return 'just now';
}

function dur(sec) {
  sec = Math.floor(sec);
  const parts = [];
  const units = [['y', 31536000], ['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];
  for (const [u, size] of units) {
    if (sec >= size) { parts.push(Math.floor(sec / size) + u); sec %= size; }
  }
  return parts.slice(0, 3).join(' ') || '0s';
}

function bytesHuman(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
}

const fmtLocal = d => d.toLocaleString(undefined, {
  weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short'
});

function timeRows(d) {
  return [
    { k: 'Your local time', v: fmtLocal(d) },
    { k: 'UTC', v: d.toISOString() },
    { k: 'Relative', v: rel(d.getTime()) },
    { k: 'Unix seconds', v: String(Math.floor(d.getTime() / 1000)) },
    { k: 'Unix milliseconds', v: String(d.getTime()) }
  ];
}

const plausibleMs = ms => ms >= 978307200000 && ms <= 4102444800000; // 2001..2100

function b64bytes(str) {
  let s = str.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  s = s.replace(/=+$/, '');
  if (s.length % 4 === 1) return null;
  s += '='.repeat((4 - s.length % 4) % 4);
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (e) { return null; }
}

function utf8text(bytes) {
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/.test(s)) return null;
    return s;
  } catch (e) { return null; }
}

function hexdump(bytes, max) {
  max = max || 48;
  let s = Array.from(bytes.slice(0, max), b => b.toString(16).padStart(2, '0')).join(' ');
  if (bytes.length > max) s += ' … (' + (bytes.length - max) + ' more bytes)';
  return s;
}

async function inflate(bytes, format) {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const ds = new DecompressionStream(format);
    const w = ds.writable.getWriter();
    w.write(bytes).catch(() => {}); w.close().catch(() => {});
    const buf = await new Response(ds.readable).arrayBuffer();
    return new Uint8Array(buf);
  } catch (e) { return null; }
}

/* ---------- secrets ---------- */
const SECRET_PATTERNS = [
  ['AWS access key ID', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{40,}\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ['Stripe live secret key', /\b[sr]k_live_[A-Za-z0-9]{16,}\b/],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['npm token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/],
  ['OpenAI-style API key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/],
  ['Private key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/]
];

function scanSecrets(s) {
  const out = [];
  for (const [name, re] of SECRET_PATTERNS) {
    const m = s.match(re);
    if (m) {
      const v = m[0];
      const masked = v.length > 14 ? v.slice(0, 8) + '…' + v.slice(-4) : v;
      if (!out.some(o => o.masked === masked)) out.push({ name, masked });
    }
  }
  return out;
}

/* ---------- JWT ---------- */
const CLAIMS = { iss: 'Issuer', sub: 'Subject', aud: 'Audience', exp: 'Expires', nbf: 'Not valid before', iat: 'Issued', jti: 'Token ID', scope: 'Scope', azp: 'Authorized party' };

function detectJwt(t) {
  const m = t.match(/^(?:Bearer\s+)?([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/);
  if (!m) return null;
  let header, payload;
  try {
    header = JSON.parse(utf8text(b64bytes(m[1])));
    payload = JSON.parse(utf8text(b64bytes(m[2])));
  } catch (e) { return null; }
  if (!header || typeof header !== 'object' || !(header.alg || header.typ)) return null;
  const rows = [{ k: 'Algorithm', v: String(header.alg || 'not stated') }];
  const notes = [];
  const now = Date.now();
  let summary = (header.alg || 'JWT') + ' token';
  if (payload && typeof payload === 'object') {
    for (const key of Object.keys(CLAIMS)) {
      if (payload[key] === undefined) continue;
      let v = payload[key];
      if (['exp', 'nbf', 'iat'].includes(key) && typeof v === 'number') {
        const d = new Date(v * 1000);
        v = fmtLocal(d) + '  (' + rel(d.getTime()) + ')';
      } else if (typeof v !== 'string') v = JSON.stringify(v);
      rows.push({ k: CLAIMS[key] + ' (' + key + ')', v });
    }
    if (typeof payload.exp === 'number') {
      const expMs = payload.exp * 1000;
      if (expMs < now) { notes.push({ level: 'bad', text: 'Expired ' + rel(expMs) + '. A server that checks exp will reject it.' }); summary += ', expired ' + rel(expMs); }
      else { notes.push({ level: 'ok', text: 'Still valid. Expires ' + rel(expMs) + '.' }); summary += ', expires ' + rel(expMs); }
      if (typeof payload.iat === 'number') rows.push({ k: 'Lifetime', v: dur(payload.exp - payload.iat) });
    } else {
      notes.push({ level: 'warn', text: 'No exp claim. This token never expires unless the server tracks it.' });
      summary += ', no expiry';
    }
    if (typeof payload.nbf === 'number' && payload.nbf * 1000 > now) notes.push({ level: 'warn', text: 'Not valid yet. It becomes valid ' + rel(payload.nbf * 1000) + '.' });
  }
  if (String(header.alg).toLowerCase() === 'none') notes.push({ level: 'bad', text: 'alg is "none": the token is unsigned. Anyone can forge it.' });
  if (!m[3] && String(header.alg).toLowerCase() !== 'none') notes.push({ level: 'warn', text: 'The signature part is empty.' });
  notes.push({ level: 'info', text: 'Decoded only. The signature is not verified, since that needs the key.' });
  return {
    kind: 'jwt', label: 'JWT', score: 98, summary, rows, notes,
    blocks: [
      { title: 'Header', text: JSON.stringify(header, null, 2) },
      { title: 'Payload', text: JSON.stringify(payload, null, 2) }
    ]
  };
}

/* ---------- JSON ---------- */
const TIME_KEY = /(time|date|_at$|At$|^exp$|^iat$|^nbf$|^ts$|timestamp|created|updated|expires|expiry|modified)/;
const JSON_CHILD = new Set(['jwt', 'json', 'url', 'timestamp', 'base64', 'urlencoded', 'cron', 'datauri', 'stack', 'curl', 'pem', 'escaped']);

function walkJson(v, path, out, st) {
  if (st.n++ > 600 || out.length >= 80) return;
  if (typeof v === 'string') {
    if (v.length >= 8) out.push({ label: path || '(root)', value: v, strict: true });
  } else if (typeof v === 'number') {
    const key = path.split(/[.\[]/).pop() || '';
    if (Number.isInteger(v) && TIME_KEY.test(key) && (plausibleMs(v * 1000) || plausibleMs(v))) {
      out.push({ label: path, value: String(v), strict: true });
    }
  } else if (Array.isArray(v)) {
    v.forEach((x, i) => walkJson(x, path + '[' + i + ']', out, st));
  } else if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      const seg = /^[A-Za-z_$][\w$]*$/.test(k) ? (path ? '.' : '') + k : '[' + JSON.stringify(k) + ']';
      walkJson(v[k], path + seg, out, st);
    }
  }
}

function jsonStats(v) {
  let keys = 0, depth = 0, nodes = 0;
  (function go(x, d) {
    nodes++; if (d > depth) depth = d;
    if (Array.isArray(x)) x.forEach(y => go(y, d + 1));
    else if (x && typeof x === 'object') for (const k in x) { keys++; go(x[k], d + 1); }
  })(v, 0);
  return { keys, depth, nodes };
}

function repairJson(src) {
  const strs = [];
  let out = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '"' || c === "'") {
      let j = i + 1, body = '';
      while (j < n && src[j] !== c) {
        if (src[j] === '\\' && j + 1 < n) {
          if (src[j + 1] === "'") body += "'"; else body += src[j] + src[j + 1];
          j += 2;
        } else {
          if (src[j] === '"' && c === "'") body += '\\"';
          else if (src[j] === '\n') body += '\\n';
          else body += src[j];
          j++;
        }
      }
      strs.push('"' + body + '"');
      out += '\u0001' + (strs.length - 1) + '\u0001';
      i = j + 1;
    } else if (c === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i++;
    } else if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2); i = e < 0 ? n : e + 2;
    } else if (c === '#' ) {
      while (i < n && src[i] !== '\n') i++;
    } else { out += c; i++; }
  }
  out = out
    .replace(/\bTrue\b/g, 'true').replace(/\bFalse\b/g, 'false').replace(/\bNone\b/g, 'null')
    .replace(/\bundefined\b/g, 'null').replace(/\bNaN\b/g, 'null')
    .replace(/([{,]\s*)([A-Za-z_$][\w$]*)(\s*:)/g, '$1"$2"$3')
    .replace(/,(\s*[}\]])/g, '$1')
    .replace(/\(/g, '[').replace(/\)/g, ']');
  out = out.replace(/\u0001(\d+)\u0001/g, (_, k) => strs[+k]);
  return out;
}

function detectJson(t) {
  const first = t[0];
  if (first !== '{' && first !== '[') return null;
  let val, err;
  try { val = JSON.parse(t); } catch (e) { err = e; }
  if (err) {
    if (!/[:,\]}]/.test(t) || t.length < 3) return null;
    const notes = [];
    const rows = [];
    const blocks = [];
    const pm = String(err.message).match(/position (\d+)/);
    let where = '';
    if (pm) {
      const pos = +pm[1];
      const before = t.slice(0, pos);
      const line = before.split('\n').length;
      const col = pos - before.lastIndexOf('\n');
      where = 'line ' + line + ', column ' + col;
      rows.push({ k: 'Breaks at', v: where });
      const ls = t.split('\n');
      const ctx = [];
      for (let k = Math.max(0, line - 3); k < Math.min(ls.length, line + 1); k++) {
        ctx.push(String(k + 1).padStart(4) + ' | ' + ls[k]);
        if (k === line - 1) ctx.push('     | ' + ' '.repeat(Math.max(0, col - 1)) + '^ here');
      }
      blocks.push({ title: 'Where the parser gave up', text: ctx.join('\n') });
    }
    rows.unshift({ k: 'Parser says', v: String(err.message).replace(/^JSON\.parse: /, '') });
    let fixed = null;
    try { fixed = JSON.parse(repairJson(t)); } catch (e) { /* not repairable */ }
    if (fixed !== null && typeof fixed === 'object') {
      const why = [];
      if (/,\s*[}\]]/.test(t)) why.push('trailing commas');
      if (/'/.test(t)) why.push('single quotes');
      if (/\b(True|False|None)\b/.test(t)) why.push('Python literals (True, False, None)');
      if (/[{,]\s*[A-Za-z_$][\w$]*\s*:/.test(t)) why.push('unquoted keys');
      if (/\/\/|\/\*|#/.test(t)) why.push('comments');
      notes.push({ level: 'ok', text: 'Repaired' + (why.length ? ' by fixing ' + why.join(', ') : '') + '. Valid JSON is below.' });
      blocks.push({ title: 'Repaired JSON', text: JSON.stringify(fixed, null, 2) });
      const kids = []; walkJson(fixed, '', kids, { n: 0 });
      return { kind: 'json', label: 'Broken JSON', score: 88, summary: 'Invalid JSON, repaired automatically', rows, notes, blocks, children: kids };
    }
    notes.push({ level: 'bad', text: 'Could not repair this automatically.' });
    return { kind: 'json', label: 'Broken JSON', score: 70, summary: 'Invalid JSON' + (where ? ' at ' + where : ''), rows, notes, blocks };
  }
  if (val === null || typeof val !== 'object') return null;
  const st = jsonStats(val);
  const isArr = Array.isArray(val);
  const pretty = JSON.stringify(val, null, 2);
  const min = JSON.stringify(val);
  const rows = [
    { k: 'Top level', v: isArr ? 'array of ' + plural(val.length, 'item') : 'object with ' + plural(Object.keys(val).length, 'key') },
    { k: 'Total keys', v: String(st.keys) },
    { k: 'Nesting depth', v: String(st.depth) },
    { k: 'Size', v: bytesHuman(enc.encode(min).length) + ' minified, ' + bytesHuman(enc.encode(pretty).length) + ' pretty' }
  ];
  const blocks = [];
  if (pretty !== t) blocks.push({ title: 'Pretty-printed', text: pretty });
  if (min !== t && min.length < 4000) blocks.push({ title: 'Minified', text: min });
  const kids = []; walkJson(val, '', kids, { n: 0 });
  return {
    kind: 'json', label: 'JSON', score: 90,
    summary: isArr ? 'JSON array, ' + plural(val.length, 'item') : 'JSON object, ' + plural(Object.keys(val).length, 'key'),
    rows, blocks, children: kids
  };
}

/* ---------- URL ---------- */
const TRACKERS = /^(utm_\w+|fbclid|gclid|gbraid|wbraid|msclkid|mc_eid|mc_cid|igshid|_hsenc|_hsmi|yclid|ref_src|si)$/i;

function detectUrl(t) {
  if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(t)) return null;
  let u;
  try { u = new URL(t); } catch (e) { return null; }
  const rows = [
    { k: 'Scheme', v: u.protocol.replace(':', '') },
    { k: 'Host', v: u.hostname }
  ];
  if (u.port) rows.push({ k: 'Port', v: u.port });
  if (u.pathname && u.pathname !== '/') {
    let p = u.pathname; try { p = decodeURIComponent(p); } catch (e) { /* keep raw */ }
    rows.push({ k: 'Path', v: p });
  }
  if (u.hash) rows.push({ k: 'Fragment', v: u.hash.slice(1) });
  const notes = [];
  if (u.username || u.password) notes.push({ level: 'bad', text: 'Credentials are embedded in this URL (' + u.username + (u.password ? ':•••' : '') + '). They end up in logs and browser history.' });
  if (u.protocol === 'http:' && !/^(localhost|127\.|\[::1\]|0\.0\.0\.0)/.test(u.hostname)) notes.push({ level: 'warn', text: 'Plain http: the request is not encrypted.' });
  const params = Array.from(u.searchParams.entries());
  const children = [];
  let table;
  const tracked = [];
  if (params.length) {
    table = { head: ['Parameter', 'Value (decoded)'], rows: params.map(([k, v]) => ({ cells: [k, v], tone: TRACKERS.test(k) ? 'dim' : '' })) };
    for (const [k, v] of params) {
      if (TRACKERS.test(k)) tracked.push(k);
      else if (v.length >= 8) children.push({ label: 'parameter ' + k, value: v });
    }
  }
  const blocks = [];
  if (tracked.length) {
    const clean = new URL(t);
    tracked.forEach(k => clean.searchParams.delete(k));
    notes.push({ level: 'info', text: plural(tracked.length, 'tracking parameter') + ' found (' + tracked.join(', ') + '). A clean copy is below.' });
    blocks.push({ title: 'Without tracking parameters', text: clean.toString() });
  }
  return {
    kind: 'url', label: 'URL', score: 92,
    summary: u.hostname + (params.length ? ', ' + plural(params.length, 'query parameter') : ''),
    rows, notes, table, blocks, children, meta: { hasQuery: params.length > 0 }
  };
}

/* ---------- data URI ---------- */
function detectDataUri(t) {
  const m = t.match(/^data:([^;,]*)((?:;[^,]*)?),/i);
  if (!m) return null;
  const mime = m[1] || 'text/plain';
  const isB64 = /;base64/i.test(m[2]);
  const body = t.slice(m[0].length);
  const rows = [{ k: 'MIME type', v: mime }, { k: 'Encoding', v: isB64 ? 'base64' : 'percent-encoded' }];
  const res = { kind: 'datauri', label: 'Data URI', score: 96, summary: mime + ' embedded as a data URI', rows, children: [] };
  let bytes = null;
  if (isB64) bytes = b64bytes(body);
  if (bytes) rows.push({ k: 'Decoded size', v: bytesHuman(bytes.length) });
  if (/^image\//i.test(mime) && t.length < 2e6) res.image = t;
  else {
    let text = null;
    if (bytes) text = utf8text(bytes); else { try { text = decodeURIComponent(body); } catch (e) { /* skip */ } }
    if (text) { res.blocks = [{ title: 'Content', text: text.slice(0, 20000) }]; res.children.push({ label: 'content', value: text }); }
  }
  return res;
}

/* ---------- timestamps and dates ---------- */
function detectTimestamp(t) {
  let ms, unit;
  if (/^\d{10}$/.test(t)) { ms = +t * 1000; unit = 'seconds'; }
  else if (/^\d{13}$/.test(t)) { ms = +t; unit = 'milliseconds'; }
  else if (/^\d{16}$/.test(t)) { ms = Number(BigInt(t) / 1000n); unit = 'microseconds'; }
  else if (/^\d{19}$/.test(t)) { ms = Number(BigInt(t) / 1000000n); unit = 'nanoseconds'; }
  else if (/^\d{10}\.\d+$/.test(t)) { ms = Math.round(parseFloat(t) * 1000); unit = 'fractional seconds'; }
  else return null;
  if (!plausibleMs(ms)) return null;
  const d = new Date(ms);
  const rows = [{ k: 'Read as', v: 'Unix time in ' + unit }].concat(timeRows(d).slice(0, 3));
  return { kind: 'timestamp', label: 'Unix timestamp', score: 85, summary: fmtLocal(d) + ', ' + rel(ms), rows };
}

function detectDate(t) {
  const iso = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?)?\s?(Z|[+-]\d{2}:?\d{2})?$/;
  const rfc = /^(?:[A-Z][a-z]{2},\s)?\d{1,2}\s[A-Z][a-z]{2}\s\d{4}\s\d{2}:\d{2}(?::\d{2})?\s?(?:GMT|UTC|[+-]\d{4})?$/;
  const m = t.match(iso);
  if (!m && !rfc.test(t)) return null;
  let src = t;
  if (m) src = t.replace(' ', 'T').replace(',', '.').replace(/\s/g, '');
  const ms = Date.parse(src);
  if (isNaN(ms)) return null;
  const d = new Date(ms);
  const notes = [];
  if (m && !m[1]) {
    notes.push(/^\d{4}-\d{2}-\d{2}$/.test(t)
      ? { level: 'info', text: 'Date only, no time or zone. Read as midnight UTC, which is how JavaScript parses it.' }
      : { level: 'warn', text: 'No timezone in the string, so it was read in your local zone. A server in another zone will read a different instant.' });
  }
  return { kind: 'date', label: 'Date and time', score: 88, summary: fmtLocal(d) + ', ' + rel(ms), rows: timeRows(d), notes };
}

/* ---------- IDs ---------- */
function detectUuid(t) {
  const m = t.match(/^\{?([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f])([0-9a-f]{3})-([0-9a-f]{4})-([0-9a-f]{12})\}?$/i);
  if (!m) return null;
  const hex = (m[1] + m[2] + m[3] + m[4] + m[5] + m[6]).toLowerCase();
  const ver = parseInt(m[3], 16);
  const rows = [];
  const names = { 1: 'time and MAC address', 2: 'DCE security', 3: 'MD5 of a name', 4: 'random', 5: 'SHA-1 of a name', 6: 'reordered time', 7: 'Unix time plus random', 8: 'custom' };
  let summary;
  if (/^0{32}$/.test(hex)) { summary = 'Nil UUID (all zeros)'; rows.push({ k: 'Version', v: 'nil' }); }
  else {
    rows.push({ k: 'Version', v: ver + (names[ver] ? ' (' + names[ver] + ')' : '') });
    summary = 'UUID version ' + ver + (names[ver] ? ', ' + names[ver] : '');
  }
  let ms = null;
  const GREG = 0x01b21dd213814000n;
  if (ver === 1) ms = Number((BigInt('0x' + m[4] + m[2] + m[1]) - GREG) / 10000n);
  if (ver === 6) ms = Number((BigInt('0x' + m[1] + m[2] + m[4]) - GREG) / 10000n);
  if (ver === 7) ms = parseInt(hex.slice(0, 12), 16);
  const notes = [];
  if (ms !== null && plausibleMs(ms)) {
    const d = new Date(ms);
    rows.push({ k: 'Created', v: fmtLocal(d) + '  (' + rel(ms) + ')' }, { k: 'Created (UTC)', v: d.toISOString() });
    summary += ', created ' + rel(ms);
    notes.push({ level: 'info', text: 'This ID leaks its creation time. Fine for database keys, worth knowing before you expose it publicly.' });
  }
  if (ver === 1) rows.push({ k: 'Node', v: m[6].match(/../g).join(':') });
  rows.push({ k: 'Without dashes', v: hex }, { k: 'Uppercase', v: t.replace(/[{}]/g, '').toUpperCase() });
  return { kind: 'uuid', label: 'UUID', score: 95, summary, rows, notes };
}

function detectUlid(t) {
  if (!/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/i.test(t)) return null;
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let ms = 0;
  for (const c of t.slice(0, 10).toUpperCase()) ms = ms * 32 + A.indexOf(c);
  if (!plausibleMs(ms)) return null;
  const d = new Date(ms);
  return { kind: 'ulid', label: 'ULID', score: 82, summary: 'ULID created ' + rel(ms), rows: [{ k: 'Created', v: fmtLocal(d) }, { k: 'Created (UTC)', v: d.toISOString() }, { k: 'Random part', v: t.slice(10) }] };
}

function detectObjectId(t) {
  if (!/^[0-9a-f]{24}$/i.test(t)) return null;
  const ms = parseInt(t.slice(0, 8), 16) * 1000;
  if (ms < 1230768000000 || ms > Date.now() + 31557600e3) return null;
  const d = new Date(ms);
  return { kind: 'objectid', label: 'MongoDB ObjectId', score: 78, summary: 'ObjectId created ' + rel(ms), rows: [{ k: 'Created', v: fmtLocal(d) }, { k: 'Created (UTC)', v: d.toISOString() }, { k: 'Counter', v: String(parseInt(t.slice(18), 16)) }] };
}

/* ---------- hex ---------- */
const HASHES = { 32: 'MD5 (128-bit)', 40: 'SHA-1 or a git commit (160-bit)', 56: 'SHA-224', 64: 'SHA-256 (256-bit)', 96: 'SHA-384', 128: 'SHA-512' };

function detectHex(t) {
  const m = t.match(/^(?:0x)?((?:[0-9a-f]{2})+)$/i);
  if (!m || m[1].length < 8 || /^\d+$/.test(m[1]) || /^[a-f]+$/i.test(m[1]) && m[1].length < 16) return null;
  const hex = m[1];
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  const text = utf8text(bytes);
  if (text && /^[\x20-\x7e\s]+$/.test(text)) {
    return { kind: 'hex', label: 'Hex-encoded text', score: 74, summary: plural(bytes.length, 'byte') + ' of text written in hex', rows: [{ k: 'Bytes', v: String(bytes.length) }], blocks: [{ title: 'Decoded', text }], children: [{ label: 'decoded text', value: text }] };
  }
  if (HASHES[hex.length]) {
    return { kind: 'hash', label: 'Hash digest', score: 70, summary: 'Length matches ' + HASHES[hex.length], rows: [{ k: 'Length', v: hex.length + ' hex characters, ' + hex.length * 4 + ' bits' }, { k: 'Likely', v: HASHES[hex.length] }], notes: [{ level: 'info', text: 'A digest cannot be reversed. To find what it hashes, hash your candidates and compare.' }] };
  }
  return { kind: 'hex', label: 'Hex bytes', score: 45, summary: plural(bytes.length, 'byte') + ' of binary data in hex', rows: [{ k: 'Bytes', v: String(bytes.length) }, { k: 'Base64', v: btoa(String.fromCharCode.apply(null, Array.from(bytes.slice(0, 3000)))) }] };
}

/* ---------- colors ---------- */
function detectColor(t) {
  let r, g, b, a = 1, m;
  if ((m = t.match(/^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i))) {
    let h = m[1];
    if (h.length <= 4) h = h.split('').map(c => c + c).join('');
    r = parseInt(h.slice(0, 2), 16); g = parseInt(h.slice(2, 4), 16); b = parseInt(h.slice(4, 6), 16);
    if (h.length === 8) a = Math.round(parseInt(h.slice(6, 8), 16) / 255 * 100) / 100;
  } else if ((m = t.match(/^rgba?\(\s*(\d{1,3})[\s,]+(\d{1,3})[\s,]+(\d{1,3})(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/i))) {
    r = +m[1]; g = +m[2]; b = +m[3];
    if (m[4]) a = m[4].endsWith('%') ? parseFloat(m[4]) / 100 : parseFloat(m[4]);
    if (r > 255 || g > 255 || b > 255) return null;
  } else if ((m = t.match(/^hsla?\(\s*([\d.]+)(?:deg)?[\s,]+([\d.]+)%[\s,]+([\d.]+)%(?:\s*[,/]\s*([\d.]+%?))?\s*\)$/i))) {
    const h = (+m[1] % 360) / 360, s = +m[2] / 100, l = +m[3] / 100;
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
    const f = x => { if (x < 0) x += 1; if (x > 1) x -= 1; return x < 1 / 6 ? p + (q - p) * 6 * x : x < 1 / 2 ? q : x < 2 / 3 ? p + (q - p) * (2 / 3 - x) * 6 : p; };
    r = Math.round(f(h + 1 / 3) * 255); g = Math.round(f(h) * 255); b = Math.round(f(h - 1 / 3) * 255);
    if (m[4]) a = m[4].endsWith('%') ? parseFloat(m[4]) / 100 : parseFloat(m[4]);
  } else return null;
  const hex = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');
  const R = r / 255, G = g / 255, B = b / 255;
  const mx = Math.max(R, G, B), mn = Math.min(R, G, B), L = (mx + mn) / 2;
  let H = 0, S = 0;
  if (mx !== mn) {
    const dd = mx - mn;
    S = L > 0.5 ? dd / (2 - mx - mn) : dd / (mx + mn);
    H = mx === R ? (G - B) / dd + (G < B ? 6 : 0) : mx === G ? (B - R) / dd + 2 : (R - G) / dd + 4;
    H *= 60;
  }
  const lin = c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  const lum = 0.2126 * lin(R) + 0.7152 * lin(G) + 0.0722 * lin(B);
  const cw = 1.05 / (lum + 0.05), cb = (lum + 0.05) / 0.05;
  const grade = c => c >= 7 ? 'passes AAA' : c >= 4.5 ? 'passes AA' : c >= 3 ? 'large text only' : 'fails';
  const rows = [
    { k: 'HEX', v: hex },
    { k: 'RGB', v: 'rgb(' + r + ' ' + g + ' ' + b + (a < 1 ? ' / ' + a : '') + ')' },
    { k: 'HSL', v: 'hsl(' + Math.round(H) + ' ' + Math.round(S * 100) + '% ' + Math.round(L * 100) + '%' + (a < 1 ? ' / ' + a : '') + ')' },
    { k: 'White text on it', v: cw.toFixed(2) + ':1, ' + grade(cw) },
    { k: 'Black text on it', v: cb.toFixed(2) + ':1, ' + grade(cb) }
  ];
  return { kind: 'color', label: 'Color', score: 93, summary: hex + ', use ' + (cw >= cb ? 'white' : 'black') + ' text on top', rows, swatch: 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')' };
}

/* ---------- cron ---------- */
const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
const DAYNAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const MONTHNAMES = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const MACROS = { '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *', '@monthly': '0 0 1 * *', '@weekly': '0 0 * * 0', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@hourly': '0 * * * *' };

function cronField(raw, min, max, names) {
  const set = new Set();
  const num = x => {
    if (/^\d+$/.test(x)) return +x;
    if (names) { const i = names.indexOf(x.toUpperCase()); if (i >= 0) return i + min; }
    return NaN;
  };
  for (const part of raw.split(',')) {
    const [range, stepRaw] = part.split('/');
    if (part.split('/').length > 2) return null;
    const step = stepRaw === undefined ? 1 : +stepRaw;
    if (!Number.isInteger(step) || step < 1) return null;
    let lo, hi;
    if (range === '*' || range === '?') { lo = min; hi = max; }
    else if (range.includes('-')) { const [a, b] = range.split('-'); lo = num(a); hi = num(b); }
    else { lo = num(range); hi = stepRaw === undefined ? lo : max; }
    if (isNaN(lo) || isNaN(hi)) return null;
    if (max === 6 && min === 0) { if (lo === 7) lo = 0; if (hi === 7) hi = lo === 0 && range.includes('-') ? 6 : 0; }
    if (lo < min || hi > max || lo > hi) return null;
    for (let v = lo; v <= hi; v += step) set.add(v);
  }
  return { set, any: raw === '*' || raw === '?', raw };
}

function listWords(arr) {
  if (arr.length <= 1) return arr.join('');
  if (arr.length === 2) return arr.join(' and ');
  return arr.slice(0, -1).join(', ') + ' and ' + arr[arr.length - 1];
}

function cronPhrase(f, fmt, unit) {
  const raw = f.raw;
  let m;
  if ((m = raw.match(/^\*\/(\d+)$/))) return { step: +m[1], text: 'every ' + (m[1] === '1' ? unit : m[1] + ' ' + unit + 's') };
  if (!/[,/]/.test(raw) && raw.includes('-')) {
    const v = Array.from(f.set);
    return { range: true, text: fmt(v[0]) + ' through ' + fmt(v[v.length - 1]) };
  }
  if ((m = raw.match(/^(.+)\/(\d+)$/))) {
    const v = Array.from(f.set);
    return { text: 'every ' + m[2] + ' ' + unit + 's from ' + fmt(v[0]) + ' through ' + fmt(v[v.length - 1]) };
  }
  const v = Array.from(f.set).sort((a, b) => a - b);
  return { list: v, text: listWords(v.map(fmt)) };
}

function detectCron(t) {
  let expr = t.trim();
  let macro = null;
  if (MACROS[expr.toLowerCase()]) { macro = expr; expr = MACROS[expr.toLowerCase()]; }
  let f = expr.split(/\s+/);
  let secs = null;
  if (f.length === 6) { secs = f.shift(); }
  if (f.length !== 5) return null;
  const tok = /^(\*|\?|\d+|[A-Za-z]{3})(([\/\-,])(\*|\d+|[A-Za-z]{3}))*$/;
  if (!f.every(x => tok.test(x)) || (secs !== null && !tok.test(secs))) return null;
  const mi = cronField(f[0], 0, 59), hr = cronField(f[1], 0, 23), dom = cronField(f[2], 1, 31);
  const mon = cronField(f[3], 1, 12, MONTHS), dow = cronField(f[4], 0, 6, DAYS);
  if (!mi || !hr || !dom || !mon || !dow) return null;
  if (secs !== null && !cronField(secs, 0, 59)) return null;

  const pm = cronPhrase(mi, String, 'minute'), ph = cronPhrase(hr, pad2, 'hour');
  let time;
  if (mi.set.size === 1 && hr.set.size === 1) time = 'At ' + pad2([...hr.set][0]) + ':' + pad2([...mi.set][0]);
  else if (mi.any && hr.any) time = 'Every minute';
  else {
    let a;
    if (mi.any) a = 'Every minute';
    else if (pm.step) a = 'Every ' + (pm.step === 1 ? 'minute' : pm.step + ' minutes');
    else if (pm.range) a = 'Every minute from :' + pad2([...mi.set][0]) + ' through :' + pad2(Math.max(...mi.set));
    else if (pm.list) a = 'At minute ' + pm.text;
    else a = pm.text[0].toUpperCase() + pm.text.slice(1);
    let b = '';
    if (!hr.any) {
      if (ph.step) b = ph.step === 1 ? ' of every hour' : ', every ' + ph.step + ' hours';
      else if (ph.range) b = ', from ' + pad2(Math.min(...hr.set)) + ':00 through ' + pad2(Math.max(...hr.set)) + ':59';
      else if (ph.list) b = (pm.list ? ' past hour ' : ', during hour ') + ph.text;
      else b = ', ' + ph.text;
    } else if (pm.list) b = ' of every hour';
    time = a + b;
  }
  const dateBits = [];
  const pd = cronPhrase(dom, String, 'day'), pw = cronPhrase(dow, v => DAYNAMES[v], 'day');
  const domR = !dom.any, dowR = !dow.any;
  if (domR) dateBits.push(pd.step ? pd.text + ' of the month' : 'on day ' + pd.text + ' of the month');
  if (dowR) dateBits.push((domR ? 'or ' : '') + (pw.step ? 'every ' + pw.step + ' days of the week' : 'on ' + pw.text));
  if (!mon.any) { const p = cronPhrase(mon, v => MONTHNAMES[v - 1], 'month'); dateBits.push(p.step ? p.text : 'in ' + p.text); }
  if (!domR && !dowR && time.startsWith('At ') && mi.set.size === 1 && hr.set.size === 1) dateBits.unshift('every day');
  const english = time + (dateBits.length ? ', ' + dateBits.join(', ') : '') + '.';

  // next runs, assuming the scheduler clock is UTC
  const runs = [];
  const d = new Date(); d.setUTCSeconds(0, 0); d.setUTCMinutes(d.getUTCMinutes() + 1);
  const limit = Date.now() + 5 * 31557600e3;
  let guard = 0;
  while (runs.length < 5 && d.getTime() < limit && guard++ < 200000) {
    if (!mon.set.has(d.getUTCMonth() + 1)) { d.setUTCMonth(d.getUTCMonth() + 1, 1); d.setUTCHours(0, 0); continue; }
    const domOk = dom.set.has(d.getUTCDate()), dowOk = dow.set.has(d.getUTCDay());
    const dayOk = domR && dowR ? (domOk || dowOk) : (domOk && dowOk);
    if (!dayOk) { d.setUTCDate(d.getUTCDate() + 1); d.setUTCHours(0, 0); continue; }
    if (!hr.set.has(d.getUTCHours())) { d.setUTCHours(d.getUTCHours() + 1, 0); continue; }
    if (!mi.set.has(d.getUTCMinutes())) { d.setUTCMinutes(d.getUTCMinutes() + 1); continue; }
    runs.push(new Date(d));
    d.setUTCMinutes(d.getUTCMinutes() + 1);
  }
  const notes = [];
  if (domR && dowR) notes.push({ level: 'warn', text: 'Day-of-month and day-of-week are both set. Cron runs when either one matches, not when both do.' });
  if (secs !== null) notes.push({ level: 'info', text: 'Six fields: the first (' + secs + ') is seconds, as in Quartz and Spring. Standard crontab has five.' });
  if (macro) notes.push({ level: 'info', text: macro + ' is shorthand for ' + expr + '.' });
  if (!runs.length) notes.push({ level: 'bad', text: 'This schedule never fires in the next five years. Check the day and month combination.' });
  else if (runs.length > 1) {
    const gap = (runs[1] - runs[0]) / 1000;
    if (gap <= 60) notes.push({ level: 'warn', text: 'This fires every minute while it matches. Make sure the job finishes in under a minute or guards against overlap.' });
  }
  const res = {
    kind: 'cron', label: 'Cron schedule', score: 90, summary: english,
    rows: [{ k: 'Minute', v: f[0] }, { k: 'Hour', v: f[1] }, { k: 'Day of month', v: f[2] }, { k: 'Month', v: f[3] }, { k: 'Day of week', v: f[4] }],
    notes
  };
  if (runs.length) {
    res.table = {
      caption: 'Next runs if the scheduler clock is UTC',
      head: ['UTC', 'Your local time', ''],
      rows: runs.map(r => ({ cells: [r.toISOString().slice(0, 16).replace('T', ' '), fmtLocal(r), rel(r.getTime())] }))
    };
  }
  return res;
}

/* ---------- IPv4 / CIDR ---------- */
function detectIp(t) {
  const m = t.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  if (o.some(x => x > 255)) return null;
  const n = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const str = x => [x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255].join('.');
  let kind = 'Public';
  if (o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168)) kind = 'Private (RFC 1918)';
  else if (o[0] === 127) kind = 'Loopback';
  else if (o[0] === 169 && o[1] === 254) kind = 'Link-local';
  else if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) kind = 'Carrier-grade NAT (also Tailscale)';
  else if (o[0] >= 224 && o[0] <= 239) kind = 'Multicast';
  else if (o[0] === 0) kind = 'Unspecified';
  const rows = [{ k: 'Range type', v: kind }];
  let summary = kind + ' IPv4 address';
  if (m[5] !== undefined) {
    const bits = +m[5];
    if (bits > 32) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const net = (n & mask) >>> 0, bc = (net | ~mask) >>> 0;
    const total = Math.pow(2, 32 - bits);
    const usable = bits >= 31 ? total : total - 2;
    rows.push(
      { k: 'Network', v: str(net) + '/' + bits },
      { k: 'Netmask', v: str(mask) },
      { k: 'First usable', v: str(bits >= 31 ? net : net + 1) },
      { k: 'Last usable', v: str(bits >= 31 ? bc : bc - 1) },
      { k: 'Broadcast', v: str(bc) },
      { k: 'Usable hosts', v: group(usable) }
    );
    summary = '/' + bits + ' block, ' + group(usable) + ' usable ' + (usable === 1 ? 'address' : 'addresses') + ' (' + str(net) + ' to ' + str(bc) + ')';
    if (net !== n) rows.push({ k: 'Note', v: str(n) + ' is a host inside this block, not the network address' });
  } else {
    rows.push({ k: 'As integer', v: String(n) }, { k: 'As hex', v: '0x' + n.toString(16).padStart(8, '0') });
  }
  return { kind: 'ip', label: m[5] !== undefined ? 'CIDR block' : 'IPv4 address', score: 93, summary, rows };
}

/* ---------- numbers ---------- */
const HTTP = { 200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content', 206: 'Partial Content', 301: 'Moved Permanently', 302: 'Found (temporary redirect)', 303: 'See Other', 304: 'Not Modified', 307: 'Temporary Redirect (method kept)', 308: 'Permanent Redirect (method kept)', 400: 'Bad Request', 401: 'Unauthorized (really: not authenticated)', 403: 'Forbidden (authenticated, not allowed)', 404: 'Not Found', 405: 'Method Not Allowed', 406: 'Not Acceptable', 408: 'Request Timeout', 409: 'Conflict', 410: 'Gone', 411: 'Length Required', 412: 'Precondition Failed', 413: 'Content Too Large', 415: 'Unsupported Media Type', 418: "I'm a teapot", 422: 'Unprocessable Content (validation failed)', 425: 'Too Early', 426: 'Upgrade Required', 428: 'Precondition Required', 429: 'Too Many Requests (rate limited)', 431: 'Request Header Fields Too Large', 451: 'Unavailable For Legal Reasons', 499: 'Client Closed Request (nginx)', 500: 'Internal Server Error', 501: 'Not Implemented', 502: 'Bad Gateway (upstream sent garbage)', 503: 'Service Unavailable', 504: 'Gateway Timeout (upstream too slow)', 520: 'Unknown error (Cloudflare)', 521: 'Web server is down (Cloudflare)', 522: 'Connection timed out (Cloudflare)', 524: 'A timeout occurred (Cloudflare)' };
const PORTS = { 22: 'SSH', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 1433: 'SQL Server', 2181: 'ZooKeeper', 3000: 'common dev server', 3306: 'MySQL', 5432: 'PostgreSQL', 5672: 'RabbitMQ', 5173: 'Vite dev server', 6379: 'Redis', 8080: 'HTTP alternate', 8443: 'HTTPS alternate', 9092: 'Kafka', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };

function detectNumber(t) {
  let n;
  const clean = t.replace(/[_,](?=\d{3})/g, '');
  try {
    if (/^-?\d+$/.test(clean)) n = BigInt(clean);
    else if (/^0x[0-9a-f]+$/i.test(t) && t.length <= 18) n = BigInt(t);
    else if (/^0b[01]+$/i.test(t)) n = BigInt(t);
    else if (/^0o[0-7]+$/i.test(t)) n = BigInt(t);
    else return null;
  } catch (e) { return null; }
  if (t.length > 40) return null;
  const neg = n < 0n, abs = neg ? -n : n;
  const rows = [
    { k: 'Decimal', v: (neg ? '-' : '') + group(abs.toString()) },
    { k: 'Hex', v: (neg ? '-' : '') + '0x' + abs.toString(16) },
    { k: 'Binary', v: (neg ? '-' : '') + '0b' + abs.toString(2) },
    { k: 'Octal', v: (neg ? '-' : '') + '0o' + abs.toString(8) }
  ];
  let score = 50, summary = 'Integer in four bases';
  const num = Number(abs);
  if (!neg && abs < 2n ** 53n) {
    if (num >= 1024) rows.push({ k: 'As a byte count', v: bytesHuman(num) });
    if (num >= 60 && num < 3.2e9) rows.push({ k: 'As seconds', v: dur(num) });
    if (num >= 1000) rows.push({ k: 'As milliseconds', v: dur(num / 1000) + (num % 1000 ? ' ' + (num % 1000) + 'ms' : '') });
    if (/^\d{3}$/.test(t) && HTTP[num]) { rows.unshift({ k: 'HTTP status', v: num + ' ' + HTTP[num] }); score = 62; summary = 'HTTP ' + num + ' ' + HTTP[num]; }
    if (PORTS[num]) { rows.unshift({ k: 'Well-known port', v: PORTS[num] }); score = 60; summary = 'Port ' + num + ' is ' + PORTS[num]; }
    if (/^0?[0-7]{3}$/.test(t) && !HTTP[num]) {
      const bits = t.slice(-3).split('').map(c => { const v = +c; return (v & 4 ? 'r' : '-') + (v & 2 ? 'w' : '-') + (v & 1 ? 'x' : '-'); });
      rows.push({ k: 'As chmod mode', v: bits.join('') + '  (owner ' + bits[0] + ', group ' + bits[1] + ', others ' + bits[2] + ')' });
    }
  }
  return { kind: 'number', label: 'Number', score, summary, rows };
}

/* ---------- base64 ---------- */
async function detectBase64(t) {
  const s = t.replace(/\s+/g, '');
  if (s.length < 12 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
  if (/^[a-z]+$/.test(s) || /^[A-Z]+$/.test(s) || /^\d+$/.test(s) || /^[0-9a-f]+$/i.test(s)) return null;
  const bytes = b64bytes(s);
  if (!bytes || bytes.length < 6) return null;
  const urlSafe = /[-_]/.test(s);
  const rows = [{ k: 'Variant', v: urlSafe ? 'URL-safe base64' : 'standard base64' }, { k: 'Decoded size', v: plural(bytes.length, 'byte') }];
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const out = await inflate(bytes, 'gzip');
    const text = out && utf8text(out);
    if (text) {
      rows.push({ k: 'Compression', v: 'gzip, ' + bytesHuman(bytes.length) + ' expands to ' + bytesHuman(out.length) });
      return { kind: 'base64', label: 'Base64 + gzip', score: 90, summary: 'Gzipped text wrapped in base64', rows, blocks: [{ title: 'Decompressed', text: text.slice(0, 20000) }], children: [{ label: 'decompressed content', value: text }] };
    }
  }
  if (bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1])) {
    const out = await inflate(bytes, 'deflate');
    const text = out && utf8text(out);
    if (text) {
      rows.push({ k: 'Compression', v: 'zlib, ' + bytesHuman(bytes.length) + ' expands to ' + bytesHuman(out.length) });
      return { kind: 'base64', label: 'Base64 + zlib', score: 90, summary: 'Zlib-compressed text wrapped in base64', rows, blocks: [{ title: 'Decompressed', text: text.slice(0, 20000) }], children: [{ label: 'decompressed content', value: text }] };
    }
  }
  const text = utf8text(bytes);
  if (text && text.trim().length >= 4) {
    return { kind: 'base64', label: 'Base64', score: 80, summary: 'Base64 that decodes to ' + plural(text.length, 'character') + ' of text', rows, blocks: [{ title: 'Decoded', text: text.slice(0, 20000) }], children: [{ label: 'decoded content', value: text }] };
  }
  const mixed = /[a-z]/.test(s) && /[A-Z]/.test(s) && /\d/.test(s);
  if (!(s.length >= 20 && (mixed || /=$/.test(s)))) return null;
  const MAGIC = [[[0x89, 0x50, 0x4e, 0x47], 'PNG image'], [[0xff, 0xd8, 0xff], 'JPEG image'], [[0x47, 0x49, 0x46], 'GIF image'], [[0x25, 0x50, 0x44, 0x46], 'PDF document'], [[0x50, 0x4b, 0x03, 0x04], 'ZIP archive (or docx, xlsx, jar)'], [[0x30, 0x82], 'DER-encoded ASN.1 (certificate or key)'], [[0x1f, 0x8b], 'gzip data']];
  const hit = MAGIC.find(([sig]) => sig.every((b, i) => bytes[i] === b));
  if (hit) rows.push({ k: 'File signature', v: hit[1] });
  if ([16, 20, 32, 48, 64].includes(bytes.length) && !hit) rows.push({ k: 'Guess', v: bytes.length * 8 + '-bit key, hash or random token' });
  rows.push({ k: 'First bytes (hex)', v: hexdump(bytes, 32) });
  return { kind: 'base64', label: 'Base64 (binary)', score: hit ? 75 : 45, summary: hit ? 'Base64 of a ' + hit[1] : 'Base64 of ' + plural(bytes.length, 'byte') + ' of binary data', rows };
}

/* ---------- percent-encoding, query strings, escapes, entities ---------- */
function detectUrlEncoded(t) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return null;
  const isQs = /^\??[\w.\-\[\]%]+=[^&\s]*(&[\w.\-\[\]%]+=[^&\s]*)+$/.test(t) || (/^\??[\w.\-\[\]%]+=[^&\s]*$/.test(t) && /%[0-9a-f]{2}/i.test(t));
  if (isQs) {
    const sp = new URLSearchParams(t.replace(/^\?/, ''));
    const entries = Array.from(sp.entries());
    return {
      kind: 'urlencoded', label: 'Query string', score: 74, summary: 'Query string with ' + plural(entries.length, 'parameter'),
      table: { head: ['Parameter', 'Value (decoded)'], rows: entries.map(([k, v]) => ({ cells: [k, v] })) },
      blocks: [{ title: 'As JSON', text: JSON.stringify(Object.fromEntries(entries), null, 2) }],
      children: entries.filter(e => e[1].length >= 8).map(([k, v]) => ({ label: 'parameter ' + k, value: v }))
    };
  }
  if (!/%[0-9a-f]{2}/i.test(t) || /\s/.test(t)) return null;
  let dec;
  try { dec = decodeURIComponent(t.replace(/\+/g, ' ')); } catch (e) { return null; }
  if (dec === t) return null;
  return { kind: 'urlencoded', label: 'Percent-encoded text', score: 76, summary: 'URL-encoded text, decoded below', blocks: [{ title: 'Decoded', text: dec }], children: [{ label: 'decoded content', value: dec }] };
}

function detectEscaped(t) {
  if (/^"(?:[^"\\]|\\.)*"$/.test(t)) {
    try {
      const v = JSON.parse(t);
      if (typeof v === 'string' && v !== t.slice(1, -1)) return { kind: 'escaped', label: 'Escaped string', score: 72, summary: 'A quoted, escaped string (often JSON inside a string)', blocks: [{ title: 'Unescaped', text: v }], children: [{ label: 'unescaped content', value: v }] };
    } catch (e) { /* fall through */ }
  }
  const hits = t.match(/\\(?:[ntr"'\\\/]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})/g);
  if (!hits || hits.length < 2 || /\n/.test(t)) return null;
  const out = t.replace(/\\(?:([ntr"'\\\/])|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))/g, (_, c, u, x) =>
    c ? ({ n: '\n', t: '\t', r: '\r' }[c] || c) : String.fromCharCode(parseInt(u || x, 16)));
  return { kind: 'escaped', label: 'Escaped string', score: 62, summary: plural(hits.length, 'escape sequence') + ' unescaped', blocks: [{ title: 'Unescaped', text: out }], children: [{ label: 'unescaped content', value: out }] };
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '©', reg: '®', hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', euro: '€', trade: '™' };
function detectEntities(t) {
  const re = /&(#\d+|#x[0-9a-f]+|[a-z]+);/gi;
  let count = 0;
  const out = t.replace(re, (m, e) => {
    let r = null;
    if (e[0] === '#') { const cp = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); if (cp > 0 && cp < 0x110000) r = String.fromCodePoint(cp); }
    else if (ENT[e.toLowerCase()]) r = ENT[e.toLowerCase()];
    if (r === null) return m;
    count++; return r;
  });
  if (count < 1 || out === t) return null;
  return { kind: 'entities', label: 'HTML entities', score: 60, summary: plural(count, 'HTML entity') .replace('entitys', 'entities') + ' decoded', blocks: [{ title: 'Decoded', text: out }], children: [{ label: 'decoded content', value: out }] };
}

/* ---------- PEM ---------- */
function detectPem(t) {
  const m = t.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/);
  if (!m) return null;
  const bytes = b64bytes(m[2]);
  const type = m[1];
  const rows = [{ k: 'Block type', v: type }];
  if (bytes) rows.push({ k: 'Body size', v: bytesHuman(bytes.length) });
  const notes = [];
  if (/PRIVATE KEY/.test(type)) notes.push({ level: 'bad', text: 'This is a private key. Nothing left this tab, but if it has been in a chat, ticket or commit, treat it as leaked and rotate it.' });
  else if (/CERTIFICATE/.test(type)) notes.push({ level: 'info', text: 'To read the fields, run: openssl x509 -noout -text -in cert.pem' });
  const count = (t.match(/-----BEGIN /g) || []).length;
  if (count > 1) rows.push({ k: 'Blocks in this paste', v: String(count) + (/CERTIFICATE/.test(type) ? ' (a chain: leaf first, then intermediates)' : '') });
  return { kind: 'pem', label: 'PEM block', score: 95, summary: type.toLowerCase().replace(/\b[a-z]/, c => c.toUpperCase()) + ' in PEM format', rows, notes };
}

/* ---------- curl ---------- */
function shellSplit(src) {
  const out = []; let cur = '', has = false, i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '\\' && (src[i + 1] === '\n' || (src[i + 1] === '\r' && src[i + 2] === '\n'))) { i += src[i + 1] === '\n' ? 2 : 3; continue; }
    if (c === '^' && src[i + 1] === '\n') { i += 2; continue; }
    if (/\s/.test(c)) { if (has) { out.push(cur); cur = ''; has = false; } i++; continue; }
    has = true;
    if (c === "'") { const e = src.indexOf("'", i + 1); const end = e < 0 ? n : e; cur += src.slice(i + 1, end); i = end + 1; }
    else if (c === '$' && src[i + 1] === "'") {
      i += 2;
      while (i < n && src[i] !== "'") {
        if (src[i] === '\\' && i + 1 < n) {
          const x = src[i + 1];
          const map = { n: '\n', t: '\t', r: '\r', "'": "'", '"': '"', '\\': '\\' };
          if (x === 'u' || x === 'x') { const len = x === 'u' ? 4 : 2; cur += String.fromCharCode(parseInt(src.substr(i + 2, len), 16)); i += 2 + len; }
          else { cur += map[x] !== undefined ? map[x] : x; i += 2; }
        } else cur += src[i++];
      }
      i++;
    }
    else if (c === '"') {
      i++;
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n && '"\\$`\n'.includes(src[i + 1])) { if (src[i + 1] !== '\n') cur += src[i + 1]; i += 2; }
        else cur += src[i++];
      }
      i++;
    }
    else if (c === '\\' && i + 1 < n) { cur += src[i + 1]; i += 2; }
    else { cur += c; i++; }
  }
  if (has) out.push(cur);
  return out;
}

const CURL_ARG = { X: 'request', H: 'header', d: 'data', u: 'user', b: 'cookie', F: 'form', A: 'user-agent', e: 'referer', o: 'output', m: 'max-time', x: 'proxy', w: 'write-out', c: 'cookie-jar', E: 'cert', T: 'upload-file', r: 'range' };
const CURL_LONG_ARG = new Set(['request', 'header', 'data', 'data-raw', 'data-binary', 'data-ascii', 'data-urlencode', 'json', 'user', 'cookie', 'form', 'form-string', 'user-agent', 'referer', 'output', 'url', 'max-time', 'connect-timeout', 'proxy', 'cacert', 'cert', 'key', 'write-out', 'retry', 'cookie-jar', 'upload-file', 'range', 'resolve', 'oauth2-bearer', 'retry-delay', 'max-redirs']);
const CURL_FLAG = { L: 'location', k: 'insecure', I: 'head', G: 'get', s: 'silent', S: 'show-error', v: 'verbose', i: 'include', f: 'fail', O: 'remote-name', g: 'globoff', N: 'no-buffer' };

function pyLit(v, ind) {
  ind = ind || 0;
  const p = ' '.repeat(ind + 4), q = ' '.repeat(ind);
  if (v === null) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return v.length ? '[\n' + v.map(x => p + pyLit(x, ind + 4)).join(',\n') + ',\n' + q + ']' : '[]';
  const ks = Object.keys(v);
  return ks.length ? '{\n' + ks.map(k => p + JSON.stringify(k) + ': ' + pyLit(v[k], ind + 4)).join(',\n') + ',\n' + q + '}' : '{}';
}
const indentRest = (s, n) => s.split('\n').map((l, i) => i ? ' '.repeat(n) + l : l).join('\n');

function detectCurl(t) {
  if (!/^\$?\s*curl(\.exe)?\s/.test(t)) return null;
  const tok = shellSplit(t.replace(/^\$\s*/, ''));
  tok.shift();
  const o = { headers: [], data: [], form: [], flags: new Set(), url: null, method: null, user: null, json: false };
  const take = (name, val) => {
    switch (name) {
      case 'request': o.method = val.toUpperCase(); break;
      case 'header': { const i = val.indexOf(':'); if (i > 0) o.headers.push([val.slice(0, i).trim(), val.slice(i + 1).trim()]); break; }
      case 'data': case 'data-raw': case 'data-binary': case 'data-ascii': o.data.push(val); break;
      case 'data-urlencode': { const i = val.indexOf('='); o.data.push(i >= 0 ? val.slice(0, i) + '=' + encodeURIComponent(val.slice(i + 1)) : encodeURIComponent(val)); break; }
      case 'json': o.data.push(val); o.json = true; break;
      case 'user': o.user = val; break;
      case 'cookie': if (val.includes('=')) o.headers.push(['Cookie', val]); break;
      case 'form': case 'form-string': o.form.push(val); break;
      case 'user-agent': o.headers.push(['User-Agent', val]); break;
      case 'referer': o.headers.push(['Referer', val]); break;
      case 'oauth2-bearer': o.headers.push(['Authorization', 'Bearer ' + val]); break;
      case 'url': o.url = val; break;
      case 'max-time': o.timeout = val; break;
      default: break;
    }
  };
  for (let i = 0; i < tok.length; i++) {
    const a = tok[i];
    if (a.startsWith('--')) {
      let name = a.slice(2), val;
      const eq = name.indexOf('=');
      if (eq > 0) { val = name.slice(eq + 1); name = name.slice(0, eq); }
      if (CURL_LONG_ARG.has(name)) take(name, val !== undefined ? val : (tok[++i] || ''));
      else o.flags.add(name);
    } else if (a.startsWith('-') && a.length > 1) {
      for (let j = 1; j < a.length; j++) {
        const ch = a[j];
        if (CURL_ARG[ch]) { const rest = a.slice(j + 1); take(CURL_ARG[ch], rest || tok[++i] || ''); break; }
        o.flags.add(CURL_FLAG[ch] || ch);
      }
    } else if (!o.url) o.url = a;
  }
  if (!o.url) return null;
  if (!/^[a-z]+:\/\//i.test(o.url)) o.url = 'http://' + o.url;
  let body = o.data.length ? o.data.join('&') : null;
  if (o.flags.has('get') && body !== null) { o.url += (o.url.includes('?') ? '&' : '?') + body; body = null; }
  if (o.json) {
    if (!o.headers.some(h => /^content-type$/i.test(h[0]))) o.headers.push(['Content-Type', 'application/json']);
    if (!o.headers.some(h => /^accept$/i.test(h[0]))) o.headers.push(['Accept', 'application/json']);
  }
  const method = o.method || (o.flags.has('head') ? 'HEAD' : (body !== null || o.form.length) ? 'POST' : 'GET');
  let bodyJson;
  if (body !== null) { try { const v = JSON.parse(body); if (v && typeof v === 'object') bodyJson = v; } catch (e) { /* raw body */ } }
  if (body !== null && !o.form.length && !o.headers.some(h => /^content-type$/i.test(h[0])) && bodyJson === undefined) o.headers.push(['Content-Type', 'application/x-www-form-urlencoded']);
  const headers = {};
  for (const [k, v] of o.headers) headers[k] = v;

  // fetch
  const jsH = Object.assign({}, headers);
  if (o.user) jsH.Authorization = 'Basic ' + btoa(o.user);
  if (o.form.length) for (const k of Object.keys(jsH)) if (/^content-type$/i.test(k)) delete jsH[k];
  const js = [];
  if (o.form.length) {
    js.push('const form = new FormData();');
    for (const f of o.form) { const i = f.indexOf('='); const k = f.slice(0, i), v = f.slice(i + 1); js.push(v.startsWith('@') ? 'form.append(' + JSON.stringify(k) + ', fileInput.files[0]); // ' + v.slice(1) : 'form.append(' + JSON.stringify(k) + ', ' + JSON.stringify(v) + ');'); }
    js.push('');
  }
  const opts = [];
  if (method !== 'GET') opts.push('  method: ' + JSON.stringify(method) + ',');
  if (Object.keys(jsH).length) opts.push('  headers: ' + indentRest(JSON.stringify(jsH, null, 2), 2) + ',');
  if (o.form.length) opts.push('  body: form,');
  else if (bodyJson !== undefined) opts.push('  body: JSON.stringify(' + indentRest(JSON.stringify(bodyJson, null, 2), 2) + '),');
  else if (body !== null) opts.push('  body: ' + JSON.stringify(body) + ',');
  js.push(opts.length ? 'const res = await fetch(' + JSON.stringify(o.url) + ', {\n' + opts.join('\n') + '\n});' : 'const res = await fetch(' + JSON.stringify(o.url) + ');');
  js.push('if (!res.ok) throw new Error(`HTTP ${res.status}`);');
  const wantsJson = bodyJson !== undefined || Object.entries(headers).some(([k, v]) => /^accept$/i.test(k) && /json/.test(v));
  js.push('const data = await res.' + (wantsJson ? 'json' : 'text') + '();');

  // python
  const std = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
  const py = ['import requests', ''];
  const args = [];
  args.push(JSON.stringify(o.url));
  const pyH = Object.assign({}, headers);
  if (bodyJson !== undefined || o.form.length) for (const k of Object.keys(pyH)) if (/^content-type$/i.test(k)) delete pyH[k];
  if (Object.keys(pyH).length) args.push('headers=' + pyLit(pyH, 4));
  if (o.form.length) {
    const d = {}, files = [];
    for (const f of o.form) { const i = f.indexOf('='); const k = f.slice(0, i), v = f.slice(i + 1); if (v.startsWith('@')) files.push('        ' + JSON.stringify(k) + ': open(' + JSON.stringify(v.slice(1).split(';')[0]) + ', "rb"),'); else d[k] = v; }
    if (Object.keys(d).length) args.push('data=' + pyLit(d, 4));
    if (files.length) args.push('files={\n' + files.join('\n') + '\n    }');
  } else if (bodyJson !== undefined) args.push('json=' + pyLit(bodyJson, 4));
  else if (body !== null) args.push('data=' + JSON.stringify(body));
  if (o.user) { const i = o.user.indexOf(':'); args.push('auth=(' + JSON.stringify(i < 0 ? o.user : o.user.slice(0, i)) + ', ' + JSON.stringify(i < 0 ? '' : o.user.slice(i + 1)) + ')'); }
  if (o.flags.has('insecure')) args.push('verify=False');
  args.push('timeout=' + (o.timeout && !isNaN(+o.timeout) ? +o.timeout : 30));
  const call = std.includes(method.toLowerCase()) ? 'requests.' + method.toLowerCase() + '(' : 'requests.request(\n    ' + JSON.stringify(method) + ',';
  py.push('res = ' + call + '\n' + args.map(a => '    ' + a + ',').join('\n') + '\n)');
  py.push('res.raise_for_status()');
  py.push(wantsJson ? 'print(res.json())' : 'print(res.text)');

  const rows = [{ k: 'Method', v: method }, { k: 'URL', v: o.url }];
  const notes = [];
  const children = [{ label: 'URL', value: o.url, needQuery: true }];
  for (const [k, v] of o.headers) {
    if (/^authorization$/i.test(k)) {
      const bm = v.match(/^Bearer\s+(.+)$/i), ba = v.match(/^Basic\s+(.+)$/i);
      if (bm) children.push({ label: 'Authorization header (bearer token)', value: bm[1] });
      if (ba) children.push({ label: 'Authorization header (basic auth)', value: ba[1] });
    }
  }
  if (body !== null) { rows.push({ k: 'Body', v: bytesHuman(enc.encode(body).length) + (bodyJson !== undefined ? ' of JSON' : '') }); children.push({ label: 'request body', value: body }); }
  let table;
  if (o.headers.length) table = { head: ['Header', 'Value'], rows: o.headers.map(([k, v]) => ({ cells: [k, v] })) };
  if (o.user) rows.push({ k: 'Basic auth user', v: o.user.split(':')[0] });
  if (o.flags.has('insecure')) notes.push({ level: 'warn', text: '-k turns off TLS certificate checks. Fine against localhost, risky anywhere else.' });
  if (o.user || o.headers.some(h => /^(authorization|cookie|x-api-key)$/i.test(h[0]))) notes.push({ level: 'warn', text: 'This command carries credentials. Strip them before pasting it into a ticket or chat.' });
  if (/^http:\/\//i.test(o.url) && !/^http:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\])/i.test(o.url)) notes.push({ level: 'warn', text: 'Plain http: headers and body travel unencrypted.' });
  let host = o.url; try { host = new URL(o.url).host; } catch (e) { /* keep */ }
  return {
    kind: 'curl', label: 'curl command', score: 96, summary: method + ' request to ' + host, rows, notes, table,
    blocks: [{ title: 'JavaScript (fetch)', text: js.join('\n') }, { title: 'Python (requests)', text: py.join('\n') }],
    children
  };
}

/* ---------- stack traces ---------- */
function detectStack(t) {
  const lines = t.split(/\r?\n/);
  let lang = null, frames = [], message = '', startIdx = -1;
  const libJs = /node_modules|node:|\(internal\/|^internal\/|webpack-internal|<anonymous>|\bnative\b/;
  const libPy = /site-packages|dist-packages|lib\/python\d|<frozen |\/usr\/lib\//;
  const libJava = /^(java\.|javax\.|jakarta\.|jdk\.|sun\.|com\.sun\.|org\.springframework|org\.apache|org\.hibernate|io\.netty|kotlin\.|kotlinx\.|scala\.|org\.junit|reactor\.|org\.eclipse|com\.fasterxml|android\.|androidx\.|dalvik\.)/;
  const libGo = /\/go\/pkg\/mod\/|\/usr\/local\/go\/|GOROOT|^runtime[./]|\/src\/runtime\/|\/src\/net\/|\/src\/testing\//;

  if (/Traceback \(most recent call last\)/.test(t)) {
    lang = 'Python';
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/^\s*File "(.+?)", line (\d+)(?:, in (.+))?$/);
      if (m) frames.push({ fn: m[3] || '<module>', loc: m[1] + ':' + m[2], lib: libPy.test(m[1]), code: (lines[i + 1] || '').trim() });
    }
    for (let i = lines.length - 1; i >= 0; i--) { if (lines[i].trim() && !/^\s/.test(lines[i]) && !/^Traceback/.test(lines[i])) { message = lines[i].trim(); break; } }
    for (let i = frames.length - 1; i >= 0; i--) if (!frames[i].lib) { startIdx = i; break; }
  } else if (/^goroutine \d+ \[/m.test(t)) {
    lang = 'Go';
    const pm = t.match(/^(panic: .+|fatal error: .+)$/m); message = pm ? pm[1] : '';
    for (let i = 0; i < lines.length - 1; i++) {
      const loc = lines[i + 1].match(/^\s+(\S+\.go):(\d+)/);
      if (loc && /^\S.*\(.*\)$|^created by /.test(lines[i])) {
        const fn = lines[i].replace(/\(.*\)$/, '').replace(/^created by /, '');
        frames.push({ fn, loc: loc[1] + ':' + loc[2], lib: libGo.test(loc[1]) || /^(runtime|panic)\b/.test(fn) });
      }
    }
    startIdx = frames.findIndex(f => !f.lib);
  } else {
    const java = [], js = [];
    let lastCause = -1;
    lines.forEach(l => {
      let m;
      if ((m = l.match(/^\s*at ([\w.$<>\/]+)\(([^()]*)\)\s*$/)) && !/:\d+:\d+$/.test(m[2])) java.push({ fn: m[1], loc: m[2], lib: libJava.test(m[1]) });
      else if ((m = l.match(/^\s*at (?:async )?(?:(.+?) \()?(.+?):(\d+):(\d+)\)?\s*$/))) js.push({ fn: m[1] || '(anonymous)', loc: m[2] + ':' + m[3] + ':' + m[4], lib: libJs.test(m[2]) });
      else if (/^Caused by: /.test(l)) { lastCause = java.length; message = l.replace(/^Caused by: /, '').trim(); }
    });
    if (java.length >= 2 && java.length >= js.length) {
      lang = 'Java / JVM'; frames = java;
      if (!message) message = (lines.find(l => l.trim() && !/^\s*at /.test(l)) || '').trim().replace(/^Exception in thread "[^"]*" /, '');
      const from = Math.max(0, lastCause);
      startIdx = frames.findIndex((f, i) => i >= from && !f.lib);
      if (startIdx < 0) startIdx = frames.findIndex(f => !f.lib);
    } else if (js.length >= 2) {
      lang = 'JavaScript'; frames = js;
      const head = [];
      for (const l of lines) { if (/^\s*at /.test(l)) break; if (l.trim()) head.push(l.trim()); }
      message = head.join(' ').slice(0, 400);
      startIdx = frames.findIndex(f => !f.lib);
    }
  }
  if (!lang || !frames.length) return null;
  const mine = frames.filter(f => !f.lib).length;
  const rows = [{ k: 'Language', v: lang }];
  if (message) rows.push({ k: lang.startsWith('Java /') && /Caused by/.test(t) ? 'Root cause' : 'Error', v: message });
  rows.push({ k: 'Frames', v: frames.length + ' total: ' + mine + ' in your code, ' + (frames.length - mine) + ' in libraries or runtime' });
  const notes = [];
  if (startIdx >= 0) {
    const f = frames[startIdx];
    notes.push({ level: 'ok', text: 'Start at ' + f.loc + ' in ' + f.fn + '. It is the ' + (lang === 'Python' ? 'deepest' : 'first') + ' frame in your own code' + (f.code ? ': ' + f.code : '.') });
  } else notes.push({ level: 'info', text: 'Every frame is library or runtime code. The bug is likely in what you passed in, so check the call that led here.' });
  if (lang === 'Python') notes.push({ level: 'info', text: 'Python prints the most recent call last, so read this one from the bottom.' });
  return {
    kind: 'stack', label: 'Stack trace', score: 91, summary: (message || lang + ' stack trace').slice(0, 160), rows, notes,
    table: { head: ['', 'Function', 'Location'], rows: frames.slice(0, 60).map((f, i) => ({ cells: [f.lib ? 'library' : 'yours', f.fn, f.loc], tone: f.lib ? 'dim' : '', mark: i === startIdx })) }
  };
}

/* ---------- plain text with things inside ---------- */
function detectText(t) {
  const lines = t.split('\n').length, words = (t.match(/\S+/g) || []).length;
  const rows = [
    { k: 'Characters', v: group(Array.from(t).length) },
    { k: 'Bytes (UTF-8)', v: group(enc.encode(t).length) },
    { k: 'Words', v: group(words) },
    { k: 'Lines', v: group(lines) }
  ];
  const children = [], seen = new Set();
  const add = (label, value) => { if (!seen.has(value) && children.length < 8) { seen.add(value); children.push({ label, value }); } };
  (t.match(/\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g) || []).forEach(v => add('token found in the text', v));
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a >= 0 && b > a + 1) { const sub = t.slice(a, b + 1); try { const v = JSON.parse(sub); if (v && typeof v === 'object') { add('JSON found in the text', sub); t = t.slice(0, a) + ' ' + t.slice(b + 1); } } catch (e) { /* not json */ } }
  (t.match(/https?:\/\/[^\s"'<>)\]}]+/g) || []).forEach(v => add('URL found in the text', v.replace(/[.,;]+$/, '')));
  (t.match(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi) || []).slice(0, 2).forEach(v => add('ID found in the text', v));
  (t.match(/\b1[5-9]\d{8}(?:\d{3})?\b/g) || []).slice(0, 3).forEach(v => add('timestamp found in the text', v));
  (t.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/g) || []).slice(0, 2).forEach(v => add('IP address found in the text', v));
  (t.match(/[A-Za-z0-9+/]{32,}={0,2}/g) || []).slice(0, 2).forEach(v => add('encoded blob found in the text', v));
  return { kind: 'text', label: 'Text', score: 10, summary: children.length ? 'Plain text with things inside worth decoding' : 'Plain text. Nothing encoded was recognized.', rows, children, meta: { embedded: true } };
}

/* ---------- driver ---------- */
const DETECTORS = [detectPem, detectCurl, detectStack, detectJwt, detectJson, detectDataUri, detectUrl, detectUuid, detectUlid, detectObjectId, detectColor, detectIp, detectTimestamp, detectDate, detectCron, detectNumber, detectHex, detectBase64, detectUrlEncoded, detectEscaped, detectEntities];
const BORING = new Set(['text', 'number', 'hash', 'color', 'entities']);

async function analyze(input, depth) {
  const t = input.trim();
  if (!t) return [];
  let results = [];
  for (const det of DETECTORS) {
    try { const r = await det(t); if (r) results.push(r); } catch (e) { /* a detector failing must not break the rest */ }
  }
  if (!results.some(r => r.score >= 40)) results.push(detectText(t));
  results.sort((x, y) => y.score - x.score);
  const top = results[0].score;
  results = depth === 0 ? results.filter((r, i) => i === 0 || (r.score >= 50 && r.score >= top - 45)).slice(0, 3) : results.slice(0, 1);
  for (const r of results) {
    const kids = r.children || [];
    r.children = [];
    if (depth >= MAX_DEPTH) continue;
    for (const c of kids) {
      if (r.children.length >= 10) break;
      if (c.value.trim() === t) continue;
      const sub = await analyze(c.value, depth + 1);
      const s = sub[0];
      if (!s || BORING.has(s.kind)) continue;
      if (c.strict && !JSON_CHILD.has(s.kind)) continue;
      if ((c.strict || c.needQuery) && s.kind === 'url' && !(s.meta && s.meta.hasQuery)) continue;
      if (r.meta && r.meta.embedded && s.score < 60) continue;
      r.children.push({ label: c.label, result: s });
    }
  }
  return results;
}

function countLayers(results) {
  let n = 0;
  const go = r => { n++; (r.children || []).forEach(c => go(c.result)); };
  if (results[0]) go(results[0]);
  return n;
}

async function peel(input) {
  const results = await analyze(input, 0);
  return { results, secrets: scanSecrets(input), layers: countLayers(results) };
}

const api = { peel, analyze, scanSecrets };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
root.Peel = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
