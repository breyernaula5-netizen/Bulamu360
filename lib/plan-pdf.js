// Bulamu360 plan PDF: turns a plan's HTML into a styled, paginated A4 PDF on the server.
// No dependencies (built-in Helvetica fonts, node:zlib). Used for the approval-email attachment
// and the /plan/<token>/pdf download.
import { deflateSync, inflateSync } from 'node:zlib';
import { readFileSync } from 'node:fs';

/* ---------------- Fonts (Helvetica AFM widths, chars 32..126) ---------------- */
const W_REG = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
const W_BOLD = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584];
const SPECIAL = { 0x2018:0x91, 0x2019:0x92, 0x201C:0x93, 0x201D:0x94, 0x2022:0x95, 0x2013:0x96, 0x2014:0x97, 0x2026:0x85, 0x20AC:0x80, 0x2122:0x99 };
const SPECIAL_W = { 0x91:[222,278], 0x92:[222,278], 0x93:[333,500], 0x94:[333,500], 0x95:[350,350], 0x96:[556,556], 0x97:[1000,1000], 0x85:[1000,1000], 0x80:[556,556], 0x99:[1000,1000] };
const REPLACE = { '→':'->', '←':'<-', '≤':'<=', '≥':'>=', '✓':'•', '✔':'•', '✕':'x', '−':'-', '‑':'-', '‐':'-', ' ':' ', '​':'', ' ':' ', ' ':' ' };

function normText(s) {
  let out = '';
  for (const ch of String(s)) {
    if (REPLACE[ch] !== undefined) { out += REPLACE[ch]; continue; }
    const c = ch.codePointAt(0);
    if ((c >= 32 && c <= 126) || (c >= 160 && c <= 255) || SPECIAL[c]) out += ch;
    else if (c === 9 || c === 10 || c === 13) out += ' ';
    // anything else (emoji, symbols) is dropped
  }
  return out;
}
function byteOf(ch) { const c = ch.codePointAt(0); return SPECIAL[c] || c; }
function charW(ch, bold) {
  const b = byteOf(ch);
  if (b >= 32 && b <= 126) return (bold ? W_BOLD : W_REG)[b - 32];
  if (SPECIAL_W[b]) return SPECIAL_W[b][bold ? 1 : 0];
  if (b === 160) return 278;
  return bold ? 611 : 556;
}
function textW(s, size, bold) { let w = 0; for (const ch of s) w += charW(ch, bold); return w * size / 1000; }
function pdfStr(s) {
  let o = '(';
  for (const ch of s) {
    const b = byteOf(ch);
    if (b === 40 || b === 41 || b === 92) o += '\\' + String.fromCharCode(b);
    else if (b < 32 || b > 126) o += '\\' + b.toString(8).padStart(3, '0');
    else o += String.fromCharCode(b);
  }
  return o + ')';
}

/* ---------------- Colours ---------------- */
const hex = h => [parseInt(h.slice(1, 3), 16) / 255, parseInt(h.slice(3, 5), 16) / 255, parseInt(h.slice(5, 7), 16) / 255];
const C = {
  forest: '#0f3d26', green: '#17693f', mid: '#1f7a4a', mint: '#e8f5ee', mint2: '#f3faf6', line: '#cfe3d7',
  text: '#1f2d25', grey: '#5f6f66', white: '#ffffff', coral: '#e2674f', coralBg: '#fdf0ec', sky: '#2f7fb3', skyBg: '#eaf4fb', chip: '#eef6f1'
};
const rgb = (h, stroke) => { const [r, g, b] = hex(h); return `${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} ${stroke ? 'RG' : 'rg'}`; };

/* ---------------- Minimal HTML parser ---------------- */
const VOID = new Set(['br', 'img', 'hr', 'meta', 'link', 'input', 'wbr', 'col', 'source', 'area', 'base']);
const ENT = { nbsp:' ', amp:'&', lt:'<', gt:'>', quot:'"', apos:"'", mdash:'—', ndash:'–', rsquo:'’', lsquo:'‘', rdquo:'”', ldquo:'“', hellip:'…', middot:'·', times:'×', bull:'•', deg:'°', frac12:'½', frac14:'¼', frac34:'¾', rarr:'→', larr:'←', le:'≤', ge:'≥', copy:'©', reg:'®', eacute:'é', plusmn:'±' };
function decode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);/gi, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch { return ''; } }
    return ENT[e.toLowerCase()] !== undefined ? ENT[e.toLowerCase()] : m;
  });
}
function parseAttrs(s) {
  const a = {}; const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g; let m;
  while ((m = re.exec(s))) a[m[1].toLowerCase()] = decode(m[2] ?? m[3] ?? m[4] ?? '');
  return a;
}
export function parseHtml(html) {
  const src = String(html)
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|head|title|svg|noscript|button|template|select|textarea)\b[\s\S]*?<\/\1\s*>/gi, '');
  const root = { tag: 'root', attrs: {}, children: [] };
  const stack = [root];
  const re = /<\/?([a-zA-Z][a-zA-Z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>|([^<]+)/g; let m;
  while ((m = re.exec(src))) {
    const top = stack[stack.length - 1];
    if (m[3] !== undefined) { top.children.push({ text: decode(m[3]) }); continue; }
    const tag = m[1].toLowerCase();
    if (m[0][1] === '/') {
      const i = stack.map(n => n.tag).lastIndexOf(tag);
      if (i > 0) stack.length = i;
      continue;
    }
    if ((tag === 'p' || tag === 'li') && top.tag === tag) stack.pop();
    if ((tag === 'td' || tag === 'th') && (top.tag === 'td' || top.tag === 'th')) stack.pop();
    if (tag === 'tr' && (top.tag === 'td' || top.tag === 'th')) { stack.pop(); if (stack[stack.length - 1].tag === 'tr') stack.pop(); }
    const node = { tag, attrs: parseAttrs(m[2] || ''), children: [] };
    stack[stack.length - 1].children.push(node);
    if (!VOID.has(tag) && !/\/\s*$/.test(m[2] || '')) stack.push(node);
  }
  return root;
}
const cls = n => (n && n.attrs && n.attrs.class ? ' ' + n.attrs.class + ' ' : '');
const hasCls = (n, c) => cls(n).includes(' ' + c + ' ');
const isHidden = n => n.attrs && (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(n.attrs.style || '') || 'hidden' in n.attrs || 'data-no-pdf' in n.attrs || /\b(no-print|print-bar|toolbar|prtbtn)\b/.test(n.attrs.class || ''));
const INLINE = new Set(['span', 'strong', 'b', 'em', 'i', 'a', 'small', 'u', 'sup', 'sub', 'mark', 'code', 'label', 'abbr', 'time', 'font', 'br', 'img']);
function textOf(n) { if (n.text !== undefined) return n.text; if (n.tag === 'br') return ' '; if (isHidden(n)) return ''; return n.children.map(textOf).join(''); }
const clean = s => normText(s).replace(/\s+/g, ' ').trim();
function find(n, pred) { if (n.text !== undefined) return null; if (pred(n)) return n; for (const c of n.children) { const r = find(c, pred); if (r) return r; } return null; }

/* ---------------- Layout ---------------- */
const PW = 595.28, PH = 841.89, ML = 46, MR = 46, TOP = 60, BOTTOM = 62;
const CW = PW - ML - MR, USABLE = PH - TOP - BOTTOM;

// A unit is { h, draw(ops, x, y) , keep? } where y is the top edge (from the page top).
const Y = y => (PH - y).toFixed(2);
function rect(ops, x, y, w, h, fill, stroke, r = 0) {
  if (fill) ops.push(rgb(fill));
  if (stroke) ops.push(rgb(stroke, true), '0.8 w');
  const op = fill && stroke ? 'B' : fill ? 'f' : 'S';
  if (!r) { ops.push(`${x.toFixed(2)} ${(PH - y - h).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re ${op}`); return; }
  r = Math.min(r, h / 2, w / 2); const k = 0.5523 * r, x0 = x, y0 = PH - y - h, x1 = x + w, y1 = PH - y;
  ops.push([`${x0 + r} ${y0} m`, `${x1 - r} ${y0} l`, `${x1 - r + k} ${y0} ${x1} ${y0 + r - k} ${x1} ${y0 + r} c`, `${x1} ${y1 - r} l`, `${x1} ${y1 - r + k} ${x1 - r + k} ${y1} ${x1 - r} ${y1} c`, `${x0 + r} ${y1} l`, `${x0 + r - k} ${y1} ${x0} ${y1 - r + k} ${x0} ${y1 - r} c`, `${x0} ${y0 + r} l`, `${x0} ${y0 + r - k} ${x0 + r - k} ${y0} ${x0 + r} ${y0} c`, op].map(s => s.replace(/(\d+\.\d{3})\d+/g, '$1')).join(' '));
}
function line(ops, x1, y1, x2, y2, color, w = 0.6) { ops.push(rgb(color, true), `${w} w`, `${x1.toFixed(2)} ${Y(y1)} m ${x2.toFixed(2)} ${Y(y2)} l S`); }
function text(ops, s, x, yBase, size, bold, color, italic) {
  if (!s) return;
  const font = bold ? '/F2' : italic ? '/F3' : '/F1';
  ops.push('BT', rgb(color), `${font} ${size} Tf`, `${x.toFixed(2)} ${Y(yBase)} Td`, `${pdfStr(s)} Tj`, 'ET');
}

// Runs: [{t, b, i, c}] -> wrapped lines [{w, parts:[{t,b,i,c,w}]}]
function wrap(runs, width, size) {
  const lines = []; let cur = { parts: [], w: 0 };
  const push = () => { while (cur.parts.length && !cur.parts[cur.parts.length - 1].t.trim()) { cur.w -= cur.parts.pop().w; } lines.push(cur); cur = { parts: [], w: 0 }; };
  for (const r of runs) {
    if (r.nl) { push(); continue; }
    const tokens = r.t.split(/(\s+)/).filter(Boolean);
    for (let tok of tokens) {
      const space = /^\s+$/.test(tok);
      if (space) { if (!cur.parts.length) continue; tok = ' '; }
      let w = textW(tok, size, r.b);
      if (!space && cur.w + w > width && cur.parts.length) push();
      if (!space && w > width) { // very long word: hard-break
        let chunk = '';
        for (const ch of tok) { const cw = textW(chunk + ch, size, r.b); if (cw > width && chunk) { cur.parts.push({ ...r, t: chunk, w: textW(chunk, size, r.b) }); push(); chunk = ch; } else chunk += ch; }
        tok = chunk; w = textW(tok, size, r.b);
      }
      const last = cur.parts[cur.parts.length - 1];
      if (last && last.b === r.b && last.i === r.i && last.c === r.c) { last.t += tok; last.w += w; } else cur.parts.push({ t: tok, b: r.b, i: r.i, c: r.c, w });
      cur.w += w;
    }
  }
  if (cur.parts.length) push();
  return lines.filter((l, i) => l.parts.length || (i > 0 && i < lines.length - 1));
}
function paraUnits(runs, width, st) {
  const size = st.size, lh = size * (st.lh || 1.42);
  const norm = runs.map(r => r.nl ? r : { ...r, t: normText(st.upper ? r.t.toUpperCase() : r.t).replace(/\s+/g, ' ') });
  if (!norm.some(r => !r.nl && r.t.trim())) return [];
  const lines = wrap(norm, width, size);
  return lines.map((ln, idx) => ({
    h: lh + (idx === lines.length - 1 ? (st.after ?? 4) : 0) + (idx === 0 ? (st.before || 0) : 0),
    keep: st.keep && idx === lines.length - 1,
    draw(ops, x, y) {
      let cx = x + (st.align === 'center' ? (width - ln.w) / 2 : 0); const base = y + (idx === 0 ? (st.before || 0) : 0) + size * 1.02 + (lh - size * 1.2) / 2;
      for (const p of ln.parts) { text(ops, p.t, cx, base, size, p.b, p.c || st.color, p.i); cx += p.w; }
    }
  }));
}
function stack(units, gap = 0) { let h = 0; const pos = units.map(u => { const y = h; h += u.h + gap; return y; }); return { h: Math.max(0, h - (units.length ? gap : 0)), draw(ops, x, y) { units.forEach((u, i) => u.draw(ops, x, y + pos[i])); } }; }
const spacer = h => ({ h, draw() {} });

// Styles by class / tag
const BASE = { size: 10, color: C.text, lh: 1.45, after: 5 };
function blockStyle(n, inh) {
  const s = { ...inh, before: 0, after: inh.after, keep: false, upper: false, align: inh.align };
  const t = n.tag;
  if (t === 'h1') Object.assign(s, { size: 20, bold: true, color: C.forest, after: 8, keep: true });
  else if (t === 'h2') Object.assign(s, { size: 16, bold: true, color: C.forest, before: 6, after: 6, keep: true });
  else if (t === 'h3') Object.assign(s, { size: 13, bold: true, color: C.green, before: 4, after: 5, keep: true });
  else if (t === 'h4' || t === 'h5' || t === 'h6') Object.assign(s, { size: 11, bold: true, color: C.green, after: 4, keep: true });
  if (hasCls(n, 'st')) Object.assign(s, { size: 14.5, bold: true, color: C.forest, after: 2, keep: true });
  if (hasCls(n, 'subtle')) Object.assign(s, { size: 8.8, bold: false, color: C.grey, after: 2, keep: true });
  if (hasCls(n, 'week-title')) Object.assign(s, { size: 15, bold: true, color: C.forest, after: 3, keep: true });
  if (hasCls(n, 'week-focus')) Object.assign(s, { size: 9.5, color: C.grey, after: 2, keep: true });
  if (hasCls(n, 'meal-time')) Object.assign(s, { size: 7.8, bold: true, color: inh.mealColor || C.green, upper: true, after: 2, keep: true });
  if (hasCls(n, 'meal-name')) Object.assign(s, { size: 12, bold: true, color: C.forest, after: 5, keep: true });
  if (hasCls(n, 'meal-box')) Object.assign(s, { size: 9, color: C.text, after: 2, lh: 1.4 });
  if (hasCls(n, 'meal-note')) Object.assign(s, { size: 8.6, color: C.grey, after: 3, lh: 1.4 });
  if (hasCls(n, 'cm-l')) Object.assign(s, { size: 7.5, bold: true, color: C.grey, upper: true, after: 1 });
  if (hasCls(n, 'cm-v')) Object.assign(s, { size: 10.5, bold: true, color: C.forest, after: 0 });
  return s;
}
const CARD = { // class -> box style
  'meal-card': { bg: C.white, border: C.line, pad: 12, r: 8, gap: 8 },
  'info-card': { bg: C.mint2, border: C.line, pad: 11, r: 8, gap: 8 },
  'summary-card': { bg: C.mint2, border: C.line, pad: 12, r: 8, gap: 8 },
  'recipe-mini': { bg: C.white, border: C.line, pad: 10, r: 8, gap: 6 },
  'phase': { bg: C.mint2, border: C.line, pad: 10, r: 8, gap: 6, bar: C.green },
  'value-list': { bg: C.mint2, border: C.line, pad: 10, r: 8, gap: 6 },
  'fc': { bg: C.mint2, border: C.line, pad: 10, r: 8, gap: 6 },
  'why-b': { bg: C.mint, border: null, pad: 12, r: 8, gap: 8, bar: C.green },
  'bmi-exp': { bg: C.mint, border: null, pad: 12, r: 8, gap: 8, bar: C.green },
  'note': { bg: C.coralBg, border: null, pad: 12, r: 8, gap: 8, bar: C.coral },
  'week-head': { bg: C.mint, border: null, pad: 14, r: 10, gap: 10, keep: true },
  'sh': { bg: null, border: null, pad: 0, padL: 12, r: 0, gap: 8, bar: C.green, keep: true }
};
const LABELLED = new Set(['meal-box', 'meal-note', 'phase', 'info-card', 'fc', 'value-list', 'recipe-mini']);
const SKIP = new Set(['gauge', 'gpin', 'orb1', 'orb2', 'leaf', 'logo', 'si', 'cover']);

function boxUnit(inner, width, box) {
  const padL = box.padL ?? box.pad, padT = box.pad, h = inner.h + padT * 2;
  return {
    h: h + (box.gap || 0), keep: box.keep,
    draw(ops, x, y) {
      if (box.bg || box.border) rect(ops, x, y, width, h, box.bg, box.border, box.r);
      if (box.bar) rect(ops, x, y + (box.bg ? 0 : 1), 3.2, box.bg ? h : h - 2, box.bar, null, box.bg ? 0 : 1.5);
      inner.draw(ops, x + padL, y + padT);
    }
  };
}

function build(node, width, st) {
  const out = [];
  let runs = [];
  const flush = () => { if (runs.length) { out.push(...paraUnits(runs, width, st)); runs = []; } };
  const inline = (n, fmt) => {
    if (n.text !== undefined) { runs.push({ t: n.text, b: fmt.b, i: fmt.i, c: fmt.c }); return; }
    if (isHidden(n)) return;
    if (n.tag === 'br') { runs.push({ nl: true }); return; }
    if (n.tag === 'img') return;
    const f = { ...fmt };
    if (n.tag === 'strong' || n.tag === 'b') f.b = true;
    if (n.tag === 'em' || n.tag === 'i') f.i = true;
    if (n.tag === 'span' && !fmt.b && /font-weight\s*:\s*(bold|[6-9]00)/i.test(n.attrs.style || '')) f.b = true;
    n.children.forEach(c => INLINE.has(c.tag) || c.text !== undefined ? inline(c, f) : (flush(), out.push(...blockUnits(c, width, st))));
  };
  const kids = node.children || [];
  const labelled = [...LABELLED].some(c => hasCls(node, c));
  let first = true;
  for (const c of kids) {
    if (c.text !== undefined) { if (c.text.trim()) first = false; inline(c, { b: st.bold, i: st.italic }); continue; }
    if (labelled && first && (c.tag === 'strong' || c.tag === 'b')) {
      out.push(...paraUnits([{ t: textOf(c) }], width, { size: 7.8, bold: true, color: C.green, upper: true, after: 3, lh: 1.3, keep: true }));
      first = false; if (kids[kids.indexOf(c) + 1] && kids[kids.indexOf(c) + 1].tag === 'br') kids.splice(kids.indexOf(c) + 1, 1);
      continue;
    }
    first = false;
    if (INLINE.has(c.tag)) inline(c, { b: st.bold, i: st.italic });
    else { flush(); out.push(...blockUnits(c, width, st)); }
  }
  flush();
  return out;
}

/* ---- colour helpers for the prettier layout ---- */
function tint(h, amt = 0.88) { const [r, g, b] = hex(h); const m = v => Math.round((v + (1 - v) * amt) * 255).toString(16).padStart(2, '0'); return '#' + m(r) + m(g) + m(b); }
const CHIP_TONES = [['#e8f5ee', '#17693f'], ['#e8f2fa', '#1c5f8a'], ['#fdf1e6', '#a8561c'], ['#f3edfa', '#6a3d96']];
const DAY_COLORS = { monday: '#17693f', tuesday: '#1c7fa6', wednesday: '#d9772b', thursday: '#8a55b8', friday: '#17a393', saturday: '#c9493a', sunday: '#2f6fb3' };
const WEEK_COLORS = ['#0f3d26', '#1c5f8a', '#6a3d96', '#a8461f'];
const SEC_TONES = { g: '#17693f', o: '#d9772b', r: '#d0553b', y: '#17a393', b: '#2f7fb3', p: '#8a55b8' };
const SHOP_COLORS = { proteins: '#c9493a', vegetables: '#17693f', fruit: '#d9772b', 'staples and grains': '#a8761c', dairy: '#2f7fb3', 'flavour and pantry': '#8a55b8', other: '#5f7468' };
function mealColor(label) {
  const t = String(label || '').toLowerCase();
  if (/breakfast/.test(t)) return '#d9772b';
  if (/mid-?morning|morning snack/.test(t)) return '#2f7fb3';
  if (/lunch/.test(t)) return '#17693f';
  if (/afternoon|snack/.test(t)) return '#17a393';
  if (/dinner|supper|evening/.test(t)) return '#8a55b8';
  return '#17693f';
}
let weekIndex = 0;

function chipsUnit(labels, width, opt = {}) {
  const size = opt.size || 7.8, padX = 7, h = size + 8, gap = 5;
  const rows = [[]]; let x = 0, k = 0;
  for (const l of labels) { const w = textW(l, size, true) + padX * 2; if (x + w > width && rows[rows.length - 1].length) { rows.push([]); x = 0; } rows[rows.length - 1].push({ l, w, x, tone: CHIP_TONES[k++ % CHIP_TONES.length] }); x += w + gap; }
  return [{
    h: rows.length * (h + gap) + 4,
    draw(ops, X, Yt) { rows.forEach((r, ri) => r.forEach(c => { rect(ops, X + c.x, Yt + ri * (h + gap), c.w, h, opt.bg || c.tone[0], null, h / 2); text(ops, c.l, X + c.x + padX, Yt + ri * (h + gap) + h / 2 + size * 0.35, size, true, opt.color || c.tone[1]); })); }
  }];
}

function sectionHeadUnit(n, width) {
  const siNode = find(n, x => hasCls(x, 'si'));
  const code = normText(clean(siNode ? textOf(siNode) : '')).slice(0, 4) || '•';
  const tone = siNode ? (Object.keys(SEC_TONES).find(k => hasCls(siNode, k)) || 'g') : 'g';
  const col = SEC_TONES[tone];
  const titleNode = find(n, x => hasCls(x, 'st')), subNode = find(n, x => hasCls(x, 'subtle'));
  const title = clean(titleNode ? textOf(titleNode) : textOf(n)), sub = clean(subNode ? textOf(subNode) : '');
  const tl = wrap([{ t: normText(title), b: true }], width - 74, 15), sl = sub ? wrap([{ t: normText(sub) }], width - 74, 8.8) : [];
  const inner = tl.length * 19 + sl.length * 12.5, h = Math.max(50, inner + 22);
  return [{ h: h + 10, keep: true, secTitle: title, draw(ops, x, y) {
    rect(ops, x, y, width, h, tint(col, 0.9), null, 14);
    rect(ops, x, y + 10, 4, h - 20, col, null, 2);
    rect(ops, x + 16, y + (h - 38) / 2, 38, 38, col, null, 11);
    const fs = code.length > 3 ? 7.8 : code.length > 2 ? 9 : 11;
    text(ops, code, x + 16 + (38 - textW(code, fs, true)) / 2, y + (h - 38) / 2 + 19 + fs * 0.36, fs, true, C.white);
    let yy = y + (h - inner) / 2 + 14;
    tl.forEach(l => { text(ops, l.parts.map(p => p.t).join(''), x + 66, yy, 15, true, C.forest); yy += 19; });
    sl.forEach(l => { text(ops, l.parts.map(p => p.t).join(''), x + 66, yy - 4, 8.8, false, C.grey); yy += 12.5; });
  } }];
}

function weekBannerUnit(n, width) {
  const titleNode = find(n, x => hasCls(x, 'week-title')), focusNode = find(n, x => hasCls(x, 'week-focus'));
  const title = normText(clean(titleNode ? textOf(titleNode) : textOf(n))), focus = normText(clean(focusNode ? textOf(focusNode) : ''));
  const col = WEEK_COLORS[weekIndex++ % WEEK_COLORS.length];
  const fl = focus ? wrap([{ t: focus }], width - 40, 9.5) : [];
  const h = 52 + fl.length * 13;
  return [{ h: h + 12, keep: true, draw(ops, x, y) {
    rect(ops, x, y, width, h, col, null, 16);
    ops.push(`q ${x.toFixed(2)} ${(PH - y - h).toFixed(2)} ${width.toFixed(2)} ${h.toFixed(2)} re W n /GS1 gs`, rgb('#ffffff')); circle(ops, x + width - 30, y + 10, 60); circle(ops, x + width - 120, y + h + 20, 40); ops.push('Q');
    text(ops, title, x + 20, y + 30, 18, true, C.white);
    fl.forEach((l, i) => text(ops, l.parts.map(p => p.t).join(''), x + 20, y + 48 + i * 13, 9.5, false, tint(col, 0.75)));
  } }];
}

function tocUnit(titles, pageOf) {
  const list = titles.slice(0, 26), colW = (CW - 16) / 2, rowH = 16, rows = Math.ceil(list.length / 2);
  const h = 44 + rows * rowH + 10;
  return { h: h + 12, toc: true, draw(ops, x, y) {
    rect(ops, x, y, CW, h, C.mint2, C.line, 14);
    text(ops, "WHAT'S INSIDE", x + 18, y + 26, 9, true, C.green);
    list.forEach((u, i) => {
      const col = i < rows ? 0 : 1, row = i < rows ? i : i - rows;
      const cx = x + 18 + col * (colW + 4), cy = y + 46 + row * rowH;
      const pg = pageOf && pageOf.get(u) ? String(pageOf.get(u)) : '';
      let t = normText(u.secTitle); while (t.length > 3 && textW(t, 8.6, false) > colW - 46) t = t.slice(0, -2);
      if (t !== normText(u.secTitle)) t = t.replace(/\s*\S?$/, '') + '…';
      text(ops, t, cx, cy, 8.6, false, C.text);
      const tw = textW(t, 8.6, false), pw = textW(pg, 8.6, true), end = cx + colW - 22;
      if (pg) { ops.push(rgb('#b9d2c3', true), '0.6 w', '[1 2] 0 d', `${(cx + tw + 4).toFixed(2)} ${Y(cy - 2)} m ${(end - pw - 4).toFixed(2)} ${Y(cy - 2)} l S`, '[] 0 d'); text(ops, pg, end - pw, cy, 8.6, true, C.green); }
    });
  } };
}

function gridUnits(items, width, cols, gap, st) {
  const colW = (width - gap * (cols - 1)) / cols, out = [];
  for (let i = 0; i < items.length; i += cols) {
    const row = items.slice(i, i + cols).map(it => stack(blockUnits(it, colW, st)));
    const h = Math.max(...row.map(r => r.h));
    out.push({ h: h + 6, draw(ops, x, y) { row.forEach((r, k) => r.draw(ops, x + k * (colW + gap), y)); } });
  }
  return out;
}

function tableUnits(node, width, opt = {}) {
  const rows = []; const walk = n => { if (n.text !== undefined || isHidden(n)) return; if (n.tag === 'tr') rows.push(n); else n.children.forEach(walk); }; walk(node);
  if (!rows.length) return [];
  const check = hasCls(node, 'shop-table'), head0 = opt.color || C.green, box = check ? 18 : 0;
  const ncol = Math.max(...rows.map(r => r.children.filter(c => c.tag === 'td' || c.tag === 'th').length)) || 1;
  const avail = width - box;
  const widths = check && ncol === 3 ? [avail * 0.4, avail * 0.42, avail * 0.18] : ncol === 2 ? [avail * 0.36, avail * 0.64] : Array(ncol).fill(avail / ncol);
  const out = [spacer(2)];
  rows.forEach((r, ri) => {
    const cells = r.children.filter(c => c.tag === 'td' || c.tag === 'th');
    const head = cells.length && cells.every(c => c.tag === 'th');
    const built = cells.map((c, ci) => stack(build(c, widths[ci] - 12, { ...BASE, size: 9, after: 0, lh: 1.35, bold: head, color: head ? C.white : C.text })));
    const h = Math.max(12, ...built.map(b => b.h)) + 10;
    out.push({ h, keep: head, draw(ops, x, y) {
      if (head) rect(ops, x, y, width, h, head0, null, 6); else if (ri % 2 === 0) rect(ops, x, y, width, h, tint(head0, 0.93));
      if (check && !head) { ops.push(rgb(head0, true), '0.9 w'); rect(ops, x + 6, y + h / 2 - 4.5, 9, 9, C.white, head0, 2); }
      let cx = x + box; built.forEach((b, ci) => { b.draw(ops, cx + 6, y + 5); cx += widths[ci]; });
      if (!head) line(ops, x, y + h, x + width, y + h, C.line, 0.5);
    } });
  });
  out.push(spacer(8));
  return out;
}

function blockUnits(n, width, inh) {
  if (n.text !== undefined) return [];
  if (isHidden(n) || [...SKIP].some(c => hasCls(n, c))) return [];
  const st = blockStyle(n, inh);
  if (n.tag === 'table') return tableUnits(n, width, { color: inh.shopColor });
  if (n.tag === 'hr') return [{ h: 14, draw(ops, x, y) { line(ops, x, y + 7, x + width, y + 7, C.line); } }];
  if (n.tag === 'img') return [];
  if (hasCls(n, 'sh')) return sectionHeadUnit(n, width);
  if (hasCls(n, 'week-head')) return weekBannerUnit(n, width);
  if (hasCls(n, 'shop-group')) {
    const cat = clean(textOf(find(n, x => hasCls(x, 'shop-cat')) || { text: '' })), col = SHOP_COLORS[cat.toLowerCase()] || C.green;
    const label = normText(cat.toUpperCase()), lw = textW(label, 8.5, true) + 26;
    const tbl = find(n, x => x.tag === 'table');
    return [{ h: 28, keep: true, draw(ops, x, y) { rect(ops, x, y + 4, lw, 20, col, null, 10); text(ops, label, x + 13, y + 17.2, 8.5, true, C.white); } }, ...(tbl ? tableUnits(tbl, width, { color: col }) : [])];
  }
  if (hasCls(n, 'day-title')) {
    const s = clean(textOf(n)); if (!s) return [];
    const col = DAY_COLORS[(s.toLowerCase().match(/monday|tuesday|wednesday|thursday|friday|saturday|sunday/) || ['monday'])[0]];
    return [spacer(6), { h: 30, keep: true, draw(ops, x, y) {
      rect(ops, x, y, width, 24, col, null, 12);
      rect(ops, x + 6, y + 5, 14, 14, tint(col, 0.75), null, 7);
      text(ops, normText(s), x + 28, y + 15.8, 11, true, C.white);
    } }];
  }
  if (hasCls(n, 'meal-chips') || hasCls(n, 'glbl') || hasCls(n, 'variety-strip')) {
    const labels = n.children.filter(c => c.text === undefined && !isHidden(c)).map(c => clean(textOf(c))).filter(Boolean);
    return labels.length ? chipsUnit(labels, width) : [];
  }
  if (hasCls(n, 'meal-grid') || hasCls(n, 'support-grid') || hasCls(n, 'phase-grid')) {
    const items = n.children.filter(c => c.text === undefined && !isHidden(c));
    return gridUnits(items, width, width > 300 ? 2 : 1, 12, st);
  }
  if (n.children.some(c => c.text === undefined && hasCls(c, 'mac'))) { // target tiles: big number + label
    const tiles = n.children.filter(c => c.text === undefined && !isHidden(c)).map(c => {
      const num = find(c, x => x.tag === 'b' || x.tag === 'strong');
      return { v: clean(num ? textOf(num) : textOf(c)), l: clean(c.children.filter(x => x !== num).map(textOf).join(' ')).toUpperCase() };
    });
    const cols = 3, gap = 10, tw = (width - gap * (cols - 1)) / cols, th = 50, tints = [C.mint, C.skyBg, C.coralBg, '#f3edfa', '#e6f7f5', C.mint];
    const out = [];
    for (let i = 0; i < tiles.length; i += cols) {
      const row = tiles.slice(i, i + cols);
      out.push({ h: th + gap, draw(ops, x, y) { row.forEach((t, k) => { const cx = x + k * (tw + gap), vs = normText(t.v), ls = normText(t.l); rect(ops, cx, y, tw, th, tints[(i + k) % tints.length], null, 8); text(ops, vs, cx + (tw - textW(vs, 17, true)) / 2, y + 25, 17, true, C.forest); text(ops, ls, cx + (tw - textW(ls, 7.2, true)) / 2, y + 40, 7.2, true, C.grey); }); } });
    }
    return out;
  }
  if (hasCls(n, 'c-meta')) {
    const items = n.children.filter(c => c.text === undefined && !isHidden(c));
    return gridUnits(items, width, 2, 12, st);
  }
  if (n.tag === 'ul' || n.tag === 'ol') {
    const out = []; let k = 0;
    for (const li of n.children) {
      if (li.text !== undefined || isHidden(li)) continue; k++;
      const inner = stack(build(li, width - 16, { ...st, after: 2 }));
      const mark = n.tag === 'ol' ? k + '.' : '•';
      out.push({ h: inner.h + 2, draw(ops, x, y) { text(ops, mark, x + 3, y + st.size * 1.2, st.size, true, C.green); inner.draw(ops, x + 16, y); } });
    }
    return out.length ? [...out, spacer(4)] : [];
  }
  const boxKey = Object.keys(CARD).find(c => hasCls(n, c));
  if (boxKey) {
    let box = CARD[boxKey], bst = st;
    if (boxKey === 'meal-card') {
      const mc = mealColor(clean(textOf(find(n, x => hasCls(x, 'meal-time')) || { text: '' })));
      box = { ...box, bar: mc, border: tint(mc, 0.7), padL: 16 };
      bst = { ...st, mealColor: mc };
    }
    const innerW = width - (box.padL ?? box.pad) - box.pad;
    const units = build(n, innerW, bst);
    if (!units.length) return [];
    const inner = stack(units);
    if (inner.h + box.pad * 2 <= USABLE * 0.9) { const u = boxUnit(inner, width, box); if (units.length > 2 && !box.keep) { u.parts = units; u.box = box; u.w = width; } return [u]; }
    // Too tall for one page: flow the children with the accent bar only.
    return units.map(u => ({ h: u.h, keep: u.keep, draw(ops, x, y) { rect(ops, x, y, 3, u.h, box.bar || C.line); u.draw(ops, x + 12, y); } }));
  }
  const out = [];
  if (hasCls(n, 'sec')) out.push(spacer(10));
  if (hasCls(n, 'week-card')) out.push({ h: 0, pageBreak: true, draw() {} });
  if (hasCls(n, 'day-block')) out.push(spacer(4));
  out.push(...build(n, width, st));
  if (hasCls(n, 'sec')) out.push(spacer(4));
  return out;
}

/* ---------------- PNG (RGBA/RGB 8-bit) -> PDF image with soft mask ---------------- */
function pngImage(buf) {
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('not png');
  let p = 8, w, h, depth, ctype, inter; const idat = [];
  while (p < buf.length) {
    const len = buf.readUInt32BE(p), type = buf.toString('latin1', p + 4, p + 8), data = buf.subarray(p + 8, p + 8 + len);
    if (type === 'IHDR') { w = data.readUInt32BE(0); h = data.readUInt32BE(4); depth = data[8]; ctype = data[9]; inter = data[12]; }
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    p += 12 + len;
  }
  if (depth !== 8 || inter || (ctype !== 6 && ctype !== 2)) throw new Error('unsupported png');
  const bpp = ctype === 6 ? 4 : 3, stride = w * bpp, raw = inflateSync(Buffer.concat(idat)), px = Buffer.alloc(h * stride);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = y * (stride + 1) + 1, o = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? px[o + x - bpp] : 0, b = y ? px[o - stride + x] : 0, c = y && x >= bpp ? px[o - stride + x - bpp] : 0, v = raw[src + x];
      let r;
      if (f === 0) r = v; else if (f === 1) r = v + a; else if (f === 2) r = v + b; else if (f === 3) r = v + ((a + b) >> 1);
      else { const pp = a + b - c, pa = Math.abs(pp - a), pb = Math.abs(pp - b), pc = Math.abs(pp - c); r = v + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c); }
      px[o + x] = r & 255;
    }
  }
  const color = Buffer.alloc(w * h * 3), alpha = ctype === 6 ? Buffer.alloc(w * h) : null;
  for (let i = 0; i < w * h; i++) { color[i * 3] = px[i * bpp]; color[i * 3 + 1] = px[i * bpp + 1]; color[i * 3 + 2] = px[i * bpp + 2]; if (alpha) alpha[i] = px[i * 4 + 3]; }
  return { w, h, color: deflateSync(color), alpha: alpha ? deflateSync(alpha) : null };
}

/* ---------------- Document assembly ---------------- */
function coverUnits(tree, meta, logo) {
  const cover = find(tree, n => hasCls(n, 'cover'));
  const titleNode = cover && find(cover, n => hasCls(n, 'c-title') || n.tag === 'h1');
  const title = clean(titleNode ? textOf(titleNode) : '') || 'Personalised Nutrition Plan';
  const subNode = cover && find(cover, n => hasCls(n, 'c-sub'));
  const sub = clean(subNode ? textOf(subNode) : '') || (meta.clientName ? 'Prepared exclusively for ' + meta.clientName : '');
  const metaNode = cover && find(cover, n => hasCls(n, 'c-meta'));
  const bmiNode = cover && find(cover, n => hasCls(n, 'bmi-b'));
  const bmi = clean(bmiNode ? bmiNode.children.map(textOf).join(' ') : '');
  const titleLines = wrap([{ t: normText(title) }], CW - 20, 30);
  const subLines = sub ? wrap([{ t: normText(sub) }], CW - 20, 12) : [];
  const bandH = 150 + titleLines.length * 36 + subLines.length * 17;
  const band = {
    h: bandH + 16,
    draw(ops, x) {
      rect(ops, 0, 0, PW, bandH, C.forest);
      // soft decorative circles
      ops.push(`q 0 ${(PH - bandH).toFixed(2)} ${PW} ${bandH.toFixed(2)} re W n /GS1 gs`, rgb('#2a8a58'));
      circle(ops, PW - 70, 60, 120); circle(ops, PW - 10, bandH - 10, 70); ops.push('Q');
      const chipW = 128, chipH = 70;
      rect(ops, ML, 34, chipW, chipH, C.white, null, 12);
      if (logo) { const iw = chipW - 20, ih = iw * logo.h / logo.w; ops.push('q', `${iw.toFixed(2)} 0 0 ${ih.toFixed(2)} ${(ML + 10).toFixed(2)} ${(PH - 34 - chipH / 2 - ih / 2).toFixed(2)} cm`, '/Im1 Do', 'Q'); }
      else text(ops, 'Bulamu360', ML + 16, 34 + 42, 18, true, C.forest);
      text(ops, 'BULAMU360  ·  BY BREYER NAULA, RDN', ML + chipW + 16, 34 + 30, 8.5, true, '#bfe8d0');
      text(ops, 'Eat better, live better', ML + chipW + 16, 34 + 46, 10, false, '#e6f5ec', true);
      let y = 136;
      titleLines.forEach(l => { text(ops, l.parts.map(p => p.t).join(''), ML, y + 26, 30, true, C.white); y += 36; });
      y += 4;
      subLines.forEach(l => { text(ops, l.parts.map(p => p.t).join(''), ML, y + 12, 12, false, '#d8efe2'); y += 17; });
      if (bmi) { const w = textW(normText(bmi), 9, true) + 22; rect(ops, PW - MR - w, bandH - 34, w, 20, '#ffffff', null, 10); text(ops, normText(bmi), PW - MR - w + 11, bandH - 20.5, 9, true, C.forest); }
    }
  };
  const out = [band];
  if (metaNode) {
    const items = metaNode.children.filter(c => c.text === undefined && !isHidden(c));
    const cells = items.map(it => ({ l: clean(textOf(find(it, n => hasCls(n, 'cm-l')) || { text: '' })), v: clean(textOf(find(it, n => hasCls(n, 'cm-v')) || it)) })).filter(c => c.v);
    const colW = (CW - 12) / 2;
    for (let i = 0; i < cells.length; i += 2) {
      const row = cells.slice(i, i + 2).map(c => ({ ...c, lines: wrap([{ t: normText(c.v), b: true }], colW - 24, 11) }));
      const h = Math.max(...row.map(c => 30 + c.lines.length * 14));
      out.push({ h: h + 10, draw(ops, x, y) { row.forEach((c, k) => { const cx = x + k * (colW + 12); rect(ops, cx, y, colW, h, C.mint2, C.line, 8); text(ops, normText(c.l.toUpperCase()), cx + 12, y + 17, 7.5, true, C.grey); c.lines.forEach((ln, li) => text(ops, ln.parts.map(p => p.t).join(''), cx + 12, y + 32 + li * 14, 11, true, C.forest)); }); } });
    }
    out.push(spacer(8));
  }
  return { units: out, found: !!cover };
}
function circle(ops, cx, cy, r) { const k = 0.5523 * r, y = PH - cy; ops.push(`${cx + r} ${y} m ${cx + r} ${y + k} ${cx + k} ${y + r} ${cx} ${y + r} c ${cx - k} ${y + r} ${cx - r} ${y + k} ${cx - r} ${y} c ${cx - r} ${y - k} ${cx - k} ${y - r} ${cx} ${y - r} c ${cx + k} ${y - r} ${cx + r} ${y - k} ${cx + r} ${y} c f`.replace(/(\d+\.\d{2})\d+/g, '$1')); }

let logoCache;
function loadLogo(path) {
  if (logoCache !== undefined) return logoCache;
  try { logoCache = pngImage(readFileSync(path)); } catch { logoCache = null; }
  return logoCache;
}

export function planPdfFromHtml(html, meta = {}) {
  const tree = parseHtml(html);
  const logo = meta.logoPath ? loadLogo(meta.logoPath) : null;
  const cover = coverUnits(tree, meta, logo);
  const bodyNode = find(tree, n => hasCls(n, 'body')) || find(tree, n => n.tag === 'body') || tree;
  weekIndex = 0;
  const body = blockUnits(bodyNode === tree ? { ...tree, tag: 'div', attrs: {} } : bodyNode, CW, BASE);
  const titles = body.filter(u => u.secTitle);
  // Pass 1 finds the page of each section; pass 2 draws the contents box with those numbers (same heights).
  let pageOf = null, pages;
  for (let pass = 0; pass < 2; pass++) {
    const r = paginate([...cover.units, ...(titles.length > 2 ? [tocUnit(titles, pageOf)] : []), ...body]);
    pages = r.pages; pageOf = r.pageOf;
  }
  return finishPlanPdf(pages, logo, meta);
}

function paginate(units) {
  const pages = [[]], pageOf = new Map(); let y = 0, pageTop = 0; // first page: cover band starts at 0
  const newPage = () => { pages.push([]); y = TOP; pageTop = TOP; };
  for (let i = 0; i < units.length; i++) {
    const u = units[i];
    if (i === 0) { u.draw(pages[0], ML, 0); y = u.h; continue; }
    const bottom = PH - BOTTOM;
    if (u.pageBreak) { if (y > pageTop + 1) newPage(); continue; }
    const isSpacer = u.draw.length === 0;
    if (isSpacer && y === pageTop) continue; // no blank gap at the top of a page
    let need = u.h;
    if (u.keep) { // headings stay with what follows them
      let j = i + 1;
      while (units[j] && need < USABLE * 0.5) { need += units[j].h; if (!units[j].keep) break; j++; }
    }
    if (u.parts && y + u.h > bottom && bottom - y > 150) { // split a card across the page break
      const room = bottom - y - u.box.pad * 2 - (u.box.gap || 0); let used = 0, k = 0;
      while (k < u.parts.length && used + u.parts[k].h <= room) used += u.parts[k++].h;
      while (k > 1 && u.parts[k - 1].keep) used -= u.parts[--k].h;
      if (k >= 1 && k < u.parts.length) {
        const first = boxUnit(stack(u.parts.slice(0, k)), u.w, { ...u.box, gap: 0 });
        const rest = boxUnit(stack(u.parts.slice(k)), u.w, u.box);
        first.draw(pages[pages.length - 1], ML, y); newPage();
        units.splice(i + 1, 0, rest); continue;
      }
    }
    if (y + Math.min(need, USABLE) > bottom && y > pageTop + 1) { newPage(); if (isSpacer) continue; }
    u.draw(pages[pages.length - 1], ML, y);
    if (u.secTitle) pageOf.set(u, pages.length);
    y += u.h;
  }
  return { pages, pageOf };
}

function finishPlanPdf(pages, logo, meta) {
  const total = pages.length, who = normText(meta.clientName || '');
  pages.forEach((ops, i) => {
    if (i > 0) {
      text(ops, 'Bulamu360', ML, 34, 9, true, C.green);
      const right = normText('Personalised Nutrition Plan' + (who ? '  ·  ' + who : ''));
      text(ops, right, PW - MR - textW(right, 8, false), 34, 8, false, C.grey);
      line(ops, ML, 42, PW - MR, 42, C.line, 0.5);
    }
    line(ops, ML, PH - 40, PW - MR, PH - 40, C.line, 0.5);
    text(ops, normText('Bulamu360 · Eat better, live better'), ML, PH - 26, 8, false, C.grey);
    const pg = `Page ${i + 1} of ${total}`; text(ops, pg, PW - MR - textW(pg, 8, false), PH - 26, 8, false, C.grey);
    const disc = 'Dietary guidance only. It does not replace diagnosis, emergency care or your clinician’s advice.';
    if (i === total - 1) text(ops, normText(disc), ML, PH - 14, 6.8, false, '#8a9990');
  });

  return { buffer: serialisePdf(pages, logo, 'Bulamu360 Plan' + (who ? ' - ' + who : '')), pages: total };
}

function serialisePdf(pages, logo, title) {
  const objs = []; const add = s => { objs.push(s); return objs.length; };
  const catalog = add(null), pagesId = add(null);
  const f1 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const f2 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  const f3 = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>');
  const gs = add('<< /Type /ExtGState /ca 0.18 /CA 0.18 >>');
  let img = 0;
  if (logo) {
    let smask = 0;
    if (logo.alpha) smask = add({ dict: `<< /Type /XObject /Subtype /Image /Width ${logo.w} /Height ${logo.h} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length ${logo.alpha.length} >>`, data: logo.alpha });
    img = add({ dict: `<< /Type /XObject /Subtype /Image /Width ${logo.w} /Height ${logo.h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode${smask ? ` /SMask ${smask} 0 R` : ''} /Length ${logo.color.length} >>`, data: logo.color });
  }
  const res = `<< /Font << /F1 ${f1} 0 R /F2 ${f2} 0 R /F3 ${f3} 0 R >> /ExtGState << /GS1 ${gs} 0 R >>${img ? ` /XObject << /Im1 ${img} 0 R >>` : ''} >>`;
  const kids = [];
  for (const ops of pages) {
    const content = deflateSync(Buffer.from(ops.filter(o => !o.includes('gs0')).join('\n'), 'latin1'));
    const c = add({ dict: `<< /Filter /FlateDecode /Length ${content.length} >>`, data: content });
    kids.push(add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 ${PW} ${PH}] /Resources ${res} /Contents ${c} 0 R >>`));
  }
  objs[catalog - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  objs[pagesId - 1] = `<< /Type /Pages /Kids [${kids.map(k => k + ' 0 R').join(' ')}] /Count ${kids.length} >>`;
  const info = add(`<< /Title ${pdfStr(normText(title))} /Author (Bulamu360) /Producer (Bulamu360) >>`);
  const chunks = [Buffer.from('%PDF-1.4\n%\xe2\xe3\xcf\xd3\n', 'latin1')]; let off = chunks[0].length; const xref = [];
  objs.forEach((o, i) => {
    xref.push(off);
    const parts = typeof o === 'string' ? [Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`, 'latin1')] : [Buffer.from(`${i + 1} 0 obj\n${o.dict}\nstream\n`, 'latin1'), o.data, Buffer.from('\nendstream\nendobj\n', 'latin1')];
    parts.forEach(p => { chunks.push(p); off += p.length; });
  });
  const xrefStr = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${xref.map(x => String(x).padStart(10, '0') + ' 00000 n \n').join('')}trailer\n<< /Size ${objs.length + 1} /Root ${catalog} 0 R /Info ${info} 0 R >>\nstartxref\n${off}\n%%EOF\n`;
  chunks.push(Buffer.from(xrefStr, 'latin1'));
  return Buffer.concat(chunks);
}

/* ---------------- Printable tracking templates ---------------- */
const TPL_PALETTE = ['#17693f', '#e2674f', '#2f7fb3', '#8a55b8', '#17a393', '#d9772b'];
const DAY_FIELDS = n => Array.from({ length: n }, (_, i) => i + 1);
export const TEMPLATES = {
  foodLog: { title: '30-Day Food Diary', sub: 'Track every meal to spot patterns and improve your nutrition', file: 'Food_Diary', kind: 'days', cols: 1,
    fields: ['Breakfast (7am)', 'Mid-morning snack (10:30am)', 'Lunch (1pm)', 'Afternoon snack (4pm)', 'Dinner (6:30pm)', 'Energy level (1-10)', 'Notes / how did you feel?'], glasses: 8 },
  sleepLog: { title: '30-Day Sleep Tracker', sub: 'Good sleep supports your metabolism, appetite and mood', file: 'Sleep_Log', kind: 'table',
    headers: ['Day', 'Bedtime', 'Wake time', 'Hours', 'Quality 1-5', 'Mood on waking', 'Notes'], widths: [0.07, 0.13, 0.13, 0.1, 0.13, 0.19, 0.25] },
  activityLog: { title: '30-Day Activity Tracker', sub: 'Connect your movement with your nutrition', file: 'Activity_Log', kind: 'days', cols: 4,
    fields: ['Activity type', 'Duration (min)', 'Intensity 1-5', 'How did you feel?'] },
  hydrationLog: { title: '30-Day Hydration Tracker', sub: 'Tick a glass each time you drink 250 ml. Aim for at least 8.', file: 'Hydration_Log', kind: 'days', cols: 1, fields: ['Notes'], glasses: 10, compact: true },
  symptomLog: { title: '30-Day Symptom Journal', sub: 'Track symptoms to find links with what you eat', file: 'Symptom_Journal', kind: 'days', cols: 2,
    fields: ['Symptoms today', 'Possible food triggers', 'Energy level 1-10', 'Mood 1-10'], premium: true },
  weeklyLog: { title: '4-Week Progress Review', sub: 'Review each week as a whole and plan the next', file: 'Weekly_Progress', kind: 'weeks', cols: 1,
    fields: ['Weight at end of week (kg)', 'Average energy 1-10', 'Average sleep hours per night', 'Exercise days completed', 'Water target hit (days out of 7)', 'Biggest nutrition win this week', 'Biggest challenge this week', 'One thing to improve next week', 'How do I feel overall?'], premium: true }
};

export function templatePdf(id, meta = {}) {
  const t = TEMPLATES[id]; if (!t) throw new Error('Unknown template');
  const logo = meta.logoPath ? loadLogo(meta.logoPath) : null;
  const pages = [[]]; let y = 0;
  const bottom = PH - BOTTOM;
  const newPage = () => { pages.push([]); y = TOP; };
  const ops = () => pages[pages.length - 1];
  // Header band
  const H = 170;
  rect(ops(), 0, 0, PW, H, C.forest);
  ops().push(`q 0 ${(PH - H).toFixed(2)} ${PW} ${H} re W n /GS1 gs`, rgb('#2a8a58')); circle(ops(), PW - 60, 40, 110); circle(ops(), PW - 170, H + 10, 60); ops().push('Q');
  rect(ops(), ML, 26, 108, 60, C.white, null, 11);
  if (logo) { const iw = 90, ih = iw * logo.h / logo.w; ops().push('q', `${iw} 0 0 ${ih.toFixed(2)} ${ML + 9} ${(PH - 26 - 30 - ih / 2).toFixed(2)} cm`, '/Im1 Do', 'Q'); }
  else text(ops(), 'Bulamu360', ML + 12, 62, 16, true, C.forest);
  text(ops(), 'TRACKING TEMPLATE', ML + 124, 50, 8.5, true, '#bfe8d0');
  text(ops(), 'Bulamu360 · Eat better, live better', ML + 124, 66, 9.5, false, '#e6f5ec', true);
  text(ops(), normText(t.title), ML, 122, 26, true, C.white);
  text(ops(), normText(t.sub), ML, 144, 11, false, '#d8efe2');
  y = H + 18;
  // Name / start date
  const half = (CW - 16) / 2;
  [['NAME', 0], ['START DATE', half + 16]].forEach(([l, dx]) => { text(ops(), l, ML + dx, y + 8, 7.5, true, C.grey); line(ops(), ML + dx, y + 26, ML + dx + half, y + 26, C.line, 0.8); });
  y += 42;

  const dashed = (x1, yy, x2) => ops().push(rgb('#b9d2c3', true), '0.8 w', '[3 3] 0 d', `${x1.toFixed(2)} ${Y(yy)} m ${x2.toFixed(2)} ${Y(yy)} l S`, '[] 0 d');
  if (t.kind === 'table') {
    const widths = t.widths.map(w => w * CW), rowH = 21;
    const head = () => { rect(ops(), ML, y, CW, 24, C.green, null, 6); let x = ML; t.headers.forEach((h, k) => { text(ops(), normText(h), x + 6, y + 15.5, 8.5, true, C.white); x += widths[k]; }); y += 26; };
    head();
    for (let d = 1; d <= 30; d++) {
      if (y + rowH > bottom) { newPage(); head(); }
      if (d % 2 === 0) rect(ops(), ML, y, CW, rowH, C.mint2);
      text(ops(), String(d), ML + 8, y + 14, 9, true, C.forest);
      let x = ML + widths[0]; for (let k = 1; k < widths.length; k++) { dashed(x + 5, y + 16, x + widths[k] - 5); x += widths[k]; }
      line(ops(), ML, y + rowH, ML + CW, y + rowH, C.line, 0.4);
      y += rowH;
    }
  } else {
    const count = t.kind === 'weeks' ? 4 : 30;
    const cols = t.cols || 1, colW = (CW - 28 - (cols - 1) * 14) / cols;
    const rows = Math.ceil(t.fields.length / cols);
    const fieldH = t.compact ? 26 : 30;
    const cardH = 30 + rows * fieldH + (t.glasses ? 30 : 0) + 8;
    for (let d = 1; d <= count; d++) {
      if (y + cardH > bottom) newPage();
      const c = TPL_PALETTE[(d - 1) % TPL_PALETTE.length];
      rect(ops(), ML, y, CW, cardH, C.white, C.line, 10);
      rect(ops(), ML, y + 1, 4, cardH - 2, c, null, 2);
      text(ops(), (t.kind === 'weeks' ? 'Week ' : 'Day ') + d, ML + 16, y + 20, 11.5, true, c);
      let fy = y + 30;
      if (t.glasses) {
        text(ops(), 'WATER', ML + 16, fy + 13, 7.2, true, C.grey);
        for (let g = 0; g < t.glasses; g++) { ops().push(rgb('#8cc6e8', true), '1 w'); const cx = ML + 70 + g * 22, cy = fy + 10; ops().push(`${cx + 7} ${Y(cy)} m ${cx + 7} ${(PH - cy + 3.9).toFixed(2)} ${cx + 3.9} ${(PH - cy + 7).toFixed(2)} ${cx} ${(PH - cy + 7).toFixed(2)} c ${cx - 3.9} ${(PH - cy + 7).toFixed(2)} ${cx - 7} ${(PH - cy + 3.9).toFixed(2)} ${cx - 7} ${Y(cy)} c ${cx - 7} ${(PH - cy - 3.9).toFixed(2)} ${cx - 3.9} ${(PH - cy - 7).toFixed(2)} ${cx} ${(PH - cy - 7).toFixed(2)} c ${cx + 3.9} ${(PH - cy - 7).toFixed(2)} ${cx + 7} ${(PH - cy - 3.9).toFixed(2)} ${cx + 7} ${Y(cy)} c S`); }
        fy += 30;
      }
      t.fields.forEach((f, k) => {
        const col = k % cols, row = Math.floor(k / cols), fx = ML + 16 + col * (colW + 14), yy = fy + row * fieldH;
        text(ops(), normText(f.toUpperCase()), fx, yy + 9, 7, true, C.grey);
        dashed(fx, yy + fieldH - 6, fx + colW);
      });
      y += cardH + 10;
    }
  }
  const total = pages.length;
  pages.forEach((o, i) => {
    if (i > 0) { text(o, 'Bulamu360', ML, 34, 9, true, C.green); const r = normText(t.title); text(o, r, PW - MR - textW(r, 8, false), 34, 8, false, C.grey); line(o, ML, 42, PW - MR, 42, C.line, 0.5); }
    line(o, ML, PH - 40, PW - MR, PH - 40, C.line, 0.5);
    text(o, normText('Bulamu360 by Breyer Naula, RDN · +256 704392545'), ML, PH - 26, 8, false, C.grey);
    const pg = `Page ${i + 1} of ${total}`; text(o, pg, PW - MR - textW(pg, 8, false), PH - 26, 8, false, C.grey);
  });
  return serialisePdf(pages, logo, t.title + ' - Bulamu360');
}

/* ---------------- Minimal ZIP writer (stored entries) ---------------- */
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
export function zipFiles(files) { // [{ name, data: Buffer }]
  const parts = [], central = []; let offset = 0;
  const now = new Date(), dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1), dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8'), crc = crc32(f.data), size = f.data.length;
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(0, 8); local.writeUInt16LE(dosTime, 10); local.writeUInt16LE(dosDate, 12); local.writeUInt32LE(crc, 14); local.writeUInt32LE(size, 18); local.writeUInt32LE(size, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
    parts.push(local, name, f.data);
    const cen = Buffer.alloc(46); cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0x0800, 8); cen.writeUInt16LE(0, 10); cen.writeUInt16LE(dosTime, 12); cen.writeUInt16LE(dosDate, 14); cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(size, 20); cen.writeUInt32LE(size, 24); cen.writeUInt16LE(name.length, 28); cen.writeUInt32LE(offset, 42);
    central.push(cen, name);
    offset += 30 + name.length + size;
  }
  const cenBuf = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cenBuf.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cenBuf, end]);
}
