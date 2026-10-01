import http from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { scrypt as scryptCb } from 'node:crypto';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import net from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { planPdfFromHtml, templatePdf, zipFiles, TEMPLATES } from './lib/plan-pdf.js';

const root = fileURLToPath(new URL('.', import.meta.url));
const dataDir = join(root, 'data');
const dbPath = join(dataDir, 'orders.json');
const adminLoginTemplatePath = join(root, 'admin-login.html');
const adminDashboardTemplatePath = join(root, 'admin-dashboard.html');
const privateRecipePath = join(root, 'recipes.js');
const sessions = new Map();

const envPath = join(root, '.env');
if (existsSync(envPath)) {
  const envText = readFileSync(envPath, 'utf8');
  for (const line of envText.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const eq = trimmed.indexOf('=');
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}

const port = Number(process.env.PORT || 8787);
const apiKey = process.env.RESEND_API_KEY || '';
const fromEmail = process.env.FROM_EMAIL || 'Bulamu360 <onboarding@resend.dev>';
const ownerEmail = process.env.OWNER_EMAIL || 'breyernaula5@gmail.com';
const publicBaseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${port}`;
const isProduction = process.env.NODE_ENV === 'production' || process.env.RENDER || process.env.RAILWAY_ENVIRONMENT;
const localAdminPassword = 'Bulamu360Admin2026!';
const adminPassword = process.env.ADMIN_PASSWORD || (isProduction ? '' : localAdminPassword);
const supabaseUrl = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const supabaseStateTable = process.env.SUPABASE_STATE_TABLE || 'bulamu_app_state';
const supabaseStateKey = process.env.SUPABASE_STATE_KEY || 'orders';
const appVersion = process.env.APP_VERSION || 'bulamu360-2026.06';
const rateLimits = new Map();
const weakAdminPasswords = new Set(['', 'change_this_admin_password', localAdminPassword]);
if (isProduction && weakAdminPasswords.has(adminPassword)) {
  throw new Error('ADMIN_PASSWORD must be set to a strong value before deploying Bulamu360.');
}
if (isProduction && !String(process.env.FROM_EMAIL || '').trim()) {
  throw new Error('FROM_EMAIL must be set to your verified Resend sender before deploying Bulamu360.');
}
if (isProduction && (!supabaseUrl || !supabaseServiceRoleKey)) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required in production so orders are not stored on temporary server disk.');
}
const allowedOrigins = String(process.env.ALLOWED_ORIGINS || process.env.CORS_ORIGIN || publicBaseUrl)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const corsOrigin = isProduction ? allowedOrigins[0] : '*';

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};

if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
if (!existsSync(dbPath)) writeFileSync(dbPath, JSON.stringify({ orders: [] }, null, 2));
let dbCache = null;
let supabaseWriteQueue = Promise.resolve();

function securityHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    // camera/microphone allowed for this site only: barcode scanning and voice food logging in the tracker.
    'Permissions-Policy': 'camera=(self), microphone=(self), geolocation=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'self'",
      "img-src 'self' data: blob: https:",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
      // Tracker food lookups: Open Food Facts (barcodes/packaged foods) and USDA FoodData Central (when a personal key is set).
      "connect-src 'self' https://world.openfoodfacts.org https://api.nal.usda.gov"
    ].join('; '),
    'Cache-Control': 'no-store',
    ...extra
  };
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': res._corsOrigin || corsOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin'
  });
  res.end(JSON.stringify(data));
}

function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, securityHeaders({ 'Content-Type': 'text/html; charset=utf-8', ...headers }));
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(302, securityHeaders({ Location: location }));
  res.end();
}

function clientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}

function rateLimit(req, res, name, { limit = 30, windowMs = 60_000 } = {}) {
  const now = Date.now();
  const key = `${name}:${clientIp(req)}`;
  const bucket = rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
  if (bucket.resetAt <= now) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }
  bucket.count += 1;
  rateLimits.set(key, bucket);
  if (bucket.count <= limit) return true;
  sendJson(res, 429, { ok: false, error: 'Too many attempts. Please wait a minute and try again.' });
  return false;
}

function healthPayload() {
  return {
    ok: true,
    app: 'Bulamu360',
    version: appVersion,
    storage: supabaseEnabled() ? 'supabase' : 'local-json',
    emailConfigured: Boolean(apiKey && fromEmail && ownerEmail),
    ownerEmailConfigured: Boolean(ownerEmail),
    publicBaseUrl,
    allowedOrigins,
    supabaseStateTable,
    supabaseStateKey,
    security: {
      adminPasswordSet: Boolean(adminPassword && !weakAdminPasswords.has(adminPassword)),
      productionMode: Boolean(isProduction),
      sameOriginAdminPostGuard: true,
      privateStaticFilesBlocked: true
    },
    time: new Date().toISOString()
  };
}

function requestHost(req) {
  return String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().toLowerCase();
}

function requestProtocol(req) {
  return String(req.headers['x-forwarded-proto'] || (isProduction ? 'https' : 'http')).split(',')[0].trim().toLowerCase();
}

function sameOriginUrl(req) {
  const host = requestHost(req);
  return host ? `${requestProtocol(req)}://${host}` : '';
}

function corsOriginForRequest(req) {
  if (!isProduction) return '*';
  const origin = String(req.headers.origin || '').trim().replace(/\/+$/, '');
  if (!origin) return corsOrigin;
  const allowed = new Set([
    ...allowedOrigins.map(x => String(x || '').replace(/\/+$/, '')),
    publicBaseUrl.replace(/\/+$/, ''),
    sameOriginUrl(req).replace(/\/+$/, '')
  ].filter(Boolean));
  if (!allowed.has(origin)) {
    console.warn('[cors] blocked-or-mismatched origin', {
      origin,
      fallback: corsOrigin,
      path: req.url || '',
      host: requestHost(req)
    });
  }
  return allowed.has(origin) ? origin : corsOrigin;
}

function verifySameOriginPost(req, res) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method || '')) return true;
  const expected = sameOriginUrl(req);
  const source = String(req.headers.origin || req.headers.referer || '').trim();
  if (!expected || (!source && !isProduction)) return true;
  if (source && source.toLowerCase().startsWith(expected.toLowerCase())) return true;
  sendHtml(res, 403, 'Security check failed. Please reload the admin page and try again.');
  return false;
}

function validateDbShape(db) {
  if (!db || typeof db !== 'object') return { orders: [], leads: [], progressEntries: [], foodDiary: [] };
  if (!Array.isArray(db.orders)) db.orders = [];
  if (!Array.isArray(db.leads)) db.leads = [];
  if (!Array.isArray(db.progressEntries)) db.progressEntries = [];
  if (!Array.isArray(db.foodDiary)) db.foodDiary = [];
  if (!Array.isArray(db.recipeReplacementReviews)) db.recipeReplacementReviews = [];
  return db;
}

function renderTemplate(filePath, values = {}) {
  let html = readFileSync(filePath, 'utf8');
  for (const [key, value] of Object.entries(values)) {
    html = html.replaceAll(`{{${key}}}`, String(value ?? ''));
  }
  return html;
}

async function readRequestBody(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 10_000_000) throw new Error('Request too large');
  }
  return body;
}

async function readRequestJson(req) {
  return JSON.parse((await readRequestBody(req)) || '{}');
}

async function readForm(req) {
  const body = await readRequestBody(req);
  return Object.fromEntries(new URLSearchParams(body));
}

function readLocalDb() {
  try {
    return validateDbShape(JSON.parse(readFileSync(dbPath, 'utf8')));
  } catch {
    return { orders: [], leads: [], progressEntries: [], foodDiary: [] };
  }
}

function readDb() {
  if (!dbCache) dbCache = readLocalDb();
  return dbCache;
}

function writeDb(db) {
  db = validateDbShape(db);
  dbCache = db;
  writeFileSync(dbPath, JSON.stringify(db, null, 2));
  if (supabaseEnabled()) {
    supabaseWriteQueue = supabaseWriteQueue
      .then(() => writeSupabaseState(db))
      .catch(err => console.error('Supabase write failed:', err.message));
  }
}

function supabaseEnabled() {
  return Boolean(supabaseUrl && supabaseServiceRoleKey);
}

function supabaseHeaders(extra = {}) {
  return {
    apikey: supabaseServiceRoleKey,
    Authorization: `Bearer ${supabaseServiceRoleKey}`,
    'Content-Type': 'application/json',
    ...extra
  };
}

async function readSupabaseState() {
  const endpoint = `${supabaseUrl}/rest/v1/${encodeURIComponent(supabaseStateTable)}?key=eq.${encodeURIComponent(supabaseStateKey)}&select=state`;
  const response = await fetch(endpoint, { headers: supabaseHeaders() });
  if (!response.ok) throw new Error(`Supabase read failed with ${response.status}`);
  const rows = await response.json();
  const state = rows && rows[0] && rows[0].state;
  return state && typeof state === 'object' ? validateDbShape(state) : null;
}

async function writeSupabaseState(db) {
  db = validateDbShape(db);
  const endpoint = `${supabaseUrl}/rest/v1/${encodeURIComponent(supabaseStateTable)}?on_conflict=key`;
  const payload = [{
    key: supabaseStateKey,
    state: db,
    updated_at: new Date().toISOString()
  }];
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: supabaseHeaders({ Prefer: 'resolution=merge-duplicates' }),
    body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`Supabase write failed with ${response.status}`);
}

async function initialiseStorage() {
  const localDb = readLocalDb();
  dbCache = localDb;
  if (!supabaseEnabled()) return;
  const remoteDb = await readSupabaseState().catch(err => {
    console.error('Supabase read failed; using local JSON cache:', err.message);
    return null;
  });
  if (remoteDb && Array.isArray(remoteDb.orders)) {
    dbCache = remoteDb;
    writeFileSync(dbPath, JSON.stringify(remoteDb, null, 2));
    return;
  }
  await writeSupabaseState(localDb).catch(err => {
    console.error('Supabase initial seed failed:', err.message);
  });
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function shortText(value, max = 120) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function toNumber(value) {
  const n = Number(String(value ?? '').replace(/[^\d.-]/g, ''));
  return Number.isFinite(n) ? n : null;
}

function avg(values) {
  const nums = values.map(toNumber).filter(n => n !== null);
  if (!nums.length) return null;
  return nums.reduce((sum, n) => sum + n, 0) / nums.length;
}

function fmtNumber(value, digits = 1) {
  return value === null || value === undefined || Number.isNaN(value) ? '-' : Number(value).toFixed(digits);
}

function increment(map, key, by = 1) {
  const clean = String(key || '').trim() || 'Not captured';
  map.set(clean, (map.get(clean) || 0) + by);
}

function topEntries(map, limit = 8) {
  return Array.from(map.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit);
}

function splitSignals(value) {
  return String(value || '')
    .split(/\r?\n|,|;|\|/)
    .map(x => x.replace(/^(and|also|plus)\s+/i, '').trim())
    .filter(x => x.length >= 3);
}

function nl2br(value) {
  return escapeHtml(value).replace(/\r?\n/g, '<br>');
}

function constantTimeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return timingSafeEqual(aa, bb);
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || '';
  for (const part of cookie.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return '';
}

function isAdmin(req) {
  const sid = getCookie(req, 'bulamu_admin');
  const session = sid && sessions.get(sid);
  if (!session) return false;
  if (session.expires <= Date.now()) {
    sessions.delete(sid);
    return false;
  }
  session.lastSeen = Date.now();
  return true;
}

function requireAdmin(req, res) {
  if (isAdmin(req)) return true;
  redirect(res, '/admin/login');
  return false;
}

function adminSessionCookie(sid, maxAge = 43200) {
  const secure = isProduction ? '; Secure' : '';
  return `bulamu_admin=${encodeURIComponent(sid || '')}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function memberSessionCookie(sid, maxAge = 60 * 60 * 24 * 30) {
  const secure = isProduction ? '; Secure' : '';
  return `bulamu_member=${encodeURIComponent(sid || '')}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function getMemberSession(req) {
  const sid = getCookie(req, 'bulamu_member');
  const session = sid && sessions.get(`member:${sid}`);
  if (!session) return null;
  if (session.expires <= Date.now()) {
    sessions.delete(`member:${sid}`);
    return null;
  }
  session.lastSeen = Date.now();
  return session;
}

function requireMember(req, res) {
  const session = getMemberSession(req);
  if (session) return session;
  redirect(res, '/?signin=1');
  return null;
}

function auditAdminAction(db, req, action, details = {}) {
  db.auditLog = Array.isArray(db.auditLog) ? db.auditLog : [];
  const cleanDetails = { ...details };
  for (const key of ['htmlContent', 'finalHtmlPlan', 'htmlPlan', 'password', 'apiKey', 'token']) {
    if (key in cleanDetails) cleanDetails[key] = '[redacted]';
  }
  db.auditLog.unshift({
    at: new Date().toISOString(),
    action,
    ip: clientIp(req),
    userAgent: shortText(req.headers['user-agent'] || '', 180),
    path: String(req.url || '').split('?')[0],
    details: cleanDetails
  });
  db.auditLog = db.auditLog.slice(0, 1000);
}

function auditSummary(db = readDb()) {
  const log = Array.isArray(db.auditLog) ? db.auditLog : [];
  return {
    count: log.length,
    latest: log[0] || null,
    recentSensitiveActions: log.slice(0, 50).filter(x => /approve|reject|delete|edit|resend|followup/i.test(x.action || '')).length
  };
}

function makeApprovalCode() {
  return `BUL-${randomBytes(3).toString('hex').toUpperCase()}-${randomBytes(2).toString('hex').toUpperCase()}`;
}

function makeDownloadToken() {
  return randomBytes(24).toString('hex');
}

function makeFollowupToken() {
  return randomBytes(24).toString('hex');
}

function makeOrderId() {
  return `ord_${Date.now().toString(36)}_${randomBytes(4).toString('hex')}`;
}

let privateRecipeCache = null;

function loadPrivateRecipes() {
  if (privateRecipeCache) return privateRecipeCache;
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(privateRecipePath, 'utf8'), sandbox, {
    filename: 'recipes.js',
    timeout: 1000
  });
  privateRecipeCache = {
    schema: sandbox.window.BULAMU_RECIPE_SCHEMA || {},
    recipes: Array.isArray(sandbox.window.BULAMU_RECIPES) ? sandbox.window.BULAMU_RECIPES : [],
    swaps: sandbox.window.BULAMU_SWAP_TABLES || {}
  };
  return privateRecipeCache;
}

function profileFromRecipeRequest(payload = {}) {
  const conds = Array.isArray(payload.conds) ? payload.conds.map(x => String(x).toLowerCase()) : [];
  const text = [
    payload.goal,
    payload.plantype,
    payload.cat,
    payload.activity,
    payload.symptoms,
    payload.diagnosis,
    payload.allergies,
    ...conds
  ].join(' ').toLowerCase();
  return {
    conds,
    text,
    goal: String(payload.goal || '').toLowerCase(),
    plantype: String(payload.plantype || '').toLowerCase(),
    cat: String(payload.cat || '').toLowerCase(),
    activity: String(payload.activity || '').toLowerCase(),
    budget: String(payload.budget || '').toLowerCase(),
    cooking: String(payload.cooking || '').toLowerCase(),
    allergies: String(payload.allergies || '').toLowerCase(),
    notes: String(payload.notes || payload.preferences || payload.foodPreferences || '').toLowerCase(),
    hasDiabetes: conds.includes('diabetes') || text.includes('diabetes'),
    hasHyper: conds.includes('hypertension') || text.includes('hypertension'),
    hasKidney: conds.includes('kidney') || text.includes('kidney'),
    hasGout: conds.includes('gout') || text.includes('gout'),
    hasCholesterol: conds.includes('cholesterol') || text.includes('cholesterol'),
    hasPMOS: conds.includes('pmos') || conds.includes('pcos') || text.includes('pmos') || text.includes('pcos'),
    hasIBS: conds.includes('ibs') || text.includes('ibs') || text.includes('gut'),
    isPrenatal: text.includes('prenatal') || text.includes('pregnan'),
    isChild: text.includes('child'),
    isFamily: text.includes('family'),
    isOver: text.includes('over') || text.includes('obese') || text.includes('weight_loss'),
    isUnder: text.includes('under')
  };
}

function profileAvoidTerms(profile = {}) {
  const raw = [
    profile.allergies,
    profile.notes
  ].filter(Boolean).join(' ').toLowerCase();
  if (!raw || /none|no allergy|no allergies|not captured|n\/a/.test(raw)) return [];
  const known = [
    'egg', 'eggs', 'milk', 'dairy', 'yogurt', 'groundnut', 'groundnuts', 'peanut', 'peanuts',
    'fish', 'mukene', 'tilapia', 'tuna', 'sardine', 'chicken', 'beef', 'pork',
    'beans', 'cowpeas', 'lentils', 'chickpea', 'soy', 'tofu', 'gluten', 'wheat',
    'banana', 'avocado', 'cabbage', 'tomato', 'onion', 'garlic', 'ginger',
    'nuts', 'tree nuts', 'sesame'
  ];
  const terms = new Set();
  known.forEach(term => {
    if (raw.includes(term)) terms.add(term);
  });
  raw.split(/[,;|/]+/).map(x => x.trim().toLowerCase()).filter(Boolean).forEach(part => {
    const cleaned = part.replace(/\b(allergy|allergic|avoid|dislike|hate|cannot eat|does not eat|don't eat|do not eat|intolerant|intolerance|sensitive|sensitivity|to|and)\b/g, ' ').replace(/\s+/g, ' ').trim();
    if (cleaned && cleaned.length >= 3 && cleaned.length <= 24 && !/none|unknown|prefer/.test(cleaned)) terms.add(cleaned);
  });
  return Array.from(terms);
}

function privateRecipeAllowed(recipe, profile) {
  const avoid = Array.isArray(recipe.avoid) ? recipe.avoid.map(x => String(x).toLowerCase()) : [];
  const tags = Array.isArray(recipe.tags) ? recipe.tags.map(x => String(x).toLowerCase()) : [];
  const allergens = Array.isArray(recipe.allergens) ? recipe.allergens.map(x => String(x).toLowerCase()) : [];
  const text = [recipe.name, recipe.method, recipe.why, recipe.portion, ...(recipe.ingredients || []), ...tags, ...allergens].join(' ').toLowerCase();
  const avoidTerms = profileAvoidTerms(profile);
  if (profile.hasDiabetes && (avoid.includes('diabetes') || avoid.includes('diabetes_strict'))) return false;
  if (profile.hasKidney && (avoid.includes('kidney') || avoid.includes('kidney_review'))) return false;
  if (profile.hasGout && avoid.includes('gout')) return false;
  if (profile.hasCholesterol && (avoid.includes('cholesterol') || avoid.includes('cholesterol_strict'))) return false;
  if (profile.hasIBS && (avoid.includes('ibs') || avoid.includes('gut_sensitive'))) return false;
  if (profile.isPrenatal && avoid.includes('pregnancy')) return false;
  if (profile.hasKidney && /avocado|banana|sweet potato|dodo|nakati|sukuma|spinach|beans|lentil|mukene|groundnut/.test(text)) return false;
  if (avoidTerms.some(term => text.includes(term))) return false;
  return true;
}

function privateRecipeScore(recipe, profile) {
  const tags = Array.isArray(recipe.tags) ? recipe.tags.map(x => String(x).toLowerCase()) : [];
  const quality = recipe.quality || {};
  let score = Number(quality.overallScore || 0);
  if (recipe.reviewStatus === 'approved') score += 5;
  if (recipe.reviewStatus === 'dietician-reviewed') score += 4;
  if (recipe.reviewStatus === 'client-tested') score += 3;
  if (recipe.reviewStatus === 'needs-dietician-review') score -= 20;
  if (profile.hasDiabetes && tags.includes('diabetes')) score += 8;
  if (profile.hasKidney && tags.includes('kidney_review')) score += 8;
  if (profile.hasIBS && (tags.includes('ibs') || tags.includes('gut'))) score += 8;
  if (profile.hasPMOS && (tags.includes('pmos') || tags.includes('pcos'))) score += 8;
  if (profile.isPrenatal && (tags.includes('pregnancy') || tags.includes('prenatal'))) score += 8;
  if (profile.isChild && (tags.includes('child') || tags.includes('family'))) score += 7;
  if (profile.budget === 'low' && (recipe.cost === 'Low' || tags.includes('budget'))) score += 6;
  if (profile.cooking === 'limited' && Number(recipe.time || 99) <= 15) score += 4;
  if (tags.includes('salad') || tags.includes('smoothie') || tags.includes('soup')) score += 2;
  return score;
}

function recipeTags(recipe = {}) {
  return Array.isArray(recipe.tags) ? recipe.tags.map(x => String(x).toLowerCase()) : [];
}

function recipeText(recipe = {}) {
  return [
    recipe.name,
    recipe.method,
    recipe.why,
    recipe.portion,
    recipe.culinary && recipe.culinary.flavourBase,
    ...(recipe.ingredients || []),
    ...(recipe.tasteProfile || []),
    ...recipeTags(recipe)
  ].filter(Boolean).join(' ').toLowerCase();
}

function hasRecipeTerm(recipe, terms) {
  const text = recipeText(recipe);
  return terms.some(term => text.includes(term));
}

function recipeCategory(recipe = {}) {
  const tags = recipeTags(recipe);
  if (tags.includes('smoothie') || hasRecipeTerm(recipe, ['smoothie'])) return 'smoothie';
  if (tags.includes('salad') || hasRecipeTerm(recipe, ['salad', 'bowl', 'slaw', 'lettuce'])) return 'salad_bowl';
  if (tags.includes('soup') || hasRecipeTerm(recipe, ['soup', 'broth'])) return 'soup_light';
  if (hasRecipeTerm(recipe, ['egg', 'fish', 'tilapia', 'mukene', 'chicken', 'sardine', 'tuna'])) return 'high_protein';
  if (hasRecipeTerm(recipe, ['beans', 'cowpeas', 'lentils', 'chickpea'])) return 'legume';
  if (hasRecipeTerm(recipe, ['matooke', 'millet', 'sorghum', 'sweet potato', 'cassava', 'posho', 'maize meal', 'rice'])) return 'cooked_staple';
  if (hasRecipeTerm(recipe, ['yogurt', 'milk'])) return 'yogurt';
  return 'balanced';
}

function isSmoothieLike(recipe = {}) {
  return recipeCategory(recipe) === 'smoothie' || hasRecipeTerm(recipe, ['smoothie', 'blend ', 'blended drink']);
}

function isEggRecipe(recipe = {}) {
  return recipeProteinFamily(recipe) === 'egg' || hasRecipeTerm(recipe, ['egg', 'eggs']);
}

function hasMealRealismProblem(recipe = {}, meal = '') {
  const text = recipeText(recipe);
  if (meal === 'breakfast' && /cabbage.*yogurt|yogurt.*cabbage/.test(text)) return true;
  if (meal === 'breakfast' && /papaya.*porridge|porridge.*papaya|pawpaw.*porridge|porridge.*pawpaw/.test(text)) return true;
  if ((meal === 'lunch' || meal === 'dinner') && /smoothie|yogurt cup|fruit cup/.test(text)) return true;
  if ((meal === 'lunch' || meal === 'dinner') && /porridge/.test(text)) return true;
  if (meal === 'dinner' && /fruit|papaya|mango|banana/.test(text) && !/stew|soup|chicken|fish|beans|cowpeas|lentils/.test(text)) return true;
  return false;
}

function mealRealismScore(recipe = {}, meal = '') {
  const text = recipeText(recipe);
  const category = recipeCategory(recipe);
  let score = 0;
  if (hasMealRealismProblem(recipe, meal)) score -= 80;
  if (meal === 'breakfast') {
    if (/porridge/.test(text) && /egg|milk|yogurt|groundnut|beans/.test(text)) score += 8;
    if (/katogo|sweet potato|matooke|sorghum|millet|egg|beans|yogurt/.test(text)) score += 7;
    if (category === 'salad_bowl') score -= 24;
    if (category === 'smoothie') score -= 8;
  }
  if (meal === 'lunch') {
    if (/matooke|rice|sweet potato|millet|posho|cassava|beans|cowpeas|chicken|fish|tilapia|greens|dodo|nakati|sukuma|cabbage|stew/.test(text)) score += 12;
    if (category === 'smoothie' || category === 'yogurt') score -= 90;
    if (/fruit|papaya|mango|banana/.test(text) && !/chicken|fish|beans|cowpeas|lentils|salad|bowl/.test(text)) score -= 35;
  }
  if (meal === 'dinner') {
    if (/soup|stew|greens|vegetable|fish|chicken|beans|cowpeas|pumpkin|cabbage|nakati|dodo|sukuma/.test(text)) score += 12;
    if (/heavy|large/.test(text)) score -= 8;
    if (category === 'smoothie' || category === 'yogurt') score -= 90;
  }
  if (meal === 'snack') {
    if (/smoothie|fruit|yogurt|groundnut|cucumber|carrot|tomato/.test(text)) score += 8;
    if (/matooke|posho|rice|full plate|katogo/.test(text)) score -= 18;
  }
  return score;
}

function recipeProteinFamily(recipe = {}) {
  if (hasRecipeTerm(recipe, ['egg'])) return 'egg';
  if (hasRecipeTerm(recipe, ['fish', 'tilapia', 'mukene', 'sardine', 'tuna'])) return 'fish';
  if (hasRecipeTerm(recipe, ['chicken'])) return 'chicken';
  if (hasRecipeTerm(recipe, ['beans', 'cowpeas', 'lentils', 'chickpea'])) return 'legume';
  if (hasRecipeTerm(recipe, ['yogurt', 'milk'])) return 'dairy';
  if (hasRecipeTerm(recipe, ['groundnut', 'peanut'])) return 'groundnut';
  return 'other';
}

function recipeFlavourFamily(recipe = {}) {
  const base = String(recipe.culinary && (recipe.culinary.flavourBase || recipe.culinary.sauce) || '').toLowerCase();
  if (base) return base;
  if (hasRecipeTerm(recipe, ['ginger'])) return 'ginger';
  if (hasRecipeTerm(recipe, ['lemon', 'lime'])) return 'lemon';
  if (hasRecipeTerm(recipe, ['groundnut', 'peanut'])) return 'groundnut';
  if (hasRecipeTerm(recipe, ['tomato'])) return 'tomato';
  if (hasRecipeTerm(recipe, ['yogurt'])) return 'yogurt';
  return 'simple';
}

function desiredMealCategory(meal, index, profile = {}) {
  const breakfast = profile.hasKidney
    ? ['high_protein', 'cooked_staple', 'yogurt', 'high_protein', 'cooked_staple', 'balanced', 'high_protein']
    : ['cooked_staple', 'high_protein', 'yogurt', 'cooked_staple', 'high_protein', 'balanced', 'smoothie'];
  const lunch = ['cooked_staple', 'salad_bowl', 'high_protein', 'legume', 'salad_bowl', 'cooked_staple', 'high_protein'];
  const dinner = ['soup_light', 'cooked_staple', 'soup_light', 'high_protein', 'legume', 'soup_light', 'cooked_staple'];
  const snack = profile.hasKidney
    ? ['high_protein', 'balanced', 'yogurt', 'balanced', 'high_protein', 'balanced', 'yogurt', 'balanced', 'high_protein', 'balanced', 'yogurt', 'balanced', 'high_protein', 'balanced']
    : ['yogurt', 'fresh', 'high_protein', 'balanced', 'salad_bowl', 'yogurt', 'fresh', 'high_protein', 'balanced', 'salad_bowl', 'yogurt', 'smoothie', 'high_protein', 'balanced'];
  const table = { breakfast, lunch, dinner, snack };
  const list = table[meal] || ['balanced'];
  return list[index % list.length];
}

function recipeCulinaryBoost(recipe = {}) {
  const quality = recipe.quality || {};
  const culinary = recipe.culinary || {};
  const practical = recipe.practical || {};
  let boost = 0;
  boost += Number(quality.flavourScore || culinary.tasteIntensity || 7) * 0.8;
  boost += Number(quality.repeatAppealScore || culinary.repeatAppeal || 7) * 0.7;
  boost += Number(quality.practicalityScore || practical.costScore || 7) * 0.45;
  boost += Number(culinary.familyAcceptance || 7) * 0.35;
  if (quality.repeatRisk === 'high') boost -= 7;
  if (quality.recommendationTier === 'default') boost += 3;
  if (quality.recommendationTier === 'use-selectively') boost -= 4;
  return boost;
}

function fallbackRecipe(meal, id, name, tags, ingredients, method, why, portion, tasteProfile, substitutions = [], extra = {}) {
  const recipe = {
    id,
    meal,
    name,
    tags,
    avoid: extra.avoid || [],
    time: extra.time || 10,
    cost: extra.cost || 'Low',
    ingredients,
    method,
    why,
    portion,
    tasteProfile,
    suitability: extra.suitability || {},
    cautions: extra.cautions || [],
    allergens: extra.allergens || [],
    substitutions,
    nutrition: extra.nutrition || { energy: 'moderate', protein: 'moderate', fibre: 'moderate', glycaemicLoad: 'low to moderate', sodium: 'low' },
    practicality: extra.practicality || { budget: 'low', equipment: 'none', batchCook: false, marketAccess: 'common' },
    culinary: {
      flavourBase: extra.flavourBase || 'fresh simple flavour',
      texture: extra.texture || ['fresh'],
      tasteIntensity: extra.tasteIntensity || 7.2,
      familyAcceptance: extra.familyAcceptance || 7.5,
      repeatAppeal: extra.repeatAppeal || 7.4,
      presentation: extra.presentation || 'simple plate or cup'
    },
    practical: { marketAvailability: 8, cookingSkill: 2, costScore: 8, prepBurden: 2, localAvailability: 'high' },
    feedback: { repeatComplaints: 0, dislikedCount: 0 },
    quality: { overallScore: extra.overallScore || 8, flavourScore: 7.5, practicalityScore: 8.5, affordabilityScore: 8, availabilityScore: 8, familyAcceptanceScore: 7.5, repeatAppealScore: 7.4, repeatRisk: 'low', recommendationTier: 'default' },
    reviewStatus: 'dietician-reviewed',
    clinicalReview: 'Fallback culinary-dietician option for variety when allergies, dislikes, or clinical restrictions narrow the main recipe pool.',
    clinicalNote: extra.clinicalNote || ''
  };
  return recipe;
}

function fallbackRecipesForMeal(meal, profile = {}) {
  const options = {
    snack: [
      fallbackRecipe('snack', 'fb_sn_cucumber_lime', 'Cucumber Lime Crunch Cup', ['snack', 'budget', 'diabetes', 'fresh'], ['cucumber', 'lime or lemon', 'pinch of roasted cumin optional'], 'Slice cucumber and dress with lemon. Add cumin if liked. Do not add table salt.', 'Very low glycaemic, refreshing, cheap, and useful when heavier snacks are not suitable.', '1 to 2 cups cucumber slices.', ['crisp', 'zesty', 'refreshing'], ['Use carrot sticks if cucumber is unavailable', 'Use tomato wedges if tolerated'], { flavourBase: 'fresh lemon-herb', texture: ['crunchy'], avoid: ['kidney_review'] }),
      fallbackRecipe('snack', 'fb_sn_guava_groundnut', 'Guava with Measured Groundnuts', ['snack', 'budget', 'local', 'fibre'], ['guava', 'unsalted roasted groundnuts'], 'Wash guava and serve with a measured spoon of groundnuts.', 'Adds fibre, crunch, vitamin C, and healthy fat without needing cooking.', '1 medium guava plus 1 tablespoon groundnuts.', ['crunchy', 'sweet-tart', 'nutty'], ['Use orange instead of guava', 'Use plain yogurt instead of groundnuts'], { allergens: ['groundnuts'], avoid: ['kidney_review', 'diabetes_strict'], flavourBase: 'fruit and nut', texture: ['crunchy'] }),
      fallbackRecipe('snack', 'fb_sn_plain_yogurt_cinnamon', 'Plain Yogurt Cinnamon Cup', ['snack', 'yogurt', 'diabetes', 'quick'], ['plain unsweetened yogurt', 'cinnamon'], 'Serve cold with cinnamon. Do not add sugar.', 'Quick protein-rich snack with gentle acidity and no added sugar.', 'Half to 1 cup plain yogurt.', ['cool', 'creamy', 'lightly spiced'], ['Use lactose-free yogurt if needed', 'Use cucumber if dairy is not tolerated'], { allergens: ['milk'], flavourBase: 'cool yogurt creaminess', texture: ['creamy'] }),
      fallbackRecipe('snack', 'fb_sn_papaya_lime', 'Papaya Lime Bowl', ['snack', 'fruit', 'light'], ['papaya', 'lime or lemon'], 'Cube papaya and squeeze lime over it.', 'Fresh sweet option that feels like dessert while staying simple and portioned.', 'Half to 1 cup papaya cubes.', ['soft', 'sweet', 'zesty'], ['Use watermelon in a small portion', 'Use orange wedges'], { avoid: ['diabetes_strict', 'kidney_review'], flavourBase: 'fresh lime fruit', texture: ['soft'] }),
      fallbackRecipe('snack', 'fb_sn_carrot_tomato_plate', 'Carrot Tomato Fresh Plate', ['snack', 'budget', 'fresh', 'diabetes'], ['carrot', 'tomato', 'lemon'], 'Slice carrot and tomato. Add lemon. Keep salt minimal.', 'Cheap colourful snack with crunch and acidity for appetite control.', '1 carrot plus 1 tomato.', ['crunchy', 'fresh', 'zesty'], ['Use cucumber instead of tomato if reflux-prone', 'Use cabbage ribbons instead of carrot'], { flavourBase: 'fresh lemon-herb', texture: ['crunchy'] }),
      fallbackRecipe('snack', 'fb_sn_avocado_cabbage_spoon', 'Avocado Cabbage Spoon Salad', ['snack', 'salad', 'filling'], ['avocado', 'cabbage', 'lemon'], 'Mash a small avocado portion with shredded cabbage and lemon.', 'Creamy, crunchy, and filling without bread or fried snacks.', 'Quarter avocado plus 1 cup shredded cabbage.', ['creamy', 'crunchy', 'zesty'], ['Use yogurt instead of avocado', 'Use cucumber instead of cabbage'], { avoid: ['kidney_review'], flavourBase: 'fresh lemon-herb', texture: ['creamy', 'crunchy'] }),
      fallbackRecipe('snack', 'fb_sn_cabbage_lime_ribbons', 'Cabbage Lime Ribbons', ['snack', 'budget', 'salad', 'fresh'], ['cabbage', 'lime or lemon', 'black pepper optional'], 'Shred cabbage finely and massage with lemon for 1 minute. Add pepper if liked.', 'Crisp, cheap, and refreshing when the client needs a no-cook snack.', '1 to 2 cups shredded cabbage.', ['crisp', 'zesty', 'fresh'], ['Use cucumber instead of cabbage', 'Add a spoon of yogurt if dairy is tolerated'], { flavourBase: 'fresh lemon-herb', texture: ['crunchy'] }),
      fallbackRecipe('snack', 'fb_sn_tomato_avocado_bites', 'Tomato Avocado Bites', ['snack', 'fresh', 'filling'], ['tomato', 'small avocado portion', 'lemon'], 'Top tomato slices with a thin avocado layer and lemon.', 'A creamy fresh snack that feels satisfying without fried food.', '1 tomato plus 2 tablespoons avocado.', ['creamy', 'fresh', 'zesty'], ['Use cucumber slices instead of tomato', 'Use yogurt instead of avocado'], { avoid: ['kidney_review'], flavourBase: 'fresh lemon-herb', texture: ['creamy'] }),
      fallbackRecipe('snack', 'fb_sn_roasted_chickpea_spoons', 'Roasted Chickpea Spoon Snack', ['snack', 'legume', 'budget'], ['roasted chickpeas', 'lemon or mild spice'], 'Use roasted chickpeas with mild spice and water. Keep salt low.', 'Crunchy budget snack with plant protein and better staying power than biscuits.', '2 to 3 tablespoons roasted chickpeas.', ['crunchy', 'savoury', 'filling'], ['Use groundnuts if chickpeas are unavailable', 'Use yogurt if legumes cause bloating'], { avoid: ['kidney_review', 'ibs'], flavourBase: 'mild spice base', texture: ['crunchy'] })
    ],
    breakfast: [
      fallbackRecipe('breakfast', 'fb_bf_sorghum_cinnamon', 'Sorghum Cinnamon Porridge Cup', ['breakfast', 'budget', 'local'], ['sorghum flour', 'water', 'cinnamon'], 'Cook sorghum flour in water until smooth. Add cinnamon, not sugar.', 'Warm local breakfast with steady energy and simple ingredients.', '180 to 220ml cooked porridge.', ['warm', 'mild', 'familiar'], ['Use millet flour instead', 'Add milk only if tolerated'], { avoid: ['diabetes_strict'], flavourBase: 'warm spice base', texture: ['soft'] }),
      fallbackRecipe('breakfast', 'fb_bf_yogurt_fruit_oats', 'Yogurt Fruit Oat Cup', ['breakfast', 'yogurt', 'quick'], ['plain yogurt', 'small oats portion', 'seasonal fruit'], 'Layer plain yogurt with a small spoon of oats and chopped fruit.', 'No-cook breakfast that adds protein, fibre, and freshness.', 'Half cup yogurt, 2 tablespoons oats, and half cup fruit.', ['cool', 'creamy', 'fresh'], ['Use papaya instead of banana', 'Use lactose-free yogurt'], { allergens: ['milk'], avoid: ['kidney_review'], flavourBase: 'cool yogurt creaminess', texture: ['creamy'] }),
      fallbackRecipe('breakfast', 'fb_bf_bean_tomato_cup', 'Bean Tomato Breakfast Cup', ['breakfast', 'budget', 'legume', 'local'], ['cooked beans', 'tomato', 'onion', 'lemon'], 'Warm a small portion of beans with tomato and onion. Finish with lemon.', 'A savoury breakfast for clients who do not want sweet foods every morning.', 'Half cup beans with tomato/onion sauce.', ['savoury', 'hearty', 'zesty'], ['Use cowpeas instead of beans', 'Use yogurt if beans cause bloating'], { avoid: ['kidney_review', 'ibs'], flavourBase: 'tomato-onion-garlic', texture: ['soft'] }),
      fallbackRecipe('breakfast', 'fb_bf_sweet_potato_greens', 'Measured Sweet Potato Greens Breakfast', ['breakfast', 'local', 'cooked_staple'], ['small sweet potato', 'sukuma or cabbage', 'tomato'], 'Boil a small sweet potato and serve with quickly cooked greens and tomato.', 'A familiar cooked breakfast with fibre and colour, kept portion-controlled.', '1 small sweet potato plus 1 to 2 cups greens.', ['familiar', 'soft', 'savoury'], ['Use pumpkin instead of sweet potato', 'Use cabbage instead of sukuma'], { avoid: ['kidney_review'], flavourBase: 'tomato-onion-garlic', texture: ['soft'] }),
      fallbackRecipe('breakfast', 'fb_bf_cabbage_yogurt_bowl', 'Cabbage Yogurt Breakfast Bowl', ['breakfast', 'salad', 'yogurt', 'quick'], ['cabbage', 'plain yogurt', 'lemon', 'tomato'], 'Mix shredded cabbage with plain yogurt, lemon, and tomato. Serve cold.', 'Fresh, creamy, and light for mornings when cooked food feels heavy.', '1 cup cabbage plus half cup yogurt.', ['cool', 'creamy', 'crunchy'], ['Use cucumber instead of cabbage', 'Use avocado instead of yogurt'], { allergens: ['milk'], flavourBase: 'cool yogurt creaminess', texture: ['creamy', 'crunchy'] }),
      fallbackRecipe('breakfast', 'fb_bf_pumpkin_millet_spoon', 'Pumpkin Millet Breakfast Spoon', ['breakfast', 'local', 'budget'], ['pumpkin', 'small millet portion', 'ginger'], 'Mash cooked pumpkin with a small spoon of millet porridge and ginger.', 'Soft warm breakfast with natural sweetness and less heaviness than a large porridge bowl.', '1 cup pumpkin plus 100ml thick millet porridge.', ['warming', 'soft', 'slightly sweet'], ['Use sorghum instead of millet', 'Use carrot instead of pumpkin'], { avoid: ['kidney_review'], flavourBase: 'warming soup base', texture: ['soft'] })
    ],
    lunch: [
      fallbackRecipe('lunch', 'fb_lu_cabbage_bean_bowl', 'Cabbage Bean Lemon Bowl', ['lunch', 'salad', 'budget', 'legume'], ['cabbage', 'beans', 'tomato', 'lemon'], 'Toss cooked beans with cabbage, tomato, and lemon. Keep oil minimal.', 'A cheap bowl that gives fibre, colour, and plant protein.', 'Half cup beans plus 2 cups cabbage/tomato.', ['fresh', 'zesty', 'filling'], ['Use cowpeas instead of beans', 'Use chicken instead if beans cause bloating'], { avoid: ['kidney_review', 'ibs'], flavourBase: 'fresh lemon-herb', texture: ['crunchy'] })
    ],
    dinner: [
      fallbackRecipe('dinner', 'fb_dn_pumpkin_ginger_soup', 'Pumpkin Ginger Light Soup', ['dinner', 'soup', 'budget', 'light'], ['pumpkin', 'ginger', 'tomato', 'onion'], 'Simmer pumpkin with ginger, tomato, and onion until soft. Blend or mash.', 'Light dinner that is warm, cheap, and easier than heavy evening starches.', '1.5 to 2 cups soup plus protein if needed.', ['warming', 'soft', 'slightly sweet'], ['Add shredded chicken if protein is needed', 'Use carrot instead of pumpkin'], { avoid: ['kidney_review'], flavourBase: 'warming soup base', texture: ['soft'] })
    ]
  };
  return (options[meal] || []).filter(recipe => privateRecipeAllowed(recipe, profile));
}

function privateRecipeVarietyScore(recipe, profile, used, meal, index) {
  const category = recipeCategory(recipe);
  const protein = recipeProteinFamily(recipe);
  const flavour = recipeFlavourFamily(recipe);
  const desired = desiredMealCategory(meal, index, profile);
  let score = privateRecipeScore(recipe, profile) + recipeCulinaryBoost(recipe) + mealRealismScore(recipe, meal);
  if (category === desired) score += 18;
  if (desired === 'high_protein' && ['egg', 'fish', 'chicken', 'legume', 'dairy'].includes(protein)) score += 10;
  if (desired === 'balanced' && !used.names.has(recipe.name)) score += 4;
  if (profile.hasKidney && ['smoothie', 'salad_bowl', 'legume'].includes(category)) score -= 12;
  if (profile.hasIBS && ['legume'].includes(category)) score -= 7;
  if (used.names.has(recipe.name)) score -= 100;
  score -= (used.categories[category] || 0) * 7;
  score -= (used.proteins[protein] || 0) * 5;
  score -= (used.flavours[flavour] || 0) * 3;
  if (index > 0 && used.lastCategory === category) score -= 12;
  if (index > 0 && used.lastProtein === protein && protein !== 'other') score -= 8;
  return score;
}

function recipeAllowedForDaySlot(recipe, profile, slot, dayUsed = {}, weekUsed = {}) {
  const meal = slot.meal;
  if (!recipe) return false;
  if (hasMealRealismProblem(recipe, meal)) return false;
  if ((meal === 'lunch' || meal === 'dinner') && isSmoothieLike(recipe)) return false;
  if (isSmoothieLike(recipe) && (dayUsed.smoothies || 0) >= 1) return false;
  if (isSmoothieLike(recipe) && ((weekUsed.categories || {}).smoothie || 0) >= 2) return false;
  if (isEggRecipe(recipe) && (dayUsed.eggs || 0) >= 1) return false;
  if (isEggRecipe(recipe) && ((weekUsed.proteins || {}).egg || 0) >= 3) return false;
  if ((profile.hasCholesterol || profile.hasKidney) && isEggRecipe(recipe) && (dayUsed.eggs || 0) >= 1) return false;
  if (meal === 'lunch' && ['smoothie', 'yogurt'].includes(recipeCategory(recipe))) return false;
  if (meal === 'dinner' && ['smoothie', 'yogurt'].includes(recipeCategory(recipe))) return false;
  if (meal === 'breakfast' && recipeCategory(recipe) === 'salad_bowl') return false;
  return true;
}

function noteDayUse(recipe, dayUsed = {}) {
  const protein = recipeProteinFamily(recipe);
  const category = recipeCategory(recipe);
  dayUsed.proteins = dayUsed.proteins || {};
  dayUsed.categories = dayUsed.categories || {};
  dayUsed.proteins[protein] = (dayUsed.proteins[protein] || 0) + 1;
  dayUsed.categories[category] = (dayUsed.categories[category] || 0) + 1;
  if (isSmoothieLike(recipe)) dayUsed.smoothies = (dayUsed.smoothies || 0) + 1;
  if (isEggRecipe(recipe)) dayUsed.eggs = (dayUsed.eggs || 0) + 1;
}

function daySlotScore(recipe, profile, slot, dayUsed, weekUsed, index) {
  const protein = recipeProteinFamily(recipe);
  const category = recipeCategory(recipe);
  let score = privateRecipeVarietyScore(recipe, profile, weekUsed, slot.meal, index);
  if (category === slot.category) score += 24;
  score += mealRealismScore(recipe, slot.meal);
  if (slot.meal === 'lunch' && ['cooked_staple', 'salad_bowl', 'high_protein', 'legume'].includes(category)) score += 12;
  if (slot.meal === 'dinner' && ['soup_light', 'cooked_staple', 'high_protein', 'legume', 'salad_bowl'].includes(category)) score += 12;
  if ((dayUsed.proteins || {})[protein]) score -= 25 * dayUsed.proteins[protein];
  if ((dayUsed.categories || {})[category]) score -= 12 * dayUsed.categories[category];
  if (isSmoothieLike(recipe) && slot.meal !== 'breakfast' && slot.meal !== 'snack') score -= 100;
  if (isEggRecipe(recipe) && (dayUsed.eggs || 0)) score -= 100;
  return score;
}

function pickForDaySlot(candidates, profile, slot, dayUsed, weekUsed, index) {
  const allowed = candidates.filter(recipe => recipeAllowedForDaySlot(recipe, profile, slot, dayUsed, weekUsed));
  const pool = allowed.length ? allowed : candidates.filter(recipe => !isSmoothieLike(recipe));
  const unusedPool = pool.filter(recipe => !weekUsed.names.has(recipe.name));
  const unusedSafeAny = candidates.filter(recipe => !weekUsed.names.has(recipe.name) && recipeAllowedForDaySlot(recipe, profile, { ...slot, category: recipeCategory(recipe) }, dayUsed, weekUsed));
  const finalPool = unusedPool.length ? unusedPool : unusedSafeAny.length ? unusedSafeAny : pool;
  return finalPool
    .sort((a, b) => daySlotScore(b, profile, slot, dayUsed, weekUsed, index) - daySlotScore(a, profile, slot, dayUsed, weekUsed, index) || String(a.name).localeCompare(String(b.name)))[0]
    || finalPool.sort((a, b) => daySlotScore(b, profile, slot, dayUsed, weekUsed, index) - daySlotScore(a, profile, slot, dayUsed, weekUsed, index))[0]
    || null;
}

function pickRealisticReplacement(byMeal, profile, slot, dayUsed, weekUsed, index) {
  const pool = byMeal[slot.meal] || [];
  return pickForDaySlot(pool, profile, slot, dayUsed, weekUsed, index);
}

function noteRecipeUse(recipe, used) {
  const category = recipeCategory(recipe);
  const protein = recipeProteinFamily(recipe);
  const flavour = recipeFlavourFamily(recipe);
  used.names.add(recipe.name);
  used.categories[category] = (used.categories[category] || 0) + 1;
  used.proteins[protein] = (used.proteins[protein] || 0) + 1;
  used.flavours[flavour] = (used.flavours[flavour] || 0) + 1;
  used.lastCategory = category;
  used.lastProtein = protein;
}

function buildWeeklyMealPlan(byMeal, profile, weekIndex = 0) {
  const weekUsed = { names: new Set(), categories: {}, proteins: {}, flavours: {}, lastCategory: '', lastProtein: '' };
  const breakfastPattern = profile.hasKidney
    ? ['cooked_staple', 'high_protein', 'yogurt', 'cooked_staple', 'balanced', 'high_protein', 'cooked_staple']
    : ['cooked_staple', 'high_protein', 'yogurt', 'cooked_staple', 'high_protein', 'balanced', 'smoothie'];
  const snackPattern = profile.hasKidney
    ? [['balanced', 'fresh'], ['high_protein', 'balanced'], ['yogurt', 'fresh'], ['balanced', 'salad_bowl'], ['fresh', 'balanced'], ['high_protein', 'balanced'], ['yogurt', 'balanced']]
    : [['fresh', 'yogurt'], ['balanced', 'fresh'], ['high_protein', 'salad_bowl'], ['balanced', 'fresh'], ['yogurt', 'legume'], ['fresh', 'balanced'], ['high_protein', 'smoothie']];
  const lunchPattern = ['cooked_staple', 'salad_bowl', 'high_protein', 'legume', 'cooked_staple', 'salad_bowl', 'high_protein'];
  const dinnerPattern = ['soup_light', 'cooked_staple', 'high_protein', 'soup_light', 'legume', 'salad_bowl', 'cooked_staple'];
  const plan = [];
  for (let day = 0; day < 7; day += 1) {
    const patternDay = (day + (weekIndex * 2)) % 7;
    const dayUsed = { smoothies: 0, eggs: 0, proteins: {}, categories: {} };
    const slots = [
      { key: 'breakfast', meal: 'breakfast', category: breakfastPattern[patternDay] },
      { key: 'snack1', meal: 'snack', category: snackPattern[patternDay][0] },
      { key: 'lunch', meal: 'lunch', category: lunchPattern[patternDay] },
      { key: 'snack2', meal: 'snack', category: snackPattern[patternDay][1] },
      { key: 'dinner', meal: 'dinner', category: dinnerPattern[patternDay] }
    ];
    const dayPlan = {};
    slots.forEach((slot, slotIndex) => {
      const pick = pickForDaySlot(byMeal[slot.meal] || [], profile, slot, dayUsed, weekUsed, (weekIndex * 35) + (day * 5) + slotIndex);
      if (pick) {
        dayPlan[slot.key] = pick;
        noteDayUse(pick, dayUsed);
        noteRecipeUse(pick, weekUsed);
      }
    });
    plan.push(dayPlan);
  }
  return plan;
}

function repairMealPlanRealism(plan = [], byMeal = {}, profile = {}, weekIndex = 0) {
  const weekUsed = { names: new Set(), categories: {}, proteins: {}, flavours: {}, lastCategory: '', lastProtein: '' };
  const slotDefs = [
    { key: 'breakfast', meal: 'breakfast', category: 'cooked_staple' },
    { key: 'snack1', meal: 'snack', category: 'fresh' },
    { key: 'lunch', meal: 'lunch', category: 'cooked_staple' },
    { key: 'snack2', meal: 'snack', category: 'balanced' },
    { key: 'dinner', meal: 'dinner', category: 'soup_light' }
  ];
  return plan.map((dayPlan, dayIndex) => {
    const dayUsed = { smoothies: 0, eggs: 0, proteins: {}, categories: {} };
    const next = { ...dayPlan };
    slotDefs.forEach((slot, slotIndex) => {
      const current = next[slot.key];
      const category = current ? recipeCategory(current) : '';
      const bad = !current
        || hasMealRealismProblem(current, slot.meal)
        || (slot.meal === 'breakfast' && category === 'salad_bowl')
        || ((slot.meal === 'lunch' || slot.meal === 'dinner') && ['smoothie', 'yogurt'].includes(category));
      if (bad) {
        const replacement = pickRealisticReplacement(byMeal, profile, slot, dayUsed, weekUsed, (weekIndex * 35) + (dayIndex * 5) + slotIndex);
        if (replacement) next[slot.key] = replacement;
      }
      if (next[slot.key]) {
        noteDayUse(next[slot.key], dayUsed);
        noteRecipeUse(next[slot.key], weekUsed);
      }
    });
    return next;
  });
}

function mealWeekMeta(weekIndex, familyPlan = false) {
  const familyMeta = [
    ['Week 1 - Foundation Menu', 'Build the shared household rhythm, record disliked meals, hunger, leftovers, symptoms, and portion needs for each member.'],
    ['Week 2 - Variety and Acceptance Menu', 'Rotate proteins, vegetables, sauces, and staples so the family does not feel trapped in one menu.'],
    ['Week 3 - Practicality and Budget Menu', 'Use batch cooking, affordable baskets, school/work lunches, and realistic leftovers to reduce cooking pressure.'],
    ['Week 4 - Review and Adjustment Menu', 'Keep the best accepted meals, remove weak meals, and adjust portions by age, activity, appetite, and condition.']
  ];
  const individualMeta = [
    ['Week 1 - Foundation Menu', 'Learn the meal rhythm, portions, water routine, protein consistency, and which meals are realistic.'],
    ['Week 2 - Variety Menu', 'Rotate proteins, vegetables, soups, salads, and cooked staples so the plan feels enjoyable and sustainable.'],
    ['Week 3 - Precision Menu', 'Adjust portions using hunger, energy, symptoms, measurements, glucose/BP readings, or lab guidance where relevant.'],
    ['Week 4 - Continuation Menu', 'Keep the strongest meals and prepare for the next 30 days using the same structure with better personal feedback.']
  ];
  return (familyPlan ? familyMeta : individualMeta)[weekIndex] || [`Week ${weekIndex + 1}`, 'Continue the same structure while rotating meals, portions, and practical swaps.'];
}

function buildMultiWeekMealPlan(byMeal, profile, weeks = 4, familyPlan = false) {
  return Array.from({ length: weeks }, (_, weekIndex) => {
    const [title, focus] = mealWeekMeta(weekIndex, familyPlan);
    return {
      title,
      focus,
      days: repairMealPlanRealism(buildWeeklyMealPlan(byMeal, profile, weekIndex), byMeal, profile, weekIndex)
    };
  });
}

function buildMealSequence(candidates, profile, meal, slots) {
  candidates = [...candidates, ...fallbackRecipesForMeal(meal, profile)]
    .filter((recipe, index, list) => list.findIndex(item => item.name === recipe.name) === index);
  const used = { names: new Set(), categories: {}, proteins: {}, flavours: {}, lastCategory: '', lastProtein: '' };
  const sequence = [];
  for (let i = 0; i < slots; i += 1) {
    const pick = candidates
      .filter(recipe => !used.names.has(recipe.name))
      .sort((a, b) => privateRecipeVarietyScore(b, profile, used, meal, i) - privateRecipeVarietyScore(a, profile, used, meal, i) || String(a.name).localeCompare(String(b.name)))[0]
      || candidates[i % Math.max(1, candidates.length)];
    if (pick) {
      sequence.push(pick);
      noteRecipeUse(pick, used);
    }
  }
  return sequence;
}

function limitedRecipePoolForProfile(payload = {}) {
  const { schema, recipes, swaps } = loadPrivateRecipes();
  const profile = profileFromRecipeRequest(payload);
  const limits = { breakfast: 18, lunch: 24, dinner: 24, snack: 18 };
  const selected = [];
  Object.keys(limits).forEach(meal => {
    const candidates = recipes
      .filter(recipe => recipe.meal === meal && privateRecipeAllowed(recipe, profile))
      .sort((a, b) => privateRecipeScore(b, profile) + recipeCulinaryBoost(b) - (privateRecipeScore(a, profile) + recipeCulinaryBoost(a)) || String(a.name).localeCompare(String(b.name)));
    const slots = meal === 'snack' ? 14 : 7;
    const sequence = buildMealSequence(candidates, profile, meal, Math.min(slots, candidates.length));
    const extra = candidates.filter(recipe => !sequence.some(item => item.name === recipe.name)).slice(0, Math.max(0, limits[meal] - sequence.length));
    [...sequence, ...extra].slice(0, limits[meal]).forEach(recipe => selected.push(recipe));
  });
  return {
    schema,
    recipes: selected,
    swaps: {
      starches: swaps.starches || [],
      proteins: swaps.proteins || [],
      vegetables: swaps.vegetables || [],
      flavour: swaps.flavour || [],
      diabetes: profile.hasDiabetes ? swaps.diabetes || [] : [],
      hypertension: profile.hasHyper ? swaps.hypertension || [] : [],
      kidney_review: profile.hasKidney ? swaps.kidney_review || [] : [],
      budget: profile.budget === 'low' ? swaps.budget || [] : [],
      salads: swaps.salads || [],
      smoothies: profile.hasKidney ? [] : swaps.smoothies || [],
      soups: swaps.soups || []
    }
  };
}

function cleanList(value) {
  if (Array.isArray(value)) return value.map(x => String(x || '').trim()).filter(Boolean);
  return String(value || '').split(/[,;|]/).map(x => x.trim()).filter(Boolean);
}

function firstRecipesByMeal(payload = {}) {
  const profile = profileFromRecipeRequest(payload);
  const pool = limitedRecipePoolForProfile(payload).recipes;
  const byMeal = { breakfast: [], lunch: [], dinner: [], snack: [] };
  pool.forEach(recipe => {
    if (byMeal[recipe.meal]) byMeal[recipe.meal].push(recipe);
  });
  Object.keys(byMeal).forEach(meal => {
    const slots = meal === 'snack' ? 14 : 7;
    byMeal[meal] = buildMealSequence(byMeal[meal], profile, meal, slots);
  });
  return byMeal;
}

function weeklyRecipesForProfile(payload = {}) {
  const byMeal = firstRecipesByMeal(payload);
  const profile = profileFromRecipeRequest(payload);
  const familyPlan = isFamilyPlanPayload(payload, payload);
  return { byMeal, days: repairMealPlanRealism(buildWeeklyMealPlan(byMeal, profile, 0), byMeal, profile, 0), weeks: buildMultiWeekMealPlan(byMeal, profile, 4, familyPlan) };
}

function pickRecipe(list, index) {
  if (!list || !list.length) return null;
  return list[index % list.length];
}

function mealVarietySummary(recipes = {}) {
  const all = ['breakfast', 'lunch', 'dinner', 'snack'].flatMap(meal => recipes[meal] || []);
  const counts = all.reduce((acc, recipe) => {
    const key = recipeCategory(recipe);
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const label = {
    salad_bowl: 'salad/bowl meals',
    smoothie: 'smoothie/yogurt-style options',
    soup_light: 'soups or light dinners',
    cooked_staple: 'cooked local staple meals',
    high_protein: 'egg/fish/chicken/protein meals',
    legume: 'legume meals',
    yogurt: 'yogurt meals',
    balanced: 'balanced meals'
  };
  return Object.keys(label)
    .filter(key => counts[key])
    .map(key => `<span>${escapeHtml(counts[key])} ${escapeHtml(label[key])}</span>`)
    .join('');
}

function culinaryDieticianGuidance(profile = {}, recipes = {}) {
  const all = ['breakfast', 'lunch', 'dinner', 'snack'].flatMap(meal => recipes[meal] || []);
  const flavourBases = Array.from(new Set(all.map(recipeFlavourFamily).filter(Boolean))).slice(0, 6);
  const proteins = Array.from(new Set(all.map(recipeProteinFamily).filter(x => x && x !== 'other'))).slice(0, 6);
  const guidance = [];
  guidance.push('Meals were selected to rotate texture, flavour base, protein source, and cooking burden so the week does not feel repetitive.');
  if (flavourBases.length) guidance.push(`Main flavour rotation: ${flavourBases.join(', ')}.`);
  if (proteins.length) guidance.push(`Protein rotation: ${proteins.join(', ')}.`);
  if (profile.hasDiabetes) guidance.push('For diabetes support, starches are measured and paired with protein, vegetables, or healthy fats to reduce glucose spikes.');
  if (profile.hasKidney) guidance.push('For kidney review, high-potassium and high-phosphorus foods are treated cautiously until labs and clinician advice confirm safety.');
  if (profile.hasIBS) guidance.push('For gut sensitivity, legumes, strong spices, and fermentable triggers are reduced where safer options are available.');
  if (profile.isPrenatal) guidance.push('For pregnancy or lactation, the engine prioritises food safety, iron/folate support, protein, gentle meals, and appetite practicality.');
  if (profile.isChild || profile.isFamily) guidance.push('For child or family plans, meals favour familiar foods, scalable portions, school/work practicality, and shared household cooking.');
  if (profile.budget === 'low') guidance.push('For low-budget plans, the engine favours market-available foods, batch-cooking, eggs, beans where safe, greens, pumpkin, and measured staples.');
  return guidance;
}

function serverMacroSummary(profile = {}) {
  const weight = Number(profile.weight || profile.currentWeight || 0);
  const height = Number(profile.height || 0);
  const age = Number(profile.age || 30);
  const sex = String(profile.sex || '').toLowerCase();
  const activity = String(profile.activity || '').toLowerCase();
  const goal = String(profile.goal || '').toLowerCase();
  let bmr = weight && height ? (10 * weight + 6.25 * height - 5 * age + (sex === 'male' ? 5 : -161)) : 1800;
  const activityFactor = activity === 'active' ? 1.6 : activity === 'moderate' ? 1.45 : activity === 'light' ? 1.35 : 1.25;
  let calories = Math.round((bmr * activityFactor) / 50) * 50;
  if (goal.includes('loss') || goal.includes('weight') || String(profile.cat || '').match(/over|obese/)) calories -= 350;
  if (goal.includes('gain') || String(profile.cat || '').includes('under')) calories += 300;
  calories = Math.max(1200, Math.min(3600, calories));
  const protein = weight ? Math.round(Math.max(55, Math.min(180, weight * 1.25))) : Math.round(calories * 0.18 / 4);
  const fat = Math.round(calories * 0.28 / 9);
  const carbs = Math.round((calories - protein * 4 - fat * 9) / 4);
  return { calories, protein, carbs, fat, water: weight ? Math.round(weight * 0.033 * 10) / 10 : 2.2, fibre: calories >= 2000 ? 30 : 25 };
}

function gaugePosServer(value) {
  const bmi = Number(value || 0);
  if (!bmi) return 50;
  if (bmi < 18.5) return Math.max(4, Math.min(22, 6 + (bmi / 18.5) * 16));
  if (bmi < 25) return 22 + ((bmi - 18.5) / 6.5) * 26;
  if (bmi < 30) return 48 + ((bmi - 25) / 5) * 24;
  return Math.min(96, 72 + ((bmi - 30) / 15) * 24);
}

function serverClinicalSummaryFromPayload(payload = {}) {
  const profile = payload.profile && typeof payload.profile === 'object' ? payload.profile : payload;
  const conds = cleanList(profile.conds || payload.conds).map(x => x.toLowerCase());
  const macros = serverMacroSummary(profile);
  const bmi = Number(profile.bmi || payload.bmi || 0);
  const cat = String(profile.cat || '').trim();
  const missing = [];
  const warnings = [];
  const blockers = [];
  if (!String(profile.allergies || '').trim()) warnings.push('Food allergy/intolerance field is blank. Confirm before final approval.');
  if (String(profile.redFlags || '').trim()) warnings.push('Red-flag symptoms or urgent concerns were submitted. Review before release.');
  if (String(profile.clinicianStatus || '').includes('not_under_doctor') && (conds.includes('kidney') || conds.includes('diabetes') || conds.includes('hypertension'))) warnings.push('Specialist condition selected without current doctor/clinic follow-up.');
  if (conds.includes('kidney') && !(profile.labs && (profile.labs.egfr || profile.labs.creatinine))) blockers.push('Kidney condition selected without kidney lab values.');
  if (conds.includes('diabetes') && !(profile.labs && (profile.labs.hba1c || profile.labs.glucose))) blockers.push('Diabetes selected without HbA1c or fasting glucose.');
  if ((conds.includes('hypertension') || String(profile.goal || '').includes('hypertension')) && !(profile.labs && profile.labs.sbp && profile.labs.dbp)) warnings.push('Hypertension selected without current BP readings.');
  if ((String(profile.goal || '').includes('prenatal') || String(profile.lifeStage || '').includes('pregnant')) && !(profile.prenatal && profile.prenatal.trimester)) blockers.push('Pregnancy selected without trimester/status details.');
  const status = blockers.length ? 'review' : warnings.length ? 'caution' : 'safe';
  const specialistItems = specialistClinicalItems(profile, { conditions: conds });
  return {
    bmi,
    category: cat,
    waist: profile.waist || '',
    waistRisk: '',
    conditions: conds,
    goal: profile.goal || '',
    lifeStage: profile.lifeStage || 'general',
    confidence: { level: missing.length ? 'Limited' : 'Moderate', missing },
    riskScore: blockers.length ? 78 : warnings.length ? 56 : 34,
    calories: macros.calories,
    protein: macros.protein,
    carbs: macros.carbs,
    fat: macros.fat,
    medicationNote: profile.meds || '',
    diagnosis: profile.diagnosis || '',
    diagnosisDate: profile.diagnosisDate || '',
    symptoms: profile.symptoms || '',
    redFlags: profile.redFlags || '',
    allergies: profile.allergies || '',
    foodDislikes: profile.foodDislikes || '',
    culturalFoods: profile.culturalFoods || '',
    monitoring: profile.monitoring || '',
    clinicianStatus: profile.clinicianStatus || '',
    specialStatus: profile.specialStatus || '',
    customerSource: profile.customerSource || '',
    referralCode: profile.referralCode || '',
    customerType: profile.customerType || '',
    budget: profile.budget || '',
    cooking: profile.cooking || '',
    safetyDecision: {
      status,
      label: status === 'review' ? 'Review required before approval' : status === 'caution' ? 'Caution review recommended' : 'Ready for standard review',
      summary: status === 'safe'
        ? 'This plan is suitable for standard nutrition follow-up based on the information submitted.'
        : status === 'caution'
          ? 'This plan can be used with follow-up, but some submitted details should be confirmed during review.'
          : 'This plan needs professional review before being treated as final guidance.',
      caution: warnings,
      review: blockers,
      missing
    },
    clinicalRules: {
      overallDecision: status,
      missing,
      allowed: [],
      caution: warnings.map(x => ({ area: 'intake', title: x, action: 'Confirm during admin review' })),
      review: blockers.map(x => ({ area: 'clinical', title: x, action: 'Review before approval' })),
      contraindications: []
    },
    planAudit: {
      score: status === 'review' ? 62 : status === 'caution' ? 78 : 90,
      status,
      label: status === 'review' ? 'Review required' : status === 'caution' ? 'Caution review' : 'Ready for approval review',
      customerMessage: 'Plan generated privately on the backend.',
      missing,
      blockers,
      warnings,
      strengths: ['Private backend plan generation', 'Recipe database not exposed to the browser'],
      checklist: [],
      stats: {}
    },
    clinicalTargets: specialistItems.flatMap(item => item.targets.map(([target, guidance]) => ({
      condition: item.title,
      target,
      guidance
    }))),
    conditionChapters: specialistItems.map(item => ({
      title: item.title,
      priority: 'patient-visible',
      review: item.chapter
    }))
  };
}

function mealSlotLabel(slotKey) {
  const labels = {
    breakfast: 'Breakfast - 7:00am',
    snack1: 'Mid-morning - 10:30am',
    lunch: 'Lunch - 1:00pm',
    snack2: 'Afternoon snack - 4:00pm',
    dinner: 'Dinner - 6:30pm'
  };
  return labels[slotKey] || 'Meal';
}

function recipeProteinLabel(recipe = {}) {
  const protein = recipeProteinFamily(recipe);
  const labels = {
    egg: 'Egg protein',
    fish: 'Fish protein',
    chicken: 'Chicken protein',
    legume: 'Plant protein',
    dairy: 'Dairy protein',
    nuts: 'Nut/seed protein',
    meat: 'Animal protein',
    mixed: 'Mixed protein'
  };
  return labels[protein] || 'Balanced';
}

function recipeEquipmentLabel(recipe = {}) {
  const text = [recipe.method, recipe.culinaryStyle, recipe.name].filter(Boolean).join(' ').toLowerCase();
  if (text.includes('blend') || isSmoothieLike(recipe)) return 'Blender';
  if (text.includes('oven') || text.includes('bake')) return 'Oven';
  if (text.includes('grill')) return 'Grill/pan';
  if (text.includes('steam')) return 'Steamer/pot';
  if (text.includes('salad') || recipeCategory(recipe) === 'salad_bowl') return 'Knife/bowl';
  return 'Pot/pan';
}

function recipeMealReason(recipe = {}) {
  const category = recipeCategory(recipe);
  const reasons = {
    cooked_staple: 'This gives a real cooked meal base while keeping starch measured and balanced with protein and vegetables.',
    salad_bowl: 'This adds freshness, fibre, colour, and crunch without making the whole day heavy.',
    high_protein: 'This supports fullness, muscle protection, and steadier appetite when portions are controlled.',
    legume: 'This adds affordable protein and fibre, with portion adjustment if digestion or kidney review is needed.',
    soup_light: 'This gives a lighter evening option with fluid, vegetables, and protein without relying on snacks.',
    smoothie: 'This is kept to breakfast or snack use only, not lunch or dinner replacement.',
    yogurt: 'This supports a simple protein-rich breakfast or snack where dairy is tolerated.',
    fresh: 'This keeps the day practical with fruit or vegetables in measured portions.'
  };
  return recipe.why || reasons[category] || 'This meal was selected to balance taste, practicality, budget, and nutrition targets.';
}

function recipeCardHtml(recipe, slotKey = '') {
  if (!recipe) return '';
  const ingredients = (recipe.ingredients || []).join(', ');
  const swapList = (recipe.substitutions || [])
    .filter(item => isEggRecipe(recipe) || !/\begg\b|\beggs\b/i.test(String(item || '')))
    .slice(0, 2);
  const swaps = swapList.join(' | ');
  const method = recipe.method || 'Prepare simply with minimal oil, sugar, and salt.';
  const portion = recipe.portion || 'Use a balanced plate: vegetables first, then protein, then measured starch if included.';
  const chips = [
    recipe.time ? `Time: ${recipe.time} min` : '',
    recipe.cost ? `Cost: ${recipe.cost}` : '',
    `Protein: ${recipeProteinLabel(recipe)}`,
    `Equipment: ${recipeEquipmentLabel(recipe)}`,
    recipe.batchCook ? 'Batch-cook friendly' : ''
  ].filter(Boolean);
  const tasteNotes = [
    recipe.tasteProfile ? `Taste: ${recipe.tasteProfile}` : '',
    recipe.allergens && recipe.allergens.length ? `Allergens: ${recipe.allergens.join(', ')}` : '',
    recipe.clinicalNotes ? `Note: ${String(recipe.clinicalNotes).split(/[.;]/)[0]}` : ''
  ].filter(Boolean).join(' | ');
  return `<div class="meal-card">
    <div class="meal-head">
      <div>
        <div class="meal-time">${escapeHtml(mealSlotLabel(slotKey) || recipe.meal || 'meal')}</div>
        <div class="meal-name">${escapeHtml(recipe.name || 'Meal')}</div>
      </div>
    </div>
    <div class="meal-chips">
      ${chips.map(chip => `<span>${escapeHtml(chip)}</span>`).join('')}
    </div>
    <div class="meal-grid">
      <div class="meal-box"><strong>Ingredients</strong><p>${escapeHtml(ingredients || 'Use listed foods in measured portions.')}</p></div>
      <div class="meal-box"><strong>Preparation</strong><p>${escapeHtml(method)}</p></div>
      <div class="meal-box"><strong>Portion guide</strong><p>${escapeHtml(portion)}</p></div>
      <div class="meal-box"><strong>Smart swaps</strong><p>${escapeHtml(swaps || 'Swap with a similar protein, vegetable, or measured staple from the plan if needed.')}</p></div>
    </div>
    <div class="meal-notes">
      <div class="meal-note"><strong>Food reason</strong><br>${escapeHtml(recipeMealReason(recipe))}</div>
      ${tasteNotes ? `<div class="meal-note"><strong>Taste and practical notes</strong><br>${escapeHtml(tasteNotes)}</div>` : ''}
    </div>
  </div>`;
}

function conditionDisplayName(value) {
  const raw = String(value || '').trim();
  const key = raw.toLowerCase();
  const names = {
    pcos: 'PMOS',
    diabetes: 'Diabetes',
    hypertension: 'Hypertension',
    cholesterol: 'Cholesterol / LDL support',
    kidney: 'Kidney review',
    gout: 'Gout',
    thyroid: 'Thyroid support',
    anemia: 'Anaemia',
    ibs: 'IBS / gut-sensitive',
    prenatal: 'Pregnancy / prenatal'
  };
  return names[key] || raw;
}

function isFamilyPlanPayload(payload = {}, profile = {}) {
  const text = [
    payload.packageName,
    payload.orderType,
    profile.plantype,
    profile.goal,
    profile.familyData && JSON.stringify(profile.familyData)
  ].filter(Boolean).join(' ').toLowerCase();
  return text.includes('family') || text.includes('household') || Boolean(profile.familyData && Object.keys(profile.familyData).length);
}

function splitFamilyField(value) {
  return String(value || '')
    .split(/[;,|]/)
    .map(item => item.trim())
    .filter(Boolean);
}

function familyMemberGroup(ageOrLabel) {
  const n = Number.parseInt(ageOrLabel, 10);
  if (Number.isFinite(n)) {
    if (n < 5) return 'Toddler / young child';
    if (n < 13) return 'Child';
    if (n < 18) return 'Teen';
    if (n >= 60) return 'Older adult';
    return 'Adult';
  }
  const text = String(ageOrLabel || '').toLowerCase();
  if (/toddler|baby|young child/.test(text)) return 'Toddler / young child';
  if (/child|kid|school/.test(text)) return 'Child';
  if (/teen|adolescent/.test(text)) return 'Teen';
  if (/grand|elder|older|senior/.test(text)) return 'Older adult';
  if (/pregnan|mother|father|adult|parent/.test(text)) return 'Adult';
  return 'Family member';
}

function memberConditionText(member = {}, householdConditions = '') {
  const text = [
    member.condition,
    member.conditions,
    member.diagnosis,
    member.health,
    member.notes,
    member.allergies
  ].filter(Boolean).join('; ');
  return text || householdConditions || '';
}

function memberPortionGuide(group, conditions = '') {
  const cond = String(conditions || '').toLowerCase();
  const base = group === 'Toddler / young child'
    ? '1/3 to 1/2 adult starch, soft child-hand protein, finely prepared vegetables, fruit in small pieces.'
    : group === 'Child'
      ? '1/2 to 2/3 adult starch, child-palm protein, vegetables prepared simply, growth snack if appetite is good.'
      : group === 'Teen'
        ? 'Adult-style plate; increase protein/starch for sport, growth, school hunger, or underweight.'
        : group === 'Older adult'
          ? '1/2 to 3/4 cup starch, palm protein, soft vegetables, hydration, and protein at each main meal.'
          : '1/2 to 1 cup starch, 1 palm protein, 2 cups vegetables, and 1 tablespoon sauce/oil/groundnuts where suitable.';
  const extras = [];
  if (/diabetes|glucose|hba1c/.test(cond)) extras.push('keep starch measured, avoid sweet drinks, pair carbs with protein and vegetables');
  if (/hypertension|blood pressure|bp/.test(cond)) extras.push('cook low-salt; use garlic, onion, tomato, lemon, ginger, and herbs for flavour');
  if (/kidney|egfr|creatinine/.test(cond)) extras.push('needs kidney-lab review before high-protein, potassium, phosphate, or salt changes');
  if (/pregnan|trimester|lactation|breastfeeding/.test(cond)) extras.push('add safe protein, iron/folate foods, calcium foods, hydration, and food-safety care');
  if (/underweight|weight gain|poor appetite/.test(cond)) extras.push('add nourishing snacks, yogurt/groundnut/avocado where safe, and do not over-restrict starch');
  if (/ibs|gut|bloat|diarrhoea|constipation/.test(cond)) extras.push('adjust beans, cabbage, milk, onions, and fibre gradually based on symptoms');
  return extras.length ? `${base} Special adjustment: ${extras.join('; ')}.` : base;
}

function memberNutritionFocus(group, conditions = '') {
  const cond = String(conditions || '').toLowerCase();
  const focus = [];
  if (group === 'Toddler / young child' || group === 'Child') focus.push('growth, school energy, iron, calcium, zinc, vitamin A');
  if (group === 'Teen') focus.push('growth, school performance, protein, iron, calcium, healthy snacks');
  if (group === 'Older adult') focus.push('muscle preservation, hydration, fibre, softer textures, fall-risk nutrition');
  if (group === 'Adult' || group === 'Family member') focus.push('energy, portion control, metabolic health, realistic cooking');
  if (/diabetes|glucose|hba1c/.test(cond)) focus.push('glucose control');
  if (/hypertension|blood pressure|bp/.test(cond)) focus.push('blood-pressure support');
  if (/kidney|egfr|creatinine/.test(cond)) focus.push('kidney review');
  if (/pregnan|trimester|lactation|breastfeeding/.test(cond)) focus.push('pregnancy/lactation safety');
  if (/ibs|gut|bloat/.test(cond)) focus.push('gut tolerance');
  return Array.from(new Set(focus)).join(', ');
}

function familyMemberProfiles(payload = {}, profile = {}) {
  const fd = profile.familyData || payload.familyData || {};
  const count = Math.max(2, Number.parseInt(fd.count || profile.familyCount || 4, 10) || 4);
  const householdConditions = String(fd.conditions || profile.familyConditions || profile.conds || '').trim();
  const rawMembers = Array.isArray(fd.members) ? fd.members
    : Array.isArray(profile.familyMembers) ? profile.familyMembers
      : [];
  if (rawMembers.length) {
    return rawMembers.slice(0, 12).map((member, index) => {
      const label = member.name || member.label || member.role || `Member ${index + 1}`;
      const age = member.age || member.years || '';
      const group = familyMemberGroup(age || label);
      const conditions = memberConditionText(member, householdConditions);
      return { label, age, group, conditions, allergies: member.allergies || '', activity: member.activity || '', appetite: member.appetite || '', notes: member.notes || '' };
    });
  }
  const names = splitFamilyField(fd.names || fd.memberNames || profile.familyNames);
  const ages = splitFamilyField(fd.ages || profile.familyAges);
  const conditionParts = splitFamilyField(fd.memberConditions || fd.conditionsByMember || '');
  return Array.from({ length: Math.min(count, 12) }, (_, index) => {
    const label = names[index] || `Member ${index + 1}`;
    const age = ages[index] || '';
    const fallbackLabel = age || label;
    const group = familyMemberGroup(fallbackLabel);
    const conditions = conditionParts[index] || householdConditions;
    return { label, age, group, conditions, allergies: '', activity: '', appetite: '', notes: '' };
  });
}

function householdConflictCards(members = []) {
  const all = members.map(member => `${member.group} ${member.conditions || ''}`).join(' ').toLowerCase();
  const cards = [];
  if (/diabetes|glucose|hba1c/.test(all) && /child|teen|underweight|weight gain|poor appetite/.test(all)) {
    cards.push(['Diabetes + child/growth needs', 'Use the same cooked meal. The diabetes plate gets measured starch and no sweet drink; the child/teen may receive a larger starch portion or extra nourishing snack.']);
  }
  if (/kidney|egfr|creatinine/.test(all)) {
    cards.push(['Kidney conflict rule', 'Do not place the whole family on kidney restrictions. Only the affected member needs kidney-lab-guided protein, potassium, phosphate, and salt review.']);
  }
  if (/pregnan|trimester|lactation/.test(all) && /weight loss|obese|overweight|diabetes/.test(all)) {
    cards.push(['Pregnancy + weight/metabolic goals', 'Use shared healthy meals, but pregnancy portions must protect protein, iron, folate, calcium, hydration, and safe weight gain rather than aggressive restriction.']);
  }
  if (/hypertension|blood pressure|bp/.test(all)) {
    cards.push(['Low-salt household advantage', 'Low-salt cooking can benefit the whole household, but children and active members still need adequate food volume and energy.']);
  }
  if (!cards.length) cards.push(['No major conflict captured', 'Use one shared meal base, then adjust portions by age, appetite, activity, allergies, and any conditions confirmed during follow-up.']);
  return cards;
}

function familyPlanSectionHtml(payload = {}, profile = {}) {
  const fd = profile.familyData || payload.familyData || {};
  if (!isFamilyPlanPayload(payload, profile)) return '';
  const count = Math.max(2, Number.parseInt(fd.count || profile.familyCount || 4, 10) || 4);
  const children = Math.max(0, Number.parseInt(fd.children || 0, 10) || 0);
  const adultCount = Math.max(0, count - children);
  const members = familyMemberProfiles(payload, profile);
  const memberRows = members.map((member, i) => {
    const details = [
      member.age ? `${member.age} years` : '',
      member.activity ? `Activity: ${member.activity}` : '',
      member.appetite ? `Appetite: ${member.appetite}` : ''
    ].filter(Boolean).join(' | ') || 'Details not captured';
    return `<tr>
      <td>${escapeHtml(i + 1)}</td>
      <td>${escapeHtml(member.label)}</td>
      <td>${escapeHtml(details)}</td>
      <td>${escapeHtml(member.group)}</td>
      <td>${escapeHtml(member.conditions || 'No individual condition captured')}</td>
      <td>${escapeHtml(memberPortionGuide(member.group, member.conditions))}</td>
      <td>${escapeHtml(memberNutritionFocus(member.group, member.conditions))}</td>
    </tr>`;
  }).join('');
  const weeklyProtein = Math.max(18, count * 5);
  const vegCups = count * 14;
  const fruitSnacks = Math.max(7, count * 5);
  const stapleServings = Math.max(14, count * 7);
  const rotation = [
    ['Week 1', 'Foundation shared menu', 'Use the 7-day menu below. Serve one shared meal base, then apply the member-by-member plate adjustments.'],
    ['Week 2', 'Protein rotation', 'Rotate beans/cowpeas, fish or mukene, chicken or lean meat, yogurt, groundnuts, and eggs only where suitable.'],
    ['Week 3', 'Budget and batch-cook week', 'Batch-cook beans, greens, soup/stew base, and measured staples. Use safe leftovers for work and school lunches.'],
    ['Week 4', 'Taste and acceptance week', 'Keep meals the family accepted, replace bland/repetitive meals, and update portions using appetite, symptoms, BP/glucose, school/work routine, and cost.'],
    ['Days 31 to 60', 'Continuation rotation', 'Repeat the best two weeks, add new vegetables/proteins, and tighten member-specific portions after follow-up review.']
  ].map(row => `<tr><td style="padding:8px;border-bottom:1px solid #eee6dc"><strong>${escapeHtml(row[0])}</strong></td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(row[1])}</td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(row[2])}</td></tr>`).join('');
  const sharedPlateRows = [
    ['Shared cooking base', 'Cook one main meal: protein or legumes, vegetables, measured staple, and sauce separately where possible.'],
    ['Adult plate', '2 cups vegetables, 1 palm protein, 1/2 to 1 cup starch, 1 tablespoon sauce/oil/groundnut paste where suitable.'],
    ['Child plate', '1/2 to 2/3 adult starch, child-palm protein, vegetables in accepted texture, and a school snack if appetite or growth needs support.'],
    ['Diabetes adjustment', 'Measure starch, increase vegetables, avoid sweet drinks, keep fruit whole and portioned, and pair carbs with protein.'],
    ['Hypertension adjustment', 'Use low-salt cooking; flavour with tomato, onion, garlic, ginger, lemon, herbs, and spices.'],
    ['Pregnancy/lactation adjustment', 'Add safe protein, iron/folate foods, calcium foods, fluids, and avoid unsafe foods.'],
    ['Kidney-review adjustment', 'Do not apply kidney restrictions to everyone. The affected member needs lab-guided review before major changes.']
  ].map(row => `<tr><td style="padding:8px;border-bottom:1px solid #eee6dc"><strong>${escapeHtml(row[0])}</strong></td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(row[1])}</td></tr>`).join('');
  const conflictCards = householdConflictCards(members).map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('');
  const lunchCards = [
    ['School snack box', 'Fruit, plain yogurt where safe, roasted groundnuts if allowed, boiled egg only where suitable, bean/vegetable bowl, or safe leftovers.'],
    ['Adult work lunch', 'Packed bowl with measured starch, protein, vegetables, and sauce separately. Avoid relying on soda, fried snacks, or very salty takeaway.'],
    ['Safe leftovers', 'Cool quickly, cover, refrigerate, reheat thoroughly, and avoid keeping cooked food at room temperature for long.'],
    ['No-soda drinks', 'Water, unsweetened hibiscus, plain tea, infused water, or diluted unsweetened passion/lemon where appropriate.']
  ].map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('');
  const cookingSchedule = [
    ['Sunday', 'Plan proteins, soak/cook beans or cowpeas, buy vegetables, and prepare one soup/stew base.'],
    ['Monday', 'Cook greens and staple portions; pack leftovers safely for school/work.'],
    ['Wednesday', 'Refresh vegetables, cook fish/chicken or mukene where safe, and prepare salad/bowl bases dry.'],
    ['Friday', 'Use leftovers creatively: soup, bowl, stew, or vegetable mix. Review what the family rejected.'],
    ['Weekend', 'Choose two meals to repeat and one meal to replace next week.']
  ].map(([day, text]) => `<div class="phase"><strong>${escapeHtml(day)}</strong><p>${escapeHtml(text)}</p></div>`).join('');
  const budgetCards = [
    ['Low-cost protein basket', 'Beans, cowpeas, peas, mukene where safe, groundnuts in small portions, yogurt where affordable, and eggs only where clinically suitable.'],
    ['Seasonal vegetable rule', 'Buy what is fresh and affordable: cabbage, dodo, nakati, sukuma, pumpkin, carrots, tomatoes, eggplant, or cucumber.'],
    ['Bulk cooking rule', 'Cook legumes and soup bases in batches, then change flavour using herbs, tomatoes, garlic, ginger, lemon, and vegetables.'],
    ['When money is tight', 'Prioritise protein, vegetables, and measured staples before snacks, sweet drinks, fried foods, or expensive extras.']
  ].map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('');
  const trackerRows = [
    ['Taste', 'Which meals were enjoyed, rejected, bland, too spicy, or too hard to prepare?'],
    ['Cost', 'Which meals were affordable, expensive, or difficult to shop for?'],
    ['Symptoms', 'Any bloating, reflux, constipation, diarrhoea, headaches, glucose/BP concerns, or allergy symptoms?'],
    ['Repetition', 'Which foods repeated too much, especially eggs, smoothies, beans, or one staple?'],
    ['Measurements', 'Weight, waist, glucose, BP, child appetite/growth, pregnancy symptoms, or other relevant markers.']
  ].map(row => `<tr><td style="padding:8px;border-bottom:1px solid #eee6dc"><strong>${escapeHtml(row[0])}</strong></td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(row[1])}</td></tr>`).join('');
  return `<div class="sec"><div class="sh"><div class="si">FM</div><div class="st">Household Personalisation Plan</div></div>
    <div class="grid">
      <div class="box"><strong>Family size</strong><br>${escapeHtml(count)} people (${escapeHtml(adultCount)} adult/teen estimate, ${escapeHtml(children)} child estimate)</div>
      <div class="box"><strong>Ages captured</strong><br>${escapeHtml(fd.ages || 'Not captured')}</div>
      <div class="box"><strong>Family goal</strong><br>${escapeHtml(fd.goal || profile.goal || 'Shared healthy eating')}</div>
      <div class="box"><strong>Budget range</strong><br>${escapeHtml(fd.budget || profile.budget || 'Not captured')}</div>
      <div class="box"><strong>Family conditions</strong><br>${escapeHtml(fd.conditions || 'None captured')}</div>
      <div class="box"><strong>Allergies/intolerances</strong><br>${escapeHtml(fd.allergies || profile.allergies || 'Not captured')}</div>
    </div>
    <div class="week-card"><div class="day-title">Household Personalisation Matrix</div><table style="width:100%;border-collapse:collapse;font-size:11px"><thead><tr><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">#</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Member</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Details</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Group</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Condition/allergy focus</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Plate adjustment</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Nutrition focus</th></tr></thead><tbody>${memberRows}</tbody></table></div>
    <div class="week-card"><div class="day-title">Shared Meal, Different Plates</div><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${sharedPlateRows}</tbody></table></div>
    <div class="support-grid">${conflictCards}</div>
    <div class="support-grid" style="margin-top:8px">${lunchCards}</div>
    <div class="phase-grid" style="margin-top:8px">${cookingSchedule}</div>
    <div class="week-card"><div class="day-title">30-day household rotation</div><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${rotation}</tbody></table></div>
    <div class="support-grid">${budgetCards}</div>
    <div class="week-card" style="margin-top:8px"><div class="day-title">Family Taste and Acceptance Tracker</div><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${trackerRows}</tbody></table></div>
    <div class="note"><strong>Shopping scale for this household:</strong> plan roughly ${escapeHtml(weeklyProtein)} palm-size protein portions per week, ${escapeHtml(vegCups)} cups of vegetables across the week, ${escapeHtml(stapleServings)} measured staple servings, and about ${escapeHtml(fruitSnacks)} fruit/snack portions for school or work. Adjust down for toddlers and up for active teens, pregnancy, sport, poor appetite, or weight gain.</div>
    <div class="note" style="margin-top:8px"><strong>Caregiver guidance:</strong> do not cook separate meals unless medically necessary. Cook the same base meal, keep salt/sugar/oil controlled at the pot level, then personalise each plate using the matrix above.</div>
  </div>`;
}

function shortDisplay(value, fallback = 'Not captured') {
  const text = String(value === undefined || value === null ? '' : value).trim();
  return text || fallback;
}

function listDisplay(value, fallback = 'None captured') {
  const list = cleanList(value);
  return list.length ? list.map(conditionDisplayName).join(', ') : fallback;
}

function labSummaryRows(labs = {}) {
  if (!labs || typeof labs !== 'object') return [];
  const labels = {
    glucose: 'Glucose',
    hba1c: 'HbA1c',
    cholesterol: 'Total cholesterol',
    ldl: 'LDL',
    hdl: 'HDL',
    trig: 'Triglycerides',
    haemoglobin: 'Haemoglobin',
    ferritin: 'Ferritin',
    vitd: 'Vitamin D',
    b12: 'Vitamin B12',
    calcium: 'Calcium',
    potassium: 'Potassium',
    uricacid: 'Uric acid',
    tsh: 'TSH',
    egfr: 'eGFR',
    creatinine: 'Creatinine',
    phosphate: 'Phosphate / phosphorus',
    sodium: 'Sodium',
    albumin: 'Albumin',
    folate: 'Folate',
    clinician_comment: 'Clinician lab comment',
    sbp: 'Systolic BP',
    dbp: 'Diastolic BP',
    other: 'Other labs'
  };
  return Object.keys(labels)
    .map(key => [labels[key], labs[key]])
    .filter(([, value]) => String(value || '').trim())
    .slice(0, 16);
}

function compactModuleSummary(profile = {}) {
  const rows = [];
  if (profile.familyData && Object.keys(profile.familyData).length) rows.push(['Family details', `Family/household data captured for ${shortDisplay(profile.familyData.count || profile.familyCount, 'multiple')} member(s).`]);
  if (profile.sport && Object.keys(profile.sport).length) rows.push(['Sports nutrition', 'Training/performance details captured.']);
  if (profile.mental && Object.keys(profile.mental).length) rows.push(['Mood and appetite', 'Mental health/eating pattern details captured.']);
  if (profile.vitality && Object.keys(profile.vitality).length) rows.push(['Vitality', 'Energy, sleep, stress, or fatigue details captured.']);
  if (profile.prenatal && Object.keys(profile.prenatal).length) rows.push(['Pregnancy/lactation', 'Pregnancy, lactation, or trimester details captured.']);
  if (profile.cycleData && Object.keys(profile.cycleData).length) rows.push(['Cycle nutrition', 'Cycle phase and menstrual pattern details captured.']);
  if (profile.intimate && Object.keys(profile.intimate).length) rows.push(['Adult wellness', 'Adult wellness details captured privately.']);
  return rows;
}

function assessmentEvidenceSection(payload = {}, profile = {}) {
  const labs = labSummaryRows(profile.labs || {});
  const modules = compactModuleSummary(profile);
  const rows = [
    ['Age / sex', [profile.age ? `${profile.age} years` : '', profile.sex].filter(Boolean).join(' / ')],
    ['Height / weight', [profile.height ? `${profile.height} cm` : '', profile.weight ? `${profile.weight} kg` : ''].filter(Boolean).join(' / ')],
    ['BMI category', [payload.bmi || profile.bmi, profile.cat].filter(Boolean).join(' / ')],
    ['Activity level', profile.activity],
    ['Primary goal', profile.goal],
    ['Plan type', profile.plantype],
    ['Health conditions', listDisplay(profile.conds || payload.conds)],
    ['Diagnosis details', profile.diagnosis],
    ['Date diagnosed / duration', profile.diagnosisDate],
    ['Symptoms noted', profile.symptoms],
    ['Red-flag symptoms / urgent concerns', profile.redFlags],
    ['Allergies/intolerances', profile.allergies],
    ['Food dislikes / foods avoided', profile.foodDislikes],
    ['Cultural / usual foods', profile.culturalFoods],
    ['Medication notes', profile.meds],
    ['Home monitoring readings', profile.monitoring],
    ['Clinician follow-up status', profile.clinicianStatus],
    ['Special status', profile.specialStatus],
    ['Budget / cooking setup', [profile.budget, profile.cooking].filter(Boolean).join(' / ')],
    ['Customer source', [profile.customerSource, profile.referralCode, profile.customerType].filter(Boolean).join(' / ')]
  ].filter(([, value]) => String(value || '').trim());
  const labHtml = labs.length
    ? `<div class="mini-table">${labs.map(([label, value]) => `<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`).join('')}</div>`
    : `<div class="note">No lab values were submitted. The plan uses nutrition-screening logic and should be refined when glucose, BP, lipid, kidney, iron, or pregnancy-related results are available.</div>`;
  const moduleHtml = modules.length
    ? `<div class="mini-table">${modules.map(([label, value]) => `<div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`).join('')}</div>`
    : `<div class="note">No advanced module details were submitted beyond the main assessment.</div>`;
  return `<div class="sec"><div class="sh"><div class="si">AU</div><div><div class="st">Assessment Used to Build This Plan</div><div class="subtle">These are the submitted details used to personalise this plan.</div></div></div>
    <div class="grid">${rows.map(([label, value]) => `<div class="box"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`).join('')}</div>
    <div class="two-col">
      <div><h3>Submitted lab / clinical values</h3>${labHtml}</div>
      <div><h3>Extra personalisation modules</h3>${moduleHtml}</div>
    </div>
  </div>`;
}

function bmiMeaningSection(payload = {}, profile = {}) {
  const rawBmi = Number(payload.bmi || profile.bmi || 0);
  const category = shortDisplay(profile.cat || payload.cat || payload.category, 'Not captured');
  const height = Number(profile.height || 0);
  const weight = Number(profile.weight || profile.currentWeight || 0);
  const healthyWeight = height ? Math.round(24.9 * Math.pow(height / 100, 2) * 10) / 10 : 0;
  let meaning = 'BMI is one screening tool. It does not replace waist measurements, body composition, lab results, symptoms, medication review, or clinical judgement.';
  if (rawBmi && rawBmi < 18.5) meaning = 'Your BMI is below the usual healthy range, so this plan prioritises steady energy, adequate protein, micronutrient density, and appetite-friendly meals.';
  if (rawBmi >= 18.5 && rawBmi < 25) meaning = 'Your BMI is within the usual healthy range, so this plan focuses on maintaining energy, metabolic health, digestion, and long-term protective eating patterns.';
  if (rawBmi >= 25 && rawBmi < 30) meaning = 'Your BMI is above the usual healthy range, so this plan uses measured starch portions, higher-fibre meals, protein at each main meal, and sustainable energy control.';
  if (rawBmi >= 30) meaning = 'Your BMI is in the obesity range, so this plan supports gradual fat loss, appetite control, glucose and blood-pressure risk reduction, and muscle preservation.';
  const targetLine = healthyWeight && weight && weight > healthyWeight
    ? `A healthy long-term reference weight for your height may be around ${healthyWeight} kg, but the first target should be gradual progress, not rapid weight loss.`
    : 'The best target is progress in energy, measurements, symptoms, appetite control, and clinical markers, not only scale weight.';
  return `<div class="sec"><div class="sh"><div class="si">BMI</div><div><div class="st">Your BMI Assessment and Clinical Meaning</div><div class="subtle">A simple screening summary to help interpret the plan safely.</div></div></div>
    <div class="gauge"><div class="gpin" style="left:${escapeHtml(gaugePosServer(rawBmi))}%"></div></div>
    <div class="glbl"><span>Underweight below 18.5</span><span>Normal 18.5 to 25</span><span>Overweight 25 to 30</span><span>Obese 30 and above</span></div>
    <div class="bmi-exp"><strong>BMI ${rawBmi ? escapeHtml(rawBmi) : 'not captured'}: ${escapeHtml(category)}.</strong> ${escapeHtml(meaning)} ${escapeHtml(targetLine)}</div>
  </div>`;
}

function projectedOutcomesSection(profile = {}, macros = {}) {
  const goal = String(profile.goal || '').toLowerCase();
  const weight = Number(profile.weight || profile.currentWeight || 0);
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const outcome = goal.includes('loss') || goal.includes('weight')
    ? 'A realistic fat-loss pace is usually about 0.25 to 0.75 kg per week when portions, protein, sleep, and activity are consistent.'
    : goal.includes('gain')
      ? 'A realistic weight-gain pace is gradual, with emphasis on appetite, strength, protein, and nutrient-dense snacks rather than sugary high-calorie foods.'
      : 'The most important outcomes are better energy, steadier appetite, improved digestion, practical eating rhythm, and stronger long-term food choices.';
  const weightNote = weight ? `Current submitted weight: ${weight} kg. Use the same scale, same time of day, once weekly.` : 'Track progress using measurements, appetite, symptoms, energy, sleep, and clinical markers where available.';
  const measures = ['weekly weight or waist trend', 'hunger and cravings', 'energy and sleep', 'digestion and stool pattern', 'meal satisfaction and cost'];
  if (condText.includes('diabetes') || condText.includes('glucose') || condText.includes('hba1c')) measures.push('fasting and post-meal glucose if available');
  if (condText.includes('hypertension') || condText.includes('blood pressure') || condText.includes('sbp')) measures.push('home blood pressure if available');
  if (condText.includes('kidney') || condText.includes('egfr')) measures.push('kidney labs before major protein or potassium changes');
  return `<div class="sec"><div class="sh"><div class="si y">TIME</div><div><div class="st">Your Projected Outcomes Over Time</div><div class="subtle">Expected progress should be realistic and measurable.</div></div></div>
    <div class="phase-grid">
      <div class="phase"><strong>Weeks 1 to 2</strong><p>Foundation phase: build meal rhythm, water routine, protein consistency, portion awareness, and record meals that feel unrealistic.</p></div>
      <div class="phase"><strong>Weeks 3 to 4</strong><p>Adjustment phase: review hunger, digestion, taste, cost, energy, cravings, repeated foods, and replace weak meals.</p></div>
      <div class="phase"><strong>Month 2</strong><p>Progress phase: increase variety, improve shopping habits, add realistic movement, and refine portions using measurements.</p></div>
      <div class="phase"><strong>Month 3</strong><p>Maintenance phase: keep the best meals, update labs if needed, and turn the plan into a repeatable lifestyle pattern.</p></div>
    </div>
    <div class="note"><strong>Expected direction:</strong> ${escapeHtml(outcome)} ${escapeHtml(weightNote)} Daily starting target: ${escapeHtml(macros.calories)} kcal, ${escapeHtml(macros.protein)} g protein, ${escapeHtml(macros.fibre)} g fibre.<br><strong>Measure:</strong> ${escapeHtml(measures.join(', '))}.</div>
  </div>`;
}

function programmeGuideSection(payload = {}, profile = {}) {
  const family = isFamilyPlanPayload(payload, profile);
  const phases = family
    ? [
        ['Week 1', 'Use the shared 7-day household menu and record appetite, cost, disliked foods, and leftovers.'],
        ['Week 2', 'Repeat the same structure but rotate proteins: fish, chicken, beans, yogurt, groundnuts, and egg where suitable.'],
        ['Weeks 3 to 4', 'Batch-cook staples, soups, beans, greens, and sauces; adjust portions by age and activity.'],
        ['Days 31 to 60', 'Keep the best accepted meals and replace weak meals using the same breakfast, snack, lunch, snack, dinner rhythm.']
      ]
    : [
        ['Week 1', 'Follow the 7-day menu as your foundation week. Record hunger, taste, energy, digestion, and disliked foods.'],
        ['Week 2', 'Repeat the structure with smart swaps: rotate staple, vegetable, protein, and sauce while keeping portions measured.'],
        ['Weeks 3 to 4', 'Use the best meals more often and replace impractical meals with similar alternatives from the plan.'],
        ['Days 31 to 60', 'Review measurements, symptoms, glucose/BP or labs where relevant, then tighten portions and variety.']
      ];
  return `<div class="sec"><div class="sh"><div class="si">30</div><div><div class="st">${family ? 'Household 30-60 Day Plan Guide' : '30-60 Day Plan Guide'}</div><div class="subtle">The 7-day menu is the first rotation, not the whole journey.</div></div></div>
    <div class="phase-grid">${phases.map(([title, text]) => `<div class="phase"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function practicalRecipeGuideSection(profile = {}) {
  const items = [
    ['Balanced breakfast bowl', 'Plain yogurt or millet porridge, fruit, and groundnuts or seeds. Keep fruit to 1 fist-size portion; add protein so it is not only sugar.'],
    ['Local cooked lunch plate', '1/2 to 1 cup staple, 1 palm-size protein, 2 cups vegetables, and 1 tablespoon sauce or groundnut paste where clinically safe.'],
    ['Light dinner soup', '1 to 2 cups soup with vegetables and protein. Add a small starch only if hungry, active, pregnant, underweight, or advised.'],
    ['Salad or bowl meal', '2 cups vegetables, 1 palm protein, 1/2 cup beans or grains if needed, avocado quarter or 1 tablespoon dressing.'],
    ['Safe smoothie or yogurt option', 'Use only for breakfast or snack: plain yogurt or milk base, 1 small fruit portion, seeds or groundnuts, and no added sugar. Do not use smoothies to replace lunch or dinner.'],
    ['Leftover upgrade', 'Turn leftover beans, fish, chicken, or greens into a bowl with fresh vegetables, lemon, and measured starch instead of repeating the exact same plate.']
  ];
  return `<div class="sec"><div class="sh"><div class="si">COOK</div><div><div class="st">Simple Recipe Guide Using Your Recommended Foods</div><div class="subtle">Use these as practical templates when repeating or swapping meals.</div></div></div>
    <div class="support-grid">${items.map(([title, text]) => `<div class="recipe-mini"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function foodAlliesSection(profile = {}) {
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const allies = [
    ['Beans, peas, and lentils', 'Affordable protein and fibre. Use measured portions and adjust if gut symptoms, gout, or kidney restrictions apply.'],
    ['Fish and mukene', 'Useful protein, calcium from small fish with bones, and omega-3 support. Grill, steam, stew, or lightly cook rather than deep-fry.'],
    ['Dark leafy vegetables', 'Support fibre, folate, potassium, magnesium, and iron. Use dodo, nakati, sukuma, spinach, cabbage, or available greens.'],
    ['Sweet potato, matooke, millet, oats', 'Better staple choices when portions are measured and paired with protein and vegetables.'],
    ['Plain yogurt', 'Useful for protein and gut support where tolerated. Choose unsweetened options.'],
    ['Avocado, nuts, and seeds', 'Helpful healthy fats, but portions matter: avocado quarter, nuts one small handful, seeds 1 tablespoon.']
  ];
  if (condText.includes('diabetes')) allies.push(['Best for glucose control', 'Vegetables, protein, beans where tolerated, oats, millet, sweet potato, and fruit in measured whole portions.']);
  if (condText.includes('hypertension') || condText.includes('blood pressure')) allies.push(['Best for blood pressure', 'Vegetables, fruit in measured portions, beans where tolerated, unsweetened hibiscus, and low-salt home cooking.']);
  if (condText.includes('pregnan') || condText.includes('lactation')) allies.push(['Best for pregnancy support', 'Well-cooked protein, iron-rich foods with vitamin C, plain yogurt, greens, folate foods, safe fish choices, and hydration.']);
  if (String(profile.budget || '').toLowerCase().includes('low')) allies.push(['Best low-budget foods', 'Beans, cowpeas, cabbage, dodo/nakati, sweet potato, pumpkin, millet, eggs where safe, and seasonal fruit.']);
  if (String(profile.goal || '').toLowerCase().includes('weight')) allies.push(['Best for weight management', 'Soup, vegetables, beans where tolerated, fish/chicken, plain yogurt, salads/bowls, and measured staples.']);
  return `<div class="sec"><div class="sh"><div class="si">FOOD</div><div><div class="st">Best Foods to Use Often</div><div class="subtle">Practical foods that support taste, budget, fullness, and nutrition goals.</div></div></div>
    <div class="support-grid">${allies.map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function progressCheckpointsSection() {
  const points = [
    ['After 7 days', 'Which meals were realistic? Which were repeated, expensive, bland, or difficult to cook?'],
    ['After 14 days', 'Check hunger, energy, digestion, sleep, cravings, and whether portions felt too large or too small.'],
    ['After 30 days', 'Review weight/waist, symptoms, BP/glucose where relevant, medication changes, and meal satisfaction.'],
    ['Before renewal', 'Use feedback to rebuild the next rotation with better taste, variety, and clinical precision.']
  ];
  return `<div class="sec"><div class="sh"><div class="si o">CHK</div><div><div class="st">Progress Checkpoints</div><div class="subtle">A professional plan improves through follow-up.</div></div></div>
    <div class="phase-grid">${points.map(([title, text]) => `<div class="phase"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function protectiveFoodsSection() {
  const foods = [
    'Garlic, ginger, onion, herbs, and spices for flavour so meals do not depend on excess salt or sugar.',
    'Colourful vegetables and fruit in measured portions: greens, carrots, pumpkin, tomato, papaya, passion fruit, mango, and berries where available.',
    'Fish, beans, lentils, yogurt, chicken, eggs where suitable, and groundnuts for protein rotation.',
    'Whole or minimally processed staples in measured portions instead of large plates of refined starch.',
    'Unsweetened drinks such as water, herbal tea, hibiscus, or plain tea without sugar.'
  ];
  return `<div class="sec"><div class="sh"><div class="si r">LONG</div><div><div class="st">Long-Term Health Foods</div><div class="subtle">Simple foods to keep in the routine after the first month.</div></div></div>
    <div class="value-list">${foods.map(food => `<p>${escapeHtml(food)}</p>`).join('')}</div>
  </div>`;
}

function hairSkinNailsSection(macros = {}) {
  const items = [
    `Protein target: aim near ${macros.protein || 'your'} g/day unless kidney or medical review says otherwise. Hair, skin, and nails need consistent protein.`,
    'Iron, zinc, vitamin D, omega-3 fats, vitamin C, and B vitamins support hair growth, skin repair, and nail strength.',
    'If hair shedding, brittle nails, fatigue, or pale skin are significant, request ferritin/iron studies, vitamin D, B12, thyroid, and clinician review.'
  ];
  return `<div class="sec"><div class="sh"><div class="si">SKIN</div><div><div class="st">Nutrition for Hair, Skin and Nail Health</div><div class="subtle">A focused beauty-and-health section without exaggerated promises.</div></div></div>
    <div class="value-list">${items.map(item => `<p>${escapeHtml(item)}</p>`).join('')}</div>
  </div>`;
}

function gutHealthSection(macros = {}) {
  const items = [
    `Aim toward ${macros.fibre || 25} g fibre daily using beans, vegetables, fruit, oats, millet, and seeds, increasing gradually if your gut is sensitive.`,
    'Use plain yogurt or fermented foods where tolerated; avoid forcing them if they worsen bloating, diarrhoea, reflux, or intolerance.',
    'Chew slowly, eat at consistent times, drink water through the day, and record foods that cause pain, bloating, constipation, or diarrhoea.'
  ];
  return `<div class="sec"><div class="sh"><div class="si">GUT</div><div><div class="st">Gut Health and Digestive Wellness</div><div class="subtle">Practical digestion support that can be adjusted during follow-up.</div></div></div>
    <div class="value-list">${items.map(item => `<p>${escapeHtml(item)}</p>`).join('')}</div>
  </div>`;
}

function weightManagementSection(profile = {}, macros = {}) {
  const items = [
    'The most reliable approach is not starvation. It is a repeatable structure: protein, vegetables, measured starch, healthy fat in small portions, water, sleep, and activity.',
    'Smoothies are kept to breakfast or snacks because drinks rarely satisfy like real meals. Lunch and dinner should usually be cooked meals, bowls, soups, legumes, fish, chicken, or vegetables.',
    'Use the hand guide: protein one palm, starch one fist or 1/2 to 1 cup, vegetables two fists, fat one thumb or 1 tablespoon.',
    'If you use diabetes medication, pregnancy care, kidney care, or blood-pressure medicine, avoid aggressive fasting or extreme dieting unless your clinician approves.'
  ];
  return `<div class="sec"><div class="sh"><div class="si o">WG</div><div><div class="st">Weight Management: What Actually Works</div><div class="subtle">Evidence-informed habits that are realistic enough to keep.</div></div></div>
    <div class="value-list">${items.map(item => `<p>${escapeHtml(item)}</p>`).join('')}</div>
  </div>`;
}

function profileTextIncludes(profile = {}, words = []) {
  const text = JSON.stringify(profile || {}).toLowerCase();
  return words.some(word => text.includes(String(word).toLowerCase()));
}

function specialistClinicalItems(profile = {}, clinicalSummary = {}) {
  const conds = cleanList(profile.conds || clinicalSummary.conditions).map(c => String(c).toLowerCase());
  const has = words => words.some(word => conds.includes(word) || profileTextIncludes(profile, [word]));
  const items = [];
  if (has(['diabetes', 'prediabetes', 'glucose', 'hba1c'])) {
    items.push({
      title: 'Diabetes / Glucose Support',
      chapter: 'This plan supports blood-glucose stability through measured carbohydrate portions, protein pairing, vegetables, fibre, consistent meal timing, and avoidance of sweet drinks. Carbohydrates should not be eaten alone where possible. If insulin or glucose-lowering medicine is used, meals should not be skipped without clinician guidance.',
      targets: [
        ['Carbohydrate distribution', 'Spread measured carbohydrates across meals; avoid one very large starch-heavy meal.'],
        ['Plate target', '2 cups vegetables, 1 palm protein, 1/2 to 1 cup measured starch at main meals.'],
        ['Monitoring', 'Track fasting and 2-hour post-meal glucose where available, especially after new meals.'],
        ['Safety gate', 'Medication users should avoid aggressive fasting or skipped meals unless approved by a clinician.']
      ]
    });
  }
  if (has(['hypertension', 'blood pressure', 'sbp', 'dbp'])) {
    items.push({
      title: 'Hypertension / Blood Pressure Support',
      chapter: 'This plan supports blood pressure by reducing salt-heavy foods, improving vegetable intake, using beans and fruit in measured portions where suitable, and replacing salty flavouring with tomato, onion, garlic, ginger, lemon, herbs, and spices.',
      targets: [
        ['Sodium direction', 'Use low-salt home cooking; reduce stock cubes, salty sauces, processed meats, salted snacks, and salty takeaways.'],
        ['Potassium caution', 'Vegetables and fruit can support BP, but kidney disease requires potassium review first.'],
        ['Monitoring', 'Record home BP if available, especially when symptoms, medication changes, or high readings occur.'],
        ['Meal pattern', 'Avoid relying on fried/salty snacks as meals; use structured meals with protein and vegetables.']
      ]
    });
  }
  if (has(['cholesterol', 'ldl', 'triglyceride', 'triglycerides', 'lipid'])) {
    items.push({
      title: 'LDL / Cholesterol Support',
      chapter: 'This plan supports LDL reduction by increasing soluble fibre, rotating lean proteins and legumes, and reducing frequent deep-fried foods, processed meats, pastries, and heavy saturated-fat patterns.',
      targets: [
        ['Soluble fibre', 'Use oats, beans, peas, lentils, vegetables, fruit, and seeds regularly, increasing fibre gradually.'],
        ['Fat quality', 'Use fish, avocado, nuts/seeds, and measured oils; reduce repeated deep-fried foods and processed meats.'],
        ['Protein rotation', 'Rotate fish, chicken, beans/lentils, yogurt, groundnuts, and eggs only where suitable.'],
        ['Monitoring', 'Review LDL, HDL, triglycerides, weight/waist, and medication changes during follow-up.']
      ]
    });
  }
  if (has(['kidney', 'egfr', 'creatinine', 'ckd'])) {
    items.push({
      title: 'Kidney Review Nutrition',
      chapter: 'Kidney nutrition must be lab-guided. Protein, potassium, phosphorus, sodium, and fluid advice should be adjusted using eGFR, creatinine, potassium, phosphate, urine results, blood pressure, swelling symptoms, appetite, and clinician advice.',
      targets: [
        ['Lab gate', 'Confirm eGFR, creatinine, potassium, phosphate, urine protein, BP, and swelling before major changes.'],
        ['Protein caution', 'Avoid aggressive high-protein dieting until kidney stage and clinician advice are known.'],
        ['Mineral caution', 'Do not automatically restrict all fruits/vegetables; adjust potassium/phosphorus only when labs require it.'],
        ['Safety', 'Swelling, breathlessness, very low urine, confusion, or severe weakness needs medical review.']
      ]
    });
  }
  if (has(['gout', 'uric', 'uric acid'])) {
    items.push({
      title: 'Gout / Uric Acid Support',
      chapter: 'This plan supports gout risk reduction through hydration, steady weight management, reduced alcohol and sweet drinks, and careful review of very high-purine foods. Food tolerance should be reviewed individually rather than using extreme restriction.',
      targets: [
        ['Hydration', 'Prioritise water and unsweetened drinks unless fluid restriction has been prescribed.'],
        ['Reduce', 'Avoid organ meats and reduce alcohol/sugary drinks; review fish and legumes based on symptoms and clinician advice.'],
        ['Weight pattern', 'Avoid crash dieting, which may worsen uric-acid instability.'],
        ['Monitoring', 'Track flare timing, uric acid results where available, alcohol intake, hydration, and trigger meals.']
      ]
    });
  }
  if (has(['ibs', 'gut', 'bloating', 'constipation', 'diarrhoea', 'reflux'])) {
    items.push({
      title: 'IBS / Gut-Sensitive Support',
      chapter: 'This plan supports gut tolerance with cooked meals, gradual fibre progression, smaller portions, symptom tracking, and structured reintroduction. It should not remove many foods permanently without review.',
      targets: [
        ['Trigger tracking', 'Track beans, milk, onions, garlic, cabbage, wheat, high-fat meals, and selected fruits if symptoms flare.'],
        ['Fibre progression', 'Increase fibre gradually; use cooked vegetables, oats, soups, and tolerated legumes in measured portions.'],
        ['Meal size', 'Use smaller regular meals if bloating/reflux worsens after large meals.'],
        ['Review', 'Blood in stool, unexplained weight loss, persistent vomiting, fever, or severe pain requires medical care.']
      ]
    });
  }
  if (has(['anemia', 'anaemia', 'haemoglobin', 'hemoglobin', 'ferritin', 'iron'])) {
    items.push({
      title: 'Iron / Anaemia Support',
      chapter: 'This plan supports iron status by pairing iron-rich foods with vitamin C and avoiding tea/coffee at iron-rich meals. Low haemoglobin, low ferritin, pregnancy, heavy bleeding, or severe fatigue needs clinical follow-up.',
      targets: [
        ['Iron foods', 'Use beans, greens, fish, lean meat where used, eggs where suitable, and fortified foods where available.'],
        ['Vitamin C pairing', 'Add citrus, tomato, passion fruit, guava, or other vitamin-C foods with iron-rich meals.'],
        ['Avoid interference', 'Keep tea/coffee away from iron-rich meals where possible.'],
        ['Monitoring', 'Review full blood count, ferritin, B12/folate where relevant, and cause of anaemia.']
      ]
    });
  }
  if (has(['thyroid', 'tsh', 'hypothyroid', 'hyperthyroid'])) {
    items.push({
      title: 'Thyroid Nutrition Support',
      chapter: 'This plan supports thyroid-related nutrition through adequate protein, iron, zinc, selenium, iodine from safe food sources, fibre, and steady meal timing. Medication timing should follow clinician or pharmacist advice.',
      targets: [
        ['Meal rhythm', 'Use regular meals to support energy and appetite stability.'],
        ['Micronutrients', 'Prioritise iron, zinc, selenium, iodine from food, vitamin D, and B12 where clinically relevant.'],
        ['Medication timing', 'Separate thyroid medication from food/supplements according to clinician/pharmacist instructions.'],
        ['Monitoring', 'Review TSH/T3/T4 results, symptoms, medication changes, weight trend, and fatigue.']
      ]
    });
  }
  if (has(['pregnant', 'pregnancy', 'trimester', 'prenatal', 'lactation', 'breastfeeding'])) {
    items.push({
      title: 'Pregnancy / Lactation Support',
      chapter: 'This plan prioritises food safety, protein, iron, folate, calcium, iodine, vitamin D, hydration, nausea-friendly meals, constipation prevention, and safe weight-gain monitoring according to trimester or breastfeeding status.',
      targets: [
        ['Food safety', 'Use well-cooked proteins; avoid alcohol, unpasteurised dairy, and unsafe high-mercury fish.'],
        ['Nutrient focus', 'Protein, iron/folate foods, calcium foods, vitamin D, iodine, fluids, and fibre.'],
        ['Symptom support', 'Use smaller frequent meals for nausea/reflux and fibre/fluids for constipation where tolerated.'],
        ['Urgent review', 'Bleeding, severe headache, severe swelling, fever, high BP, reduced foetal movement, or severe vomiting needs clinical care.']
      ]
    });
  }
  if (has(['pmos', 'pcos', 'polycystic', 'insulin resistance'])) {
    items.push({
      title: 'PMOS / Insulin-Resistance Support',
      chapter: 'This plan supports PMOS-related metabolic health through protein at meals, measured carbohydrates, fibre, strength-friendly nutrition, sleep support, and reduced sugary drinks. It should not promise cure or diagnose hormonal disease.',
      targets: [
        ['Carb quality', 'Use measured whole staples and avoid large refined-starch or sugary-drink patterns.'],
        ['Protein/fibre', 'Include protein and vegetables at main meals to support appetite and glucose stability.'],
        ['Movement', 'Strength training and walking can support insulin sensitivity where safe and realistic.'],
        ['Monitoring', 'Track cycles, acne/hair changes, waist, glucose/HbA1c if available, and medication use.']
      ]
    });
  }
  if (has(['obesity', 'metabolic syndrome', 'weight loss', 'overweight'])) {
    items.push({
      title: 'Obesity / Metabolic Health Support',
      chapter: 'This plan supports gradual fat loss and metabolic health without starvation. The focus is protein consistency, vegetables, measured starches, hydration, sleep, movement, and sustainable meal repetition with variety.',
      targets: [
        ['Pace', 'Aim for gradual progress, usually about 0.25 to 0.75 kg per week when appropriate.'],
        ['Plate structure', 'Protein + vegetables first, measured starch, and small healthy-fat portions.'],
        ['Appetite', 'Use real cooked meals, soups, bowls, and protein snacks rather than drink-only days.'],
        ['Monitoring', 'Track weight/waist weekly, hunger, cravings, sleep, energy, and adherence.']
      ]
    });
  }
  if (has(['cancer', 'oncology', 'chemotherapy', 'radiotherapy'])) {
    items.push({
      title: 'Cancer Supportive Nutrition',
      chapter: 'This plan can support nourishment during cancer care but must not replace oncology treatment. Priorities are maintaining intake, protein, safe food handling, symptom-aware meals, hydration, and clinician-led adjustments during treatment.',
      targets: [
        ['Protein and energy', 'Use small frequent meals and protein-rich foods if appetite is low, unless restricted by the care team.'],
        ['Food safety', 'Use careful hygiene, safe storage, and well-cooked foods when immunity may be low.'],
        ['Symptom support', 'Adjust texture, smell, spice, acidity, and portion size for nausea, mouth sores, diarrhoea, constipation, or taste changes.'],
        ['Clinical gate', 'Unplanned weight loss, poor intake, fever, severe diarrhoea/vomiting, or swallowing difficulty needs medical review.']
      ]
    });
  }
  if (isFamilyPlanPayload({}, profile)) {
    items.push({
      title: 'Family Plan Clinical Personalisation',
      chapter: 'The household should use one shared meal base, then adjust each plate by age, appetite, activity, pregnancy, child growth, older-adult needs, and any individual conditions. One member\'s clinical restriction should not automatically be applied to everyone.',
      targets: [
        ['Shared base', 'Cook one protein/legume, vegetable, staple, and sauce base where possible.'],
        ['Individual portions', 'Adjust starch, protein, salt, sugar, texture, and snacks per member.'],
        ['Condition conflicts', 'Diabetes, kidney, pregnancy, child growth, and older-adult needs require different plate adjustments.'],
        ['Follow-up', 'Review taste, cost, acceptance, symptoms, repeated foods, and member-specific measurements.']
      ]
    });
  }
  return items;
}

function conditionChaptersSection(profile = {}, clinicalSummary = {}) {
  const chapters = specialistClinicalItems(profile, clinicalSummary);
  if (!chapters.length) return '';
  const targetRows = chapters.flatMap(item => item.targets.map(([target, guidance]) => [item.title, target, guidance]));
  return `<div class="sec"><div class="sh"><div class="si b">CL</div><div><div class="st">Condition-Specific Nutrition Chapters</div><div class="subtle">Targeted guidance for the health concerns submitted in the assessment.</div></div></div>
    <div class="support-grid">${chapters.map(item => `<div class="info-card"><strong>${escapeHtml(item.title)}</strong><p>${escapeHtml(item.chapter)}</p></div>`).join('')}</div>
    <div class="week-card" style="margin-top:8px"><div class="day-title">Clinical Targets for This Specialist Plan</div><table style="width:100%;border-collapse:collapse;font-size:11.5px"><thead><tr><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Condition</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Target area</th><th style="text-align:left;padding:7px;border-bottom:1px solid #eee6dc">Patient-safe guidance</th></tr></thead><tbody>${targetRows.map(([condition, target, guidance]) => `<tr><td style="padding:8px;border-bottom:1px solid #eee6dc"><strong>${escapeHtml(condition)}</strong></td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(target)}</td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(guidance)}</td></tr>`).join('')}</tbody></table></div>
  </div>`;
}

function foodAvoidReplacementSection(profile = {}) {
  const conds = cleanList(profile.conds).map(c => String(c).toLowerCase());
  const rows = [];
  rows.push(['Soda, sweet juice, and energy drinks', 'Water, unsweetened hibiscus, unsweetened tea, lemon water, or diluted fresh fruit flavour without added sugar.']);
  rows.push(['Deep-fried foods as the default cooking method', 'Grill, steam, stew, bake, air-fry lightly, or pan-cook with measured oil.']);
  rows.push(['Large posho, rice, pasta, or white-bread portions', 'Measured matooke, sweet potato, millet, oats, vegetables, beans, or 1/2 to 1 cup cooked starch depending on the plan.']);
  rows.push(['Salty processed foods, stock cubes, and heavy sauces', 'Herbs, tomato, onion, garlic, lemon, ginger, vinegar, pepper, and spices.']);
  if (conds.includes('diabetes') || profileTextIncludes(profile, ['diabetes', 'glucose', 'hba1c'])) rows.push(['Sugary drinks and large refined starch plates', 'Water, unsweetened tea, measured whole staples, vegetables, and protein-paired meals.']);
  if (conds.includes('hypertension') || profileTextIncludes(profile, ['hypertension', 'blood pressure'])) rows.push(['High-salt processed foods and salty cooking', 'Herbs, garlic, ginger, onion, tomato, lemon, vinegar, and measured salt.']);
  if (conds.includes('cholesterol') || profileTextIncludes(profile, ['cholesterol', 'ldl'])) rows.push(['Frequent deep-fried foods and processed meats', 'Grilled fish, chicken, beans, yogurt, vegetable stews, and measured healthy fats.']);
  if (conds.includes('kidney') || profileTextIncludes(profile, ['kidney', 'egfr'])) rows.push(['Unreviewed high-protein or high-potassium diets', 'Lab-guided portions and clinician-reviewed protein, potassium, phosphorus, and sodium targets.']);
  if (conds.includes('ibs') || profileTextIncludes(profile, ['ibs', 'bloating'])) rows.push(['Large portions of personal trigger foods', 'Smaller cooked portions, symptom tracking, and structured reintroduction after symptoms calm.']);
  if (!rows.length) {
    rows.push(['Ultra-processed snacks and sweetened drinks', 'Whole meals with protein, vegetables, fibre, measured starch, and water.']);
    rows.push(['Skipping meals then overeating later', 'Regular meal rhythm with practical snacks when needed.']);
  }
  return `<div class="sec"><div class="sh"><div class="si r">SWAP</div><div><div class="st">Foods to Reduce and Smarter Replacements</div><div class="subtle">Practical swaps that make meals easier to follow.</div></div></div>
    <div class="support-grid">${rows.map(([avoid, replace]) => `<div class="info-card"><strong>Reduce: ${escapeHtml(avoid)}</strong><p><b>Replace with:</b> ${escapeHtml(replace)}</p></div>`).join('')}</div>
  </div>`;
}

function personalisedFoodStrategySection(profile = {}, macros = {}) {
  const conds = cleanList(profile.conds).map(c => String(c).toLowerCase());
  const strategy = [];
  if (conds.includes('diabetes') || profileTextIncludes(profile, ['diabetes', 'glucose', 'hba1c'])) {
    strategy.push(['Glucose-stable plate', 'At lunch and dinner, use 2 cups vegetables, 1 palm protein, and 1/2 to 1 cup measured starch. Avoid taking starch alone.']);
  }
  if (conds.includes('hypertension') || profileTextIncludes(profile, ['hypertension', 'blood pressure'])) {
    strategy.push(['Blood-pressure friendly flavour', 'Build flavour with tomato, onion, garlic, ginger, lemon, herbs, and spices so salt does not carry the whole meal.']);
  }
  if (conds.includes('cholesterol') || profileTextIncludes(profile, ['cholesterol', 'ldl'])) {
    strategy.push(['LDL-lowering fibre', 'Use oats, beans, peas, lentils, fruit, vegetables, and seeds regularly. Fibre should rise gradually if the gut is sensitive.']);
  }
  if (conds.includes('ibs') || profileTextIncludes(profile, ['ibs', 'bloating'])) {
    strategy.push(['Gut-sensitive rotation', 'Use smaller portions, softer cooked foods, soups, rice/oats/sweet potato where tolerated, and track personal triggers.']);
  }
  if (conds.includes('kidney') || profileTextIncludes(profile, ['kidney', 'egfr'])) {
    strategy.push(['Kidney lab gate', 'Do not force high-protein, high-potassium, or high-phosphorus foods until kidney labs confirm the safe target range.']);
  }
  if (profileTextIncludes(profile, ['pregnant', 'pregnancy', 'lactation', 'breastfeeding'])) {
    strategy.push(['Pregnancy-safe meals', 'Use well-cooked proteins, safe dairy, iron and folate foods, hydration, and small frequent meals if nausea or reflux is present.']);
  }
  if (!strategy.length) {
    strategy.push(['Core plate method', 'Use vegetables first, then protein, then measured starch. This creates fullness and better energy without extreme dieting.']);
    strategy.push(['Protein rhythm', `Aim for protein at each main meal so the daily target of about ${macros.protein || 'your'} g is easier to reach.`]);
  }
  strategy.push(['Taste principle', 'A plan only works if the food is enjoyable. Use herbs, acidity, texture, sauces in measured portions, and smart swaps instead of plain boring meals.']);
  return `<div class="sec"><div class="sh"><div class="si">MAP</div><div><div class="st">Personalised Food Strategy</div><div class="subtle">The simple food logic behind this plan, written for real life.</div></div></div>
    <div class="support-grid">${strategy.map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function shoppingItemQty(item, count, profile = {}) {
  const family = count > 1;
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const kidney = condText.includes('kidney') || condText.includes('egfr') || condText.includes('creatinine');
  const gout = condText.includes('gout') || condText.includes('uric');
  const cholesterol = condText.includes('cholesterol') || condText.includes('ldl');
  const eggSensitive = /egg allergy|allergic to egg|eggs allergy|avoid egg|avoid eggs/.test(condText);
  const qty = {
    avocado: family ? '3-5 pieces' : '1-2 pieces',
    beans: family ? '1-2 kg dry beans/cowpeas' : '500g-1 kg dry beans/cowpeas',
    cabbage: family ? '2 heads' : '1 head',
    carrot: family ? '1 kg' : '500g',
    dodo: kidney ? 'use only after potassium review' : family ? '3-5 bunches' : '1-2 bunches',
    nakati: kidney ? 'use only after potassium review' : family ? '2-4 bunches' : '1-2 bunches',
    eggs: eggSensitive ? 'avoid' : cholesterol || kidney ? '6-10 eggs maximum if approved' : family ? '10-15 eggs, not a full tray unless heavily used' : '4-6 eggs',
    garlic: family ? '1-2 bulbs' : '1 bulb',
    ginger: '1 medium piece',
    groundnuts: kidney ? 'use only after potassium/phosphorus review' : family ? '500g' : '250g',
    lemon: family ? '5-8 pieces' : '3-4 pieces',
    mukene: kidney || gout ? 'avoid until reviewed' : family ? '250-500g, rinse well' : '150-250g, rinse well',
    onion: family ? '1 kg' : '500g',
    pumpkin: family ? '1 medium pumpkin' : '1 small pumpkin or 1/2 medium',
    sweet_potato: kidney ? 'use only after potassium review' : family ? '2-3 kg' : '1-2 kg',
    tilapia: gout || kidney ? 'fresh fish only if clinician/dietician approves' : family ? '3-5 palm-size portions' : '2-3 palm-size portions',
    tomato: family ? '1.5-2 kg' : '500g-1 kg',
    yogurt: family ? '4-6 cups plain unsweetened' : '2-3 cups plain unsweetened',
    chicken: family ? '3-5 palm-size portions' : '2 palm-size portions',
    oats: family ? '500g-1 kg' : '500g',
    millet: family ? '1-2 kg' : '500g-1 kg',
    cucumber: family ? '3-5 pieces' : '1-2 pieces',
    fruit: family ? '7-14 pieces seasonal fruit' : '4-7 pieces seasonal fruit'
  };
  return qty[item] || (family ? 'family quantity' : 'single-person quantity');
}

function shoppingItemLabel(item) {
  const labels = {
    sweet_potato: 'sweet potato',
    fruit: 'seasonal fruit'
  };
  return labels[item] || item;
}

function planShoppingWeeks(profile = {}, count = 1) {
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const kidney = condText.includes('kidney') || condText.includes('egfr') || condText.includes('creatinine');
  const gout = condText.includes('gout') || condText.includes('uric');
  const eggSensitive = /egg allergy|allergic to egg|eggs allergy|avoid egg|avoid eggs/.test(condText);
  const base = ['beans', 'cabbage', 'carrot', 'tomato', 'onion', 'garlic', 'ginger', 'lemon', 'pumpkin', 'yogurt', 'fruit'];
  const greenSet = kidney ? ['cabbage', 'cucumber'] : ['dodo', 'nakati', 'cabbage'];
  const proteinWeek1 = eggSensitive ? ['chicken', 'tilapia'] : ['eggs', 'tilapia'];
  const proteinWeek2 = kidney || gout ? ['chicken', 'beans'] : ['mukene', 'beans'];
  const proteinWeek3 = eggSensitive ? ['chicken', 'yogurt'] : ['eggs', 'beans', 'yogurt'];
  const proteinWeek4 = kidney || gout ? ['chicken', 'tilapia'] : ['tilapia', 'beans'];
  const weeks = [
    ['Week 1', [...base, ...greenSet, ...proteinWeek1, 'sweet_potato', 'avocado']],
    ['Week 2', [...base, ...greenSet, ...proteinWeek2, 'millet', 'oats']],
    ['Week 3', [...base, ...greenSet, ...proteinWeek3, 'sweet_potato', 'groundnuts']],
    ['Week 4', [...base, ...greenSet, ...proteinWeek4, 'millet', 'avocado']]
  ];
  return weeks.map(([title, items]) => {
    const seen = new Set();
    return {
      title,
      items: items.filter(item => {
        if (seen.has(item)) return false;
        seen.add(item);
        return true;
      }).map(item => [shoppingItemLabel(item), shoppingItemQty(item, count, profile)])
    };
  });
}

function weeklyShoppingMealPrepSection(payload = {}, profile = {}) {
  const family = isFamilyPlanPayload(payload, profile);
  const fd = profile.familyData || payload.familyData || {};
  const count = family ? Math.max(2, Number.parseInt(fd.count || profile.familyCount || 4, 10) || 4) : 1;
  const multiplier = family ? count : 1;
  const budget = String(profile.budget || fd.budget || '').toLowerCase();
  const lowBudget = budget.includes('low') || budget.includes('budget');
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const basket = [
    ['Weekly protein basket', lowBudget ? 'Beans, cowpeas, peas, lentils, eggs where suitable, mukene where safe and affordable.' : 'Fish, chicken, beans, yogurt, eggs where suitable, peas, lentils, or lean meat in measured portions.'],
    ['Vegetable basket', 'Dodo, nakati, sukuma wiki, cabbage, carrots, tomatoes, onions, cucumber, pumpkin, eggplant, or available seasonal vegetables.'],
    ['Measured staple basket', 'Matooke, sweet potato, millet, oats, rice, cassava, or posho in measured portions depending on the plan.'],
    ['Taste and snack basket', 'Plain yogurt, fruit, groundnuts, avocado, seeds, lemon, ginger, garlic, herbs, and unsweetened drinks.']
  ];
  if (lowBudget) basket.push(['Low-budget basket', 'Beans/cowpeas, cabbage, dodo/nakati, sweet potato, pumpkin, millet, seasonal fruit, groundnuts in small portions, and eggs where safe.']);
  if (family) basket.push(['Family basket', 'One shared protein base, two vegetable options, one soup/stew base, two measured staples, fruit for snacks, and packed-lunch foods.']);
  if (condText.includes('diabetes')) basket.push(['Diabetic-friendly basket', 'Non-starchy vegetables, beans where tolerated, plain yogurt, fish/chicken/eggs where safe, oats/millet, sweet potato, avocado, and unsweetened drinks.']);
  if (condText.includes('pregnan') || condText.includes('lactation')) basket.push(['Pregnancy basket', 'Well-cooked protein, plain yogurt or pasteurised dairy, iron-rich foods, greens, citrus/vitamin C foods, safe fish choices, and nausea-friendly staples.']);
  const weeklyQty = family
    ? [
        ['Week 1 foundation basket', `${count * 7} palm-size protein portions, ${count * 14} cups vegetables across the week, 2 staple choices, 1 soup/stew base, and fruit/snacks for school or work.`],
        ['Week 2 protein rotation basket', `Rotate proteins: beans/cowpeas twice, fish or mukene twice where safe, chicken or lean meat once or twice, yogurt/snack protein, and eggs only where suitable.`],
        ['Week 3 budget batch basket', `Batch-cook beans/cowpeas, greens, pumpkin/sweet potato, and one sauce base. Buy seasonal vegetables first, then add fish/chicken if budget allows.`],
        ['Week 4 refresh basket', `Repeat the best accepted meals, replace disliked meals, and buy only the proteins/staples that supported appetite, cost, symptoms, and household acceptance.`]
      ]
    : [
        ['Week 1 foundation basket', '7 palm-size protein portions, 10 to 14 cups vegetables across the week, 2 staple choices, 2 fruit types, plain yogurt or snack protein, herbs/spices, and unsweetened drinks.'],
        ['Week 2 protein rotation basket', 'Rotate fish/chicken/beans/yogurt/groundnuts/egg where safe. Keep lunch and dinner as real meals, not drinks.'],
        ['Week 3 budget batch basket', 'Batch beans or lentils, greens, soup base, sweet potato/pumpkin, and one salad/bowl base so cooking stays realistic.'],
        ['Week 4 refresh basket', 'Repeat the meals that tasted good and replace meals that were expensive, bland, repetitive, or difficult to prepare.']
      ];
  const prep = [
    'Batch-cook beans, cowpeas, or lentils once or twice weekly. Freeze or refrigerate in meal-size containers.',
    'Steam or roast sweet potatoes, pumpkin, or matooke ahead, then portion before serving.',
    'Wash and chop greens for 2 to 3 days. Cook greens briefly so they stay bright, tasty, and not watery.',
    'Grill, steam, stew, or pan-cook fish/chicken with measured oil. Avoid making deep-frying the default.',
    'Make salad bases dry: cabbage/cucumber/carrot/tomato separately from dressing so they stay fresh.',
    'Prepare yogurt/smoothie options safely: unsweetened base, one small fruit portion, no added sugar, and use only for breakfast/snacks.',
    'Store leftovers safely: cool quickly, cover, refrigerate, reheat thoroughly, and avoid keeping cooked food at room temperature for long.'
  ];
  const scaleNote = family
    ? `For this household, multiply most vegetable portions by about ${multiplier}; scale protein by palm-size portions per person; reduce toddler portions and increase active teen/adult portions.`
    : 'For one person, cook two to three base foods at a time so the plan stays realistic without eating the same meal every day.';
  const shoppingWeeks = planShoppingWeeks(profile, count).map(week => `<div class="week-card"><div class="week-head"><div class="week-title">${escapeHtml(week.title)} Market List</div><div class="week-focus">Starting quantities. Adjust after taste, budget, symptoms, and leftovers are reviewed.</div></div><div class="day-block"><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${week.items.map(([item, qty]) => `<tr><td style="padding:8px;border-bottom:1px solid #eee6dc"><strong>${escapeHtml(item)}</strong></td><td style="padding:8px;border-bottom:1px solid #eee6dc">${escapeHtml(qty)}</td></tr>`).join('')}</tbody></table></div></div>`).join('');
  return `<div class="sec"><div class="sh"><div class="si o">SHOP</div><div><div class="st">Weekly Shopping and Meal Prep Guide</div><div class="subtle">This turns the plan from a document into food that can actually happen.</div></div></div>
    <div class="support-grid">
      ${basket.map(([title, item]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(item)}</p></div>`).join('')}
    </div>
    <div style="margin-top:10px">${shoppingWeeks}</div>
    <div class="phase-grid" style="margin-top:8px">
      ${weeklyQty.map(([title, item]) => `<div class="phase"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(item)}</p></div>`).join('')}
    </div>
    <div class="value-list" style="margin-top:8px">${prep.map(item => `<p>${escapeHtml(item)}</p>`).join('')}<p><strong>Scaling note:</strong> ${escapeHtml(scaleNote)}</p></div>
  </div>`;
}

function followUpRoadmapSection(profile = {}) {
  const rows = [
    ['Day 7', 'Report taste, hunger, bloating, cost, disliked meals, repeated foods, and whether portions felt realistic.'],
    ['Day 14', 'Review adherence, cravings, energy, sleep, digestion, and barriers such as shopping, cooking time, school, or work.'],
    ['Day 30', 'Review weight/waist, BP or glucose where relevant, symptoms, menstrual/pregnancy changes, and meal satisfaction.'],
    ['Day 60', 'Decide what to continue, what to replace, whether labs are needed, and whether the next plan should intensify or simplify.']
  ];
  if (profileTextIncludes(profile, ['diabetes', 'glucose', 'hba1c'])) rows.push(['Glucose review', 'If available, compare fasting and post-meal glucose readings with the meals that caused the best and worst responses.']);
  if (profileTextIncludes(profile, ['hypertension', 'blood pressure', 'sbp', 'dbp'])) rows.push(['BP review', 'Track home BP if available, salt-heavy meals, sleep, stress, alcohol, and medication adherence.']);
  if (profileTextIncludes(profile, ['kidney', 'egfr', 'creatinine'])) rows.push(['Kidney review', 'Bring kidney labs before major protein, potassium, phosphorus, or sodium changes.']);
  return `<div class="sec"><div class="sh"><div class="si b">ROAD</div><div><div class="st">Follow-Up and Progress Roadmap</div><div class="subtle">Customers should know exactly how the plan becomes stronger over time.</div></div></div>
    <div class="phase-grid">${rows.slice(0, 4).map(([title, text]) => `<div class="phase"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
    ${rows.length > 4 ? `<div class="value-list" style="margin-top:8px">${rows.slice(4).map(([title, text]) => `<p><strong>${escapeHtml(title)}:</strong> ${escapeHtml(text)}</p>`).join('')}</div>` : ''}
  </div>`;
}

function premiumFamilySupportSection(payload = {}, profile = {}) {
  if (!isFamilyPlanPayload(payload, profile)) return '';
  const fd = profile.familyData || payload.familyData || {};
  const count = Math.max(2, Number.parseInt(fd.count || profile.familyCount || 4, 10) || 4);
  const children = Math.max(0, Number.parseInt(fd.children || 0, 10) || 0);
  const adults = Math.max(1, count - children);
  const schoolNote = children ? 'Include school-friendly foods: fruit, boiled egg/yogurt where safe, roasted groundnuts if allowed, vegetable wraps/bowls, beans, or leftovers packed safely.' : 'Use work-friendly leftovers: bowls, soups, cooked staples, vegetables, and protein packed separately where possible.';
  const ages = String(fd.ages || '').split(/[,;|]/).map(x => x.trim()).filter(Boolean).slice(0, 10);
  const memberRows = (ages.length ? ages : ['Adult', 'Teen/child']).map((age, index) => {
    const n = Number.parseInt(age, 10);
    const group = Number.isFinite(n) ? (n < 6 ? 'young child' : n < 13 ? 'child' : n < 18 ? 'teen' : n >= 60 ? 'older adult' : 'adult') : age;
    const portion = group === 'young child' ? '1/3 to 1/2 adult starch, soft protein, finely prepared vegetables.'
      : group === 'child' ? '1/2 to 2/3 adult starch, child palm protein, vegetables prepared simply.'
      : group === 'teen' ? 'Adult-style plate; increase protein/starch if active or growing fast.'
      : group === 'older adult' ? 'Protein at each meal, softer textures if needed, hydration and fibre focus.'
      : 'Standard plate: 2 cups vegetables, 1 palm protein, 1/2 to 1 cup starch.';
    return `<div class="info-card"><strong>Member ${index + 1}: ${escapeHtml(group)}</strong><p>${escapeHtml(portion)}</p></div>`;
  }).join('');
  const shoppingQty = `Weekly household guide: about ${count * 7} palm-size protein portions, ${count * 14} cups vegetables across the week, 2 to 3 staple options, and fruit/snacks planned for school or work.`;
  return `<div class="sec"><div class="sh"><div class="si">FAM</div><div><div class="st">Family and Household Value Guide</div><div class="subtle">Extra guidance so household plans feel properly personalised.</div></div></div>
    <div class="support-grid">
      <div class="info-card"><strong>Household size</strong><span>${escapeHtml(count)}</span><p>${escapeHtml(adults)} adult/teen estimate and ${escapeHtml(children)} child estimate.</p></div>
      <div class="info-card"><strong>Shared cooking</strong><p>Cook one base meal, then adjust starch, protein, vegetables, sauce, and snack portions by age, appetite, activity, and medical needs.</p></div>
      <div class="info-card"><strong>Lunch practicality</strong><p>${escapeHtml(schoolNote)}</p></div>
      <div class="info-card"><strong>Household shopping quantities</strong><p>${escapeHtml(shoppingQty)}</p></div>
    </div>
    <div class="support-grid" style="margin-top:8px">${memberRows}</div>
    <div class="note" style="margin-top:8px"><strong>30-day family rotation:</strong> Week 1 uses the menu below. Week 2 rotates proteins. Week 3 rotates staples and vegetables. Week 4 keeps the meals the household accepted best and replaces impractical meals.</div>
  </div>`;
}

function cycleBasedNutritionSection(profile = {}) {
  const data = profile.cycleData || profile.cycle || {};
  const phase = String(data.phase || data.currentPhase || '').toLowerCase();
  if (!phase && !profileTextIncludes(profile, ['menstrual', 'cycle', 'pms', 'period', 'menopause'])) return '';
  const phaseMap = {
    menstrual: ['Menstrual Phase', 'Prioritise iron-rich foods, vitamin C with meals, magnesium-rich foods, warm fluids, and gentle meals if appetite is low. Severe bleeding, faintness, or severe pain needs clinical care.'],
    follicular: ['Follicular Phase', 'Energy often improves. This is a good time to build consistency with protein, vegetables, whole staples, hydration, and exercise.'],
    ovulatory: ['Ovulatory Phase', 'Focus on antioxidant-rich foods, zinc, B vitamins, protein, colourful fruit and vegetables, and hydration.'],
    luteal: ['Luteal Phase / PMS Support', 'Prioritise magnesium, calcium, protein, and slow carbohydrates. Reduce excess sugar, alcohol, and salty snacks if bloating or cravings worsen.'],
    menopause: ['Perimenopause / Menopause Support', 'Support protein, calcium, vitamin D, magnesium, fibre, omega-3 foods, strength training, and sleep quality. Hot flashes may worsen with alcohol and excess caffeine.']
  };
  const chosen = phaseMap[phase] || ['Cycle-Based Nutrition Guide', 'Nutrition should respond to energy, appetite, cravings, bleeding pattern, cramps, sleep, and mood changes across the cycle. Track symptoms for two to three cycles to refine the plan.'];
  return `<div class="sec"><div class="sh"><div class="si p">CY</div><div><div class="st">Cycle-Based Nutrition Guide</div><div class="subtle">Included because cycle or hormonal details were submitted.</div></div></div>
    <div class="note"><strong>${escapeHtml(chosen[0])}:</strong> ${escapeHtml(chosen[1])}</div>
  </div>`;
}

function pregnancyLactationSection(profile = {}, macros = {}) {
  const data = profile.prenatal || {};
  const isRelevant = profile.isPrenatal || profileTextIncludes(profile, ['pregnant', 'pregnancy', 'lactation', 'breastfeeding', 'trimester']);
  if (!isRelevant && !Object.keys(data).length) return '';
  const trimester = String(data.trimester || profile.trimester || '').toLowerCase();
  const focus = trimester.includes('1') || trimester.includes('first')
    ? 'First trimester support: nausea-friendly meals, hydration, folate-rich foods, food safety, and small frequent meals if appetite is low.'
    : trimester.includes('2') || trimester.includes('second')
      ? 'Second trimester support: protein, iron, calcium, vitamin D, omega-3 foods, vegetables, and steady energy as growth increases.'
      : trimester.includes('3') || trimester.includes('third')
        ? 'Third trimester support: adequate protein, iron, calcium, hydration, constipation prevention, reflux-friendly meals, and safe weight-gain monitoring.'
        : 'Pregnancy/lactation support: food safety, protein, iron, folate, calcium, iodine, vitamin D, hydration, and appetite-friendly meals.';
  return `<div class="sec"><div class="sh"><div class="si b">PN</div><div><div class="st">Pregnancy and Lactation Nutrition</div><div class="subtle">A safety-first section for pregnancy, post-partum, or breastfeeding support.</div></div></div>
    <div class="value-list">
      <p>${escapeHtml(focus)}</p>
      <p>Use safe, well-cooked protein foods; avoid alcohol; limit high-mercury fish; avoid unpasteurised dairy; and follow antenatal or clinician guidance for supplements and medication.</p>
      <p>Starting nutrition target in this plan: ${escapeHtml(macros.calories)} kcal and ${escapeHtml(macros.protein)} g protein, to be adjusted by trimester, appetite, weight trend, and clinical review.</p>
    </div>
  </div>`;
}

function sportsPerformanceSection(profile = {}, macros = {}) {
  const sport = profile.sport || {};
  const isRelevant = Object.keys(sport).length || profileTextIncludes(profile, ['sport', 'athlete', 'training', 'gym', 'football', 'running', 'workout']);
  if (!isRelevant) return '';
  const training = shortDisplay(sport.frequency || sport.trainingFrequency || profile.trainingFrequency, 'training schedule not captured');
  return `<div class="sec"><div class="sh"><div class="si b">SP</div><div><div class="st">Sports and Athletic Performance Nutrition</div><div class="subtle">Fuel, recovery, hydration, and muscle-preservation guidance.</div></div></div>
    <div class="support-grid">
      <div class="info-card"><strong>Training pattern</strong><p>${escapeHtml(training)}. Use this plan as a base and adjust portions on heavy training days.</p></div>
      <div class="info-card"><strong>Protein and recovery</strong><p>Target about ${escapeHtml(macros.protein)} g protein daily unless kidney review says otherwise. Spread protein across meals rather than taking it all at dinner.</p></div>
      <div class="info-card"><strong>Before exercise</strong><p>Use a balanced meal 2 to 3 hours before training, or a light snack such as fruit plus yogurt/groundnuts 30 to 60 minutes before if needed.</p></div>
      <div class="info-card"><strong>After exercise</strong><p>Within 1 to 2 hours, combine protein, fluids, and a measured carbohydrate source to support recovery and reduce overeating later.</p></div>
    </div>
  </div>`;
}

function vitalityHormonalSection(profile = {}, macros = {}) {
  const vitality = profile.vitality || {};
  const isRelevant = Object.keys(vitality).length || profileTextIncludes(profile, ['fatigue', 'low energy', 'hormonal', 'sleep', 'stamina', 'vitality']);
  if (!isRelevant) return '';
  return `<div class="sec"><div class="sh"><div class="si p">VIT</div><div><div class="st">Vitality and Hormonal Wellness</div><div class="subtle">Energy, sleep, stress, appetite, and recovery support.</div></div></div>
    <div class="value-list">
      <p>Low energy can come from low iron, low vitamin D, poor sleep, under-eating, dehydration, stress, thyroid issues, glucose swings, infection, or medication effects. Nutrition helps, but persistent fatigue deserves clinical review.</p>
      <p>Build every main meal around protein, colourful vegetables or fruit, measured starch where needed, and water. Avoid using caffeine and sugar as the main energy strategy.</p>
      <p>Useful labs to consider if fatigue persists: full blood count, ferritin, vitamin D, B12, thyroid function, glucose/HbA1c, and pregnancy test where relevant.</p>
    </div>
  </div>`;
}

function mentalMoodAppetiteSection(profile = {}) {
  const mental = profile.mental || {};
  const isRelevant = Object.keys(mental).length || profileTextIncludes(profile, ['stress', 'anxiety', 'mood', 'depression', 'emotional eating', 'binge', 'poor appetite']);
  if (!isRelevant) return '';
  return `<div class="sec"><div class="sh"><div class="si p">MOOD</div><div><div class="st">Mood, Stress and Appetite Support</div><div class="subtle">Nutrition support for real-life eating patterns.</div></div></div>
    <div class="value-list">
      <p>Keep meals regular enough to prevent extreme hunger, cravings, and late-day overeating. Protein at breakfast and lunch often improves appetite control.</p>
      <p>Use magnesium-rich foods, omega-3 foods, fibre, hydration, and sleep routines as support. Nutrition is supportive care, not a replacement for mental-health treatment when needed.</p>
      <p>If appetite is very low, use smaller meals more often: yogurt bowl, soup, eggs/beans where suitable, fruit, nuts, or a fortified porridge depending on clinical safety.</p>
    </div>
  </div>`;
}

function adultWellnessSection(profile = {}) {
  const age = Number(profile.age || 0);
  const isRelevant = age >= 55 || profileTextIncludes(profile, ['elderly', 'older adult', 'senior']);
  if (!isRelevant) return '';
  return `<div class="sec"><div class="sh"><div class="si r">AD</div><div><div class="st">Adult Wellness Nutrition Support</div><div class="subtle">Supportive nutrition guidance for older adults.</div></div></div>
    <div class="value-list">
      <p>Older adult nutrition should protect muscle, bone strength, hydration, appetite, digestion, medication safety, and steady energy.</p>
      <p>Food priorities: protein at main meals, fish where safe, beans or lentils where tolerated, vegetables, fruit in measured portions, calcium-rich foods, fluids, and softer meals where chewing is difficult.</p>
      <p>Sudden appetite loss, falls, weakness, swelling, confusion, severe fatigue, or unexplained weight loss should be discussed with a clinician.</p>
    </div>
  </div>`;
}

function exerciseMovementSection(profile = {}) {
  const goal = String(profile.goal || '').toLowerCase();
  const age = Number(profile.age || 0);
  const activity = String(profile.activity || '').toLowerCase();
  const needs = goal.includes('weight') || goal.includes('fitness') || activity || profileTextIncludes(profile, ['gym', 'exercise', 'sedentary', 'sport', 'training']);
  if (!needs) return '';
  const condText = JSON.stringify(profile || {}).toLowerCase();
  const hasDiabetes = condText.includes('diabetes') || condText.includes('glucose') || condText.includes('hba1c');
  const hasHypertension = condText.includes('hypertension') || condText.includes('blood pressure') || condText.includes('sbp') || condText.includes('dbp');
  const isPregnancy = condText.includes('pregnan') || condText.includes('trimester') || condText.includes('lactation');
  const lowFitness = age >= 55 || activity.includes('sedentary') || profileTextIncludes(profile, ['low fitness', 'unfit', 'older adult', 'senior']);
  const weightFocus = goal.includes('loss') || goal.includes('weight') || goal.includes('obese') || goal.includes('overweight');
  const intensity = lowFitness
    ? 'Use low-impact cardio, balance work, flexibility, and supervised strength training if new to exercise.'
    : 'Use a mixture of walking/cardio, strength training, mobility, and active rest. Increase gradually.';
  const cards = [['Starter weekly plan', 'Walk 10 to 20 minutes on 3 to 5 days weekly. Add 5 minutes per week until the routine feels comfortable, then add gentle strength work.']];
  if (weightFocus) cards.push(['Weight-management plan', 'Use 4 to 5 walking/cardio days plus 2 strength sessions weekly. Keep strength sessions simple: chair squats, wall push-ups, rows, hip hinges, and core bracing.']);
  if (hasDiabetes) cards.push(['Diabetes-focused movement', 'Use a 10 to 20 minute easy walk after larger meals where possible. Avoid skipping meals around exercise if glucose-lowering medicine may cause low sugar.']);
  if (hasHypertension) cards.push(['Blood-pressure-focused movement', 'Use moderate steady movement, warm up and cool down, breathe normally during strength work, and avoid sudden maximal effort if readings are uncontrolled.']);
  if (isPregnancy) cards.push(['Pregnancy-focused movement', 'Use antenatal-safe walking, gentle strength, pelvic stability, hydration, and clinician guidance if bleeding, dizziness, pain, high BP, or warning symptoms occur.']);
  if (lowFitness) cards.push(['Older adult / low-fitness plan', 'Prioritise low-impact walking, sit-to-stand practice, balance holds near support, flexibility, and light resistance 2 days weekly.']);
  if (profileTextIncludes(profile, ['gym', 'exercise', 'sport', 'training']) || weightFocus) {
    cards.push(['Before exercise', 'Eat a balanced meal 2 to 3 hours before training, or a small fruit/yogurt/groundnut snack 30 to 60 minutes before if needed.']);
    cards.push(['After exercise', 'Within 1 to 2 hours, use protein plus fluid and a measured carbohydrate source if the session was long or intense.']);
  }
  return `<div class="sec"><div class="sh"><div class="si b">MOVE</div><div><div class="st">Movement and Exercise Guidance</div><div class="subtle">Food works better when paired with realistic movement.</div></div></div>
    <div class="support-grid">
      <div class="info-card"><strong>Weekly rhythm</strong><p>Start with 3 to 5 movement days weekly depending on fitness, pain, schedule, and clinician advice.</p></div>
      <div class="info-card"><strong>Strength</strong><p>Include 2 strength sessions weekly to protect muscle, glucose control, posture, and metabolism.</p></div>
      <div class="info-card"><strong>Cardio</strong><p>Walk, cycle, swim, dance, or use gym cardio at a pace where breathing increases but control is maintained.</p></div>
      <div class="info-card"><strong>Safety</strong><p>${escapeHtml(intensity)} Stop and seek care for chest pain, fainting, severe breathlessness, or unusual symptoms.</p></div>
    </div>
    <div class="support-grid" style="margin-top:8px">${cards.map(([title, text]) => `<div class="info-card"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('')}</div>
  </div>`;
}

function patientPreMealExpertSections(payload = {}, profile = {}, clinicalSummary = {}, macros = {}) {
  return [
    foodAvoidReplacementSection(profile),
    cycleBasedNutritionSection(profile),
    pregnancyLactationSection(profile, macros),
    sportsPerformanceSection(profile, macros),
    vitalityHormonalSection(profile, macros),
    mentalMoodAppetiteSection(profile),
    adultWellnessSection(profile),
    exerciseMovementSection(profile)
  ].join('');
}

function patientValueSupportSections(payload = {}, profile = {}, clinicalSummary = {}, macros = {}) {
  return [
    weeklyShoppingMealPrepSection(payload, profile),
    premiumFamilySupportSection(payload, profile),
    practicalRecipeGuideSection(profile),
    foodAlliesSection(profile),
    followUpRoadmapSection(profile),
    progressCheckpointsSection(),
    protectiveFoodsSection(),
    hairSkinNailsSection(macros),
    gutHealthSection(macros),
    weightManagementSection(profile, macros)
  ].join('');
}

function backendPlanHtml(payload = {}, clinicalSummary = {}) {
  const profile = payload.profile && typeof payload.profile === 'object' ? payload.profile : payload;
  const macros = serverMacroSummary(profile);
  const recipePlan = weeklyRecipesForProfile(profile);
  const recipes = recipePlan.byMeal;
  const weekPlan = recipePlan.days;
  const weekBlocks = recipePlan.weeks && recipePlan.weeks.length ? recipePlan.weeks : [{ title: 'Week 1 - Foundation Menu', focus: 'Use this as the first rotation, then repeat with swaps and feedback.', days: weekPlan }];
  const issued = new Date().toLocaleDateString('en-UG', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  const familyPlan = isFamilyPlanPayload(payload, profile);
  const conditions = cleanList(profile.conds || payload.conds).map(conditionDisplayName).join(', ') || 'General nutrition support';
  const rows = [
    ['Name', payload.name || profile.name],
    ['Package', payload.packageName],
    ['Goal', profile.goal || 'General wellness'],
    ['Conditions', conditions],
    ['BMI', payload.bmi || profile.bmi || 'Not captured'],
    ['Budget', profile.budget || 'Not captured'],
    ['Cooking access', profile.cooking || 'Not captured']
  ].filter(([, value]) => String(value || '').trim());
  const bmiValue = Number(payload.bmi || profile.bmi || 0);
  const bmiLabel = shortDisplay(profile.cat || payload.cat || 'Not captured');
  const actualWeekMeals = { breakfast: [], lunch: [], dinner: [], snack: [] };
  weekBlocks.forEach(week => (week.days || []).forEach(day => {
    if (day.breakfast) actualWeekMeals.breakfast.push(day.breakfast);
    if (day.snack1) actualWeekMeals.snack.push(day.snack1);
    if (day.snack2) actualWeekMeals.snack.push(day.snack2);
    if (day.lunch) actualWeekMeals.lunch.push(day.lunch);
    if (day.dinner) actualWeekMeals.dinner.push(day.dinner);
  }));
  const programmePhases = [
    ['Days 1-14', 'Learn your portions, remove sugary drinks, reduce excess oil and salt, and record meals that do not feel realistic.'],
    ['Days 15-30', 'Improve variety, shopping rhythm, protein rotation, vegetable intake, and the meals you enjoy most.'],
    ['Days 31-45', 'Adjust portions from measurements, appetite, symptoms, glucose/BP, or lab feedback where relevant.'],
    ['Days 46-60', 'Maintain the best meals, replace weak meals, and request review if symptoms, hunger, or measurements worsen.']
  ].map(([title, text]) => `<div class="phase"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`).join('');
  let mealProgrammeHtml = `<div class="sec"><div class="sh"><div class="si y">MP</div><div><div class="st">${familyPlan ? 'Dietician-Style Household 30-60 Day Meal Programme' : 'Dietician-Style 30-60 Day Meal Programme'}</div><div class="subtle">Weeks 1-4 are written out. For Days 31-60, repeat the strongest meals, use the swaps, and adjust from follow-up feedback.</div></div></div>
    <div class="why-b">Each meal card focuses on what the patient needs most: ingredients, preparation, exact food portions, taste, and practical swaps. Lunch and dinner prioritise real meals; smoothies stay as breakfast or snack options only where clinically safe.</div>
    <div class="phase-grid" style="margin-top:10px;margin-bottom:12px">${programmePhases}</div>
    <div class="variety-strip">${mealVarietySummary(actualWeekMeals)}</div>`;
  weekBlocks.forEach((week, weekIndex) => {
    mealProgrammeHtml += `<div class="week-card"><div class="week-head"><div class="week-title">${escapeHtml(week.title || `Week ${weekIndex + 1}`)}</div><div class="week-focus">${escapeHtml(week.focus || 'Rotate meals while keeping portions measured and practical.')}</div></div>`;
    days.forEach((day, i) => {
      const dayMeals = (week.days || [])[i] || {};
      const planDayNumber = (weekIndex * 7) + i + 1;
      mealProgrammeHtml += `<div class="day-block"><div class="day-title">${day} - Day ${planDayNumber}</div>`;
      mealProgrammeHtml += recipeCardHtml(dayMeals.breakfast || pickRecipe(recipes.breakfast, i + weekIndex), 'breakfast');
      mealProgrammeHtml += recipeCardHtml(dayMeals.snack1 || pickRecipe(recipes.snack, i + weekIndex), 'snack1');
      mealProgrammeHtml += recipeCardHtml(dayMeals.lunch || pickRecipe(recipes.lunch, i + weekIndex), 'lunch');
      mealProgrammeHtml += recipeCardHtml(dayMeals.snack2 || pickRecipe(recipes.snack, i + 7 + weekIndex), 'snack2');
      mealProgrammeHtml += recipeCardHtml(dayMeals.dinner || pickRecipe(recipes.dinner, i + weekIndex), 'dinner');
      mealProgrammeHtml += `</div>`;
    });
    mealProgrammeHtml += `</div>`;
  });
  mealProgrammeHtml += `</div>`;
  let html = `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Plan: ${escapeHtml(payload.name || profile.name || 'Client')}</title>
  <link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:Outfit,"Segoe UI",Arial,sans-serif;background:#f7f3ec;color:#2a1f14;font-size:13px;line-height:1.7}
    .page{max-width:820px;margin:0 auto;background:#fff;box-shadow:0 18px 55px rgba(30,58,26,.10)}
    .cover{background:linear-gradient(160deg,#0f2009,#1a3514,#0d2a0d);padding:52px 48px;color:#fff;position:relative;overflow:hidden}
    .orb1{position:absolute;width:500px;height:500px;border-radius:50%;background:radial-gradient(circle,rgba(62,122,48,.25),transparent 65%);top:-150px;right:-100px}.orb2{position:absolute;width:360px;height:360px;border-radius:50%;background:radial-gradient(circle,rgba(185,92,28,.18),transparent 65%);bottom:-80px;left:-70px}
    .logo{display:flex;align-items:center;gap:12px;margin-bottom:36px;position:relative}.leaf{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,#2d5c24,#5ea84a);display:flex;align-items:center;justify-content:center;font-size:21px}.brand{font-family:"Libre Baskerville",Georgia,serif;font-size:24px;font-weight:700;color:#fff}.brand-sub{font-size:10px;color:rgba(255,255,255,.48);letter-spacing:.12em;text-transform:uppercase;display:block;margin-top:2px}
    .c-title{font-family:"Libre Baskerville",Georgia,serif;font-size:36px;font-weight:700;color:#fff;line-height:1.1;margin-bottom:8px;position:relative;letter-spacing:0}.c-title em{font-style:italic;color:#9dd48a}.c-sub{font-size:15px;color:rgba(255,255,255,.68);margin-bottom:26px;position:relative}
    .c-meta{display:flex;flex-wrap:wrap;gap:18px;padding:18px;background:rgba(255,255,255,.08);border-radius:13px;border:1px solid rgba(255,255,255,.12);position:relative}.cm{min-width:120px}.cm-l{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:rgba(255,255,255,.42);margin-bottom:3px}.cm-v{font-size:13px;font-weight:700;color:#fff}
    .bmi-b{display:inline-flex;align-items:center;gap:10px;padding:9px 16px;background:rgba(255,255,255,.13);border-radius:100px;border:1px solid rgba(255,255,255,.2);margin-top:16px;position:relative}.bmi-n{font-family:"Libre Baskerville",Georgia,serif;font-size:24px;font-weight:700;color:#9dd48a}.bmi-t{font-size:13px;color:rgba(255,255,255,.76)}
    .body{padding:40px 48px}.sec{margin-bottom:30px}.sh{display:flex;align-items:center;gap:10px;margin-bottom:13px;padding-bottom:8px;border-bottom:2px solid #e2dbcf}.si{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#1e3a1a,#3d7a30);color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;flex-shrink:0}.si.o{background:linear-gradient(135deg,#7a3c10,#c06820)}.si.r{background:linear-gradient(135deg,#5a0e0e,#a02020)}.si.b{background:linear-gradient(135deg,#142048,#2860b0)}.si.p{background:linear-gradient(135deg,#2e0860,#8030c0)}.si.y{background:linear-gradient(135deg,#5a4000,#b08800)}
    .st{font-family:"Libre Baskerville",Georgia,serif;font-size:17px;font-weight:700;color:#1e3a1a}.subtle{color:#8a7a68;font-size:12px;margin-top:2px}
    .gauge{height:11px;border-radius:6px;background:linear-gradient(90deg,#5ea84a,#e8c030,#e07030,#c02020);position:relative;margin:11px 0 6px}.gpin{position:absolute;top:-5px;width:21px;height:21px;border-radius:50%;background:#fff;border:3px solid #1e3a1a;transform:translateX(-50%);box-shadow:0 2px 6px rgba(0,0,0,.18)}.glbl{display:flex;justify-content:space-between;font-size:9px;color:#8a7a68;font-weight:700}.bmi-exp,.why-b,.note{border-radius:9px;padding:13px;font-size:13px;line-height:1.75}.bmi-exp{background:linear-gradient(135deg,#ebf7e8,#d4eecc);color:#1e3a1a;margin-top:10px}.why-b{background:linear-gradient(135deg,#fdf8f0,#ede8df);color:#2a1f14;border-left:4px solid #c06820}.note{background:linear-gradient(135deg,#fff8e8,#fde8c8);border-left:4px solid #c06820}
    .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.box,.info-card,.recipe-mini{background:#fafdf7;border:1px solid #e2dbcf;border-radius:9px;padding:10px 12px}.box strong,.info-card strong,.recipe-mini strong{display:block;font-size:10px;color:#7a3c10;text-transform:uppercase;letter-spacing:.06em;margin-bottom:3px}.box span{font-size:13px;font-weight:700;color:#2a1f14}.info-card span{display:block;font-family:"Libre Baskerville",Georgia,serif;font-size:22px;font-weight:700;color:#7a3c10;margin:3px 0}.info-card p,.recipe-mini p{font-size:11.8px;color:#5a4a38;line-height:1.6;margin-top:3px}
    .two-col{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}.two-col h3{font-size:11px;color:#1e3a1a;text-transform:uppercase;letter-spacing:.08em;margin:0 0 7px}.mini-table{display:grid;gap:6px}.mini-table div{background:#fafdf7;border:1px solid #e2dbcf;border-radius:8px;padding:8px 9px}.mini-table strong{display:block;font-size:9.5px;text-transform:uppercase;letter-spacing:.07em;color:#7a3c10}.mini-table span{font-size:11.5px;font-weight:700}
    .macro{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:8px}.macro div{border-radius:8px;padding:12px;text-align:center;background:linear-gradient(135deg,#e8f5e4,#d4eecc)}.macro div:nth-child(2){background:linear-gradient(135deg,#e8eeff,#d8e8ff)}.macro div:nth-child(3){background:linear-gradient(135deg,#fdf5e6,#fde8c8)}.macro div:nth-child(4){background:linear-gradient(135deg,#feeee8,#fde0d8)}.macro div:nth-child(5){background:linear-gradient(135deg,#e8f0ff,#d0e0ff)}.macro b{display:block;font-family:"Libre Baskerville",Georgia,serif;font-size:19px;color:#1e3a1a;line-height:1}.macro span{font-size:10px;font-weight:700;color:#8a7a68;text-transform:uppercase}
    .mg3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.mac{border-radius:8px;padding:12px;text-align:center}.mac b{display:block;font-family:"Libre Baskerville",Georgia,serif;font-size:19px;color:#1e3a1a;line-height:1}.mac span{font-size:10px;font-weight:800;color:#8a7a68;text-transform:uppercase}.mc1{background:linear-gradient(135deg,#e8f5e4,#d4eecc)}.mc2{background:linear-gradient(135deg,#e8eeff,#d8e8ff)}.mc3{background:linear-gradient(135deg,#fdf5e6,#fde8c8)}.mc4{background:linear-gradient(135deg,#feeee8,#fde0d8)}.mc5{background:linear-gradient(135deg,#e8f0ff,#d0e0ff)}.mc6{background:linear-gradient(135deg,#f0e8ff,#e4d8ff)}
    .plan-summary{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}.summary-card{background:#fafdf7;border:1px solid #e2dbcf;border-radius:9px;padding:11px;font-size:12px}.summary-card strong{color:#1e3a1a}
    .week-card{margin-bottom:24px;border-radius:14px;border:1px solid #d8cfbf;overflow:hidden;break-inside:avoid;box-shadow:0 8px 22px rgba(30,58,26,.06)}.week-head{background:linear-gradient(135deg,#1e3a1a,#2d5c24);color:#fff;padding:14px 16px}.week-title{font-family:"Libre Baskerville",Georgia,serif;font-size:17px;font-weight:700}.week-focus{font-size:11.5px;color:rgba(255,255,255,.78);margin-top:3px}.day-block{padding:15px;border-top:1px solid rgba(30,58,26,.12);break-inside:avoid}.day-title{font-family:"Libre Baskerville",Georgia,serif;font-size:15px;font-weight:700;color:#1e3a1a;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid rgba(30,58,26,.16)}
    .meal-card{background:#fff;border:1px solid #e2dbcf;border-radius:10px;padding:11px;margin-bottom:10px;break-inside:avoid}.meal-time{font-size:10px;font-weight:800;color:#8a7a68;text-transform:uppercase;letter-spacing:.07em;margin-bottom:2px}.meal-name{font-size:13.5px;font-weight:800;color:#2a1f14;line-height:1.25;margin-bottom:6px}.meal-chips{display:flex;flex-wrap:wrap;gap:5px;margin:6px 0 8px}.meal-chips span{font-size:9.5px;font-weight:700;color:#1e3a1a;background:#ebf7e8;border:1px solid #d4eecc;border-radius:999px;padding:3px 7px}.meal-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:8px}.meal-box{background:#fafdf7;border-radius:7px;padding:8px;border-left:3px solid #d4b080}.meal-box.wide{grid-column:1/-1}.meal-box strong{display:block;font-size:10px;color:#7a3c10;text-transform:uppercase;letter-spacing:.05em;margin-bottom:3px}.meal-box p{font-size:11.2px;color:#5a4a38;line-height:1.55;margin:0}.meal-note{font-size:10.8px;color:#5a4a38;line-height:1.5;background:#f7f3ec;border-radius:7px;padding:8px;margin-top:6px;border:1px solid #e2dbcf}
    .variety-strip{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 13px}.variety-strip span{font-size:9.5px;font-weight:700;color:#1e3a1a;background:#ebf7e8;border:1px solid #d4eecc;border-radius:999px;padding:4px 8px}.support-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.phase-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:7px}.phase{background:linear-gradient(135deg,#ebf7e8,#d4eecc);border-radius:8px;padding:11px;text-align:center}.phase strong{display:block;font-size:9px;font-weight:800;color:#2d5c24;margin-bottom:3px;text-transform:uppercase;letter-spacing:.05em}.phase p{font-size:11px;color:#1e3a1a;line-height:1.5;margin:0}.value-list{display:grid;gap:7px}.value-list p{margin:0;padding:9px 11px;background:#fafdf7;border-radius:7px;border:1px solid #e2dbcf;border-left:3px solid #3d7a30;font-size:11.8px;color:#5a4a38;line-height:1.6}
    .foot{background:linear-gradient(135deg,#0f2009,#1e3a1a);padding:28px 48px;color:#fff}.fi{display:flex;justify-content:space-between;align-items:flex-end;flex-wrap:wrap;gap:14px}.fb{font-family:"Libre Baskerville",Georgia,serif;font-size:17px;font-weight:700;color:#fff;margin-bottom:4px}.fc{font-size:12px;color:rgba(255,255,255,.58);line-height:1.8}.fd{font-size:10px;color:rgba(255,255,255,.36);margin-top:10px;line-height:1.65}.fr{text-align:right}.fdt{font-size:10px;color:rgba(255,255,255,.42);margin-bottom:3px}.ftag{font-family:"Libre Baskerville",Georgia,serif;font-size:12px;font-style:italic;color:rgba(255,255,255,.42)}
    .footer-note{font-size:11px;color:#8a7a68;border-top:1px solid #e2dbcf;padding-top:12px;margin-top:14px}.prtbtn{display:block;text-align:center;padding:18px;background:#f7f3ec}
    @media print{body{background:#fff}.page{box-shadow:none}.sec,.week-card,.day-block,.meal-card{page-break-inside:avoid}.prtbtn{display:none!important}.cover{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
    @media(max-width:700px){.meal-grid,.grid,.macro,.mg3,.support-grid,.phase-grid,.plan-summary,.two-col{grid-template-columns:1fr}.body{padding:28px 22px}.cover{padding:42px 24px}.c-title{font-size:31px}.fr{text-align:left}}
  </style></head><body><div class="page"><div class="cover"><div class="orb1"></div><div class="orb2"></div><div class="logo"><div class="leaf">B360</div><div><div class="brand">Bulamu360</div><span class="brand-sub">by Breyer Naula, RDN</span></div></div><h1 class="c-title">Personalised<br><em>Nutrition Plan</em></h1><p class="c-sub">Prepared exclusively for ${escapeHtml(payload.name || profile.name || 'Client')}</p><div class="c-meta"><div class="cm"><div class="cm-l">Date Issued</div><div class="cm-v">${escapeHtml(issued)}</div></div><div class="cm"><div class="cm-l">Package</div><div class="cm-v">${escapeHtml(payload.packageName || 'Bulamu360 plan')}</div></div><div class="cm"><div class="cm-l">Goal</div><div class="cm-v">${escapeHtml(profile.goal || 'General Wellness')}</div></div><div class="cm"><div class="cm-l">Height / Weight</div><div class="cm-v">${escapeHtml([profile.height ? `${profile.height}cm` : '', profile.weight ? `${profile.weight}kg` : ''].filter(Boolean).join(' / ') || 'Not captured')}</div></div></div><div class="bmi-b"><span class="bmi-n">${bmiValue ? escapeHtml(bmiValue) : 'NA'}</span><span class="bmi-t">BMI &nbsp;<strong style="color:#fff">${escapeHtml(bmiLabel)}</strong></span></div></div><div class="body">`;
  html += bmiMeaningSection(payload, profile);
  html += `<div class="sec"><div class="sh"><div class="si o">WHY</div><div><div class="st">Why This Plan Was Selected for You</div><div class="subtle">Written for the patient, without private backend or admin notes.</div></div></div><div class="why-b">This plan was selected for ${escapeHtml(profile.goal || 'your nutrition goal')} while keeping meals practical for your budget, cooking access, appetite, culture, health needs, and routine. ${familyPlan ? "For the household plan, one shared menu base is adapted by age, appetite, activity, and each member's health needs." : 'The programme uses measured portions, protein rotation, vegetables, practical preparation, and realistic follow-up adjustments.'}</div></div>`;
  if (clinicalSummary.safetyDecision) {
    const sd = clinicalSummary.safetyDecision;
    html += `<div class="sec"><div class="sh"><div class="si r">SF</div><div><div class="st">Important Safety Note</div><div class="subtle">Use this plan alongside medical care where symptoms, medication, pregnancy, diabetes, kidney disease, or abnormal labs are involved.</div></div></div><div class="note"><strong>${escapeHtml(sd.label || 'Safety review')}</strong><br>${escapeHtml(sd.summary || 'Use this plan as nutrition guidance, not emergency medical care. Seek clinical care for severe or worsening symptoms.')}</div></div>`;
  }
  html += `<div class="sec"><div class="sh"><div class="si o">NT</div><div><div class="st">Daily Nutritional Targets</div><div class="subtle">Starting targets for daily structure and follow-up review.</div></div></div><div class="mg3"><div class="mac mc1"><b>${macros.calories}</b><span>kcal/day</span></div><div class="mac mc2"><b>${macros.protein}g</b><span>protein</span></div><div class="mac mc3"><b>${macros.carbs}g</b><span>carbohydrate</span></div><div class="mac mc4"><b>${macros.fat}g</b><span>fat</span></div><div class="mac mc5"><b>${macros.water}L</b><span>water</span></div><div class="mac mc6"><b>${macros.fibre}g</b><span>fibre</span></div></div><div class="plan-summary"><div class="summary-card"><strong>How to use this plan:</strong> follow the meal rhythm, keep portions measured, and use the shopping guide to prepare realistic meals for the week.</div><div class="summary-card"><strong>Clinical note:</strong> targets should be refined using measurements, appetite, glucose/BP or lab data where relevant.</div></div></div>`;
  html += projectedOutcomesSection(profile, macros);
  html += mealProgrammeHtml;
  html += patientPreMealExpertSections(payload, profile, clinicalSummary, macros);
  html += familyPlanSectionHtml(payload, profile);
  html += patientValueSupportSections(payload, profile, clinicalSummary, macros);
  html += `<div class="sec"><div class="footer-note">Bulamu360 plans are personalised nutrition support documents. They do not replace medical diagnosis, emergency care, prescribed medicine, or direct care from a qualified clinician.</div></div>`;
  html += `</div><div class="foot"><div class="fi"><div><div class="fb">Bulamu360 by Breyer Naula, RDN</div><div class="fc">Certified Registered Dietician and Nutritionist</div><div class="fc">breyernaula5@gmail.com &nbsp;|&nbsp; +256 704392545 &nbsp;|&nbsp; Uganda</div><div class="fd">All nutritional guidance is prepared as professional dietary support based on submitted information. This plan does not replace in-person medical diagnosis, emergency care, prescribed medicine, or direct care from a qualified clinician.</div></div><div class="fr"><div class="fdt">Issued: ${escapeHtml(issued)}</div><div class="ftag">Your personal nutrition coach, anytime.</div></div></div></div><div class="prtbtn"><button onclick="window.print()" style="background:linear-gradient(135deg,#1e3a1a,#3d7a30);color:#fff;border:none;padding:12px 28px;border-radius:100px;font-size:14px;font-weight:700;cursor:pointer;font-family:Outfit,sans-serif;box-shadow:0 6px 18px rgba(30,58,26,.3)">Print or Save as PDF</button><p style="margin-top:8px;font-size:11px;color:#8a7a68">Use your browser Print function and choose Save as PDF as the destination.</p></div></div></body></html>`;
  return html;
}

async function handleRecipePool(req, res) {
  const payload = await readRequestJson(req);
  const pool = limitedRecipePoolForProfile(payload);
  sendJson(res, 200, { ok: true, ...pool });
}

function planEmailHtml(payload, downloadUrl) {
  const name = escapeHtml(payload.name || 'Client');
  const pkg = escapeHtml(payload.packageName || 'Bulamu360 Plan');
  const amount = escapeHtml(payload.amount || '');
  const txRef = escapeHtml(payload.txRef || '');
  const link = downloadUrl ? `<p><a href="${escapeHtml(downloadUrl)}" style="background:#1e3a1a;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;display:inline-block">Download your plan (PDF)</a></p>` : '';
  const followupUrl = payload.followupToken ? `${publicBaseUrl}/followup/${payload.followupToken}` : '';
  const followupLink = followupUrl ? `<p><a href="${escapeHtml(followupUrl)}" style="background:#ede8df;color:#1e3a1a;padding:11px 16px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:700">Submit progress review</a></p>` : '';
  const scheduleHtml = followupUrl ? `<div style="background:#f7f3ec;border-left:4px solid #c06820;padding:12px 14px;margin:14px 0">
    <strong>Your follow-up schedule</strong>
    <ul>
      <li>Day 7: tolerance, appetite, symptoms, and meal practicality</li>
      <li>Day 14: adherence, disliked meals, and routine barriers</li>
      <li>Day 30: outcomes, weight/waist, BP or glucose where relevant</li>
      <li>Day 60: continuation review, labs, and next plan cycle</li>
    </ul>
  </div>` : '';
  const review = payload.adminReview || {};
  const reviewHtml = (review.clinicalNote || review.approvalCondition || review.requestedLab || review.dietaryCorrection || review.followUpInstruction)
    ? `<div style="background:#f7f3ec;border-left:4px solid #1e3a1a;padding:12px 14px;margin:14px 0">
        <strong>Breyer's review notes</strong>
        ${review.clinicalNote ? `<p><strong>Clinical note:</strong><br>${nl2br(review.clinicalNote)}</p>` : ''}
        ${review.approvalCondition ? `<p><strong>Approval condition:</strong><br>${nl2br(review.approvalCondition)}</p>` : ''}
        ${review.requestedLab ? `<p><strong>Requested follow-up data:</strong><br>${nl2br(review.requestedLab)}</p>` : ''}
        ${review.dietaryCorrection ? `<p><strong>Dietary correction:</strong><br>${nl2br(review.dietaryCorrection)}</p>` : ''}
        ${review.followUpInstruction ? `<p><strong>Follow-up instruction:</strong><br>${nl2br(review.followUpInstruction)}</p>` : ''}
      </div>`
    : '';
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;color:#2a1f14;line-height:1.6">
    <h2 style="color:#1e3a1a">Your Bulamu360 plan is approved</h2>
    <p>Hello ${name},</p>
    <p>Your payment reference has been approved. Your personalised plan is attached as a PDF.</p>
    ${link}
    ${followupLink}
    ${scheduleHtml}
    ${reviewHtml}
    <p><strong>Package:</strong> ${pkg}<br><strong>Amount:</strong> ${amount}<br><strong>Transaction reference:</strong> ${txRef}<br><strong>Approval code:</strong> ${escapeHtml(payload.approvalCode || '')}</p>
    <p style="font-size:13px;color:#5a4a38">Bulamu360 provides dietary guidance and does not replace diagnosis, emergency care, medication, or your clinician's advice.</p>
  </body></html>`;
}

async function sendResendEmail({ to, subject, html, attachments = [] }) {
  if (!apiKey) return { skipped: true, reason: 'Missing RESEND_API_KEY' };
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from: fromEmail, to, subject, html, attachments })
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text }; }
  if (!response.ok) throw new Error(data.message || data.error || `Resend failed with ${response.status}`);
  return data;
}

async function sendCustomerOrderSubmittedEmail(order) {
  return await sendResendEmail({
    to: order.email,
    subject: 'Bulamu360 payment reference received',
    html: `<p>Hello ${escapeHtml(order.name)},</p><p>Your payment reference has been received and is pending Breyer's approval.</p><p><strong>Package:</strong> ${escapeHtml(order.packageName)}<br><strong>Amount:</strong> ${escapeHtml(order.amount)}<br><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p>`
  });
}

async function sendOwnerOrderSubmittedEmail(order) {
  if (!ownerEmail) throw new Error('OWNER_EMAIL is not configured.');
  return await sendResendEmail({
    to: ownerEmail,
    subject: `Pending Bulamu360 order - ${order.name}`,
    html: `<p>A new Bulamu360 order is pending approval.</p><p><strong>Name:</strong> ${escapeHtml(order.name)}<br><strong>Email:</strong> ${escapeHtml(order.email)}<br><strong>Phone:</strong> ${escapeHtml(order.phone)}<br><strong>Package:</strong> ${escapeHtml(order.packageName)}<br><strong>Amount:</strong> ${escapeHtml(order.amount)}<br><strong>Network:</strong> ${escapeHtml(order.network)}<br><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p><p><a href="${publicBaseUrl}/admin">Open admin dashboard</a></p>`
  });
}

async function sendOrderSubmittedEmails(order) {
  await Promise.all([
    sendCustomerOrderSubmittedEmail(order),
    sendOwnerOrderSubmittedEmail(order)
  ]);
}

function planAttachmentFileName(order = {}) {
  const cleanName = String(order.name || 'Client')
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80) || 'Client';
  return `${cleanName} - Bulamu360 Plan.pdf`;
}

// The client's plan as a real, styled PDF (server-side, no browser needed).
function planPdfForOrder(order, audience = 'patient') {
  const html = sanitizePlanHtml(planHtmlForOrder(order, { audience }));
  return planPdfFromHtml(html, { clientName: order.name || '', logoPath: join(root, 'bulamu360-logo.png') }).buffer;
}

function sendPlanPdf(res, order, audience = 'patient') {
  if (!order) return sendHtml(res, 404, 'Plan not found');
  const pdf = planPdfForOrder(order, audience);
  const name = planAttachmentFileName(order).replace(/[^\x20-\x7e]/g, '');
  res.writeHead(200, securityHeaders({ 'Content-Type': 'application/pdf', 'Content-Length': pdf.length, 'Content-Disposition': `attachment; filename="${name.replace(/"/g, '')}"`, 'Cache-Control': 'no-store' }));
  res.end(pdf);
}

async function sendApprovalEmail(order) {
  if (order.kind === 'subscription') {
    const cyc = memberCycleInfo(order);
    return await sendResendEmail({
      to: order.email,
      subject: 'Your Bulamu360 subscription is active',
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#123524"><h2 style="color:#0f3d26">Welcome to ${escapeHtml(order.packageName.replace(/ \(monthly\)$/, ''))}</h2><p>Hello ${escapeHtml(order.name || '')},</p><p>Your payment is approved. Your new tools are open in your Bulamu360 account until <strong>${escapeHtml(cyc.activeUntil)}</strong>. Renew each month to keep them.</p><p><a href="${publicBaseUrl}/?signin=1" style="background:#17693f;color:#fff;padding:12px 18px;border-radius:999px;text-decoration:none;display:inline-block">Open my account</a></p></div>`
    });
  }
  if (order.kind === 'template') {
    return await sendResendEmail({
      to: order.email,
      subject: 'Your Bulamu360 template is unlocked',
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#123524"><h2 style="color:#0f3d26">Your template is ready</h2><p>Hello ${escapeHtml(order.name || '')},</p><p>Thank you. <strong>${escapeHtml(order.packageName)}</strong> is now unlocked in your Bulamu360 account.</p><p><a href="${publicBaseUrl}/?signin=1#templates-section" style="background:#17693f;color:#fff;padding:12px 18px;border-radius:999px;text-decoration:none;display:inline-block">Sign in and download (PDF)</a></p></div>`
    });
  }
  const attachmentContent = planPdfForOrder(order, 'patient').toString('base64');
  const downloadUrl = `${publicBaseUrl}/plan/${order.downloadToken}/pdf`;
  return await sendResendEmail({
    to: order.email,
    subject: `${order.name || 'Your'} Bulamu360 Plan is ready`,
    html: planEmailHtml(order, downloadUrl),
    attachments: [{ filename: planAttachmentFileName(order), content: attachmentContent, content_type: 'application/pdf' }]
  });
}

function appendEmailLog(orderId, entry) {
  const db = readDb();
  const order = findOrder(db, orderId);
  if (!order) return;
  order.emailLog = Array.isArray(order.emailLog) ? order.emailLog : [];
  order.emailLog.push({ at: new Date().toISOString(), ...entry });
  writeDb(db);
}

function queueOrderEmail(order, type, task, extra = {}) {
  const orderId = order.id;
  appendEmailLog(orderId, { type, status: 'queued', ...extra });
  logOrderEvent('email-queued', { orderId, type, to: extra.to || '' });
  setTimeout(async () => {
    try {
      const result = await task();
      if (result && result.skipped) throw new Error(result.reason || 'Email sending was skipped.');
      appendEmailLog(orderId, {
        type,
        status: 'sent',
        id: result && result.id ? result.id : '',
        ...extra
      });
      logOrderEvent('email-sent', {
        orderId,
        type,
        to: extra.to || '',
        providerId: result && result.id ? result.id : ''
      });
    } catch (err) {
      appendEmailLog(orderId, {
        type,
        status: 'failed',
        error: err.message || 'Email sending failed.',
        ...extra
      });
      logOrderEvent('email-failed', {
        orderId,
        type,
        to: extra.to || '',
        error: err.message || 'Email sending failed.'
      });
    }
  }, 0);
}

function reviewChecklistFromForm(form = {}) {
  return {
    paymentConfirmed: Boolean(form.paymentConfirmed),
    allergiesReviewed: Boolean(form.allergiesReviewed),
    safetyReviewed: Boolean(form.safetyReviewed),
    auditReviewed: Boolean(form.auditReviewed),
    finalFitToSend: Boolean(form.finalFitToSend)
  };
}

function checklistComplete(checklist = {}) {
  return Boolean(checklist.paymentConfirmed && checklist.allergiesReviewed && checklist.safetyReviewed && checklist.auditReviewed && checklist.finalFitToSend);
}

function reviewFromForm(form = {}, previous = {}) {
  return {
    ...previous,
    clinicalNote: String(form.clinicalNote || '').trim(),
    customerReleaseNote: String(form.customerReleaseNote || '').trim(),
    approvalCondition: String(form.approvalCondition || '').trim(),
    requestedLab: String(form.requestedLab || '').trim(),
    dietaryCorrection: String(form.dietaryCorrection || '').trim(),
    followUpInstruction: String(form.followUpInstruction || '').trim(),
    actualAmountPaid: String(form.actualAmountPaid || '').trim(),
    paymentVerifier: String(form.paymentVerifier || '').trim(),
    paymentMismatchReason: String(form.paymentMismatchReason || '').trim(),
    urgencyLevel: String(form.urgencyLevel || '').trim(),
    clinicianReferralRecommended: Boolean(form.clinicianReferralRecommended),
    referralReason: String(form.referralReason || '').trim(),
    redFlagSymptoms: String(form.redFlagSymptoms || '').trim(),
    medicationClass: String(form.medicationClass || '').trim(),
    adminOverrideReason: String(form.adminOverrideReason || '').trim(),
    planVersion: String(form.planVersion || 'Bulamu360 HTML 2026.05').trim(),
    rulesEngineVersion: String(form.rulesEngineVersion || 'clinical-rules-2026.05').trim(),
    recipeDatabaseVersion: String(form.recipeDatabaseVersion || '').trim(),
    checklist: reviewChecklistFromForm(form),
    checklistComplete: checklistComplete(reviewChecklistFromForm(form)),
    updatedAt: new Date().toISOString()
  };
}

function adminReviewSection(order) {
  const review = order.adminReview || {};
  const rows = [
    ['Clinical note', review.clinicalNote],
    ['Approval condition', review.approvalCondition],
    ['Requested follow-up data', review.requestedLab],
    ['Dietary correction', review.dietaryCorrection],
    ['Follow-up instruction', review.followUpInstruction],
    ['Urgency level', review.urgencyLevel],
    ['Medication class', review.medicationClass],
    ['Clinician referral reason', review.referralReason],
    ['Red-flag symptoms', review.redFlagSymptoms],
    ['Admin override reason', review.adminOverrideReason],
    ['Plan version', review.planVersion],
    ['Rules engine version', review.rulesEngineVersion],
    ['Recipe database version', review.recipeDatabaseVersion]
  ].filter(([, value]) => String(value || '').trim());
  if (!rows.length) return '';
  return `<div class="sec"><div class="sh"><div class="si o">RN</div><div class="st">Breyer's Final Review Notes</div></div>
    <div style="background:linear-gradient(135deg,#fdf8f0,#ede8df);border-radius:9px;padding:14px;border-left:4px solid #1e3a1a;font-size:12.5px;line-height:1.75">
      <p style="margin-bottom:10px"><strong>This section was added during admin clinical review before approval.</strong></p>
      ${rows.map(([label, value]) => `<div style="background:#fff;border:1px solid #e2dbcf;border-radius:8px;padding:10px;margin-top:8px"><strong style="color:#1e3a1a">${escapeHtml(label)}</strong><div style="margin-top:4px">${nl2br(value)}</div></div>`).join('')}
    </div>
  </div>`;
}

function customerReleaseSection(order) {
  const review = order.adminReview || {};
  const rows = [
    ['Breyer note', review.customerReleaseNote],
    ['Follow-up instruction', review.followUpInstruction]
  ].filter(([, value]) => String(value || '').trim());
  if (!rows.length) return '';
  return `<div class="sec"><div class="sh"><div class="si o">RN</div><div class="st">Breyer's Release Note</div></div>
    <div style="background:linear-gradient(135deg,#fdf8f0,#ede8df);border-radius:9px;padding:14px;border-left:4px solid #1e3a1a;font-size:12.5px;line-height:1.75">
      ${rows.map(([label, value]) => `<div style="background:#fff;border:1px solid #e2dbcf;border-radius:8px;padding:10px;margin-top:8px"><strong style="color:#1e3a1a">${escapeHtml(label)}</strong><div style="margin-top:4px">${nl2br(value)}</div></div>`).join('')}
    </div>
  </div>`;
}

function applyAdminAmendments(order) {
  const base = String(order.htmlPlan || '');
  const section = adminReviewSection(order);
  if (!section || !base) return base;
  if (base.includes("Breyer's Final Review Notes")) return base;
  const marker = '<div class="body">';
  if (base.includes(marker)) return base.replace(marker, `${marker}${section}`);
  return base.replace('</body>', `${section}</body>`);
}

function stripInternalPatientSections(html = '') {
  let output = String(html || '');
  const blockedTitles = [
    "Breyer's Final Review Notes",
    'Specialist Clinical Reasoning and Safety Gates',
    'Clinical Decision Matrix',
    'Plan Quality Audit',
    'Clinical Targets for This Specialist Plan',
    'Condition-Specific Nutrition Chapters',
    'Condition-Specific Clinical Chapters',
    'Assessment Used to Build This Plan',
    'Client Snapshot',
    'Personalised Food Strategy',
    'Meal Selection Rationale',
    'Recipe Practicality, Taste, and Substitution Notes'
  ];
  for (const title of blockedTitles) {
    let titleIndex = output.indexOf(title);
    while (titleIndex >= 0) {
      const start = output.lastIndexOf('<div class="sec"', titleIndex);
      const next = output.indexOf('<div class="sec"', titleIndex + title.length);
      const end = next >= 0 ? next : output.indexOf('</div></body>', titleIndex);
      if (start < 0 || end < 0 || end <= start) break;
      output = output.slice(0, start) + output.slice(end);
      titleIndex = output.indexOf(title);
    }
  }
  return output;
}

function cleanPatientMealCardLanguage(html = '') {
  return String(html || '')
    .replace(/\s*(Diabetes|Kidney|Hypertension|Lipid|Pregnancy|Weight-loss|Higher-energy) adjustment:[^<]*?(?:\.|(?=<))/g, '')
    .replace(/\s*(Diabetes|Hypertension|Kidney|Gout|Cholesterol|BP\/kidney medication):[^<]*?(?:\.|(?=<))/g, '')
    .replace(/<strong>Why selected:<\/strong>/g, '<strong>Practical note:</strong>')
    .replace(/<strong>Use this meal safely:<\/strong>/g, '<strong>Small safety note:</strong>')
    .replace(/<strong>Nutrition note:<\/strong>[^<]*(?=<\/div>)/g, '');
}

function applyCustomerReleaseNote(order) {
  const base = cleanPatientMealCardLanguage(stripInternalPatientSections(order.finalHtmlPlan || order.htmlPlan || ''));
  const section = customerReleaseSection(order);
  if (!section || !base) return base;
  if (base.includes("Breyer's Release Note")) return base;
  const marker = '<div class="body">';
  if (base.includes(marker)) return base.replace(marker, `${marker}${section}`);
  return base.replace('</body>', `${section}</body>`);
}

function planHtmlForOrder(order, options = {}) {
  const audience = options.audience || 'patient';
  if (audience === 'admin') return order.finalHtmlPlan || applyAdminAmendments(order);
  return applyCustomerReleaseNote(order);
}

async function sendRejectionEmail(order) {
  await sendResendEmail({
    to: order.email,
    subject: 'Bulamu360 payment reference needs review',
    html: `<p>Hello ${escapeHtml(order.name)},</p><p>Breyer could not approve the payment reference you submitted yet.</p><p><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p><p>${escapeHtml(order.adminNote || 'Please WhatsApp your payment SMS to +256 704392545 for review. Payment numbers: Airtel Money +256 704392545; MTN MoMo +256 791790934.')}</p>`
  });
}

async function sendFollowupSubmittedEmail(order, followup) {
  if (!ownerEmail) return;
  await sendResendEmail({
    to: ownerEmail,
    subject: `Bulamu360 follow-up submitted - ${order.name}`,
    html: `<p>A customer progress review is waiting.</p>
      <p><strong>Name:</strong> ${escapeHtml(order.name)}<br>
      <strong>Review point:</strong> ${escapeHtml(followup.reviewPoint)}<br>
      <strong>Weight:</strong> ${escapeHtml(followup.weight || '-')}<br>
      <strong>Waist:</strong> ${escapeHtml(followup.waist || '-')}<br>
      <strong>Reading:</strong> ${escapeHtml(followup.clinicalReading || '-')}<br>
      <strong>Energy:</strong> ${escapeHtml(followup.energy || '-')} / 10<br>
      <strong>Adherence:</strong> ${escapeHtml(followup.adherence || '-')} / 10<br>
      <strong>Outcome trend:</strong> ${escapeHtml(followup.outcomeTrend || '-')}<br>
      <strong>Taste:</strong> ${escapeHtml(followup.tasteSatisfaction || '-')} / 10<br>
      <strong>Budget/cooking/availability burden:</strong> ${escapeHtml(followup.budgetDifficulty || '-')} / ${escapeHtml(followup.cookingDifficulty || '-')} / ${escapeHtml(followup.foodAvailabilityDifficulty || '-')}</p>
      <p><strong>Symptoms/concerns:</strong><br>${nl2br(followup.symptoms || '-')}</p>
      <p><strong>Practical barriers:</strong><br>${nl2br([followup.householdSupport, followup.expensiveMeals, followup.hardToCookMeals, followup.requestedSubstitutions].filter(Boolean).join('\\n\\n') || '-')}</p>
      <p><a href="${publicBaseUrl}/admin/orders/${escapeHtml(order.id)}/followups/${escapeHtml(followup.id)}">Open follow-up review</a></p>`
  });
}

async function sendFollowupAdjustmentEmail(order, followup) {
  const adj = followup.adminAdjustment || {};
  await sendResendEmail({
    to: order.email,
    subject: `Bulamu360 follow-up response - ${followup.reviewPoint}`,
    html: `<p>Hello ${escapeHtml(order.name)},</p>
      <p>Breyer has reviewed your progress submission.</p>
      <p><strong>Action:</strong> ${escapeHtml(adj.action || 'Review completed')}<br>
      <strong>Escalation status:</strong> ${escapeHtml(adj.escalationStatus || 'routine')}</p>
      ${adj.note ? `<p><strong>Adjustment note:</strong><br>${nl2br(adj.note)}</p>` : ''}
      ${adj.requestedLabs ? `<p><strong>Requested labs/readings:</strong><br>${nl2br(adj.requestedLabs)}</p>` : ''}
      ${adj.nextReview ? `<p><strong>Next review:</strong><br>${nl2br(adj.nextReview)}</p>` : ''}
      ${order.followupToken ? `<p><a href="${publicBaseUrl}/followup/${escapeHtml(order.followupToken)}" style="background:#1e3a1a;color:#fff;padding:11px 16px;border-radius:8px;text-decoration:none;display:inline-block">Submit another progress review</a></p>` : ''}
      <p style="font-size:13px;color:#5a4a38">If symptoms are severe, urgent, or worsening, please seek medical care promptly.</p>`
  });
}

async function sendFollowupReminderEmail(order, reviewPoint = 'progress review') {
  if (!order.followupToken) throw new Error('This order does not have a follow-up link yet.');
  await sendResendEmail({
    to: order.email,
    subject: `Bulamu360 reminder: ${reviewPoint}`,
    html: `<p>Hello ${escapeHtml(order.name)},</p>
      <p>This is your Bulamu360 ${escapeHtml(reviewPoint)} reminder. Please submit your progress so Breyer can review how the plan is working.</p>
      <p><a href="${publicBaseUrl}/followup/${escapeHtml(order.followupToken)}" style="background:#1e3a1a;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;display:inline-block">Submit progress review</a></p>
      <p>Helpful details: current weight, waist, BP/glucose if relevant, energy, symptoms, adherence, disliked meals, and questions.</p>`
  });
}

function validateOrderPayload(payload) {
  const email = String(payload.email || payload.to || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Please provide a valid customer email address.';
  if (!String(payload.name || '').trim()) return 'Customer name is required.';
  if (!String(payload.phone || '').trim()) return 'Phone number is required.';
  if (!String(payload.packageName || '').trim()) return 'Package is required.';
  const txCompact = String(payload.txRef || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (txCompact.length < 6) return 'Transaction reference is required. Copy the transaction ID/reference from the Airtel Money or MTN MoMo SMS.';
  if (!payload.profile || typeof payload.profile !== 'object') return 'Customer profile is required for private plan generation.';
  return '';
}

function logOrderEvent(event, details = {}) {
  const safe = {
    event,
    at: new Date().toISOString(),
    ...details
  };
  console.log('[orders]', JSON.stringify(safe));
}

async function handleCreateOrder(req, res) {
  try {
    const payload = await readRequestJson(req);
    logOrderEvent('received', {
      origin: req.headers.origin || '',
      host: requestHost(req),
      name: shortText(payload.name, 80),
      email: shortText(payload.email || payload.to, 120),
      phonePresent: Boolean(String(payload.phone || '').trim()),
      packageName: shortText(payload.packageName, 120),
      network: shortText(payload.network, 40),
      txRefLength: String(payload.txRef || '').replace(/[^A-Z0-9]/gi, '').length,
      hasProfile: Boolean(payload.profile && typeof payload.profile === 'object')
    });
    /* B360 SUBSCRIPTIONS */
    const isSub = payload.kind === 'subscription';
    const subTier = isSub ? SUBSCRIPTIONS[String(payload.tier || '').toLowerCase()] : null;
    if (isSub) {
      if (!subTier) return sendJson(res, 400, { ok: false, error: 'Please choose Pantry, Greenwell or Banquet.' });
      payload.packageName = subTier.name;
      payload.amount = 'UGX ' + subTier.price.toLocaleString('en-US') + ' / month';
      payload.orderType = 'Monthly subscription';
      if (!payload.profile || typeof payload.profile !== 'object') payload.profile = {};
    }
    const isTemplate = payload.kind === 'template';
    const tplId = isTemplate ? String(payload.templateId || '') : '';
    if (isTemplate) {
      if (!TEMPLATES[tplId] || !TEMPLATES[tplId].premium) return sendJson(res, 400, { ok: false, error: 'That template is not for sale.' });
      payload.packageName = 'Template - ' + TEMPLATES[tplId].title;
      payload.amount = 'UGX ' + TEMPLATE_PRICE.toLocaleString('en-US');
      if (!payload.profile || typeof payload.profile !== 'object') payload.profile = {};
    }
    const error = validateOrderPayload(payload);
    if (error) {
      logOrderEvent('validation-failed', { error });
      return sendJson(res, 400, { ok: false, error });
    }
    const db = readDb();
    const buyer = currentAccount(req, db);
    if ((isTemplate || isSub) && !buyer) return sendJson(res, 401, { ok: false, error: isSub ? 'Please sign in to your Bulamu360 account to subscribe.' : 'Please sign in to your Bulamu360 account to buy a template.' });
    const now = new Date().toISOString();
    const clinicalSummary = (isTemplate || isSub) ? {} : serverClinicalSummaryFromPayload(payload);
    const privateHtmlPlan = (isTemplate || isSub) ? `<!doctype html><html><body><h1>Template purchase</h1><p>${escapeHtml(payload.packageName)}</p></body></html>` : backendPlanHtml(payload, clinicalSummary);
    const order = {
      id: makeOrderId(),
      status: 'pending',
      createdAt: now,
      updatedAt: now,
      name: String(payload.name).trim(),
      email: String(payload.email || payload.to).trim(),
      phone: String(payload.phone || '').trim(),
      packageName: String(payload.packageName || '').trim(),
      amount: String(payload.amount || '').trim(),
      consultationAddon: Boolean(payload.consultationAddon),
      orderType: String(payload.orderType || (payload.consultationAddon ? 'Nutrition Plan + Consultation Add-on' : 'Nutrition Plan')).trim(),
      network: String(payload.network || '').trim(),
      txRef: String(payload.txRef || '').trim().toUpperCase(),
      bmi: payload.bmi || '',
      profile: payload.profile && typeof payload.profile === 'object' ? payload.profile : {},
      clinicalSummary,
      htmlPlan: privateHtmlPlan,
      htmlHash: createHash('sha256').update(privateHtmlPlan).digest('hex'),
      planEngine: 'backend-private-v1',
      kind: isTemplate ? 'template' : isSub ? 'subscription' : 'plan',
      templateId: tplId,
      accountId: buyer ? buyer.id : '',
      approvalCode: '',
      downloadToken: '',
      followupToken: '',
      followups: [],
      adminNote: '',
      adminReview: {
        clinicalNote: '',
        approvalCondition: '',
        requestedLab: '',
        dietaryCorrection: '',
        followUpInstruction: '',
        checklist: {},
        checklistComplete: false,
        updatedAt: ''
      },
      reviewHistory: [],
      finalHtmlPlan: '',
      emailLog: []
    };
    db.orders.unshift(order);
    writeDb(db);
    logOrderEvent('saved', {
      orderId: order.id,
      status: order.status,
      storage: supabaseEnabled() ? 'supabase-with-local-cache' : 'local-json',
      pendingCount: db.orders.filter(o => o.status === 'pending').length,
      totalOrders: db.orders.length
    });
    queueOrderEmail(order, 'customer-order-submitted', () => sendCustomerOrderSubmittedEmail(order), { to: order.email });
    queueOrderEmail(order, 'owner-order-submitted', () => sendOwnerOrderSubmittedEmail(order), { to: ownerEmail || 'not configured' });
    logOrderEvent('response-sent', { orderId: order.id, status: order.status });
    sendJson(res, 200, { ok: true, orderId: order.id, status: order.status });
  } catch (error) {
    logOrderEvent('failed', { error: error.message || 'Could not create order.' });
    sendJson(res, 500, { ok: false, error: error.message || 'Could not create order.' });
  }
}

function validateLeadPayload(payload) {
  const email = String(payload.email || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Please provide a valid email address.';
  if (!String(payload.name || '').trim()) return 'Name is required.';
  if (!String(payload.phone || '').trim()) return 'Phone number is required.';
  if (!payload.consentAccepted) return 'Please agree to the Terms and Privacy Policy before getting your snapshot.';
  return '';
}

async function handleCreateLead(req, res) {
  try {
    const payload = await readRequestJson(req);
    const error = validateLeadPayload(payload);
    if (error) return sendJson(res, 400, { ok: false, error });
    const db = readDb();
    const now = new Date().toISOString();
    const email = String(payload.email || '').trim().toLowerCase();
    const phone = String(payload.phone || '').trim();
    const existing = db.leads.find(l => String(l.email || '').toLowerCase() === email || (phone && String(l.phone || '').trim() === phone));
    const profile = payload.profile && typeof payload.profile === 'object' ? payload.profile : {};
    const leadRecord = {
      id: existing && existing.id ? existing.id : `LEAD-${randomBytes(4).toString('hex').toUpperCase()}`,
      createdAt: existing && existing.createdAt ? existing.createdAt : now,
      updatedAt: now,
      status: existing && existing.status ? existing.status : 'free-assessment',
      name: String(payload.name || '').trim(),
      email,
      phone,
      goal: String(payload.goal || profile.goal || '').trim(),
      planType: String(payload.planType || profile.plantype || '').trim(),
      bmi: String(payload.bmi || profile.bmi || '').trim(),
      conditions: Array.isArray(payload.conditions) ? payload.conditions : (Array.isArray(profile.conds) ? profile.conds : []),
      customerSource: String(payload.customerSource || profile.customerSource || '').trim(),
      referralCode: String(payload.referralCode || profile.referralCode || '').trim(),
      consentAccepted: true,
      consentAt: existing && existing.consentAt ? existing.consentAt : now,
      consentVersion: String(payload.consentVersion || 'privacy-terms-2026-07').trim(),
      marketingStage: existing && existing.marketingStage ? existing.marketingStage : 'snapshot-only',
      paidOrderId: existing && existing.paidOrderId ? existing.paidOrderId : '',
      profile
    };
    if (existing) Object.assign(existing, leadRecord);
    else db.leads.unshift(leadRecord);
    writeDb(db);
    sendJson(res, 200, { ok: true, leadId: leadRecord.id, status: leadRecord.status });
  } catch (error) {
    sendJson(res, 500, { ok: false, error: error.message || 'Could not save assessment lead.' });
  }
}

async function handleUnlockPlan(req, res) {
  try {
    const payload = await readRequestJson(req);
    const rawCode = String(payload.code || '').trim().toUpperCase();
    const code = rawCode.replace(/[^A-Z0-9]/g, '');
    const email = String(payload.email || '').trim().toLowerCase();
    const db = readDb();
    const order = db.orders.find(o => {
      const savedCode = String(o.approvalCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      return o.status === 'approved' && savedCode && savedCode === code;
    });
    if (!order) {
      return sendJson(res, 404, {
        ok: false,
        error: 'No approved plan found for that approval code. Check that the order is approved in the admin dashboard and that the full code was entered.'
      });
    }
    if (email && String(order.email || '').toLowerCase() !== email) {
      return sendJson(res, 403, {
        ok: false,
        error: 'This approval code is approved, but it is linked to a different email address. Use the same email used on the order, or ask the admin to confirm the customer email.'
      });
    }
    const membership = memberSubscriptionStatus(order);
    sendJson(res, 200, {
      ok: true,
      order: {
        id: order.id,
        name: order.name,
        packageName: order.packageName,
        amount: order.amount,
        approvalCode: order.approvalCode,
        downloadUrl: `/plan/${order.downloadToken}`,
        memberLevel: memberLevelFromPackage(order.packageName),
        activeUntil: membership.activeUntil || '',
        daysRemaining: membership.daysRemaining || 0,
        renewalReminder: membership.renewalReminder || ''
      },
      htmlPlan: planHtmlForOrder(order, { audience: 'patient' })
    });
  } catch (error) {
    sendJson(res, 500, { ok: false, error: error.message || 'Unlock failed.' });
  }
}

function adminLoginPage(error = '') {
  return renderTemplate(adminLoginTemplatePath, {
    ERROR_HTML: error ? `<p class="err">${escapeHtml(error)}</p>` : ''
  });
}

function emailStatusHtml(order) {
  const log = Array.isArray(order.emailLog) ? order.emailLog : [];
  const latest = log.length ? log[log.length - 1] : null;
  if (!order.approvalCode) return '<small>Email: waits for approval</small>';
  if (!latest) return '<small>Email: no error recorded</small>';
  if (latest.status === 'queued') {
    return `<div class="email-status email-queued">Email queued<br><small>${escapeHtml(latest.type || 'message')}</small></div>`;
  }
  if (latest.error) {
    return `<div class="email-status email-error"><strong>Email failed:</strong><br>${escapeHtml(shortText(latest.error, 190))}</div>`;
  }
  return `<div class="email-status email-ok">Email sent${latest.id ? ` - ${escapeHtml(latest.id)}` : ''}</div>`;
}

function coachSignalText(value) {
  return String(value || '').toLowerCase();
}

function coachHasAny(value, words) {
  const text = coachSignalText(value);
  return words.some(word => text.includes(word));
}

function buildCoachReviewQueue(db = readDb()) {
  const byEmail = new Map();
  const orders = Array.isArray(db.orders) ? db.orders : [];
  const progress = Array.isArray(db.progressEntries) ? db.progressEntries : [];
  const diary = Array.isArray(db.foodDiary) ? db.foodDiary : [];
  function itemFor(email) {
    const clean = String(email || '').toLowerCase().trim();
    if (!clean) return null;
    if (!byEmail.has(clean)) {
      const relatedOrders = orders.filter(o => String(o.email || '').toLowerCase() === clean);
      const latestOrder = relatedOrders.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))[0] || null;
      byEmail.set(clean, {
        email: clean,
        name: latestOrder ? latestOrder.name : '',
        phone: latestOrder ? latestOrder.phone : '',
        latestOrder,
        score: 0,
        severity: 'watch',
        signals: [],
        latestAt: '',
        progressCount: 0,
        diaryCount: 0
      });
    }
    return byEmail.get(clean);
  }
  function addSignal(item, points, label, detail, at) {
    if (!item) return;
    item.score += points;
    item.signals.push({ label, detail: shortText(detail || '', 160), points, at });
    if (at && String(at) > String(item.latestAt || '')) item.latestAt = at;
  }
  for (const p of progress) {
    const item = itemFor(p.email);
    if (!item) continue;
    item.name = item.name || p.name || '';
    item.progressCount += 1;
    if (p.createdAt && String(p.createdAt) > String(item.latestAt || '')) item.latestAt = p.createdAt;
    if (coachHasAny(p.symptoms, ['chest pain', 'faint', 'fainting', 'blood in stool', 'severe', 'swelling', 'vomit', 'rapid weight loss'])) addSignal(item, 5, 'Clinical safety symptom', p.symptoms, p.createdAt);
    else if (String(p.symptoms || '').trim()) addSignal(item, 2, 'Symptoms reported', p.symptoms, p.createdAt);
    if (coachHasAny(p.energy, ['low'])) addSignal(item, 2, 'Low energy', p.energy, p.createdAt);
    if (coachHasAny(p.hunger, ['high', 'very high'])) addSignal(item, 2, 'High hunger', p.hunger, p.createdAt);
    if (coachHasAny(p.sleep, ['poor'])) addSignal(item, 1, 'Poor sleep', p.sleep, p.createdAt);
    if (coachHasAny(p.mood, ['low', 'stressed'])) addSignal(item, 1, 'Mood support needed', p.mood, p.createdAt);
    if (String(p.bloodPressure || '').match(/\b1[4-9]\d\s*\/|[2-9]\d{2}\s*\//)) addSignal(item, 3, 'Blood pressure review', p.bloodPressure, p.createdAt);
    if (String(p.notes || '').trim()) addSignal(item, 1, 'Member note', p.notes, p.createdAt);
  }
  for (const d of diary) {
    const item = itemFor(d.email);
    if (!item) continue;
    item.name = item.name || d.name || '';
    item.diaryCount += 1;
    if (d.createdAt && String(d.createdAt) > String(item.latestAt || '')) item.latestAt = d.createdAt;
    if (coachHasAny(d.taste, ['not tasty'])) addSignal(item, 2, 'Meal not tasty', d.meal || d.dislikedRepeated, d.createdAt);
    if (coachHasAny(d.cost, ['expensive'])) addSignal(item, 2, 'Meal too expensive', d.meal || d.portion, d.createdAt);
    if (coachHasAny(d.symptomsAfter, ['bloat', 'reflux', 'nausea', 'headache', 'sleepy', 'pain', 'diarrhoea', 'diarrhea', 'vomit'])) addSignal(item, 3, 'Meal symptom reaction', `${d.meal || ''} - ${d.symptomsAfter || ''}`, d.createdAt);
    if (coachHasAny(d.dislikedRepeated, ['repeat', 'boring', 'dislike', 'unrealistic', 'hard'])) addSignal(item, 2, 'Meal fit problem', d.dislikedRepeated, d.createdAt);
    if (coachHasAny(d.replacementRequest, ['yes'])) addSignal(item, 2, 'Replacement requested', `${d.replacementRequest || ''} ${d.meal || ''}`, d.createdAt);
  }
  return Array.from(byEmail.values())
    .filter(item => item.score > 0)
    .map(item => {
      item.severity = item.score >= 8 || item.signals.some(s => s.points >= 5) ? 'urgent' : item.score >= 4 ? 'priority' : 'watch';
      item.signals = item.signals.sort((a, b) => b.points - a.points || String(b.at || '').localeCompare(String(a.at || ''))).slice(0, 6);
      return item;
    })
    .sort((a, b) => b.score - a.score || String(b.latestAt || '').localeCompare(String(a.latestAt || '')));
}

function adminCoachQueuePage() {
  const queue = buildCoachReviewQueue();
  const rows = queue.map(item => {
    const order = item.latestOrder || {};
    const signalRows = item.signals.map(s => `<span><strong>${escapeHtml(s.label)}</strong>: ${escapeHtml(s.detail || 'Captured')} (${escapeHtml(s.points)} pts)</span>`).join('');
    return `<tr><td><strong>${escapeHtml(item.name || 'Member')}</strong><br><small>${escapeHtml(item.email)}<br>${escapeHtml(item.phone || '')}</small></td><td><span class="tag ${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span><br><strong>${escapeHtml(item.score)}</strong> review points<br><small>Latest: ${escapeHtml(item.latestAt ? new Date(item.latestAt).toLocaleString() : '-')}</small></td><td>${escapeHtml(order.packageName || 'No paid plan captured')}<br><small>${escapeHtml(order.status || '')}</small></td><td><div class="risk-list">${signalRows}</div></td><td><a class="btn ghost" href="/admin?status=approved">Orders</a>${order.id ? ` <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Review order</a>` : ''}</td></tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Coach Review Queue</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#241a10;margin:0}.wrap{max-width:1320px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}.btn{display:inline-flex;background:#1e3a1a;color:#fff;text-decoration:none;border-radius:8px;padding:9px 12px;font-weight:800;margin:3px}.ghost{background:#ede8df;color:#241a10}.panel{background:#fffdf8;border:1px solid #e6dccd;border-radius:14px;overflow:auto;box-shadow:0 12px 38px #2a1f1412}table{width:100%;border-collapse:collapse;min-width:980px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px;line-height:1.45}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#786855;background:#fbf8f3}.tag{display:inline-flex;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:900;text-transform:uppercase}.urgent{background:#ffe1dc;color:#8a1010}.priority{background:#fff1c7;color:#8a6200}.watch{background:#e4f5dd;color:#1e5a1a}.risk-list span{display:block;border-left:3px solid #d8cfbf;padding-left:8px;margin:5px 0}small,p{color:#6d5d4b}h1{color:#1e3a1a;margin:0 0 6px}.metric{display:inline-block;background:#fffdf8;border:1px solid #e6dccd;border-radius:12px;padding:10px 13px;margin-top:10px}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Coach Review Queue</h1><p>Members who may need attention based on progress check-ins and food diary feedback.</p><div class="metric"><strong>${escapeHtml(queue.length)}</strong> member(s) needing review</div></div><div><a class="btn ghost" href="/admin">Back to dashboard</a><a class="btn ghost" href="/admin/coach-queue.csv">Export CSV</a></div></div>
  <div class="panel"><table><thead><tr><th>Member</th><th>Priority</th><th>Plan</th><th>Signals</th><th>Action</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No review signals yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function adminDashboard(req) {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const statusFilter = url.searchParams.get('status') || 'all';
  const db = readDb();
  const orders = db.orders.filter(o => statusFilter === 'all' || o.status === statusFilter);
  const counts = db.orders.reduce((acc, o) => (acc[o.status] = (acc[o.status] || 0) + 1, acc), {});
  const rows = orders.map(o => {
    const cs = o.clinicalSummary || {};
    const confidence = cs.confidence && cs.confidence.level ? cs.confidence.level : 'Not captured';
    const orderType = o.orderType || (o.consultationAddon ? 'Nutrition Plan + Consultation Add-on' : 'Nutrition Plan');
    const review = o.adminReview || {};
    const safety = cs.safetyDecision || {};
    const audit = cs.planAudit || {};
    const safetyStatus = safety.status || 'not-captured';
    const safetyLabel = safety.label || 'Safety status not captured';
    const reviewItems = Array.isArray(safety.review) ? safety.review.slice(0, 3) : [];
    const cautionItems = Array.isArray(safety.caution) ? safety.caution.slice(0, 2) : [];
    const rules = cs.clinicalRules || {};
    const ruleReview = Array.isArray(rules.review) ? rules.review.slice(0, 2) : [];
    const ruleCaution = Array.isArray(rules.caution) ? rules.caution.slice(0, 2) : [];
    const contraindications = Array.isArray(rules.contraindications) ? rules.contraindications.slice(0, 3) : [];
    const chapters = Array.isArray(cs.conditionChapters) ? cs.conditionChapters.slice(0, 4).map(c => c.title).filter(Boolean) : [];
    const conditions = Array.isArray(cs.conditions) ? cs.conditions : [];
    const clinicalLine = cs.riskScore ? `<br><small>Risk snapshot: ${escapeHtml(cs.riskScore)}/100 - ${escapeHtml(confidence)} confidence</small>` : '';
    const waistLine = cs.waist ? `<br><small>Waist: ${escapeHtml(cs.waist)} cm - ${escapeHtml(cs.waistRisk || '')}</small>` : '';
    const safetyLine = `<div class="safety ${escapeHtml(safetyStatus)}">${escapeHtml(safetyLabel)}</div>`;
    const reviewLine = reviewItems.length ? `<div class="risk-list"><strong>Review gates:</strong>${reviewItems.map(x => `<span>${escapeHtml(x)}</span>`).join('')}</div>` : '';
    const cautionLine = cautionItems.length ? `<div class="risk-list"><strong>Cautions:</strong>${cautionItems.map(x => `<span>${escapeHtml(x)}</span>`).join('')}</div>` : '';
    const ruleLine = (ruleReview.length || ruleCaution.length || contraindications.length)
      ? `<div class="risk-list"><strong>Rules engine:</strong>${ruleReview.map(x => `<span>Review: ${escapeHtml(x.area || '')} - ${escapeHtml(x.title || '')}</span>`).join('')}${ruleCaution.map(x => `<span>Caution: ${escapeHtml(x.area || '')} - ${escapeHtml(x.title || '')}</span>`).join('')}${contraindications.map(x => `<span>Avoid: ${escapeHtml(x.area || '')} - ${escapeHtml(x.reason || '')}</span>`).join('')}</div>`
      : '';
    const chapterLine = chapters.length ? `<div class="chips">${chapters.map(x => `<span>${escapeHtml(x)}</span>`).join('')}</div>` : '<small>No specialist chapters captured</small>';
    const auditStatus = audit.status || 'not-captured';
    const auditLine = `<div class="safety ${escapeHtml(auditStatus === 'ready' ? 'safe' : auditStatus === 'caution' ? 'caution' : auditStatus === 'review' ? 'review' : 'not-captured')}">${escapeHtml(audit.label || 'Audit not captured')} ${audit.score !== undefined ? `(${escapeHtml(audit.score)}/100)` : ''}</div>`;
    const auditBlockers = Array.isArray(audit.blockers) ? audit.blockers.slice(0, 3) : [];
    const auditWarnings = Array.isArray(audit.warnings) ? audit.warnings.slice(0, 2) : [];
    const auditDetail = (auditBlockers.length || auditWarnings.length)
      ? `<div class="risk-list"><strong>Audit:</strong>${auditBlockers.map(x => `<span>Blocker: ${escapeHtml(x)}</span>`).join('')}${auditWarnings.map(x => `<span>Warning: ${escapeHtml(x)}</span>`).join('')}</div>`
      : (audit.stats ? `<small>${escapeHtml(audit.stats.uniqueMeals || 0)} unique meals - ${escapeHtml(audit.stats.weeks || 0)} weeks</small>` : '');
    const contextLine = [
      cs.diagnosis ? `Diagnosis: ${cs.diagnosis}` : '',
      cs.allergies ? `Allergies: ${cs.allergies}` : '',
      cs.symptoms ? `Symptoms: ${cs.symptoms}` : ''
    ].filter(Boolean).map(x => `<small>${escapeHtml(x)}</small>`).join('<br>');
    const acquisitionLine = [
      cs.customerSource ? `Source: ${cs.customerSource}` : '',
      cs.customerType ? `Type: ${cs.customerType}` : '',
      cs.referralCode ? `Referral: ${cs.referralCode}` : ''
    ].filter(Boolean).map(x => `<small>${escapeHtml(x)}</small>`).join('<br>');
    const reviewLine2 = review.updatedAt ? `<br><small>Admin review: ${review.checklistComplete ? 'checklist complete' : 'incomplete'} - ${new Date(review.updatedAt).toLocaleString()}</small>` : '<br><small>Admin review not started</small>';
    return `<tr>
    <td><strong>${escapeHtml(o.name)}</strong><br><small>${escapeHtml(o.email)}<br>${escapeHtml(o.phone)}</small>${acquisitionLine ? `<br>${acquisitionLine}` : ''}</td>
    <td>${escapeHtml(o.packageName)}<br><small>${escapeHtml(o.amount)}</small><br><small><strong>${escapeHtml(orderType)}</strong></small>${clinicalLine}${waistLine}<br>${conditions.length ? `<small>Conditions: ${escapeHtml(conditions.join(', '))}</small>` : ''}${contextLine ? `<br>${contextLine}` : ''}</td>
    <td>${escapeHtml(o.network)}<br><small>${escapeHtml(o.txRef)}</small>${review.actualAmountPaid ? `<br><small>Paid: ${escapeHtml(review.actualAmountPaid)}</small>` : ''}${review.paymentVerifier ? `<br><small>Verified by: ${escapeHtml(review.paymentVerifier)}</small>` : ''}</td>
    <td>${safetyLine}${reviewLine}${cautionLine}${ruleLine}</td>
    <td>${auditLine}${auditDetail}</td>
    <td>${chapterLine}</td>
    <td><span class="badge ${o.status}">${escapeHtml(o.status)}</span><br><small>${new Date(o.createdAt).toLocaleString()}</small>${reviewLine2}</td>
    <td>${o.approvalCode ? `<code>${escapeHtml(o.approvalCode)}</code><br><a href="/plan/${escapeHtml(o.downloadToken)}" target="_blank">customer link</a>${o.followupToken ? `<br><a href="/followup/${escapeHtml(o.followupToken)}" target="_blank">follow-up link</a>` : ''}<br>${emailStatusHtml(o)}` : '<small>Not approved yet</small>'}</td>
    <td class="actions">
      <a class="btn ghost" href="/admin/orders/${o.id}/plan" target="_blank">View plan</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/content">Edit content</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/edit">Edit plan</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/review">Review</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/download">Download</a>
      ${o.status === 'pending' ? `<form method="post" action="/admin/orders/${o.id}/reject"><input name="note" placeholder="Reason for rejection"><button class="btn reject">Reject</button></form>` : ''}
      ${o.status === 'approved' ? `<form method="post" action="/admin/orders/${o.id}/resend"><button class="btn">Resend email</button></form><form method="post" action="/admin/orders/${o.id}/reminder"><select name="reviewPoint"><option>7-day check-in</option><option>14-day adherence check</option><option>30-day outcome review</option><option>60-day continuation review</option></select><button class="btn ghost">Send reminder</button></form>` : ''}
      <a class="btn danger" href="/admin/orders/${escapeHtml(o.id)}/delete">Delete</a>
    </td>
  </tr>`;
  }).join('');
  return renderTemplate(adminDashboardTemplatePath, {
    PENDING_COUNT: counts.pending || 0,
    APPROVED_COUNT: counts.approved || 0,
    REJECTED_COUNT: counts.rejected || 0,
    LEAD_COUNT: (db.leads || []).length,
    COACH_QUEUE_COUNT: buildCoachReviewQueue(db).length,
    REPLACEMENT_QUEUE_COUNT: buildRecipeReplacementQueue(db).length,
    LOW_FIT_COUNT: buildPlanFitQueue(db).filter(row => row.fit.score < 65).length,
    ROWS_HTML: rows || '<tr class="empty-row"><td colspan="9">No orders yet.</td></tr>'
  });
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Admin Dashboard</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1480px;margin:0 auto;padding:28px}header{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:20px}.tabs a{display:inline-block;padding:9px 13px;background:#fff;border-radius:999px;text-decoration:none;color:#1e3a1a;margin-right:6px;border:1px solid #e2dbcf}.panel{background:#fff;border-radius:18px;box-shadow:0 10px 35px #0001;overflow:auto}table{width:100%;border-collapse:collapse;min-width:1320px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;background:#fbf8f3}.badge{padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}.pending{background:#fff1c7;color:#8a6200}.approved{background:#dff3d8;color:#1e3a1a}.rejected{background:#ffe1dc;color:#8a1010}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:8px 10px;border-radius:8px;text-decoration:none;font-weight:700;cursor:pointer;margin:3px 0}.ghost{background:#ede8df;color:#2a1f14}.approve{background:#1e3a1a}.reject{background:#8a1010}.actions form{margin:6px 0}.actions input{display:block;width:220px;max-width:100%;padding:8px;border:1px solid #ddd;border-radius:8px;margin-bottom:4px}small{color:#6c5b49}code{background:#f1eadf;padding:4px 6px;border-radius:6px}.email-status{margin-top:8px;border-radius:8px;padding:8px;font-size:11px;line-height:1.35;font-weight:700}.email-error{background:#ffe1dc;color:#8a1010}.email-ok{background:#e4f5dd;color:#1e3a1a}.email-queued{background:#fff1c7;color:#8a6200}.safety{border-radius:9px;padding:8px 10px;font-size:12px;font-weight:800;margin-bottom:7px}.safety.safe{background:#e4f5dd;color:#1e3a1a}.safety.caution{background:#fff1c7;color:#8a6200}.safety.review{background:#ffe1dc;color:#8a1010}.safety.not-captured{background:#eee6dc;color:#6c5b49}.risk-list{font-size:11.5px;line-height:1.45;margin-top:6px}.risk-list span{display:block;border-left:3px solid #d8cfbf;padding-left:7px;margin-top:4px}.chips{display:flex;flex-wrap:wrap;gap:5px}.chips span{background:#f1eadf;border:1px solid #e2dbcf;border-radius:999px;padding:5px 8px;font-size:11px;color:#2a1f14}</style></head>
  <body><div class="wrap"><header><div><h1>Bulamu360 Orders</h1><p>Pending: ${counts.pending || 0} - Approved: ${counts.approved || 0} - Rejected: ${counts.rejected || 0}</p></div><div><a class="btn ghost" href="/admin/insights">Insights</a> <a class="btn ghost" href="/admin/orders.csv">Export CSV</a> <a class="btn ghost" href="/admin/logout">Logout</a></div></header>
  <div class="tabs"><a href="/admin">All</a><a href="/admin?status=pending">Pending</a><a href="/admin?status=approved">Approved</a><a href="/admin?status=rejected">Rejected</a><a href="/admin/followups">Progress follow-ups</a><a href="/admin/insights">Insights</a></div>
  <div class="panel"><table><thead><tr><th>Customer</th><th>Plan</th><th>Payment</th><th>Clinical Safety</th><th>Quality Audit</th><th>Chapters</th><th>Status</th><th>Access</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="9">No orders yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function adminSystemPage() {
  const db = readDb();
  const counts = db.orders.reduce((acc, o) => (acc[o.status] = (acc[o.status] || 0) + 1, acc), {});
  const audit = auditSummary(db);
  const rows = [
    ['App version', appVersion],
    ['Storage mode', supabaseEnabled() ? 'Supabase' : 'Local JSON'],
    ['Supabase URL configured', supabaseUrl ? 'Yes' : 'No'],
    ['Supabase service role configured', supabaseServiceRoleKey ? 'Yes' : 'No'],
    ['Email API configured', apiKey ? 'Yes' : 'No'],
    ['From email', fromEmail],
    ['Owner email', ownerEmail],
    ['Public base URL', publicBaseUrl],
    ['Allowed origins', allowedOrigins.join(', ') || 'None'],
    ['Total orders', db.orders.length],
    ['Pending orders', counts.pending || 0],
    ['Approved orders', counts.approved || 0],
    ['Rejected orders', counts.rejected || 0],
    ['Audit log entries', audit.count],
    ['Recent sensitive admin actions', audit.recentSensitiveActions],
    ['Latest admin action', audit.latest ? `${audit.latest.action} at ${audit.latest.at}` : 'None yet'],
    ['Active admin sessions', sessions.size],
    ['Security headers', 'Enabled'],
    ['Admin same-origin POST guard', 'Enabled'],
    ['Private source/static file block', 'Enabled']
  ];
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 System Status</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:900px;margin:0 auto;padding:28px}.card{background:#fff;border-radius:16px;padding:20px;box-shadow:0 10px 35px #0001}.btn{display:inline-block;background:#ede8df;color:#2a1f14;padding:9px 12px;border-radius:8px;text-decoration:none;font-weight:800}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{text-align:left;border-bottom:1px solid #eee6dc;padding:12px;vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68}code{background:#f1eadf;padding:3px 6px;border-radius:6px}.warn{background:#fff1c7;border-left:4px solid #c06820;padding:12px 14px;border-radius:10px;margin:14px 0}.ok{background:#e4f5dd;border-left:4px solid #1e3a1a;padding:12px 14px;border-radius:10px;margin:14px 0}</style></head>
  <body><div class="wrap"><p><a class="btn" href="/admin">Back to dashboard</a> <a class="btn" href="/admin/audit">Audit log</a> <a class="btn" href="/admin/backup.json">Download backup</a></p><div class="card"><h1>System Status</h1>
  ${supabaseEnabled() ? '<div class="ok">Orders are configured to sync to Supabase.</div>' : '<div class="warn">Orders are using local JSON. This is acceptable for development only, not for the live public app.</div>'}
  <table><thead><tr><th>Setting</th><th>Status</th></tr></thead><tbody>${rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(v)}</code></td></tr>`).join('')}</tbody></table>
  <p style="color:#6c5b49;font-size:13px">Secret values are intentionally hidden. This page only shows whether each setting is configured.</p></div></div></body></html>`;
}

function adminAuditPage() {
  const db = readDb();
  const rows = (Array.isArray(db.auditLog) ? db.auditLog : []).slice(0, 250).map(entry => `<tr>
    <td><strong>${escapeHtml(entry.action || '')}</strong><br><small>${escapeHtml(entry.at || '')}</small></td>
    <td>${escapeHtml(entry.ip || '')}<br><small>${escapeHtml(shortText(entry.userAgent || '', 120))}</small></td>
    <td><code>${escapeHtml(entry.path || '')}</code></td>
    <td><pre>${escapeHtml(JSON.stringify(entry.details || {}, null, 2))}</pre></td>
  </tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Audit Log</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1280px;margin:0 auto;padding:28px}.btn{display:inline-block;background:#ede8df;color:#2a1f14;padding:9px 12px;border-radius:8px;text-decoration:none;font-weight:800}.panel{background:#fff;border-radius:16px;box-shadow:0 10px 35px #0001;overflow:auto;margin-top:14px}table{width:100%;border-collapse:collapse;min-width:1050px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #eee6dc;padding:12px;font-size:13px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;background:#fbf8f3}small{color:#6c5b49}code{background:#f1eadf;padding:3px 6px;border-radius:6px}pre{white-space:pre-wrap;margin:0;font:12px Consolas,monospace;background:#faf7f1;border:1px solid #eee6dc;border-radius:8px;padding:8px;max-width:520px}</style></head>
  <body><div class="wrap"><p><a class="btn" href="/admin">Back to dashboard</a> <a class="btn" href="/admin/system">System status</a></p><h1>Audit Log</h1><p>Recent admin-sensitive activity. Secret fields are redacted.</p><div class="panel"><table><thead><tr><th>Action</th><th>Source</th><th>Path</th><th>Details</th></tr></thead><tbody>${rows || '<tr><td colspan="4">No audit events yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function exportBackupJson(res) {
  const db = readDb();
  res.writeHead(200, securityHeaders({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="bulamu360-backup-${new Date().toISOString().slice(0, 10)}.json"`
  }));
  res.end(JSON.stringify({
    exportedAt: new Date().toISOString(),
    app: 'Bulamu360',
    version: appVersion,
    data: db
  }, null, 2));
}

function buildInsights(db = readDb()) {
  const orders = Array.isArray(db.orders) ? db.orders : [];
  const followups = allFollowups(db);
  const packageCounts = new Map();
  const sourceCounts = new Map();
  const conditionCounts = new Map();
  const rejectionReasons = new Map();
  const escalationCounts = new Map();
  const barrierCounts = new Map();
  const substitutionCounts = new Map();
  const symptomFoodCounts = new Map();
  const trendCounts = new Map();
  const reviewStatusCounts = new Map();
  const auditStatusCounts = new Map();
  let revenueExpected = 0;
  let revenueVerified = 0;
  let paymentMismatch = 0;
  let clinicianReferral = 0;
  let redFlagOrders = 0;
  let reviewIncomplete = 0;

  for (const order of orders) {
    const cs = order.clinicalSummary || {};
    const review = order.adminReview || {};
    const audit = cs.planAudit || {};
    const safety = cs.safetyDecision || {};
    increment(packageCounts, order.packageName);
    increment(sourceCounts, cs.customerSource || cs.customerType || 'Not captured');
    revenueExpected += toNumber(order.amount) || 0;
    revenueVerified += toNumber(review.actualAmountPaid) || 0;
    if (review.paymentMismatchReason) paymentMismatch += 1;
    if (review.clinicianReferralRecommended) clinicianReferral += 1;
    if (review.redFlagSymptoms) redFlagOrders += 1;
    if (order.status === 'approved' && !review.checklistComplete) reviewIncomplete += 1;
    if (order.status === 'rejected') increment(rejectionReasons, order.adminNote || review.paymentMismatchReason || 'No reason captured');
    increment(reviewStatusCounts, safety.status || 'Not captured');
    increment(auditStatusCounts, audit.status || 'Not captured');
    if (Array.isArray(cs.conditions)) cs.conditions.forEach(c => increment(conditionCounts, c));
    if (review.urgencyLevel) increment(escalationCounts, review.urgencyLevel);
  }

  for (const { followup } of followups) {
    increment(trendCounts, followup.outcomeTrend || 'Not captured');
    splitSignals(followup.expensiveMeals).forEach(x => increment(barrierCounts, `Expensive: ${x}`));
    splitSignals(followup.hardToCookMeals).forEach(x => increment(barrierCounts, `Hard to cook: ${x}`));
    splitSignals(followup.dislikedFoods).forEach(x => increment(barrierCounts, `Disliked: ${x}`));
    splitSignals(followup.requestedSubstitutions).forEach(x => increment(substitutionCounts, x));
    splitSignals(followup.foodsCausingSymptoms).forEach(x => increment(symptomFoodCounts, x));
    const burdenValues = [followup.budgetDifficulty, followup.cookingDifficulty, followup.foodAvailabilityDifficulty, followup.mealPrepBurden].map(toNumber);
    if (burdenValues.some(n => n !== null && n >= 8)) increment(escalationCounts, 'High practicality burden');
  }

  const avgEnergy = avg(followups.map(x => x.followup.energy));
  const avgAdherence = avg(followups.map(x => x.followup.adherence));
  const avgTaste = avg(followups.map(x => x.followup.tasteSatisfaction));
  const avgBudget = avg(followups.map(x => x.followup.budgetDifficulty));
  const avgCooking = avg(followups.map(x => x.followup.cookingDifficulty));
  const avgAvailability = avg(followups.map(x => x.followup.foodAvailabilityDifficulty));
  const avgPrep = avg(followups.map(x => x.followup.mealPrepBurden));

  const recommendations = [];
  if (paymentMismatch) recommendations.push(`${paymentMismatch} order(s) have payment mismatch notes. Review payment copy and refund/cancel process.`);
  if (clinicianReferral || redFlagOrders) recommendations.push(`${clinicianReferral + redFlagOrders} order(s) show referral/red-flag signals. Keep specialist plans gated before release.`);
  if ((avgTaste !== null && avgTaste < 7) || topEntries(barrierCounts, 1).length) recommendations.push('Recipe practicality is limiting adherence. Prioritize substitutions for the most repeated expensive, disliked, or hard-to-cook meals.');
  if (avgAdherence !== null && avgAdherence < 7) recommendations.push('Average adherence is below expert target. Add simpler default meal rotations and stronger follow-up adjustments.');
  if (reviewIncomplete) recommendations.push(`${reviewIncomplete} approved order(s) lack completed admin review checklist. Tighten approval discipline.`);
  if (!recommendations.length) recommendations.push('No critical operational issue is visible yet. Keep collecting follow-up data to strengthen the pattern.');

  return {
    orders,
    followups,
    revenueExpected,
    revenueVerified,
    paymentMismatch,
    clinicianReferral,
    redFlagOrders,
    avgEnergy,
    avgAdherence,
    avgTaste,
    avgBudget,
    avgCooking,
    avgAvailability,
    avgPrep,
    packageCounts,
    sourceCounts,
    conditionCounts,
    rejectionReasons,
    escalationCounts,
    barrierCounts,
    substitutionCounts,
    symptomFoodCounts,
    trendCounts,
    reviewStatusCounts,
    auditStatusCounts,
    recommendations
  };
}

function bars(title, entries, empty = 'No data captured yet.') {
  const max = entries.reduce((m, [, v]) => Math.max(m, v), 0);
  return `<div class="card"><h2>${escapeHtml(title)}</h2>${entries.length ? entries.map(([label, value]) => `<div class="barrow"><div><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div><div class="bar"><i style="width:${max ? Math.max(6, Math.round((value / max) * 100)) : 0}%"></i></div></div>`).join('') : `<p class="muted">${escapeHtml(empty)}</p>`}</div>`;
}

function adminInsightsPage() {
  const data = buildInsights();
  const approved = data.orders.filter(o => o.status === 'approved').length;
  const pending = data.orders.filter(o => o.status === 'pending').length;
  const rejected = data.orders.filter(o => o.status === 'rejected').length;
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Insights</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1380px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:9px 12px;border-radius:8px;text-decoration:none;font-weight:800}.ghost{background:#ede8df;color:#2a1f14}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.card{background:#fff;border-radius:16px;padding:18px;box-shadow:0 10px 35px #0001}.metric b{display:block;font-size:27px;color:#1e3a1a}.metric span,.muted{color:#6c5b49;font-size:13px}.barrow{margin:13px 0}.barrow div:first-child{display:flex;justify-content:space-between;gap:12px;font-size:13px}.bar{height:9px;background:#eee6dc;border-radius:999px;overflow:hidden;margin-top:5px}.bar i{display:block;height:100%;background:#c06820;border-radius:999px}.rec li{margin:9px 0;line-height:1.45}.score{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.score div{background:#faf7f1;border:1px solid #e2dbcf;border-radius:12px;padding:12px}.score b{display:block;font-size:22px;color:#1e3a1a}@media(max-width:900px){.grid,.two,.score{grid-template-columns:1fr}}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Bulamu360 Insights</h1><p>Operational, clinical, recipe, and follow-up intelligence from captured orders.</p></div><div><a class="btn ghost" href="/admin">Back to orders</a> <a class="btn ghost" href="/admin/followups">Follow-ups</a> <a class="btn ghost" href="/admin/recipes">Recipe intelligence</a> <a class="btn ghost" href="/admin/insights.csv">Export insights CSV</a></div></div>
  <div class="grid">
    <div class="card metric"><b>${data.orders.length}</b><span>Total orders</span><p class="muted">Approved ${approved} - Pending ${pending} - Rejected ${rejected}</p></div>
    <div class="card metric"><b>${data.followups.length}</b><span>Follow-up submissions</span><p class="muted">Shows real-world adherence and practicality.</p></div>
    <div class="card metric"><b>UGX ${Math.round(data.revenueVerified || data.revenueExpected).toLocaleString()}</b><span>${data.revenueVerified ? 'Verified revenue tracked' : 'Expected revenue tracked'}</span><p class="muted">From order/payment records.</p></div>
    <div class="card metric"><b>${data.clinicianReferral + data.redFlagOrders}</b><span>Clinical escalation signals</span><p class="muted">Referral recommendations plus red-flag orders.</p></div>
  </div>
  <div class="card" style="margin-top:14px"><h2>Follow-up Scores</h2><div class="score">
    <div><b>${fmtNumber(data.avgAdherence)}</b><span>Avg adherence / 10</span></div>
    <div><b>${fmtNumber(data.avgTaste)}</b><span>Avg taste / 10</span></div>
    <div><b>${fmtNumber(data.avgBudget)}</b><span>Budget difficulty / 10</span></div>
    <div><b>${fmtNumber(data.avgCooking)}</b><span>Cooking difficulty / 10</span></div>
    <div><b>${fmtNumber(data.avgEnergy)}</b><span>Energy / 10</span></div>
    <div><b>${fmtNumber(data.avgAvailability)}</b><span>Availability difficulty / 10</span></div>
    <div><b>${fmtNumber(data.avgPrep)}</b><span>Meal prep burden / 10</span></div>
    <div><b>${data.paymentMismatch}</b><span>Payment mismatch notes</span></div>
  </div></div>
  <div class="two">
    ${bars('Package Demand', topEntries(data.packageCounts))}
    ${bars('Customer Sources', topEntries(data.sourceCounts))}
    ${bars('Condition Mix', topEntries(data.conditionCounts))}
    ${bars('Outcome Trend', topEntries(data.trendCounts))}
    ${bars('Clinical Safety Status', topEntries(data.reviewStatusCounts))}
    ${bars('Plan Audit Status', topEntries(data.auditStatusCounts))}
    ${bars('Practical Recipe Barriers', topEntries(data.barrierCounts, 10), 'No meal barriers submitted yet.')}
    ${bars('Requested Substitutions', topEntries(data.substitutionCounts, 10), 'No substitutions requested yet.')}
    ${bars('Foods Causing Symptoms', topEntries(data.symptomFoodCounts, 10), 'No symptom-causing foods submitted yet.')}
    ${bars('Escalation Signals', topEntries(data.escalationCounts, 10), 'No escalation signals captured yet.')}
  </div>
  <div class="card" style="margin-top:14px"><h2>Expert Recommendations</h2><ul class="rec">${data.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>
  </div></body></html>`;
}

function exportInsightsCsv(res) {
  const data = buildInsights();
  const rows = [
    ['metric','value'],
    ['totalOrders', data.orders.length],
    ['approvedOrders', data.orders.filter(o => o.status === 'approved').length],
    ['pendingOrders', data.orders.filter(o => o.status === 'pending').length],
    ['rejectedOrders', data.orders.filter(o => o.status === 'rejected').length],
    ['followupSubmissions', data.followups.length],
    ['revenueExpected', data.revenueExpected],
    ['revenueVerified', data.revenueVerified],
    ['paymentMismatchNotes', data.paymentMismatch],
    ['clinicalEscalationSignals', data.clinicianReferral + data.redFlagOrders],
    ['avgEnergy', fmtNumber(data.avgEnergy)],
    ['avgAdherence', fmtNumber(data.avgAdherence)],
    ['avgTaste', fmtNumber(data.avgTaste)],
    ['avgBudgetDifficulty', fmtNumber(data.avgBudget)],
    ['avgCookingDifficulty', fmtNumber(data.avgCooking)],
    ['avgFoodAvailabilityDifficulty', fmtNumber(data.avgAvailability)],
    ['avgMealPrepBurden', fmtNumber(data.avgPrep)],
    ...topEntries(data.packageCounts, 20).map(([k, v]) => [`package:${k}`, v]),
    ...topEntries(data.sourceCounts, 20).map(([k, v]) => [`source:${k}`, v]),
    ...topEntries(data.conditionCounts, 30).map(([k, v]) => [`condition:${k}`, v]),
    ...topEntries(data.barrierCounts, 30).map(([k, v]) => [`barrier:${k}`, v]),
    ...topEntries(data.substitutionCounts, 30).map(([k, v]) => [`substitution:${k}`, v]),
    ...data.recommendations.map((r, i) => [`recommendation:${i + 1}`, r])
  ];
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-insights.csv"'
  });
  res.end(rows.map(row => row.map(csvEscape).join(',')).join('\n'));
}

function pushSignal(map, key, payload = {}) {
  const clean = String(key || '').trim();
  if (!clean) return;
  if (!map.has(clean)) map.set(clean, { label: clean, count: 0, orders: new Set(), examples: [], categories: new Set(), scores: [] });
  const item = map.get(clean);
  item.count += 1;
  if (payload.orderId) item.orders.add(payload.orderId);
  if (payload.category) item.categories.add(payload.category);
  if (payload.score !== undefined && payload.score !== null) item.scores.push(payload.score);
  if (payload.example && item.examples.length < 4) item.examples.push(payload.example);
}

function recipeSignalRows(map, limit = 20) {
  return Array.from(map.values())
    .map(item => ({
      label: item.label,
      count: item.count,
      customerCount: item.orders.size,
      categories: Array.from(item.categories).join(', '),
      avgScore: avg(item.scores),
      examples: item.examples.join(' | ')
    }))
    .sort((a, b) => b.count - a.count || b.customerCount - a.customerCount || a.label.localeCompare(b.label))
    .slice(0, limit);
}

function recipeSeverity(row) {
  const score = (row.count * 2) + row.customerCount + (row.avgScore !== null && row.avgScore >= 8 ? 3 : 0);
  if (score >= 10) return 'urgent';
  if (score >= 6) return 'priority';
  return 'watch';
}

function buildRecipeIntelligence(db = readDb()) {
  const items = allFollowups(db);
  const expensive = new Map();
  const hardToCook = new Map();
  const disliked = new Map();
  const substitutions = new Map();
  const symptomFoods = new Map();
  const repeated = new Map();
  const householdBarriers = new Map();
  const lowTaste = [];
  const lowAdherence = [];

  for (const { order, followup } of items) {
    const base = {
      orderId: order.id,
      example: `${order.name} (${followup.reviewPoint || 'follow-up'})`
    };
    splitSignals(followup.expensiveMeals).forEach(x => pushSignal(expensive, x, { ...base, category: 'expensive', score: toNumber(followup.budgetDifficulty) }));
    splitSignals(followup.hardToCookMeals).forEach(x => pushSignal(hardToCook, x, { ...base, category: 'hard-to-cook', score: toNumber(followup.cookingDifficulty) || toNumber(followup.mealPrepBurden) }));
    splitSignals(followup.dislikedFoods).forEach(x => pushSignal(disliked, x, { ...base, category: 'disliked', score: toNumber(followup.tasteSatisfaction) }));
    splitSignals(followup.requestedSubstitutions).forEach(x => pushSignal(substitutions, x, { ...base, category: 'substitution-request' }));
    splitSignals(followup.foodsCausingSymptoms).forEach(x => pushSignal(symptomFoods, x, { ...base, category: 'symptom-trigger' }));
    splitSignals(followup.repeatedMeals).forEach(x => pushSignal(repeated, x, { ...base, category: 'repeated' }));
    splitSignals(followup.householdSupport).forEach(x => pushSignal(householdBarriers, x, { ...base, category: 'household-barrier' }));
    const taste = toNumber(followup.tasteSatisfaction);
    const adherence = toNumber(followup.adherence);
    if (taste !== null && taste <= 6) lowTaste.push({ order, followup, taste });
    if (adherence !== null && adherence <= 6) lowAdherence.push({ order, followup, adherence });
  }

  const painRows = [
    ...recipeSignalRows(expensive, 50).map(r => ({ ...r, category: 'Too expensive' })),
    ...recipeSignalRows(hardToCook, 50).map(r => ({ ...r, category: 'Hard to cook' })),
    ...recipeSignalRows(disliked, 50).map(r => ({ ...r, category: 'Disliked' })),
    ...recipeSignalRows(symptomFoods, 50).map(r => ({ ...r, category: 'Caused symptoms' })),
    ...recipeSignalRows(substitutions, 50).map(r => ({ ...r, category: 'Requested substitution' }))
  ].sort((a, b) => {
    const sev = { urgent: 3, priority: 2, watch: 1 };
    return sev[recipeSeverity(b)] - sev[recipeSeverity(a)] || b.count - a.count || a.label.localeCompare(b.label);
  });

  const recommendations = [];
  const topSymptom = recipeSignalRows(symptomFoods, 1)[0];
  const topExpensive = recipeSignalRows(expensive, 1)[0];
  const topCook = recipeSignalRows(hardToCook, 1)[0];
  const topDisliked = recipeSignalRows(disliked, 1)[0];
  if (topSymptom) recommendations.push(`Review symptom-trigger reports first: "${topSymptom.label}" appears ${topSymptom.count} time(s). Add cautions, alternatives, or condition-specific exclusions.`);
  if (topExpensive) recommendations.push(`Create cheaper substitutions for "${topExpensive.label}" because cost is affecting practicality.`);
  if (topCook) recommendations.push(`Rewrite preparation for "${topCook.label}" into a simpler method or replace it in low-equipment plans.`);
  if (topDisliked) recommendations.push(`Improve taste profile for "${topDisliked.label}" using seasoning, texture, sauce, or a culturally preferred swap.`);
  if (lowTaste.length) recommendations.push(`${lowTaste.length} follow-up(s) report taste satisfaction of 6/10 or below. Improve recipe flavour notes and give 2 alternatives per weak meal.`);
  if (lowAdherence.length) recommendations.push(`${lowAdherence.length} follow-up(s) report adherence of 6/10 or below. Simplify the plan and reduce shopping/cooking friction.`);
  if (!recommendations.length) recommendations.push('No strong recipe pain point is visible yet. Keep collecting 7-day and 14-day follow-ups to build a stronger recipe evidence base.');

  return {
    items,
    expensive: recipeSignalRows(expensive),
    hardToCook: recipeSignalRows(hardToCook),
    disliked: recipeSignalRows(disliked),
    substitutions: recipeSignalRows(substitutions),
    symptomFoods: recipeSignalRows(symptomFoods),
    repeated: recipeSignalRows(repeated),
    householdBarriers: recipeSignalRows(householdBarriers),
    painRows: painRows.slice(0, 30),
    lowTaste,
    lowAdherence,
    avgTaste: avg(items.map(x => x.followup.tasteSatisfaction)),
    avgAdherence: avg(items.map(x => x.followup.adherence)),
    avgBudget: avg(items.map(x => x.followup.budgetDifficulty)),
    avgCooking: avg(items.map(x => x.followup.cookingDifficulty)),
    avgAvailability: avg(items.map(x => x.followup.foodAvailabilityDifficulty)),
    avgPrep: avg(items.map(x => x.followup.mealPrepBurden)),
    recommendations
  };
}

function recipeTable(title, rows, empty = 'No recipe signals captured yet.') {
  return `<div class="card"><h2>${escapeHtml(title)}</h2><table><thead><tr><th>Signal</th><th>Count</th><th>Customers</th><th>Avg score</th><th>Examples</th></tr></thead><tbody>${rows.length ? rows.map(row => `<tr><td><strong>${escapeHtml(row.label)}</strong><br><span class="tag ${recipeSeverity(row)}">${escapeHtml(recipeSeverity(row))}</span></td><td>${escapeHtml(row.count)}</td><td>${escapeHtml(row.customerCount)}</td><td>${escapeHtml(fmtNumber(row.avgScore))}</td><td>${escapeHtml(shortText(row.examples || '-', 160))}</td></tr>`).join('') : `<tr><td colspan="5" class="muted">${escapeHtml(empty)}</td></tr>`}</tbody></table></div>`;
}

function adminRecipeIntelligencePage() {
  const data = buildRecipeIntelligence();
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Recipe Intelligence</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1420px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:9px 12px;border-radius:8px;text-decoration:none;font-weight:800}.ghost{background:#ede8df;color:#2a1f14}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}.card{background:#fff;border-radius:16px;padding:18px;box-shadow:0 10px 35px #0001;overflow:auto}.metric b{display:block;font-size:24px;color:#1e3a1a}.metric span,.muted{color:#6c5b49;font-size:13px}table{width:100%;border-collapse:collapse;min-width:620px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #eee6dc;padding:10px;font-size:13px}th{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;background:#fbf8f3}.tag{display:inline-block;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:800;text-transform:uppercase;margin-top:5px}.urgent{background:#ffe1dc;color:#8a1010}.priority{background:#fff1c7;color:#8a6200}.watch{background:#e4f5dd;color:#1e3a1a}.rec li{margin:9px 0;line-height:1.45}@media(max-width:1000px){.grid,.two{grid-template-columns:1fr}}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Recipe Intelligence</h1><p>Evidence from customer follow-ups: taste, practicality, substitutions, symptoms, and meal-development priorities.</p></div><div><a class="btn ghost" href="/admin">Back to orders</a> <a class="btn ghost" href="/admin/insights">Insights</a> <a class="btn ghost" href="/admin/recipes.csv">Export recipe CSV</a></div></div>
  <div class="grid">
    <div class="card metric"><b>${data.items.length}</b><span>Follow-up records</span></div>
    <div class="card metric"><b>${fmtNumber(data.avgTaste)}</b><span>Avg taste / 10</span></div>
    <div class="card metric"><b>${fmtNumber(data.avgAdherence)}</b><span>Avg adherence / 10</span></div>
    <div class="card metric"><b>${fmtNumber(data.avgBudget)}</b><span>Budget difficulty / 10</span></div>
    <div class="card metric"><b>${fmtNumber(data.avgCooking)}</b><span>Cooking difficulty / 10</span></div>
    <div class="card metric"><b>${fmtNumber(data.avgPrep)}</b><span>Prep burden / 10</span></div>
  </div>
  <div class="card" style="margin-top:14px"><h2>Recipe Development Queue</h2><table><thead><tr><th>Priority</th><th>Issue Type</th><th>Meal/Food Signal</th><th>Count</th><th>Customers</th><th>Examples</th><th>Expert action</th></tr></thead><tbody>${data.painRows.length ? data.painRows.map(row => `<tr><td><span class="tag ${recipeSeverity(row)}">${escapeHtml(recipeSeverity(row))}</span></td><td>${escapeHtml(row.category)}</td><td><strong>${escapeHtml(row.label)}</strong></td><td>${escapeHtml(row.count)}</td><td>${escapeHtml(row.customerCount)}</td><td>${escapeHtml(shortText(row.examples || '-', 150))}</td><td>${escapeHtml(recipeSeverity(row) === 'urgent' ? 'Rewrite, substitute, or add condition-specific caution before scaling.' : recipeSeverity(row) === 'priority' ? 'Improve recipe instructions and add cheaper/tastier alternatives.' : 'Monitor and gather more follow-up evidence.')}</td></tr>`).join('') : '<tr><td colspan="7" class="muted">No recipe-development queue yet.</td></tr>'}</tbody></table></div>
  <div class="two">
    ${recipeTable('Foods or Meals Causing Symptoms', data.symptomFoods, 'No symptom-trigger foods reported yet.')}
    ${recipeTable('Too Expensive', data.expensive, 'No expensive meals reported yet.')}
    ${recipeTable('Hard to Cook', data.hardToCook, 'No hard-to-cook meals reported yet.')}
    ${recipeTable('Disliked Meals or Foods', data.disliked, 'No disliked meals reported yet.')}
    ${recipeTable('Requested Substitutions', data.substitutions, 'No substitution requests yet.')}
    ${recipeTable('Repeated Meals', data.repeated, 'No repeated meal patterns reported yet.')}
  </div>
  <div class="card" style="margin-top:14px"><h2>Expert Recipe Recommendations</h2><ul class="rec">${data.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>
  </div></body></html>`;
}

function exportRecipeIntelligenceCsv(res) {
  const data = buildRecipeIntelligence();
  const header = ['category','severity','signal','count','customerCount','avgScore','examples'];
  const rows = data.painRows.map(row => ({
    category: row.category,
    severity: recipeSeverity(row),
    signal: row.label,
    count: row.count,
    customerCount: row.customerCount,
    avgScore: fmtNumber(row.avgScore),
    examples: row.examples
  }));
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-recipe-intelligence.csv"'
  });
  res.end([header.join(','), ...rows.map(row => header.map(k => csvEscape(row[k])).join(','))].join('\n'));
}

function adminReplacementQueuePage() {
  const rows = buildRecipeReplacementQueue();
  const tableRows = rows.map(row => {
    const suggestions = row.suggestions.length
      ? row.suggestions.map(s => `<div class="suggestion"><strong>${escapeHtml(s.name)}</strong><br><small>${escapeHtml(s.meal || '')}</small><p>${escapeHtml(shortText(s.why, 140))}</p><p><b>Portion:</b> ${escapeHtml(shortText(s.portion, 140))}</p><p><b>Swap:</b> ${escapeHtml(shortText(s.smartSwap, 120))}</p></div>`).join('')
      : '<span class="muted">Needs manual review.</span>';
    return `<tr><td><strong>${escapeHtml(row.name || 'Member')}</strong><br><small>${escapeHtml(row.email)}<br>${escapeHtml(row.createdAt ? new Date(row.createdAt).toLocaleString() : '')}</small></td><td><strong>${escapeHtml(row.mealTime || 'Meal')}</strong><br>${escapeHtml(shortText(row.meal || '-', 150))}</td><td>${escapeHtml(shortText(row.issue || 'Replacement requested', 220))}</td><td>${suggestions}</td></tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Meal Replacement Queue</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#241a10;margin:0}.wrap{max-width:1380px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}.btn{display:inline-flex;background:#1e3a1a;color:#fff;text-decoration:none;border-radius:8px;padding:9px 12px;font-weight:800;margin:3px}.ghost{background:#ede8df;color:#241a10}.panel{background:#fffdf8;border:1px solid #e6dccd;border-radius:14px;overflow:auto;box-shadow:0 12px 38px #2a1f1412}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px;line-height:1.45}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#786855;background:#fbf8f3}.suggestion{background:#faf7ef;border:1px solid #e6dccd;border-radius:12px;padding:11px;margin:6px 0}.suggestion strong,h1{color:#1e3a1a}.suggestion p{margin:5px 0;color:#6d5d4b;font-size:13px}.muted,small,p{color:#6d5d4b}.metric{display:inline-block;background:#fffdf8;border:1px solid #e6dccd;border-radius:12px;padding:10px 13px;margin-top:10px}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Meal Replacement Queue</h1><p>Customer food diary complaints matched with practical replacement ideas from the Bulamu360 recipe database.</p><div class="metric"><strong>${escapeHtml(rows.length)}</strong> replacement request(s)</div></div><div><a class="btn ghost" href="/admin">Back to dashboard</a><a class="btn ghost" href="/admin/recipes">Recipe intelligence</a><a class="btn ghost" href="/admin/replacements.csv">Export CSV</a></div></div>
  <div class="panel"><table><thead><tr><th>Member</th><th>Reported meal</th><th>Issue</th><th>Suggested replacements</th></tr></thead><tbody>${tableRows || '<tr><td colspan="4" class="muted">No replacement requests yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function exportReplacementQueueCsv(res) {
  const rows = buildRecipeReplacementQueue();
  const header = ['id','createdAt','email','name','mealTime','meal','issue','suggestion1','suggestion2','suggestion3'];
  const csvRows = rows.map(row => {
    const values = {
      id: row.id,
      createdAt: row.createdAt,
      email: row.email,
      name: row.name,
      mealTime: row.mealTime,
      meal: row.meal,
      issue: row.issue,
      suggestion1: row.suggestions[0] ? `${row.suggestions[0].name} - ${row.suggestions[0].portion}` : '',
      suggestion2: row.suggestions[1] ? `${row.suggestions[1].name} - ${row.suggestions[1].portion}` : '',
      suggestion3: row.suggestions[2] ? `${row.suggestions[2].name} - ${row.suggestions[2].portion}` : ''
    };
    return header.map(k => csvEscape(values[k])).join(',');
  });
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-meal-replacement-queue.csv"'
  });
  res.end([header.join(','), ...csvRows].join('\n'));
}

function adminPlanFitPage() {
  const rows = buildPlanFitQueue();
  const tableRows = rows.map(row => `<tr><td><strong>${escapeHtml(row.name || 'Member')}</strong><br><small>${escapeHtml(row.email)}<br>${escapeHtml(row.phone || '')}</small></td><td><strong>${escapeHtml(row.packageName || 'No paid plan captured')}</strong><br><small>${escapeHtml(row.status || '')}</small></td><td><span class="tag ${escapeHtml(row.fit.cls)}">${escapeHtml(row.fit.score)}% - ${escapeHtml(row.fit.label)}</span><br><small>${escapeHtml(row.fit.diaryCount)} diary / ${escapeHtml(row.fit.progressCount)} progress / ${escapeHtml(row.fit.replacementCount)} replacements</small></td><td>${row.fit.needs.map(n => `<span>${escapeHtml(n)}</span>`).join('')}</td><td>${row.fit.strengths.map(s => `<span>${escapeHtml(s)}</span>`).join('') || '<span>No strengths captured yet.</span>'}</td></tr>`).join('');
  const priority = rows.filter(row => row.fit.score < 65).length;
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Plan Fit Scores</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#241a10;margin:0}.wrap{max-width:1380px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}.btn{display:inline-flex;background:#1e3a1a;color:#fff;text-decoration:none;border-radius:8px;padding:9px 12px;font-weight:800;margin:3px}.ghost{background:#ede8df;color:#241a10}.panel{background:#fffdf8;border:1px solid #e6dccd;border-radius:14px;overflow:auto;box-shadow:0 12px 38px #2a1f1412}table{width:100%;border-collapse:collapse;min-width:1080px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px;line-height:1.45}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#786855;background:#fbf8f3}.tag{display:inline-flex;border-radius:999px;padding:5px 10px;font-size:11px;font-weight:900;text-transform:uppercase}.approved{background:#dff3d8;color:#1e5a1a}.pending{background:#fff1c7;color:#8a6200}.rejected{background:#ffe1dc;color:#8a1010}.signals span{display:block;border-left:3px solid #d8cfbf;padding-left:8px;margin:5px 0}.muted,small,p{color:#6d5d4b}h1{color:#1e3a1a;margin:0 0 6px}.metric{display:inline-block;background:#fffdf8;border:1px solid #e6dccd;border-radius:12px;padding:10px 13px;margin-top:10px;margin-right:8px}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Plan Fit Scores</h1><p>A gentle adherence and fit view based on progress check-ins, food diary entries, symptoms, hunger, taste, cost, and replacement requests.</p><div class="metric"><strong>${escapeHtml(rows.length)}</strong> tracked member(s)</div><div class="metric"><strong>${escapeHtml(priority)}</strong> needing review</div></div><div><a class="btn ghost" href="/admin">Back to dashboard</a><a class="btn ghost" href="/admin/coach-queue">Coach queue</a><a class="btn ghost" href="/admin/plan-fit.csv">Export CSV</a></div></div>
  <div class="panel"><table><thead><tr><th>Member</th><th>Plan</th><th>Fit score</th><th>Needs</th><th>Strengths</th></tr></thead><tbody>${tableRows || '<tr><td colspan="5" class="muted">No member tracking entries yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function exportPlanFitCsv(res) {
  const rows = buildPlanFitQueue();
  const header = ['email','name','phone','packageName','status','score','label','diaryCount','progressCount','replacementCount','needs','strengths','latestAt'];
  const csvRows = rows.map(row => {
    const values = {
      email: row.email,
      name: row.name,
      phone: row.phone,
      packageName: row.packageName,
      status: row.status,
      score: row.fit.score,
      label: row.fit.label,
      diaryCount: row.fit.diaryCount,
      progressCount: row.fit.progressCount,
      replacementCount: row.fit.replacementCount,
      needs: row.fit.needs.join(' | '),
      strengths: row.fit.strengths.join(' | '),
      latestAt: row.fit.latestAt
    };
    return header.map(k => csvEscape(values[k])).join(',');
  });
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-plan-fit-scores.csv"'
  });
  res.end([header.join(','), ...csvRows].join('\n'));
}

async function handleAdminLogin(req, res) {
  if (!rateLimit(req, res, 'admin-login', { limit: 8, windowMs: 60_000 })) return;
  const form = await readForm(req);
  if (!constantTimeEqual(form.password || '', adminPassword)) return sendHtml(res, 401, adminLoginPage('Incorrect password.'));
  const sid = randomUUID();
  sessions.set(sid, { createdAt: Date.now(), expires: Date.now() + 1000 * 60 * 60 * 12 });
  const db = readDb();
  auditAdminAction(db, req, 'admin-login', { result: 'success' });
  writeDb(db);
  res.writeHead(302, securityHeaders({
    Location: '/admin',
    'Set-Cookie': adminSessionCookie(sid)
  }));
  res.end();
}

function memberLoginPage(message = '') {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bulamu360 Member Login</title>
  <style>body{margin:0;font-family:Arial,sans-serif;background:#f7f3ec;color:#241a10}.wrap{min-height:100vh;display:grid;place-items:center;padding:24px}.card{width:min(520px,100%);background:#fffdf8;border:1px solid #e6dccd;border-radius:22px;padding:30px;box-shadow:0 24px 70px #2a1f1418}.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#b85c1c;font-weight:800}h1{margin:8px 0 10px;color:#1e3a1a;font-size:34px;line-height:1.05}p{color:#6d5d4b;line-height:1.55}label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#6d5d4b;font-weight:800;margin:16px 0 6px}input{width:100%;box-sizing:border-box;border:1px solid #ddd2c2;border-radius:12px;padding:13px;font-size:15px;background:#fff}button,.btn{display:inline-flex;align-items:center;justify-content:center;border:0;background:#1e3a1a;color:#fff;border-radius:999px;padding:13px 18px;font-weight:800;cursor:pointer;text-decoration:none;margin-top:18px}.ghost{background:#ede8df;color:#241a10;margin-left:8px}.msg{background:#ffe1dc;color:#8a1010;border-left:4px solid #8a1010;padding:11px;border-radius:10px;margin:12px 0}.hint{font-size:12px;color:#6d5d4b;background:#f7f3ec;border-radius:12px;padding:12px;margin-top:14px}</style></head>
  <body><div class="wrap"><form class="card" method="post" action="/member/login"><div class="eyebrow">Bulamu360 Members</div><h1>Your Nutrition Portal</h1><p>Use the email from your assessment plus your payment reference or approval code to view plan status, saved plans, and active Advanced membership tools.</p>${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <label>Email used for your assessment</label><input type="email" name="email" required placeholder="your@email.com">
  <label>Payment reference or approval code</label><input type="text" name="code" required placeholder="MTN/Airtel reference or BUL code">
  <button type="submit">Open My Portal</button><a class="btn ghost" href="/">Back to Bulamu360</a>
  <div class="hint">If your payment is still pending, use the transaction reference you submitted. If your Advanced Nutrition Program is approved, your premium tool access stays active for 35 days, then renews monthly when you pay again.</div>
  </form></div></body></html>`;
}

function memberLevelFromPackage(packageName = '') {
  const name = String(packageName || '').toLowerCase();
  if (name.startsWith('template')) return 'free';
  if (name.includes('banquet') || name.includes('feast')) return 'advanced';
  if (name.includes('greenwell')) return 'specialist';
  if (name.includes('pantry')) return 'personal';
  if (name.includes('advanced') || name.includes('program') || name.includes('200')) return 'advanced';
  if (name.includes('specialist') || name.includes('clinical') || name.includes('120')) return 'specialist';
  if (name.includes('personal') || name.includes('household') || name.includes('family') || name.includes('70')) return 'personal';
  return 'free';
}

const ADVANCED_MEMBER_DAYS = 35; // assessment plans
const SUBSCRIPTION_DAYS = 31; // monthly subscriptions
const SUBSCRIPTIONS = {
  pantry: { name: 'Pantry subscription (monthly)', price: 75000 },
  greenwell: { name: 'Greenwell subscription (monthly)', price: 150000 },
  banquet: { name: 'Banquet subscription (monthly)', price: 250000 }
};

function memberDateLabel(value) {
  if (!value) return '';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleDateString('en-UG', { year: 'numeric', month: 'long', day: 'numeric' });
}

function memberCycleInfo(order) {
  const approvedAt = order && order.approvedAt ? Date.parse(order.approvedAt) : 0;
  if (!approvedAt) return { approvedAt: '', expiresAt: '', activeUntil: '', daysRemaining: 0, active: false };
  const expiresAtMs = approvedAt + (order && order.kind === 'subscription' ? SUBSCRIPTION_DAYS : ADVANCED_MEMBER_DAYS) * 86400000;
  const daysRemaining = Math.max(0, Math.ceil((expiresAtMs - Date.now()) / 86400000));
  return {
    approvedAt: new Date(approvedAt).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    activeUntil: memberDateLabel(expiresAtMs),
    daysRemaining,
    active: Date.now() <= expiresAtMs
  };
}

function memberSubscriptionStatus(order) {
  if (!order) return { label: 'No paid plan yet', cls: 'pending', detail: 'Complete payment verification to activate your member plan.', active: false, daysRemaining: 0 };
  if (order.status === 'pending') return { label: 'Awaiting approval', cls: 'pending', detail: 'Your payment reference is waiting for review.', active: false, daysRemaining: 0 };
  if (order.status === 'rejected') return { label: 'Needs attention', cls: 'rejected', detail: order.adminNote || 'Your payment reference was not approved.', active: false, daysRemaining: 0 };
  const cycle = memberCycleInfo(order);
  const level = memberLevelFromPackage(order.packageName);
  if (order.status === 'approved' && cycle.active) {
    const reminder = cycle.daysRemaining <= 7
      ? ` Renewal reminder: ${cycle.daysRemaining} day(s) left. Renew before expiry to keep premium tools open.`
      : '';
    const planLabel = level === 'advanced' ? 'Advanced access' : 'Plan access';
    return {
      label: 'Active',
      cls: 'approved',
      detail: `${planLabel} is active until ${cycle.activeUntil}.${reminder}`,
      active: true,
      activeUntil: cycle.activeUntil,
      expiresAt: cycle.expiresAt,
      daysRemaining: cycle.daysRemaining,
      renewalReminder: reminder.trim()
    };
  }
  if (order.status === 'approved') {
    const ended = cycle.activeUntil ? ` Your last access ended on ${cycle.activeUntil}.` : '';
    return {
      label: 'Renewal due',
      cls: 'pending',
      detail: `${ended} Renew Advanced monthly for premium tools, updated guidance, and follow-up support.`.trim(),
      active: false,
      activeUntil: cycle.activeUntil,
      expiresAt: cycle.expiresAt,
      daysRemaining: 0,
      renewalReminder: 'Renew your Advanced membership to reopen premium tools.'
    };
  }
  return { label: order.status || 'Unknown', cls: 'pending', detail: 'Status is being reviewed.', active: false, daysRemaining: 0 };
}

function memberAccessStatus(req) {
  const session = getMemberSession(req);
  if (!session) {
    const adb = readDb(), acct = currentAccount(req, adb);
    if (acct) {
      const p = accountPlan(adb, acct);
      return { ok: true, loggedIn: true, active: p.level !== 'free', email: acct.email, name: acct.name, level: p.level, tier: p.tier, packageName: p.packageName,
        statusLabel: p.level !== 'free' ? 'Active' : 'Free account', detail: p.level !== 'free' ? `${p.tier} package is active until ${p.activeUntil}.` : 'Choose Pantry, Greenwell or Banquet to unlock more tools.',
        activeUntil: p.activeUntil, daysRemaining: p.daysRemaining, renewalReminder: '', renewalDue: false, templates: p.templates, allTemplates: p.allTemplates, templateZip: p.templateZip };
    }
    return {
      ok: true,
      loggedIn: false,
      active: false,
      level: 'free',
      statusLabel: 'Not logged in',
      detail: 'Sign in to your Bulamu360 account to unlock paid tools.'
    };
  }
  const db = readDb();
  const email = String(session.email || '').toLowerCase();
  const approvedOrders = db.orders
    .filter(o => String(o.email || '').toLowerCase() === email && o.status === 'approved')
    .sort((a, b) => String(b.approvedAt || b.createdAt || '').localeCompare(String(a.approvedAt || a.createdAt || '')));
  const activeOrder = approvedOrders.find(o => memberSubscriptionStatus(o).active) || null;
  const latest = activeOrder || latestMemberOrder(db, email);
  const sub = memberSubscriptionStatus(latest);
  return {
    ok: true,
    loggedIn: true,
    active: Boolean(activeOrder),
    email,
    name: session.name || latest?.name || '',
    level: activeOrder ? memberLevelFromPackage(activeOrder.packageName) : 'free',
    packageName: activeOrder?.packageName || latest?.packageName || '',
    orderId: activeOrder?.id || latest?.id || '',
    statusLabel: activeOrder ? 'Active' : sub.label,
    detail: activeOrder ? memberSubscriptionStatus(activeOrder).detail : sub.detail,
    approvedAt: activeOrder?.approvedAt || '',
    activeUntil: sub.activeUntil || '',
    expiresAt: sub.expiresAt || '',
    daysRemaining: sub.daysRemaining || 0,
    renewalReminder: sub.renewalReminder || '',
    renewalDue: sub.label === 'Renewal due'
  };
}

function latestMemberOrder(db, email) {
  return db.orders
    .filter(o => String(o.email || '').toLowerCase() === String(email || '').toLowerCase())
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))[0] || null;
}

function toShortFormText(value, max = 700) {
  return shortText(String(value || '').trim(), max);
}

async function handleMemberProgress(req, res, session) {
  const form = await readForm(req);
  const db = readDb();
  const email = String(session.email || '').toLowerCase();
  const order = latestMemberOrder(db, email);
  const entry = {
    id: `mp_${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`,
    createdAt: new Date().toISOString(),
    email,
    name: session.name || (order && order.name) || '',
    orderId: order ? order.id : '',
    weight: toShortFormText(form.weight, 40),
    waist: toShortFormText(form.waist, 40),
    bloodPressure: toShortFormText(form.bloodPressure, 80),
    bloodSugar: toShortFormText(form.bloodSugar, 80),
    hunger: toShortFormText(form.hunger, 40),
    mood: toShortFormText(form.mood, 40),
    energy: toShortFormText(form.energy, 40),
    sleep: toShortFormText(form.sleep, 40),
    cravings: toShortFormText(form.cravings, 140),
    bowelHabits: toShortFormText(form.bowelHabits, 140),
    symptoms: toShortFormText(form.symptoms, 240),
    cyclePregnancyNotes: toShortFormText(form.cyclePregnancyNotes, 240),
    notes: toShortFormText(form.notes, 500)
  };
  db.progressEntries.unshift(entry);
  db.progressEntries = db.progressEntries.slice(0, 5000);
  writeDb(db);
  redirect(res, '/member?saved=progress');
}

async function handleMemberFoodDiary(req, res, session) {
  const form = await readForm(req);
  const db = readDb();
  const email = String(session.email || '').toLowerCase();
  const order = latestMemberOrder(db, email);
  const entry = {
    id: `fd_${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`,
    createdAt: new Date().toISOString(),
    email,
    name: session.name || (order && order.name) || '',
    orderId: order ? order.id : '',
    mealTime: toShortFormText(form.mealTime, 40),
    meal: toShortFormText(form.meal, 500),
    portion: toShortFormText(form.portion, 240),
    hungerBefore: toShortFormText(form.hungerBefore, 40),
    fullnessAfter: toShortFormText(form.fullnessAfter, 40),
    taste: toShortFormText(form.taste, 40),
    cost: toShortFormText(form.cost, 40),
    symptomsAfter: toShortFormText(form.symptomsAfter, 240),
    dislikedRepeated: toShortFormText(form.dislikedRepeated, 240),
    replacementRequest: toShortFormText(form.replacementRequest, 240)
  };
  db.foodDiary.unshift(entry);
  db.foodDiary = db.foodDiary.slice(0, 8000);
  writeDb(db);
  redirect(res, '/member?saved=food');
}

function memberProfilePayload(db, email) {
  const clean = String(email || '').toLowerCase();
  const order = latestMemberOrder(db, clean);
  const lead = (db.leads || []).find(l => String(l.email || '').toLowerCase() === clean);
  const profile = lead && lead.profile && typeof lead.profile === 'object' ? lead.profile : {};
  const cs = order && order.clinicalSummary ? order.clinicalSummary : {};
  return {
    ...profile,
    name: order?.name || lead?.name || profile.name || '',
    email: clean,
    goal: order?.goal || profile.goal || cs.goal || '',
    plantype: order?.planType || profile.plantype || '',
    packageName: order?.packageName || profile.packageName || '',
    conds: Array.isArray(profile.conds) ? profile.conds : (Array.isArray(cs.conditions) ? cs.conditions : []),
    diagnosis: order?.diagnosis || profile.diagnosis || cs.diagnosis || '',
    allergies: order?.allergies || profile.allergies || cs.allergies || '',
    symptoms: order?.symptoms || profile.symptoms || cs.symptoms || '',
    foodDislikes: order?.foodDislikes || profile.foodDislikes || '',
    notes: [profile.notes, profile.foodDislikes, order?.foodDislikes].filter(Boolean).join(', '),
    budget: profile.budget || order?.budget || '',
    cooking: profile.cooking || order?.cooking || ''
  };
}

function diaryNeedsReplacement(entry = {}) {
  const text = [
    entry.replacementRequest,
    entry.taste,
    entry.cost,
    entry.symptomsAfter,
    entry.dislikedRepeated
  ].join(' ').toLowerCase();
  return /\byes\b|not tasty|expensive|hard|symptom|bloat|reflux|nausea|headache|diarrh|dislike|boring|repeat|unrealistic/.test(text);
}

function replacementProblemTerms(entry = {}) {
  const raw = [
    entry.meal,
    entry.dislikedRepeated,
    entry.symptomsAfter,
    entry.replacementRequest
  ].join(' ').toLowerCase();
  const known = [
    'egg', 'eggs', 'smoothie', 'milk', 'yogurt', 'beans', 'cowpeas', 'lentils', 'fish', 'tilapia',
    'mukene', 'chicken', 'groundnut', 'peanut', 'matooke', 'posho', 'rice', 'sweet potato',
    'cabbage', 'avocado', 'salad', 'soup', 'oats', 'porridge'
  ];
  return known.filter(term => raw.includes(term));
}

function replacementMealType(entry = {}) {
  const meal = String(entry.mealTime || '').toLowerCase();
  if (meal.includes('break')) return 'breakfast';
  if (meal.includes('lunch')) return 'lunch';
  if (meal.includes('dinner')) return 'dinner';
  if (meal.includes('snack') || meal.includes('drink')) return 'snack';
  return '';
}

function recipeReplacementCandidates(entry = {}, profilePayload = {}, limit = 3) {
  const meal = replacementMealType(entry);
  const profile = profileFromRecipeRequest({
    ...profilePayload,
    allergies: [profilePayload.allergies, profilePayload.foodDislikes, replacementProblemTerms(entry).join(', ')].filter(Boolean).join(', ')
  });
  const problemTerms = replacementProblemTerms(entry);
  const replacementReason = String(entry.replacementRequest || '').toLowerCase();
  const allRecipes = loadPrivateRecipes().recipes || [];
  const candidates = allRecipes
    .filter(recipe => (!meal || recipe.meal === meal) && privateRecipeAllowed(recipe, profile))
    .filter(recipe => !problemTerms.some(term => recipeText(recipe).includes(term)))
    .filter(recipe => {
      if ((meal === 'lunch' || meal === 'dinner') && isSmoothieLike(recipe)) return false;
      if (replacementReason.includes('hard') && Number(recipe.time || 99) > 25) return false;
      if (replacementReason.includes('expensive') && !['Low', 'Medium'].includes(String(recipe.cost || ''))) return false;
      return true;
    })
    .sort((a, b) => {
      const aScore = privateRecipeScore(a, profile) + recipeCulinaryBoost(a) + mealRealismScore(a, meal || a.meal);
      const bScore = privateRecipeScore(b, profile) + recipeCulinaryBoost(b) + mealRealismScore(b, meal || b.meal);
      return bScore - aScore || String(a.name).localeCompare(String(b.name));
    });
  return candidates.slice(0, limit).map(recipe => ({
    name: recipe.name || 'Alternative meal',
    meal: recipe.meal || meal || '',
    portion: recipe.portion || 'Use a balanced plate: measured starch, palm-size protein, and plenty of vegetables.',
    ingredients: Array.isArray(recipe.ingredients) ? recipe.ingredients.slice(0, 8) : [],
    method: shortText(recipe.method || 'Prepare simply with familiar ingredients and minimal oil, sugar, and salt.', 260),
    smartSwap: Array.isArray(recipe.substitutions) && recipe.substitutions.length ? recipe.substitutions[0] : 'Use a similar local staple, protein, or vegetable that fits your budget and tolerance.',
    why: replacementReason.includes('expensive') ? 'Suggested because it is more budget-friendly.' :
      replacementReason.includes('hard') ? 'Suggested because it should be easier to prepare.' :
      String(entry.symptomsAfter || '').trim() ? 'Suggested as a gentler alternative to review for tolerance.' :
      'Suggested to improve taste, variety, and real-life fit.'
  }));
}

function memberReplacementRows(db, email, limit = 6) {
  const clean = String(email || '').toLowerCase();
  const profile = memberProfilePayload(db, clean);
  return (db.foodDiary || [])
    .filter(entry => String(entry.email || '').toLowerCase() === clean && diaryNeedsReplacement(entry))
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
    .slice(0, limit)
    .map(entry => ({ entry, suggestions: recipeReplacementCandidates(entry, profile, 3) }));
}

function buildRecipeReplacementQueue(db = readDb()) {
  const rows = [];
  for (const entry of (db.foodDiary || [])) {
    if (!diaryNeedsReplacement(entry)) continue;
    const profile = memberProfilePayload(db, entry.email);
    const suggestions = recipeReplacementCandidates(entry, profile, 3);
    rows.push({
      id: entry.id,
      createdAt: entry.createdAt || '',
      email: String(entry.email || '').toLowerCase(),
      name: entry.name || profile.name || '',
      mealTime: entry.mealTime || '',
      meal: entry.meal || '',
      issue: [entry.replacementRequest, entry.dislikedRepeated, entry.symptomsAfter, entry.cost, entry.taste].filter(Boolean).join(' | '),
      suggestions
    });
  }
  return rows.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
}

function buildPlanFitScore(db, email) {
  const clean = String(email || '').toLowerCase();
  const progress = (db.progressEntries || [])
    .filter(x => String(x.email || '').toLowerCase() === clean)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
    .slice(0, 10);
  const diary = (db.foodDiary || [])
    .filter(x => String(x.email || '').toLowerCase() === clean)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
    .slice(0, 20);
  let score = 72;
  const strengths = [];
  const needs = [];
  const severeTerms = /chest pain|faint|fainting|blood in stool|severe|swelling|vomit|rapid weight loss/i;
  const symptomTerms = /bloat|reflux|nausea|headache|sleepy|pain|diarrhoea|diarrhea|vomit/i;
  const expensiveCount = diary.filter(d => /expensive/i.test(d.cost || '')).length;
  const notTastyCount = diary.filter(d => /not tasty/i.test(d.taste || '')).length;
  const goodTasteCount = diary.filter(d => /delicious|good/i.test(d.taste || '')).length;
  const replacementCount = diary.filter(diaryNeedsReplacement).length;
  const symptomMeals = diary.filter(d => symptomTerms.test(d.symptomsAfter || '')).length;
  const highHunger = progress.filter(p => /high|very high/i.test(p.hunger || '')).length;
  const lowEnergy = progress.filter(p => /low/i.test(p.energy || '')).length;
  const poorSleep = progress.filter(p => /poor/i.test(p.sleep || '')).length;
  const symptoms = progress.filter(p => String(p.symptoms || '').trim()).length;
  const severe = progress.some(p => severeTerms.test(p.symptoms || '')) || diary.some(d => severeTerms.test(d.symptomsAfter || ''));

  score += Math.min(10, diary.length * 1.2);
  score += Math.min(8, progress.length * 1.5);
  score += Math.min(10, goodTasteCount * 2);
  score -= expensiveCount * 4;
  score -= notTastyCount * 5;
  score -= replacementCount * 4;
  score -= symptomMeals * 6;
  score -= highHunger * 4;
  score -= lowEnergy * 4;
  score -= poorSleep * 2;
  score -= symptoms * 2;
  if (severe) score = Math.min(score, 35);
  score = Math.max(0, Math.min(100, Math.round(score)));

  if (diary.length) strengths.push(`${diary.length} food diary entr${diary.length === 1 ? 'y' : 'ies'} captured.`);
  if (progress.length) strengths.push(`${progress.length} progress check-in${progress.length === 1 ? '' : 's'} captured.`);
  if (goodTasteCount) strengths.push(`${goodTasteCount} meal${goodTasteCount === 1 ? '' : 's'} reported as good or delicious.`);
  if (!diary.length && !progress.length) needs.push('Start logging meals or progress so Bulamu can understand fit better.');
  if (replacementCount) needs.push('Some meals may need replacement for taste, cost, symptoms, or practicality.');
  if (expensiveCount) needs.push('Cost may be affecting adherence. Consider lower-budget swaps.');
  if (notTastyCount) needs.push('Taste needs attention so the plan feels easier to follow.');
  if (symptomMeals || symptoms) needs.push('Symptoms were reported. Review patterns and seek medical care if severe or worsening.');
  if (highHunger) needs.push('Hunger is high. Portions, protein, fibre, or meal timing may need adjustment.');
  if (lowEnergy) needs.push('Energy is low. Review calories, iron-rich foods, hydration, sleep, and medical factors.');
  if (severe) needs.unshift('Red-flag symptoms may need urgent medical care.');
  if (!needs.length) needs.push('Keep tracking. The plan currently looks workable from the available entries.');

  const label = score >= 82 ? 'Strong fit' : score >= 65 ? 'Good fit, keep adjusting' : score >= 45 ? 'Needs review' : 'Priority review';
  const cls = score >= 82 ? 'approved' : score >= 65 ? 'pending' : 'rejected';
  return {
    score,
    label,
    cls,
    strengths: strengths.slice(0, 4),
    needs: needs.slice(0, 5),
    diaryCount: diary.length,
    progressCount: progress.length,
    replacementCount,
    latestAt: [progress[0]?.createdAt, diary[0]?.createdAt].filter(Boolean).sort().pop() || ''
  };
}

function buildPlanFitQueue(db = readDb()) {
  const emails = new Set();
  (db.orders || []).forEach(o => { if (o.email) emails.add(String(o.email).toLowerCase()); });
  (db.leads || []).forEach(l => { if (l.email) emails.add(String(l.email).toLowerCase()); });
  (db.progressEntries || []).forEach(p => { if (p.email) emails.add(String(p.email).toLowerCase()); });
  (db.foodDiary || []).forEach(d => { if (d.email) emails.add(String(d.email).toLowerCase()); });
  return Array.from(emails).map(email => {
    const latest = latestMemberOrder(db, email);
    const lead = (db.leads || []).find(l => String(l.email || '').toLowerCase() === email);
    return {
      email,
      name: latest?.name || lead?.name || '',
      phone: latest?.phone || lead?.phone || '',
      packageName: latest?.packageName || '',
      status: latest?.status || 'lead',
      fit: buildPlanFitScore(db, email)
    };
  }).filter(row => row.fit.diaryCount || row.fit.progressCount)
    .sort((a, b) => a.fit.score - b.fit.score || String(b.fit.latestAt || '').localeCompare(String(a.fit.latestAt || '')));
}

function memberDashboardPage(req, session) {
  const db = readDb();
  const email = String(session.email || '').toLowerCase();
  const orders = db.orders
    .filter(o => String(o.email || '').toLowerCase() === email)
    .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  const lead = (db.leads || []).find(l => String(l.email || '').toLowerCase() === email);
  const latest = orders[0] || null;
  const activeOrder = orders.find(o => o.status === 'approved' && memberSubscriptionStatus(o).active) || null;
  const advancedOrder = orders.find(o => memberLevelFromPackage(o.packageName) === 'advanced') || null;
  const statusOrder = activeOrder || advancedOrder || latest;
  const sub = memberSubscriptionStatus(statusOrder);
  const renewalNotice = sub.renewalReminder
    ? `<div class="saved" style="background:#fff1c7;color:#765100;border-left-color:#b98900">${escapeHtml(sub.renewalReminder)}</div>`
    : '';
  const saved = new URL(req.url || '/', `http://${req.headers.host}`).searchParams.get('saved') || '';
  const progress = (db.progressEntries || []).filter(x => String(x.email || '').toLowerCase() === email).slice(0, 8);
  const diary = (db.foodDiary || []).filter(x => String(x.email || '').toLowerCase() === email).slice(0, 8);
  const replacements = memberReplacementRows(db, email, 5);
  const fit = buildPlanFitScore(db, email);
  const rows = orders.map(o => {
    const status = memberSubscriptionStatus(o);
    const approvedLinks = o.status === 'approved'
      ? `<a class="btn" href="/plan/${escapeHtml(o.downloadToken)}" target="_blank">Open plan</a>${o.followupToken ? ` <a class="btn ghost" href="/followup/${escapeHtml(o.followupToken)}" target="_blank">Submit progress</a>` : ''}`
      : '<span class="muted">Available after approval</span>';
    return `<tr><td><strong>${escapeHtml(o.packageName || 'Nutrition plan')}</strong><br><small>${escapeHtml(o.amount || '')}</small></td><td><span class="badge ${escapeHtml(status.cls)}">${escapeHtml(status.label)}</span><br><small>${escapeHtml(status.detail)}</small></td><td><small>${escapeHtml(new Date(o.createdAt || Date.now()).toLocaleString())}</small><br><small>Reference: ${escapeHtml(o.txRef || '')}</small></td><td>${approvedLinks}</td></tr>`;
  }).join('');
  const progressRows = progress.map(p => `<tr><td><strong>${escapeHtml(new Date(p.createdAt).toLocaleDateString())}</strong><br><small>${escapeHtml(new Date(p.createdAt).toLocaleTimeString())}</small></td><td>${escapeHtml(p.weight || '-')} kg<br><small>Waist: ${escapeHtml(p.waist || '-')}</small></td><td>${escapeHtml(p.energy || '-')}<br><small>Mood: ${escapeHtml(p.mood || '-')} | Sleep: ${escapeHtml(p.sleep || '-')}</small></td><td>${escapeHtml(shortText([p.symptoms, p.notes].filter(Boolean).join(' | '), 160) || '-')}</td></tr>`).join('');
  const diaryRows = diary.map(d => `<tr><td><strong>${escapeHtml(d.mealTime || 'Meal')}</strong><br><small>${escapeHtml(new Date(d.createdAt).toLocaleDateString())}</small></td><td>${escapeHtml(shortText(d.meal || '-', 120))}<br><small>Portion: ${escapeHtml(shortText(d.portion || '-', 80))}</small></td><td>${escapeHtml(d.taste || '-')}<br><small>Cost: ${escapeHtml(d.cost || '-')}</small></td><td>${escapeHtml(shortText([d.symptomsAfter, d.replacementRequest].filter(Boolean).join(' | '), 150) || '-')}</td></tr>`).join('');
  const replacementHtml = replacements.map(({ entry, suggestions }) => `<div class="swap-card"><h3>${escapeHtml(entry.mealTime || 'Meal')} replacement ideas</h3><p><strong>Reported meal:</strong> ${escapeHtml(shortText(entry.meal || '-', 140))}</p><p><strong>Reason:</strong> ${escapeHtml(shortText([entry.replacementRequest, entry.dislikedRepeated, entry.symptomsAfter].filter(Boolean).join(' | ') || 'Requested meal support', 180))}</p><div class="swap-grid">${suggestions.length ? suggestions.map(s => `<article><strong>${escapeHtml(s.name)}</strong><small>${escapeHtml(s.meal || '')}</small><p>${escapeHtml(s.why)}</p><p><b>Portion:</b> ${escapeHtml(shortText(s.portion, 160))}</p><p><b>Smart swap:</b> ${escapeHtml(shortText(s.smartSwap, 140))}</p></article>`).join('') : '<p class="muted">Breyer will review this meal and suggest a personalised replacement.</p>'}</div></div>`).join('');
  const savedMessage = saved === 'progress' ? '<div class="saved">Progress check-in saved.</div>' : saved === 'food' ? '<div class="saved">Food diary entry saved.</div>' : '';
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bulamu360 Member Portal</title>
  <style>body{margin:0;font-family:Arial,sans-serif;background:#f7f3ec;color:#241a10}.wrap{max-width:1180px;margin:0 auto;padding:26px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:18px}.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#b85c1c;font-weight:800}h1{margin:6px 0;color:#1e3a1a;font-size:34px}h2{color:#1e3a1a;margin:0 0 8px}h3{color:#1e3a1a;margin:0 0 8px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}.card{background:#fffdf8;border:1px solid #e6dccd;border-radius:18px;padding:18px;box-shadow:0 16px 45px #2a1f1410}.card b{display:block;color:#1e3a1a;font-size:25px;margin-top:5px}.muted,small,p{color:#6d5d4b;line-height:1.5}.panel{background:#fffdf8;border:1px solid #e6dccd;border-radius:18px;overflow:auto;box-shadow:0 16px 45px #2a1f1410;margin-top:14px}table{width:100%;border-collapse:collapse;min-width:860px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#786855;background:#fbf8f3}.badge{display:inline-flex;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800}.approved{background:#dff3d8;color:#1e5a1a}.pending{background:#fff1c7;color:#8a6200}.rejected{background:#ffe1dc;color:#8a1010}.btn{display:inline-flex;align-items:center;justify-content:center;background:#1e3a1a;color:#fff;text-decoration:none;border-radius:999px;padding:9px 12px;font-weight:800;font-size:12px;margin:3px;border:0;cursor:pointer}.ghost{background:#ede8df;color:#241a10}.forms{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px}.form-grid,.swap-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#786855;font-weight:800;margin:9px 0 5px}input,select,textarea{width:100%;box-sizing:border-box;border:1px solid #ddd2c2;border-radius:10px;padding:10px;font:14px Arial,sans-serif;background:#fff}textarea{min-height:78px}.saved{background:#e4f5dd;color:#1e5a1a;border-left:4px solid #1e5a1a;border-radius:10px;padding:11px 13px;margin:10px 0;font-weight:800}.locked{opacity:.62}.fit-list{margin:8px 0 0;padding-left:18px;color:#6d5d4b;font-size:13px;line-height:1.45}.swap-card{background:#fffdf8;border:1px solid #e6dccd;border-radius:18px;padding:16px;margin-top:12px;box-shadow:0 16px 45px #2a1f1410}.swap-card article{background:#faf7ef;border:1px solid #e6dccd;border-radius:14px;padding:13px}.swap-card article strong{display:block;color:#1e3a1a}.swap-card article small{display:block;margin:4px 0 7px;text-transform:uppercase;letter-spacing:.08em;font-size:10px}.swap-card article p{font-size:13px;margin:7px 0}@media(max-width:950px){.top{display:block}.grid,.forms,.form-grid,.swap-grid{grid-template-columns:1fr}.wrap{padding:16px}}</style></head>
  <body><div class="wrap"><div class="top"><div><div class="eyebrow">Bulamu360 Member Portal</div><h1>Hello ${escapeHtml(session.name || latest?.name || lead?.name || 'there')}</h1><p>View your plan status, saved approved plans, progress timeline, food diary, and member tools.</p></div><div><a class="btn ghost" href="/">Main app</a><a class="btn" href="/#pricing">Subscribe / Renew Membership</a><a class="btn ghost" href="/member/logout">Logout</a></div></div>${savedMessage}${renewalNotice}
  <section class="grid"><div class="card"><span class="muted">Membership status</span><b>${escapeHtml(sub.label)}</b><p>${escapeHtml(sub.detail)}</p>${sub.activeUntil ? `<a class="btn" href="/#pricing">Renew Membership</a>` : `<a class="btn" href="/#pricing">Subscribe / Renew Membership</a>`}</div><div class="card"><span class="muted">Advanced access</span><b>${escapeHtml(sub.activeUntil ? `Until ${sub.activeUntil}` : 'Not active')}</b><p>${escapeHtml(sub.daysRemaining ? `${sub.daysRemaining} day(s) remaining.` : 'Choose Advanced to open premium member tools.')}</p></div><div class="card"><span class="muted">Plan fit score</span><b>${escapeHtml(fit.score)}%</b><p><span class="badge ${escapeHtml(fit.cls)}">${escapeHtml(fit.label)}</span></p><ul class="fit-list">${fit.needs.slice(0,2).map(n => `<li>${escapeHtml(n)}</li>`).join('')}</ul></div><div class="card"><span class="muted">Latest request</span><b>${escapeHtml(latest ? latest.status : 'Lead only')}</b><p>${escapeHtml(latest ? latest.packageName : 'Free assessment captured. Choose a plan when ready.')}</p></div></section>
  <section class="panel"><table><thead><tr><th>Plan</th><th>Status</th><th>Date and reference</th><th>Access</th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="muted">No paid plan requests yet. Your free assessment details have been captured.</td></tr>'}</tbody></table></section>
  <section class="forms">
    <form class="card" method="post" action="/member/progress"><h2>Progress Check-in</h2><p>Track real changes gently. This helps Breyer understand what is working, what feels hard, and what needs review.</p><div class="form-grid"><div><label>Weight kg</label><input name="weight" placeholder="e.g. 74"></div><div><label>Waist cm</label><input name="waist" placeholder="e.g. 88"></div><div><label>Blood pressure</label><input name="bloodPressure" placeholder="e.g. 128/82"></div><div><label>Blood sugar</label><input name="bloodSugar" placeholder="e.g. fasting 6.1"></div><div><label>Hunger</label><select name="hunger"><option></option><option>Low</option><option>Comfortable</option><option>High</option><option>Very high</option></select></div><div><label>Energy</label><select name="energy"><option></option><option>Low</option><option>Improving</option><option>Good</option><option>Very good</option></select></div><div><label>Mood</label><select name="mood"><option></option><option>Low</option><option>Stressed</option><option>Stable</option><option>Good</option></select></div><div><label>Sleep</label><select name="sleep"><option></option><option>Poor</option><option>Fair</option><option>Good</option><option>Excellent</option></select></div></div><label>Cravings</label><input name="cravings" placeholder="e.g. sugar in the evening"><label>Bowel habits</label><input name="bowelHabits" placeholder="e.g. constipation, normal, diarrhoea"><label>Symptoms</label><textarea name="symptoms" placeholder="Headaches, reflux, bloating, dizziness, swelling, nausea..."></textarea><label>Cycle or pregnancy notes</label><textarea name="cyclePregnancyNotes" placeholder="Optional: period symptoms, pregnancy changes, breastfeeding, cravings..."></textarea><label>Notes for Breyer</label><textarea name="notes" placeholder="What changed this week? What feels difficult?"></textarea><button class="btn" type="submit">Save Progress</button></form>
    <form class="card" method="post" action="/member/food-diary"><h2>Food Diary</h2><p>Log meals in a practical way: what you ate, portion, taste, cost, symptoms, and what you want changed.</p><div class="form-grid"><div><label>Meal time</label><select name="mealTime"><option>Breakfast</option><option>Snack</option><option>Lunch</option><option>Dinner</option><option>Drink</option></select></div><div><label>Taste</label><select name="taste"><option></option><option>Delicious</option><option>Good</option><option>Okay</option><option>Not tasty</option></select></div><div><label>Hunger before</label><select name="hungerBefore"><option></option><option>Not hungry</option><option>Comfortable</option><option>Hungry</option><option>Very hungry</option></select></div><div><label>Fullness after</label><select name="fullnessAfter"><option></option><option>Still hungry</option><option>Satisfied</option><option>Too full</option></select></div><div><label>Cost</label><select name="cost"><option></option><option>Affordable</option><option>Manageable</option><option>Expensive</option></select></div><div><label>Need replacement?</label><select name="replacementRequest"><option></option><option>No</option><option>Yes, dislike this meal</option><option>Yes, too expensive</option><option>Yes, hard to cook</option><option>Yes, caused symptoms</option></select></div></div><label>Meal eaten</label><textarea name="meal" placeholder="e.g. matooke, beans, dodo, avocado"></textarea><label>Portion</label><input name="portion" placeholder="e.g. 1 fist matooke, 1 cup beans, 2 cups greens"><label>Symptoms after eating</label><textarea name="symptomsAfter" placeholder="Bloating, reflux, nausea, headache, sleepiness, none..."></textarea><label>Disliked or repeated meals</label><textarea name="dislikedRepeated" placeholder="Any food that felt boring, repeated, unrealistic, or unpleasant?"></textarea><button class="btn" type="submit">Save Meal</button></form>
  </section>
  <section class="panel"><table><thead><tr><th>Date</th><th>Body measures</th><th>Energy and mood</th><th>Symptoms / notes</th></tr></thead><tbody>${progressRows || '<tr><td colspan="4" class="muted">No progress check-ins yet.</td></tr>'}</tbody></table></section>
  <section class="panel"><table><thead><tr><th>Meal</th><th>Food and portion</th><th>Taste and cost</th><th>Symptoms / replacement</th></tr></thead><tbody>${diaryRows || '<tr><td colspan="4" class="muted">No food diary entries yet.</td></tr>'}</tbody></table></section>
  <section style="margin-top:16px"><div class="card"><h2>Meal Replacement Ideas</h2><p>When you report a meal as not tasty, repeated, expensive, hard to cook, or symptom-triggering, Bulamu suggests practical alternatives for Breyer to review with you.</p></div>${replacementHtml || '<div class="card" style="margin-top:12px"><p>No replacement requests yet. Add a food diary entry when a meal feels unrealistic, repetitive, expensive, or uncomfortable.</p></div>'}</section>
  <section class="card" style="margin-top:16px"><h2>Member tools</h2><p><strong>Ask Bulamu Coach</strong>, meal replacement support, progress tracking, and diary review are connected to your active member status.</p></section>
  </div></body></html>`;
}

async function handleMemberLogin(req, res) {
  if (!rateLimit(req, res, 'member-login', { limit: 12, windowMs: 60_000 })) return;
  const form = await readForm(req);
  const email = String(form.email || '').trim().toLowerCase();
  const code = String(form.code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  const db = readDb();
  const orders = db.orders.filter(o => String(o.email || '').toLowerCase() === email);
  const order = orders.find(o => {
    const approval = String(o.approvalCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const tx = String(o.txRef || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    return (approval && approval === code) || (tx && tx === code);
  });
  if (!order) return sendHtml(res, 401, memberLoginPage('No matching order was found for that email and code/reference.'));
  const sid = randomBytes(24).toString('hex');
  sessions.set(`member:${sid}`, {
    type: 'member',
    email,
    name: order.name || '',
    createdAt: Date.now(),
    expires: Date.now() + 1000 * 60 * 60 * 24 * 30
  });
  res.writeHead(302, securityHeaders({
    Location: '/member',
    'Set-Cookie': memberSessionCookie(sid)
  }));
  res.end();
}

function findOrder(db, id) {
  return db.orders.find(o => o.id === id);
}

function deleteOrderPage(order) {
  if (!order) return '<p>Order not found.</p>';
  return `<!doctype html><html><head><meta charset="utf-8"><title>Delete Order - Bulamu360</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:760px;margin:0 auto;padding:28px}.card{background:#fff;border:1px solid #e6dccd;border-radius:14px;padding:22px;box-shadow:0 10px 34px #2a1f1412}.warn{background:#ffe1dc;border-left:4px solid #8a1010;border-radius:10px;padding:12px 14px;margin:14px 0;color:#651010;line-height:1.55}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:14px 0}.box{background:#faf7f1;border:1px solid #e6dccd;border-radius:10px;padding:11px}.box strong{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#7a3c10;margin-bottom:4px}textarea{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:12px;font:14px Arial,sans-serif;min-height:92px;background:#fffdf9}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.btn{display:inline-flex;align-items:center;justify-content:center;border:0;background:#1e3a1a;color:#fff;padding:11px 14px;border-radius:9px;text-decoration:none;font-weight:800;cursor:pointer}.ghost{background:#ede8df;color:#2a1f14}.danger{background:#8a1010;color:#fff}
  </style></head><body><div class="wrap"><div class="card">
    <h1>Delete order?</h1>
    <div class="warn"><strong>This permanently removes the order from the admin dashboard.</strong><br>The customer approval link and admin access for this order will stop working after deletion. Use this for test orders, duplicates, mistakes, or records you no longer need.</div>
    <div class="grid">
      <div class="box"><strong>Customer</strong>${escapeHtml(order.name || '')}<br>${escapeHtml(order.email || '')}</div>
      <div class="box"><strong>Plan</strong>${escapeHtml(order.packageName || '')}<br>${escapeHtml(order.amount || '')}</div>
      <div class="box"><strong>Status</strong>${escapeHtml(order.status || '')}</div>
      <div class="box"><strong>Reference</strong>${escapeHtml(order.txRef || '')}</div>
    </div>
    <form method="post" action="/admin/orders/${escapeHtml(order.id)}/delete">
      <label><strong>Reason for deleting</strong></label>
      <textarea name="deleteReason" placeholder="Example: test order, duplicate, wrong customer details, cleanup after export"></textarea>
      <div class="actions">
        <button class="btn danger">Yes, delete this order</button>
        <a class="btn ghost" href="/admin">Cancel</a>
        <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/plan" target="_blank">View plan first</a>
      </div>
    </form>
  </div></div></body></html>`;
}

function removeSectionsByTitles(html = '', titles = []) {
  let output = String(html || '');
  for (const title of titles) {
    let titleIndex = output.indexOf(title);
    while (titleIndex >= 0) {
      const start = output.lastIndexOf('<div class="sec"', titleIndex);
      const next = output.indexOf('<div class="sec"', titleIndex + title.length);
      const end = next >= 0 ? next : output.indexOf('</div></body>', titleIndex);
      if (start < 0 || end < 0 || end <= start) break;
      output = output.slice(0, start) + output.slice(end);
      titleIndex = output.indexOf(title);
    }
  }
  return output;
}

function planSectionVisibilityFromForm(form = {}) {
  return {
    shopping: Boolean(form.showShopping),
    exercise: Boolean(form.showExercise),
    followup: Boolean(form.showFollowup),
    longTerm: Boolean(form.showLongTerm),
    family: Boolean(form.showFamily),
    gut: Boolean(form.showGut),
    skin: Boolean(form.showSkin)
  };
}

function applyPlanSectionControls(html = '', visibility = {}) {
  let output = String(html || '');
  if (!visibility.shopping) output = removeSectionsByTitles(output, ['Weekly Shopping and Meal Prep Guide', 'Weekly Shopping Lists']);
  if (!visibility.exercise) output = removeSectionsByTitles(output, ['Movement and Exercise Guidance']);
  if (!visibility.followup) output = removeSectionsByTitles(output, ['Follow-Up and Progress Roadmap', 'Progress Checkpoints']);
  if (!visibility.longTerm) output = removeSectionsByTitles(output, ['Long-Term Health Foods', 'Protective Foods for Long-Term Health']);
  if (!visibility.family) output = removeSectionsByTitles(output, ['Household Personalisation Plan', 'Family and Household Value Guide']);
  if (!visibility.gut) output = removeSectionsByTitles(output, ['Gut Health and Digestive Wellness']);
  if (!visibility.skin) output = removeSectionsByTitles(output, ['Nutrition for Hair, Skin and Nail Health']);
  return output;
}

function checkbox(name, label, checkedValue = true) {
  return `<label class="check"><input type="checkbox" name="${escapeHtml(name)}" ${checkedValue ? 'checked' : ''}> ${escapeHtml(label)}</label>`;
}

function escapeRegExp(value) {
  return String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function decodeHtmlEntities(value = '') {
  return String(value ?? '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => {
      const code = Number(n);
      return Number.isFinite(code) ? String.fromCharCode(code) : _;
    });
}

function htmlToPlain(value = '') {
  return decodeHtmlEntities(String(value ?? '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>\s*<p>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .trim());
}

function plainToHtmlText(value = '') {
  return escapeHtml(String(value ?? '').trim()).replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>');
}

function sanitizePlanHtml(html = '') {
  return String(html || '')
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<(iframe|object|embed)\b[\s\S]*?<\/\1>/gi, '')
    .replace(/\s(on[a-z]+)\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, (match, attr, value) => {
      const cleanValue = String(value || '').replace(/^['"]|['"]$/g, '').trim();
      return attr.toLowerCase() === 'onclick' && cleanValue === 'window.print()' ? match : '';
    })
    .replace(/\s(href|src)\s*=\s*("|')\s*javascript:[\s\S]*?\2/gi, '');
}

function findDivBlocksByClass(html = '', className = '') {
  const source = String(html || '');
  const blocks = [];
  const marker = `<div class="${className}"`;
  let searchFrom = 0;
  while (searchFrom < source.length) {
    const start = source.indexOf(marker, searchFrom);
    if (start < 0) break;
    const divRe = /<\/?div\b[^>]*>/gi;
    divRe.lastIndex = start;
    let depth = 0;
    let end = -1;
    let match;
    while ((match = divRe.exec(source))) {
      if (match[0].startsWith('</')) depth -= 1;
      else depth += 1;
      if (depth === 0) {
        end = divRe.lastIndex;
        break;
      }
    }
    if (end < 0) break;
    blocks.push({ start, end, html: source.slice(start, end) });
    searchFrom = end;
  }
  return blocks;
}

function extractTaggedText(html = '', className = '', tag = 'div') {
  const re = new RegExp(`<${tag} class="${escapeRegExp(className)}">([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = String(html || '').match(re);
  return htmlToPlain(match ? match[1] : '');
}

function extractMealBoxText(cardHtml = '', label = '') {
  const re = new RegExp(`<div class="meal-box"><strong>${escapeRegExp(label)}<\\/strong><p>([\\s\\S]*?)<\\/p><\\/div>`, 'i');
  const match = String(cardHtml || '').match(re);
  return htmlToPlain(match ? match[1] : '');
}

function extractMealNoteText(cardHtml = '', label = '') {
  const re = new RegExp(`<div class="meal-note"><strong>${escapeRegExp(label)}<\\/strong><br>([\\s\\S]*?)<\\/div>`, 'i');
  const match = String(cardHtml || '').match(re);
  return htmlToPlain(match ? match[1] : '');
}

function mealCardsForEditor(html = '') {
  return findDivBlocksByClass(html, 'meal-card').map((block, index) => ({
    index,
    time: extractTaggedText(block.html, 'meal-time'),
    name: extractTaggedText(block.html, 'meal-name'),
    ingredients: extractMealBoxText(block.html, 'Ingredients'),
    preparation: extractMealBoxText(block.html, 'Preparation'),
    portion: extractMealBoxText(block.html, 'Portion guide'),
    swaps: extractMealBoxText(block.html, 'Smart swaps'),
    reason: extractMealNoteText(block.html, 'Food reason'),
    taste: extractMealNoteText(block.html, 'Taste and practical notes')
  }));
}

function replaceMealBoxText(cardHtml = '', label = '', value = '') {
  const re = new RegExp(`(<div class="meal-box"><strong>${escapeRegExp(label)}<\\/strong><p>)[\\s\\S]*?(<\\/p><\\/div>)`, 'i');
  return String(cardHtml || '').replace(re, `$1${plainToHtmlText(value)}$2`);
}

function replaceMealNoteText(cardHtml = '', label = '', value = '') {
  const re = new RegExp(`(<div class="meal-note"><strong>${escapeRegExp(label)}<\\/strong><br>)[\\s\\S]*?(<\\/div>)`, 'i');
  return String(cardHtml || '').replace(re, `$1${plainToHtmlText(value)}$2`);
}

function applyMealContentEdits(html = '', form = {}) {
  const blocks = findDivBlocksByClass(html, 'meal-card');
  let output = String(html || '');
  for (let i = blocks.length - 1; i >= 0; i -= 1) {
    const block = blocks[i];
    let card = block.html;
    const name = form[`mealName_${i}`];
    if (typeof name === 'string') {
      card = card.replace(/(<div class="meal-name">)[\s\S]*?(<\/div>)/i, `$1${escapeHtml(name.trim())}$2`);
    }
    card = replaceMealBoxText(card, 'Ingredients', form[`ingredients_${i}`] ?? extractMealBoxText(card, 'Ingredients'));
    card = replaceMealBoxText(card, 'Preparation', form[`preparation_${i}`] ?? extractMealBoxText(card, 'Preparation'));
    card = replaceMealBoxText(card, 'Portion guide', form[`portion_${i}`] ?? extractMealBoxText(card, 'Portion guide'));
    card = replaceMealBoxText(card, 'Smart swaps', form[`swaps_${i}`] ?? extractMealBoxText(card, 'Smart swaps'));
    card = replaceMealNoteText(card, 'Food reason', form[`reason_${i}`] ?? extractMealNoteText(card, 'Food reason'));
    card = replaceMealNoteText(card, 'Taste and practical notes', form[`taste_${i}`] ?? extractMealNoteText(card, 'Taste and practical notes'));
    output = output.slice(0, block.start) + card + output.slice(block.end);
  }
  return output;
}

function mealContentFields(card) {
  const title = `${card.time || `Meal ${card.index + 1}`} - ${card.name || 'Untitled meal'}`;
  return `<details class="meal-edit" ${card.index < 5 ? 'open' : ''}>
    <summary>${escapeHtml(title)}</summary>
    <div class="field"><label>Meal name</label><input name="mealName_${card.index}" value="${escapeHtml(card.name)}"></div>
    <div class="field"><label>Ingredients</label><textarea name="ingredients_${card.index}">${escapeHtml(card.ingredients)}</textarea></div>
    <div class="field"><label>Preparation</label><textarea name="preparation_${card.index}">${escapeHtml(card.preparation)}</textarea></div>
    <div class="field"><label>Detailed portion guide</label><textarea name="portion_${card.index}">${escapeHtml(card.portion)}</textarea></div>
    <div class="field"><label>Smart swaps</label><textarea name="swaps_${card.index}">${escapeHtml(card.swaps)}</textarea></div>
    <div class="field"><label>Food reason</label><textarea name="reason_${card.index}">${escapeHtml(card.reason)}</textarea></div>
    <div class="field"><label>Taste and practical notes</label><textarea name="taste_${card.index}">${escapeHtml(card.taste)}</textarea></div>
  </details>`;
}

function planContentEditorPage(order, message = '') {
  if (!order) return '<p>Order not found.</p>';
  const html = order.finalHtmlPlan || applyCustomerReleaseNote(order);
  const cards = mealCardsForEditor(html);
  return `<!doctype html><html><head><meta charset="utf-8"><title>Edit Plan Content - Bulamu360</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1500px;margin:0 auto;padding:24px}.top{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:14px}.btn{display:inline-flex;align-items:center;justify-content:center;border:0;background:#1e3a1a;color:#fff;padding:10px 13px;border-radius:9px;text-decoration:none;font-weight:800;cursor:pointer}.ghost{background:#ede8df;color:#2a1f14}.grid{display:grid;grid-template-columns:minmax(520px,1fr) minmax(420px,.85fr);gap:14px}.panel{background:#fff;border:1px solid #e6dccd;border-radius:14px;padding:16px;box-shadow:0 10px 34px #2a1f1412}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}.hint{font-size:13px;color:#6d5d4b;line-height:1.5}.field{margin:10px 0}.field label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;font-weight:800;color:#7a6a57;margin-bottom:5px}input,textarea{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:10px;font:14px Arial,sans-serif;background:#fffdf9;color:#241a10;line-height:1.45}textarea{min-height:74px;resize:vertical}.meal-edit{border:1px solid #e6dccd;border-radius:12px;background:#faf7f1;margin:10px 0;overflow:hidden}.meal-edit summary{cursor:pointer;padding:12px 14px;font-weight:900;color:#1e3a1a}.meal-edit .field{padding:0 14px}.meal-edit .field:last-child{padding-bottom:12px}.preview{height:820px;border:1px solid #d8d0c4;border-radius:12px;overflow:hidden;background:#fff}.preview iframe{width:100%;height:100%;border:0}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:12px}.meta{font-size:13px;color:#6d5d4b}.empty{background:#fff1c7;color:#6f4b00;border-radius:10px;padding:12px;line-height:1.5}@media(max-width:1000px){.grid{grid-template-columns:1fr}.preview{height:560px}.top{display:block}.actions{margin-top:12px}}
  </style></head><body><div class="wrap">
    <div class="top">
      <div><h1>Edit Plan Content</h1><p class="meta">${escapeHtml(order.name || '')} - ${escapeHtml(order.packageName || '')} - ${escapeHtml(order.status || '')}</p></div>
      <div class="actions"><a class="btn ghost" href="/admin">Dashboard</a><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Review</a><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/edit">Advanced HTML editor</a><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/plan" target="_blank">Open preview</a></div>
    </div>
    ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
    <form method="post" action="/admin/orders/${escapeHtml(order.id)}/content">
      <div class="grid">
        <div class="panel">
          <h2>Simple Meal Editor</h2>
          <p class="hint">Use this for normal dietician review. It edits the words inside each meal card while preserving the approved Bulamu360 layout, branding, and lower sections.</p>
          ${cards.length ? cards.map(mealContentFields).join('') : '<div class="empty">No meal cards were found in this plan. Use the advanced HTML editor for this older draft.</div>'}
          <div class="actions">
            <button class="btn" name="intent" value="save">Save Plan Content</button>
            ${order.status === 'pending' ? `<button class="btn" name="intent" value="approve">Save, Approve and Send</button>` : ''}
            <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Back to review</a>
          </div>
        </div>
        <div class="panel">
          <h2>Live Preview</h2>
          <p class="hint">After saving, refresh or reopen preview to confirm the customer copy still looks polished.</p>
          <div class="preview"><iframe src="/admin/orders/${escapeHtml(order.id)}/plan"></iframe></div>
        </div>
      </div>
    </form>
  </div></body></html>`;
}

async function handlePlanContentEditor(req, res, id) {
  const db = readDb();
  const order = findOrder(db, id);
  if (!order) return sendHtml(res, 404, 'Order not found');
  if (req.method === 'GET') return sendHtml(res, 200, planContentEditorPage(order));
  const form = await readForm(req);
  const baseHtml = order.finalHtmlPlan || applyCustomerReleaseNote(order);
  order.finalHtmlPlan = sanitizePlanHtml(applyMealContentEdits(baseHtml, form));
  order.planContentEditHistory = Array.isArray(order.planContentEditHistory) ? order.planContentEditHistory : [];
  order.planContentEditHistory.push({
    at: new Date().toISOString(),
    intent: String(form.intent || 'save'),
    mealCardCount: findDivBlocksByClass(order.finalHtmlPlan || '', 'meal-card').length,
    hash: createHash('sha256').update(order.finalHtmlPlan || '').digest('hex')
  });
  auditAdminAction(db, req, 'plan-content-edit', {
    orderId: order.id,
    customer: order.email,
    intent: String(form.intent || 'save'),
    mealCardCount: findDivBlocksByClass(order.finalHtmlPlan || '', 'meal-card').length
  });
  order.finalHtmlHash = createHash('sha256').update(order.finalHtmlPlan || '').digest('hex');
  order.planEditedAt = new Date().toISOString();
  order.updatedAt = order.planEditedAt;
  writeDb(db);
  if (form.intent === 'approve') {
    if (!(order.adminReview && order.adminReview.checklistComplete)) {
      return sendHtml(res, 400, planContentEditorPage(order, 'Saved, but approval checklist is not complete. Complete the review checklist before sending.'));
    }
    approveOrder(db, order, form);
    writeDb(db);
    return redirect(res, '/admin?status=approved');
  }
  return sendHtml(res, 200, planContentEditorPage(order, 'Plan content saved without touching the raw HTML layout.'));
}

function planEditorPage(order, message = '') {
  if (!order) return '<p>Order not found.</p>';
  const html = order.finalHtmlPlan || applyCustomerReleaseNote(order);
  const visibility = order.planSectionVisibility || {
    shopping: true,
    exercise: true,
    followup: true,
    longTerm: true,
    family: true,
    gut: true,
    skin: true
  };
  return `<!doctype html><html><head><meta charset="utf-8"><title>Edit Plan - Bulamu360</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1500px;margin:0 auto;padding:24px}.top{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:14px}.btn{display:inline-flex;align-items:center;justify-content:center;border:0;background:#1e3a1a;color:#fff;padding:10px 13px;border-radius:9px;text-decoration:none;font-weight:800;cursor:pointer}.ghost{background:#ede8df;color:#2a1f14}.danger{background:#8a1010;color:#fff}.grid{display:grid;grid-template-columns:minmax(420px,1fr) minmax(420px,1fr);gap:14px}.panel{background:#fff;border:1px solid #e6dccd;border-radius:14px;padding:16px;box-shadow:0 10px 34px #2a1f1412}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}.check{display:block;background:#faf7f1;border:1px solid #e6dccd;border-radius:9px;padding:9px;margin:7px 0;font-size:13px}textarea{width:100%;height:760px;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:12px;font:12px Consolas,monospace;background:#fffdf9;color:#241a10;line-height:1.45}.preview{height:820px;border:1px solid #d8d0c4;border-radius:12px;overflow:hidden;background:#fff}.preview iframe{width:100%;height:100%;border:0}.actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:12px}.hint{font-size:13px;color:#6d5d4b;line-height:1.5}.meta{font-size:13px;color:#6d5d4b}@media(max-width:1000px){.grid{grid-template-columns:1fr}.preview{height:560px}.top{display:block}.actions{margin-top:12px}}
  </style></head><body><div class="wrap">
    <div class="top">
      <div><h1>Edit Draft Plan</h1><p class="meta">${escapeHtml(order.name || '')} - ${escapeHtml(order.packageName || '')} - ${escapeHtml(order.status || '')}</p></div>
      <div class="actions"><a class="btn ghost" href="/admin">Dashboard</a><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Review</a><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/plan" target="_blank">Open preview</a></div>
    </div>
    ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
    <form method="post" action="/admin/orders/${escapeHtml(order.id)}/edit">
      <div class="grid">
        <div class="panel">
          <h2>Final Plan HTML</h2>
          <p class="hint">Edit the plan here before approval. This final version is what the customer receives after approval. Keep the main HTML structure intact.</p>
          <textarea name="htmlContent" spellcheck="false">${escapeHtml(html)}</textarea>
          <div class="actions">
            <button class="btn" name="intent" value="save">Save Final Plan</button>
            ${order.status === 'pending' ? `<button class="btn" name="intent" value="approve">Save, Approve and Send</button>` : ''}
            <button class="btn ghost" name="intent" value="reset">Reset to Generated Draft</button>
          </div>
        </div>
        <div class="panel">
          <h2>Section Control</h2>
          <p class="hint">Untick sections you do not want in the final customer copy. This removes the whole section when you save.</p>
          ${checkbox('showShopping', 'Show shopping list and meal prep', visibility.shopping)}
          ${checkbox('showExercise', 'Show exercise guidance', visibility.exercise)}
          ${checkbox('showFollowup', 'Show follow-up roadmap and checkpoints', visibility.followup)}
          ${checkbox('showLongTerm', 'Show long-term health foods', visibility.longTerm)}
          ${checkbox('showFamily', 'Show family/household guidance', visibility.family)}
          ${checkbox('showGut', 'Show gut health section', visibility.gut)}
          ${checkbox('showSkin', 'Show hair, skin and nail section', visibility.skin)}
          <h2>Preview</h2>
          <div class="preview"><iframe src="/admin/orders/${escapeHtml(order.id)}/plan"></iframe></div>
        </div>
      </div>
    </form>
  </div></body></html>`;
}

async function handlePlanEditor(req, res, id) {
  const db = readDb();
  const order = findOrder(db, id);
  if (!order) return sendHtml(res, 404, 'Order not found');
  if (req.method === 'GET') return sendHtml(res, 200, planEditorPage(order));
  const form = await readForm(req);
  if (form.intent === 'reset') {
    order.finalHtmlPlan = applyCustomerReleaseNote({ ...order, finalHtmlPlan: '', adminReview: order.adminReview || {} });
    order.planSectionVisibility = { shopping: true, exercise: true, followup: true, longTerm: true, family: true, gut: true, skin: true };
  } else {
    const visibility = planSectionVisibilityFromForm(form);
    const edited = String(form.htmlContent || '').trim();
    order.planSectionVisibility = visibility;
    order.finalHtmlPlan = sanitizePlanHtml(applyPlanSectionControls(edited || applyCustomerReleaseNote(order), visibility));
  }
  order.planEditHistory = Array.isArray(order.planEditHistory) ? order.planEditHistory : [];
  order.planEditHistory.push({
    at: new Date().toISOString(),
    intent: String(form.intent || 'save'),
    hash: createHash('sha256').update(order.finalHtmlPlan || '').digest('hex'),
    visibility: order.planSectionVisibility
  });
  auditAdminAction(db, req, 'plan-html-edit', {
    orderId: order.id,
    customer: order.email,
    intent: String(form.intent || 'save'),
    visibility: order.planSectionVisibility
  });
  order.finalHtmlHash = createHash('sha256').update(order.finalHtmlPlan || '').digest('hex');
  order.planEditedAt = new Date().toISOString();
  order.updatedAt = order.planEditedAt;
  writeDb(db);
  if (form.intent === 'approve') {
    if (!(order.adminReview && order.adminReview.checklistComplete)) {
      return sendHtml(res, 400, planEditorPage(order, 'Saved, but approval checklist is not complete. Complete the review checklist before sending.'));
    }
    approveOrder(db, order, form);
    writeDb(db);
    return redirect(res, '/admin?status=approved');
  }
  return sendHtml(res, 200, planEditorPage(order, form.intent === 'reset' ? 'Plan reset to the generated draft.' : 'Final plan saved.'));
}

function checked(value) {
  return value ? 'checked' : '';
}

function adminReviewPage(order, message = '') {
  const cs = order.clinicalSummary || {};
  const safety = cs.safetyDecision || {};
  const audit = cs.planAudit || {};
  const rules = cs.clinicalRules || {};
  const review = order.adminReview || {};
  const checklist = review.checklist || {};
  const chapters = Array.isArray(cs.conditionChapters) ? cs.conditionChapters : [];
  const blockerItems = Array.isArray(audit.blockers) ? audit.blockers : [];
  const warningItems = Array.isArray(audit.warnings) ? audit.warnings : [];
  const ruleReview = Array.isArray(rules.review) ? rules.review : [];
  const ruleCaution = Array.isArray(rules.caution) ? rules.caution : [];
  return `<!doctype html><html><head><meta charset="utf-8"><title>Review ${escapeHtml(order.name)} - Bulamu360</title>
  <style>
  body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1180px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:10px 13px;border-radius:9px;text-decoration:none;font-weight:700;cursor:pointer}.ghost{background:#ede8df;color:#2a1f14}.danger{background:#8a1010}.panel{background:#fff;border-radius:18px;padding:20px;box-shadow:0 10px 35px #0001;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;font-weight:700;margin-bottom:5px}.value{font-size:14px;line-height:1.55}.pill{display:inline-block;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800;margin:3px;background:#f1eadf}.safe{background:#e4f5dd;color:#1e3a1a}.caution{background:#fff1c7;color:#8a6200}.review{background:#ffe1dc;color:#8a1010}.list span{display:block;border-left:3px solid #d8cfbf;padding-left:8px;margin-top:6px;font-size:13px;line-height:1.45}textarea,input[type=text],select{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:11px;font:14px Arial,sans-serif;background:#fffdf9}textarea{min-height:86px}.check{display:flex;gap:9px;align-items:flex-start;background:#faf7f1;border:1px solid #e2dbcf;border-radius:10px;padding:10px;margin:8px 0}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.preview{height:520px;border:1px solid #d8d0c4;border-radius:14px;overflow:hidden;background:#fff}.preview iframe{width:100%;height:100%;border:0}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}
  </style></head><body><div class="wrap">
  <div class="top"><div><h1>Admin Plan Review</h1><p>${escapeHtml(order.name)} - ${escapeHtml(order.packageName)} - ${escapeHtml(order.amount)}</p></div><div><a class="btn ghost" href="/admin">Back to dashboard</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/content">Edit content</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/edit">Edit plan</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/plan" target="_blank">Open plan</a></div></div>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <div class="grid">
    <div class="panel"><h2>Customer and Payment</h2>
      <div class="label">Customer</div><div class="value"><strong>${escapeHtml(order.name)}</strong><br>${escapeHtml(order.email)}<br>${escapeHtml(order.phone)}</div><br>
      <div class="label">Payment</div><div class="value">${escapeHtml(order.network)} - ${escapeHtml(order.txRef)}<br>${escapeHtml(order.amount)} - ${escapeHtml(order.status)}</div><br>
      <div class="label">Clinical context</div><div class="value">Conditions: ${escapeHtml(Array.isArray(cs.conditions) ? cs.conditions.join(', ') : '') || 'None captured'}<br>Diagnosis: ${escapeHtml(cs.diagnosis || '') || 'Not captured'}<br>Allergies: ${escapeHtml(cs.allergies || '') || 'Not captured'}<br>Symptoms: ${escapeHtml(cs.symptoms || '') || 'Not captured'}</div>
    </div>
    <div class="panel"><h2>Safety and Quality</h2>
      <span class="pill ${escapeHtml(safety.status || 'review')}">${escapeHtml(safety.label || 'Safety not captured')}</span>
      <span class="pill ${escapeHtml(audit.status === 'ready' ? 'safe' : audit.status || 'review')}">${escapeHtml(audit.label || 'Audit not captured')} ${audit.score !== undefined ? escapeHtml(audit.score) + '/100' : ''}</span>
      <div class="list">${blockerItems.map(x => `<span><strong>Blocker:</strong> ${escapeHtml(x)}</span>`).join('')}${warningItems.slice(0,4).map(x => `<span><strong>Warning:</strong> ${escapeHtml(x)}</span>`).join('')}</div>
    </div>
  </div>
  <div class="grid">
    <div class="panel"><h2>Rules Engine</h2><div class="list">
      ${ruleReview.slice(0,5).map(r => `<span><strong>Review:</strong> ${escapeHtml(r.area || '')} - ${escapeHtml(r.title || '')}</span>`).join('')}
      ${ruleCaution.slice(0,5).map(r => `<span><strong>Caution:</strong> ${escapeHtml(r.area || '')} - ${escapeHtml(r.title || '')}</span>`).join('')}
      ${(!ruleReview.length && !ruleCaution.length) ? '<span>No rule cautions captured.</span>' : ''}
    </div></div>
    <div class="panel"><h2>Condition Chapters</h2><div>
      ${chapters.length ? chapters.map(c => `<span class="pill">${escapeHtml(c.title || '')}</span>`).join('') : '<p>No condition chapters captured.</p>'}
    </div></div>
  </div>
  <form class="panel" method="post" action="/admin/orders/${escapeHtml(order.id)}/review">
    <h2>Admin Amendments</h2>
    <div class="grid">
      <div><div class="label">Clinical note</div><textarea name="clinicalNote" placeholder="Clinical interpretation or final note">${escapeHtml(review.clinicalNote || '')}</textarea></div>
      <div><div class="label">Patient-facing release note</div><textarea name="customerReleaseNote" placeholder="Only write what the customer should safely see">${escapeHtml(review.customerReleaseNote || '')}</textarea></div>
      <div><div class="label">Approval condition</div><textarea name="approvalCondition" placeholder="Condition under which the plan is approved">${escapeHtml(review.approvalCondition || '')}</textarea></div>
      <div><div class="label">Requested missing lab / data</div><textarea name="requestedLab" placeholder="e.g. Send HbA1c, BP readings, eGFR, potassium">${escapeHtml(review.requestedLab || '')}</textarea></div>
      <div><div class="label">Dietary correction</div><textarea name="dietaryCorrection" placeholder="Specific correction to apply before/after approval">${escapeHtml(review.dietaryCorrection || '')}</textarea></div>
    </div>
    <div style="margin-top:12px"><div class="label">Follow-up instruction</div><textarea name="followUpInstruction" placeholder="When and how to follow up">${escapeHtml(review.followUpInstruction || '')}</textarea></div>
    <h2>Payment and Clinical Tracking</h2>
    <div class="grid">
      <div><div class="label">Actual amount paid</div><input type="text" name="actualAmountPaid" value="${escapeHtml(review.actualAmountPaid || '')}" placeholder="e.g. UGX 120,000"></div>
      <div><div class="label">Payment verifier/admin name</div><input type="text" name="paymentVerifier" value="${escapeHtml(review.paymentVerifier || '')}" placeholder="Who verified the transaction?"></div>
      <div><div class="label">Payment mismatch/refund/cancel reason</div><textarea name="paymentMismatchReason" placeholder="If amount/reference did not match, explain">${escapeHtml(review.paymentMismatchReason || '')}</textarea></div>
      <div><div class="label">Urgency level</div><select name="urgencyLevel"><option value="">Select</option><option value="routine" ${review.urgencyLevel === 'routine' ? 'selected' : ''}>Routine</option><option value="priority" ${review.urgencyLevel === 'priority' ? 'selected' : ''}>Priority</option><option value="urgent" ${review.urgencyLevel === 'urgent' ? 'selected' : ''}>Urgent</option></select></div>
      <div><div class="label">Medication class</div><input type="text" name="medicationClass" value="${escapeHtml(review.medicationClass || '')}" placeholder="e.g. insulin, metformin, ACE inhibitor, statin"></div>
      <div><div class="label">Red-flag symptoms</div><textarea name="redFlagSymptoms" placeholder="Severe symptoms, warning signs, urgent concerns">${escapeHtml(review.redFlagSymptoms || '')}</textarea></div>
      <div><div class="label">Referral reason</div><textarea name="referralReason" placeholder="Why clinician referral is recommended">${escapeHtml(review.referralReason || '')}</textarea></div>
      <div><div class="label">Admin override reason</div><textarea name="adminOverrideReason" placeholder="Why approval is allowed despite warnings/blockers">${escapeHtml(review.adminOverrideReason || '')}</textarea></div>
      <div><div class="label">Plan version</div><input type="text" name="planVersion" value="${escapeHtml(review.planVersion || 'Bulamu360 HTML 2026.05')}"></div>
      <div><div class="label">Rules engine version</div><input type="text" name="rulesEngineVersion" value="${escapeHtml(review.rulesEngineVersion || 'clinical-rules-2026.05')}"></div>
      <div><div class="label">Recipe database version</div><input type="text" name="recipeDatabaseVersion" value="${escapeHtml(review.recipeDatabaseVersion || '')}" placeholder="e.g. 2026.05.expert-1"></div>
    </div>
    <label class="check"><input type="checkbox" name="clinicianReferralRecommended" ${checked(review.clinicianReferralRecommended)}> Clinician referral recommended</label>
    <h2>Approval Checklist</h2>
    <label class="check"><input type="checkbox" name="paymentConfirmed" ${checked(checklist.paymentConfirmed)}> Payment reference checked against mobile money record</label>
    <label class="check"><input type="checkbox" name="allergiesReviewed" ${checked(checklist.allergiesReviewed)}> Allergies/intolerances reviewed or requested if missing</label>
    <label class="check"><input type="checkbox" name="safetyReviewed" ${checked(checklist.safetyReviewed)}> Clinical safety gates and contraindications reviewed</label>
    <label class="check"><input type="checkbox" name="auditReviewed" ${checked(checklist.auditReviewed)}> Quality audit blockers/warnings reviewed</label>
    <label class="check"><input type="checkbox" name="finalFitToSend" ${checked(checklist.finalFitToSend)}> Final plan is fit to send or approved with stated conditions</label>
    <input type="hidden" name="note" value="${escapeHtml(order.adminNote || '')}">
    <div class="actions">
      <button class="btn ghost" name="intent" value="save">Save review notes</button>
      ${order.status === 'pending' ? `<button class="btn" name="intent" value="approve">Approve and send amended plan</button>` : ''}
      <button class="btn danger" name="intent" value="reject">Reject order</button>
    </div>
  </form>
  <div class="panel"><h2>Plan Preview</h2><div class="preview"><iframe src="/admin/orders/${escapeHtml(order.id)}/plan"></iframe></div></div>
  </div></body></html>`;
}

function saveAdminReview(order, form) {
  const previous = order.adminReview || {};
  const next = reviewFromForm(form, previous);
  order.reviewHistory = Array.isArray(order.reviewHistory) ? order.reviewHistory : [];
  order.reviewHistory.push({ at: next.updatedAt, type: form.intent || 'save', adminReview: next });
  order.adminReview = next;
  order.adminNote = String(form.note || order.adminNote || '').trim();
  if (!order.finalHtmlPlan) {
    order.finalHtmlPlan = applyAdminAmendments(order);
    order.finalHtmlHash = createHash('sha256').update(order.finalHtmlPlan).digest('hex');
  }
  order.updatedAt = next.updatedAt;
}

function followupSchedule() {
  return [
    { day: 7, label: '7-day check-in', purpose: 'Early tolerance, appetite, symptoms, and meal practicality.' },
    { day: 14, label: '14-day adherence check', purpose: 'Routine consistency, disliked meals, barriers, and first adjustments.' },
    { day: 30, label: '30-day outcome review', purpose: 'Weight, waist, BP/glucose where relevant, symptoms, and target progress.' },
    { day: 60, label: '60-day continuation review', purpose: 'Maintenance, intensification, new labs, and next plan cycle.' }
  ];
}

function followupPage(order, message = '') {
  if (!order) return '<p>Follow-up link not found.</p>';
  const latest = Array.isArray(order.followups) && order.followups.length ? order.followups[order.followups.length - 1] : null;
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Follow-up</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:860px;margin:0 auto;padding:28px}.card{background:#fff;border-radius:18px;padding:24px;box-shadow:0 10px 35px #0001;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;font-weight:800;margin-bottom:5px}input,select,textarea{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:12px;font:14px Arial,sans-serif;background:#fffdf9}textarea{min-height:90px}.btn{border:0;background:#1e3a1a;color:#fff;padding:13px 18px;border-radius:10px;font-weight:800;cursor:pointer}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}.sched{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.sched div{background:#faf7f1;border:1px solid #e2dbcf;border-radius:10px;padding:10px;font-size:12px;line-height:1.45}@media(max-width:700px){.grid,.sched{grid-template-columns:1fr}}</style>
  </head><body><div class="wrap"><div class="card"><h1>Bulamu360 Progress Review</h1><p>Hello ${escapeHtml(order.name)}, use this form to tell Breyer how the plan is working in real life.</p><p><strong>Plan:</strong> ${escapeHtml(order.packageName)} - <strong>Approved:</strong> ${escapeHtml(order.approvedAt || '')}</p></div>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <div class="card"><h2>Review Schedule</h2><div class="sched">${followupSchedule().map(s => `<div><strong>${escapeHtml(s.label)}</strong><br>${escapeHtml(s.purpose)}</div>`).join('')}</div></div>
  ${latest ? `<div class="card"><h2>Latest Submission</h2><p>${escapeHtml(new Date(latest.createdAt).toLocaleString())} - ${escapeHtml(latest.reviewPoint || '')}</p><p><strong>Admin response:</strong> ${escapeHtml(latest.adminAdjustment && latest.adminAdjustment.action ? latest.adminAdjustment.action : 'Pending review')}</p></div>` : ''}
  <form class="card" method="post" action="/followup/${escapeHtml(order.followupToken)}">
    <h2>Submit Progress</h2>
    <div class="grid">
      <div><label>Review point</label><select name="reviewPoint" required><option value="7-day">7-day check-in</option><option value="14-day">14-day adherence check</option><option value="30-day">30-day outcome review</option><option value="60-day">60-day continuation review</option><option value="other">Other</option></select></div>
      <div><label>Current weight (kg)</label><input name="weight" type="text" placeholder="e.g. 72.5"></div>
      <div><label>Current waist (cm)</label><input name="waist" type="text" placeholder="e.g. 86"></div>
      <div><label>BP / glucose if relevant</label><input name="clinicalReading" type="text" placeholder="e.g. BP 128/82, FBG 6.1"></div>
      <div><label>Energy 1-10</label><input name="energy" type="number" min="1" max="10" placeholder="1 to 10"></div>
      <div><label>Adherence 1-10</label><input name="adherence" type="number" min="1" max="10" placeholder="1 to 10"></div>
      <div><label>Outcome trend</label><select name="outcomeTrend"><option value="">Select</option><option value="improving">Improving</option><option value="unchanged">Unchanged</option><option value="worsening">Worsening</option></select></div>
      <div><label>Taste satisfaction 1-10</label><input name="tasteSatisfaction" type="number" min="1" max="10" placeholder="1 to 10"></div>
      <div><label>Budget difficulty 1-10</label><input name="budgetDifficulty" type="number" min="1" max="10" placeholder="1 easy, 10 hard"></div>
      <div><label>Cooking difficulty 1-10</label><input name="cookingDifficulty" type="number" min="1" max="10" placeholder="1 easy, 10 hard"></div>
      <div><label>Food availability difficulty 1-10</label><input name="foodAvailabilityDifficulty" type="number" min="1" max="10" placeholder="1 easy, 10 hard"></div>
      <div><label>Meal prep burden 1-10</label><input name="mealPrepBurden" type="number" min="1" max="10" placeholder="1 easy, 10 hard"></div>
    </div>
    <p><label>Appetite / hunger changes</label><textarea name="appetite" placeholder="Are you too hungry, too full, or okay?"></textarea></p>
    <p><label>Symptoms or concerns</label><textarea name="symptoms" placeholder="Dizziness, swelling, constipation, vomiting, low energy, headaches, cravings..."></textarea></p>
    <p><label>Household support / barriers</label><textarea name="householdSupport" placeholder="Who helps with shopping/cooking? Any family barriers?"></textarea></p>
    <p><label>Foods causing symptoms</label><textarea name="foodsCausingSymptoms" placeholder="Which foods caused bloating, reflux, nausea, diarrhoea, constipation, headaches, or glucose spikes?"></textarea></p>
    <p><label>Expensive meals</label><textarea name="expensiveMeals" placeholder="Which meals were too expensive to repeat?"></textarea></p>
    <p><label>Hard-to-cook meals</label><textarea name="hardToCookMeals" placeholder="Which meals took too much time, equipment, or skill?"></textarea></p>
    <p><label>Foods disliked or difficult to follow</label><textarea name="dislikedFoods" placeholder="Which meals were impractical, expensive, or disliked?"></textarea></p>
    <p><label>Meals repeated most</label><textarea name="repeatedMeals" placeholder="Which meals did you repeat most often?"></textarea></p>
    <p><label>Requested substitutions</label><textarea name="requestedSubstitutions" placeholder="Which foods should Breyer replace, and with what if you know?"></textarea></p>
    <p><label>Question for Breyer</label><textarea name="question" placeholder="What would you like Breyer to review?"></textarea></p>
    <button class="btn">Submit progress review</button>
  </form></div></body></html>`;
}

async function handleFollowup(req, res, token) {
  const db = readDb();
  const order = db.orders.find(o => o.followupToken === token && o.status === 'approved');
  if (!order) return sendHtml(res, 404, '<p>Follow-up link not found or plan is not approved yet.</p>');
  if (req.method === 'GET') return sendHtml(res, 200, followupPage(order));
  const form = await readForm(req);
  const entry = {
    id: `fu_${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`,
    createdAt: new Date().toISOString(),
    reviewPoint: String(form.reviewPoint || '').trim(),
    weight: String(form.weight || '').trim(),
    waist: String(form.waist || '').trim(),
    clinicalReading: String(form.clinicalReading || '').trim(),
    energy: String(form.energy || '').trim(),
    adherence: String(form.adherence || '').trim(),
    outcomeTrend: String(form.outcomeTrend || '').trim(),
    tasteSatisfaction: String(form.tasteSatisfaction || '').trim(),
    budgetDifficulty: String(form.budgetDifficulty || '').trim(),
    cookingDifficulty: String(form.cookingDifficulty || '').trim(),
    foodAvailabilityDifficulty: String(form.foodAvailabilityDifficulty || '').trim(),
    mealPrepBurden: String(form.mealPrepBurden || '').trim(),
    appetite: String(form.appetite || '').trim(),
    symptoms: String(form.symptoms || '').trim(),
    householdSupport: String(form.householdSupport || '').trim(),
    foodsCausingSymptoms: String(form.foodsCausingSymptoms || '').trim(),
    expensiveMeals: String(form.expensiveMeals || '').trim(),
    hardToCookMeals: String(form.hardToCookMeals || '').trim(),
    dislikedFoods: String(form.dislikedFoods || '').trim(),
    repeatedMeals: String(form.repeatedMeals || '').trim(),
    requestedSubstitutions: String(form.requestedSubstitutions || '').trim(),
    question: String(form.question || '').trim(),
    adminAdjustment: {}
  };
  order.followups = Array.isArray(order.followups) ? order.followups : [];
  order.followups.push(entry);
  order.updatedAt = entry.createdAt;
  writeDb(db);
  await sendFollowupSubmittedEmail(order, entry).catch(err => {
    order.emailLog = Array.isArray(order.emailLog) ? order.emailLog : [];
    order.emailLog.push({ at: new Date().toISOString(), type: 'followup-submitted', error: err.message });
    writeDb(db);
  });
  return sendHtml(res, 200, followupPage(order, 'Progress review submitted. Breyer can now review it in the admin dashboard.'));
}

async function handleReview(req, res, id) {
  const db = readDb();
  const order = findOrder(db, id);
  if (!order) return sendHtml(res, 404, 'Order not found');
  if (req.method === 'GET') return sendHtml(res, 200, adminReviewPage(order));
  const form = await readForm(req);
  saveAdminReview(order, form);
  auditAdminAction(db, req, 'admin-review', {
    orderId: order.id,
    customer: order.email,
    intent: String(form.intent || 'save'),
    checklistComplete: Boolean(order.adminReview && order.adminReview.checklistComplete)
  });
  if (form.intent === 'reject') {
    order.status = 'rejected';
    order.rejectedAt = order.updatedAt;
    writeDb(db);
    queueOrderEmail(order, 'rejection', () => sendRejectionEmail(order));
    return redirect(res, '/admin?status=pending');
  }
  if (form.intent === 'approve') {
    if (!order.adminReview.checklistComplete) {
      writeDb(db);
      return sendHtml(res, 400, adminReviewPage(order, 'Complete every approval checklist item before approving.'));
    }
    approveOrder(db, order, form);
    return redirect(res, '/admin?status=pending');
  }
  writeDb(db);
  return sendHtml(res, 200, adminReviewPage(order, 'Review notes saved.'));
}

async function handleDeleteOrder(req, res, id) {
  const db = readDb();
  const index = db.orders.findIndex(o => o.id === id);
  if (index < 0) return sendHtml(res, 404, 'Order not found');
  if (req.method === 'GET') return sendHtml(res, 200, deleteOrderPage(db.orders[index]));
  const form = await readForm(req);
  const [removed] = db.orders.splice(index, 1);
  db.deletedOrders = Array.isArray(db.deletedOrders) ? db.deletedOrders : [];
  db.deletedOrders.unshift({
    id: removed.id,
    deletedAt: new Date().toISOString(),
    reason: String(form.deleteReason || '').trim(),
    name: removed.name || '',
    email: removed.email || '',
    packageName: removed.packageName || '',
    amount: removed.amount || '',
    status: removed.status || '',
    txRef: removed.txRef || '',
    createdAt: removed.createdAt || ''
  });
  auditAdminAction(db, req, 'order-delete', {
    orderId: removed.id,
    customer: removed.email,
    packageName: removed.packageName,
    status: removed.status,
    reason: String(form.deleteReason || '').trim()
  });
  db.deletedOrders = db.deletedOrders.slice(0, 500);
  writeDb(db);
  redirect(res, '/admin');
}

function approveOrder(db, order, form = {}) {
  order.status = 'approved';
  order.updatedAt = new Date().toISOString();
  order.approvedAt = order.updatedAt;
  order.adminNote = form.note || order.adminNote || '';
  order.approvalCode = order.approvalCode || makeApprovalCode();
  order.downloadToken = order.downloadToken || makeDownloadToken();
  order.followupToken = order.followupToken || makeFollowupToken();
  order.finalHtmlPlan = order.finalHtmlPlan || applyAdminAmendments(order);
  order.finalHtmlHash = createHash('sha256').update(order.finalHtmlPlan).digest('hex');
  writeDb(db);
  queueOrderEmail(order, 'approval', () => sendApprovalEmail(order));
}

function allFollowups(db) {
  return db.orders.flatMap(order => (Array.isArray(order.followups) ? order.followups : []).map(f => ({ order, followup: f })))
    .sort((a, b) => String(b.followup.createdAt).localeCompare(String(a.followup.createdAt)));
}

function adminFollowupsPage() {
  const db = readDb();
  const items = allFollowups(db);
  const rows = items.map(({ order, followup }) => {
    const adj = followup.adminAdjustment || {};
    return `<tr>
      <td><strong>${escapeHtml(order.name)}</strong><br><small>${escapeHtml(order.email)}<br>${escapeHtml(order.phone)}</small></td>
      <td>${escapeHtml(followup.reviewPoint)}<br><small>${escapeHtml(new Date(followup.createdAt).toLocaleString())}</small></td>
      <td><small>Weight: ${escapeHtml(followup.weight || '-')} - Waist: ${escapeHtml(followup.waist || '-')}</small><br><small>Reading: ${escapeHtml(followup.clinicalReading || '-')}</small><br><small>Energy: ${escapeHtml(followup.energy || '-')} - Adherence: ${escapeHtml(followup.adherence || '-')}</small></td>
      <td><small>Trend: ${escapeHtml(followup.outcomeTrend || '-')}</small><br><small>Taste: ${escapeHtml(followup.tasteSatisfaction || '-')} / 10</small><br><small>Budget: ${escapeHtml(followup.budgetDifficulty || '-')} - Cook: ${escapeHtml(followup.cookingDifficulty || '-')} - Availability: ${escapeHtml(followup.foodAvailabilityDifficulty || '-')}</small><br><small>Prep burden: ${escapeHtml(followup.mealPrepBurden || '-')}</small></td>
      <td>${escapeHtml(shortText(followup.symptoms || followup.requestedSubstitutions || followup.question || 'No concern written', 180))}</td>
      <td>${adj.action ? `<span class="badge approved">${escapeHtml(adj.action)}</span><br><small>${escapeHtml(adj.updatedAt || '')}</small>` : '<span class="badge pending">Pending review</span>'}</td>
      <td><a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/followups/${escapeHtml(followup.id)}">Review</a></td>
    </tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Follow-ups</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1380px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.panel{background:#fff;border-radius:18px;box-shadow:0 10px 35px #0001;overflow:auto}table{width:100%;border-collapse:collapse;min-width:1180px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;background:#fbf8f3}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:8px 10px;border-radius:8px;text-decoration:none;font-weight:700}.ghost{background:#ede8df;color:#2a1f14}.badge{padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}.pending{background:#fff1c7;color:#8a6200}.approved{background:#dff3d8;color:#1e3a1a}small{color:#6c5b49}</style></head>
  <body><div class="wrap"><div class="top"><div><h1>Progress Follow-ups</h1><p>${items.length} submission(s)</p></div><div><a class="btn ghost" href="/admin">Back to orders</a> <a class="btn ghost" href="/admin/followups.csv">Export CSV</a></div></div>
  <div class="panel"><table><thead><tr><th>Customer</th><th>Review point</th><th>Measurements</th><th>Practicality</th><th>Concern / question</th><th>Admin response</th><th>Action</th></tr></thead><tbody>${rows || '<tr><td colspan="7">No follow-ups yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function findFollowup(db, orderId, followupId) {
  const order = findOrder(db, orderId);
  if (!order) return {};
  const followup = (order.followups || []).find(f => f.id === followupId);
  return { order, followup };
}

function adminFollowupReviewPage(order, followup, message = '') {
  const adj = followup.adminAdjustment || {};
  return `<!doctype html><html><head><meta charset="utf-8"><title>Review Follow-up</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:980px;margin:0 auto;padding:28px}.card{background:#fff;border-radius:18px;padding:22px;box-shadow:0 10px 35px #0001;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;font-weight:800;margin-bottom:4px}.box{background:#faf7f1;border:1px solid #e2dbcf;border-radius:10px;padding:11px;line-height:1.55}select,textarea{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:11px;font:14px Arial,sans-serif;background:#fffdf9}textarea{min-height:92px}.btn{border:0;background:#1e3a1a;color:#fff;padding:12px 16px;border-radius:10px;font-weight:800;cursor:pointer}.ghost{display:inline-block;background:#ede8df;color:#2a1f14;text-decoration:none}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}@media(max-width:700px){.grid{grid-template-columns:1fr}}</style></head>
  <body><div class="wrap"><div class="card"><h1>Follow-up Review</h1><p>${escapeHtml(order.name)} - ${escapeHtml(order.packageName)} - ${escapeHtml(followup.reviewPoint)}</p><a class="btn ghost" href="/admin/followups">Back to follow-ups</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Order review</a></div>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <div class="card"><h2>Customer Submission</h2><div class="grid">
    <div class="box"><div class="label">Measurements</div>Weight: ${escapeHtml(followup.weight || '-')}<br>Waist: ${escapeHtml(followup.waist || '-')}<br>Reading: ${escapeHtml(followup.clinicalReading || '-')}</div>
    <div class="box"><div class="label">Scores</div>Energy: ${escapeHtml(followup.energy || '-')} / 10<br>Adherence: ${escapeHtml(followup.adherence || '-')} / 10<br>Submitted: ${escapeHtml(new Date(followup.createdAt).toLocaleString())}</div>
    <div class="box"><div class="label">Outcome and taste</div>Trend: ${escapeHtml(followup.outcomeTrend || '-')}<br>Taste satisfaction: ${escapeHtml(followup.tasteSatisfaction || '-')} / 10</div>
    <div class="box"><div class="label">Practicality burden</div>Budget: ${escapeHtml(followup.budgetDifficulty || '-')} / 10<br>Cooking: ${escapeHtml(followup.cookingDifficulty || '-')} / 10<br>Availability: ${escapeHtml(followup.foodAvailabilityDifficulty || '-')} / 10<br>Meal prep: ${escapeHtml(followup.mealPrepBurden || '-')} / 10</div>
    <div class="box"><div class="label">Appetite</div>${nl2br(followup.appetite || '-')}</div>
    <div class="box"><div class="label">Symptoms</div>${nl2br(followup.symptoms || '-')}</div>
    <div class="box"><div class="label">Household support</div>${nl2br(followup.householdSupport || '-')}</div>
    <div class="box"><div class="label">Foods causing symptoms</div>${nl2br(followup.foodsCausingSymptoms || '-')}</div>
    <div class="box"><div class="label">Expensive / hard-to-cook meals</div>${nl2br((followup.expensiveMeals || '-') + '\\n\\n' + (followup.hardToCookMeals || ''))}</div>
    <div class="box"><div class="label">Requested substitutions</div>${nl2br(followup.requestedSubstitutions || '-')}</div>
    <div class="box"><div class="label">Disliked / difficult foods</div>${nl2br(followup.dislikedFoods || '-')}</div>
    <div class="box"><div class="label">Repeated meals / question</div>${nl2br((followup.repeatedMeals || '-') + '\\n\\n' + (followup.question || ''))}</div>
  </div></div>
  <form class="card" method="post" action="/admin/orders/${escapeHtml(order.id)}/followups/${escapeHtml(followup.id)}">
    <h2>Admin Adjustment</h2>
    <p><label class="label">Action</label><select name="action"><option value="continue" ${adj.action === 'continue' ? 'selected' : ''}>Continue as is</option><option value="increase_calories" ${adj.action === 'increase_calories' ? 'selected' : ''}>Increase calories</option><option value="decrease_calories" ${adj.action === 'decrease_calories' ? 'selected' : ''}>Decrease calories</option><option value="change_meals" ${adj.action === 'change_meals' ? 'selected' : ''}>Change meal options</option><option value="request_labs" ${adj.action === 'request_labs' ? 'selected' : ''}>Request labs/readings</option><option value="schedule_consult" ${adj.action === 'schedule_consult' ? 'selected' : ''}>Schedule consultation</option><option value="escalate_clinician" ${adj.action === 'escalate_clinician' ? 'selected' : ''}>Escalate to clinician</option></select></p>
    <p><label class="label">Escalation status</label><select name="escalationStatus"><option value="routine" ${adj.escalationStatus === 'routine' ? 'selected' : ''}>Routine</option><option value="watch" ${adj.escalationStatus === 'watch' ? 'selected' : ''}>Watch closely</option><option value="escalate" ${adj.escalationStatus === 'escalate' ? 'selected' : ''}>Escalate clinically</option><option value="urgent" ${adj.escalationStatus === 'urgent' ? 'selected' : ''}>Urgent referral advised</option></select></p>
    <p><label class="label">Adjustment note</label><textarea name="note" placeholder="What should the customer change now?">${escapeHtml(adj.note || '')}</textarea></p>
    <p><label class="label">Requested labs / readings</label><textarea name="requestedLabs" placeholder="BP log, fasting glucose, HbA1c, eGFR, potassium...">${escapeHtml(adj.requestedLabs || '')}</textarea></p>
    <p><label class="label">Next review timing</label><textarea name="nextReview" placeholder="e.g. Submit another follow-up in 14 days">${escapeHtml(adj.nextReview || '')}</textarea></p>
    <button class="btn">Save adjustment</button>
  </form></div></body></html>`;
}

async function handleAdminFollowupReview(req, res, orderId, followupId) {
  const db = readDb();
  const { order, followup } = findFollowup(db, orderId, followupId);
  if (!order || !followup) return sendHtml(res, 404, 'Follow-up not found');
  if (req.method === 'GET') return sendHtml(res, 200, adminFollowupReviewPage(order, followup));
  const form = await readForm(req);
  followup.adminAdjustment = {
    action: String(form.action || '').trim(),
    escalationStatus: String(form.escalationStatus || '').trim(),
    note: String(form.note || '').trim(),
    requestedLabs: String(form.requestedLabs || '').trim(),
    nextReview: String(form.nextReview || '').trim(),
    updatedAt: new Date().toISOString()
  };
  order.updatedAt = followup.adminAdjustment.updatedAt;
  auditAdminAction(db, req, 'followup-adjustment', {
    orderId: order.id,
    customer: order.email,
    followupId: followup.id,
    action: followup.adminAdjustment.action,
    escalationStatus: followup.adminAdjustment.escalationStatus
  });
  writeDb(db);
  await sendFollowupAdjustmentEmail(order, followup).catch(err => {
    order.emailLog = Array.isArray(order.emailLog) ? order.emailLog : [];
    order.emailLog.push({ at: new Date().toISOString(), type: 'followup-adjustment', error: err.message });
    writeDb(db);
  });
  return sendHtml(res, 200, adminFollowupReviewPage(order, followup, 'Follow-up adjustment saved.'));
}

async function handleFollowupReminder(req, res, id) {
  const form = await readForm(req);
  const db = readDb();
  const order = findOrder(db, id);
  if (!order || order.status !== 'approved') return sendHtml(res, 404, 'Approved order not found');
  const reviewPoint = String(form.reviewPoint || 'progress review').trim();
  auditAdminAction(db, req, 'followup-reminder', { orderId: order.id, customer: order.email, reviewPoint });
  writeDb(db);
  await sendFollowupReminderEmail(order, reviewPoint).catch(err => {
    order.emailLog = Array.isArray(order.emailLog) ? order.emailLog : [];
    order.emailLog.push({ at: new Date().toISOString(), type: 'followup-reminder', error: err.message, reviewPoint });
    writeDb(db);
  });
  redirect(res, '/admin?status=approved');
}

function exportFollowupsCsv(res) {
  const db = readDb();
  const header = ['orderId','name','email','phone','packageName','reviewPoint','createdAt','weight','waist','clinicalReading','energy','adherence','outcomeTrend','tasteSatisfaction','budgetDifficulty','cookingDifficulty','foodAvailabilityDifficulty','mealPrepBurden','appetite','symptoms','householdSupport','foodsCausingSymptoms','expensiveMeals','hardToCookMeals','dislikedFoods','repeatedMeals','requestedSubstitutions','question','adminAction','adminEscalationStatus','adminNote','requestedLabs','nextReview'];
  const rows = allFollowups(db).map(({ order, followup }) => {
    const adj = followup.adminAdjustment || {};
    const row = {
      orderId: order.id,
      name: order.name,
      email: order.email,
      phone: order.phone,
      packageName: order.packageName,
      ...followup,
      adminAction: adj.action || '',
      adminEscalationStatus: adj.escalationStatus || '',
      adminNote: adj.note || '',
      requestedLabs: adj.requestedLabs || '',
      nextReview: adj.nextReview || ''
    };
    return header.map(k => csvEscape(row[k])).join(',');
  });
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-followups.csv"'
  });
  res.end([header.join(','), ...rows].join('\n'));
}

async function handleApprove(req, res, id) {
  const form = await readForm(req);
  const db = readDb();
  const order = findOrder(db, id);
  if (!order) return sendHtml(res, 404, 'Order not found');
  if (order.kind !== 'template' && order.kind !== 'subscription' && !(order.adminReview && order.adminReview.checklistComplete)) return redirect(res, `/admin/orders/${encodeURIComponent(id)}/review`);
  auditAdminAction(db, req, 'order-approve', { orderId: order.id, customer: order.email });
  approveOrder(db, order, form);
  redirect(res, '/admin?status=pending');
}

async function handleReject(req, res, id) {
  const form = await readForm(req);
  const db = readDb();
  const order = findOrder(db, id);
  if (!order) return sendHtml(res, 404, 'Order not found');
  order.status = 'rejected';
  order.updatedAt = new Date().toISOString();
  order.rejectedAt = order.updatedAt;
  order.adminNote = form.note || '';
  auditAdminAction(db, req, 'order-reject', { orderId: order.id, customer: order.email, note: order.adminNote });
  writeDb(db);
  queueOrderEmail(order, 'rejection', () => sendRejectionEmail(order));
  redirect(res, '/admin?status=pending');
}

async function handleResend(req, res, id) {
  const db = readDb();
  const order = findOrder(db, id);
  if (!order || order.status !== 'approved') return sendHtml(res, 404, 'Approved order not found');
  auditAdminAction(db, req, 'plan-email-resend', { orderId: order.id, customer: order.email });
  writeDb(db);
  queueOrderEmail(order, 'resend', () => sendApprovalEmail(order));
  redirect(res, '/admin?status=approved');
}

function csvEscape(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function exportCsv(res) {
  const db = readDb();
  const header = ['id','createdAt','status','name','email','phone','customerSource','customerType','referralCode','packageName','amount','orderType','consultationAddon','network','txRef','approvalCode','riskScore','confidence','safetyStatus','safetyLabel','auditScore','auditStatus','auditLabel','auditBlockers','auditWarnings','auditUniqueMeals','auditWeeks','adminReviewComplete','adminClinicalNote','customerReleaseNote','adminApprovalCondition','adminRequestedLab','adminDietaryCorrection','adminFollowUpInstruction','actualAmountPaid','paymentVerifier','paymentMismatchReason','urgencyLevel','clinicianReferralRecommended','referralReason','redFlagSymptoms','medicationClass','adminOverrideReason','planVersion','rulesEngineVersion','recipeDatabaseVersion','rulesOverall','ruleReview','ruleCaution','contraindications','reviewGates','cautions','conditionChapters','diagnosis','diagnosisDate','allergies','foodDislikes','culturalFoods','symptoms','redFlags','monitoring','clinicianStatus','specialStatus','waist','waistRisk','adminNote'];
  const rows = db.orders.map(o => {
    const cs = o.clinicalSummary || {};
    const safety = cs.safetyDecision || {};
    const rules = cs.clinicalRules || {};
    const audit = cs.planAudit || {};
    const review = o.adminReview || {};
    const row = {
      ...o,
      orderType: o.orderType || (o.consultationAddon ? 'Nutrition Plan + Consultation Add-on' : 'Nutrition Plan'),
      consultationAddon: o.consultationAddon ? 'yes' : 'no',
      customerSource: cs.customerSource || '',
      customerType: cs.customerType || '',
      referralCode: cs.referralCode || '',
      riskScore: cs.riskScore || '',
      confidence: cs.confidence && cs.confidence.level ? cs.confidence.level : '',
      safetyStatus: safety.status || '',
      safetyLabel: safety.label || '',
      auditScore: audit.score ?? '',
      auditStatus: audit.status || '',
      auditLabel: audit.label || '',
      auditBlockers: Array.isArray(audit.blockers) ? audit.blockers.join(' | ') : '',
      auditWarnings: Array.isArray(audit.warnings) ? audit.warnings.join(' | ') : '',
      auditUniqueMeals: audit.stats && audit.stats.uniqueMeals ? audit.stats.uniqueMeals : '',
      auditWeeks: audit.stats && audit.stats.weeks ? audit.stats.weeks : '',
      adminReviewComplete: review.checklistComplete ? 'yes' : 'no',
      adminClinicalNote: review.clinicalNote || '',
      customerReleaseNote: review.customerReleaseNote || '',
      adminApprovalCondition: review.approvalCondition || '',
      adminRequestedLab: review.requestedLab || '',
      adminDietaryCorrection: review.dietaryCorrection || '',
      adminFollowUpInstruction: review.followUpInstruction || '',
      actualAmountPaid: review.actualAmountPaid || '',
      paymentVerifier: review.paymentVerifier || '',
      paymentMismatchReason: review.paymentMismatchReason || '',
      urgencyLevel: review.urgencyLevel || '',
      clinicianReferralRecommended: review.clinicianReferralRecommended ? 'yes' : 'no',
      referralReason: review.referralReason || '',
      redFlagSymptoms: review.redFlagSymptoms || '',
      medicationClass: review.medicationClass || '',
      adminOverrideReason: review.adminOverrideReason || '',
      planVersion: review.planVersion || '',
      rulesEngineVersion: review.rulesEngineVersion || '',
      recipeDatabaseVersion: review.recipeDatabaseVersion || '',
      rulesOverall: rules.overallDecision || '',
      ruleReview: Array.isArray(rules.review) ? rules.review.map(r => `${r.area || ''}: ${r.title || ''}`).join(' | ') : '',
      ruleCaution: Array.isArray(rules.caution) ? rules.caution.map(r => `${r.area || ''}: ${r.title || ''}`).join(' | ') : '',
      contraindications: Array.isArray(rules.contraindications) ? rules.contraindications.map(c => `${c.area || ''}: ${c.reason || ''}`).join(' | ') : '',
      reviewGates: Array.isArray(safety.review) ? safety.review.join(' | ') : '',
      cautions: Array.isArray(safety.caution) ? safety.caution.join(' | ') : '',
      conditionChapters: Array.isArray(cs.conditionChapters) ? cs.conditionChapters.map(c => c.title).filter(Boolean).join(' | ') : '',
      diagnosis: cs.diagnosis || '',
      diagnosisDate: cs.diagnosisDate || '',
      allergies: cs.allergies || '',
      foodDislikes: cs.foodDislikes || '',
      culturalFoods: cs.culturalFoods || '',
      symptoms: cs.symptoms || '',
      redFlags: cs.redFlags || '',
      monitoring: cs.monitoring || '',
      clinicianStatus: cs.clinicianStatus || '',
      specialStatus: cs.specialStatus || '',
      waist: cs.waist || '',
      waistRisk: cs.waistRisk || ''
    };
    return header.map(k => csvEscape(row[k])).join(',');
  });
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-orders.csv"'
  });
  res.end([header.join(','), ...rows].join('\n'));
}

function exportLeadsCsv(res) {
  const db = readDb();
  const header = ['id','createdAt','updatedAt','status','name','email','phone','goal','planType','bmi','conditions','customerSource','referralCode','marketingStage','paidOrderId','consentAccepted','consentAt','consentVersion','age','sex','height','weight','activity','budget','cooking','allergies','foodDislikes','symptoms','redFlags'];
  const rows = (db.leads || []).map(l => {
    const p = l.profile || {};
    const row = {
      id: l.id,
      createdAt: l.createdAt,
      updatedAt: l.updatedAt,
      status: l.status,
      name: l.name,
      email: l.email,
      phone: l.phone,
      goal: l.goal,
      planType: l.planType,
      bmi: l.bmi,
      conditions: Array.isArray(l.conditions) ? l.conditions.join('; ') : '',
      customerSource: l.customerSource,
      referralCode: l.referralCode,
      marketingStage: l.marketingStage,
      paidOrderId: l.paidOrderId,
      consentAccepted: l.consentAccepted ? 'yes' : 'no',
      consentAt: l.consentAt,
      consentVersion: l.consentVersion,
      age: p.age,
      sex: p.sex,
      height: p.height,
      weight: p.weight,
      activity: p.activity,
      budget: p.budget,
      cooking: p.cooking,
      allergies: p.allergies,
      foodDislikes: p.foodDislikes,
      symptoms: p.symptoms,
      redFlags: p.redFlags
    };
    return header.map(key => csvEscape(row[key])).join(',');
  });
  res.writeHead(200, securityHeaders({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-free-assessment-leads.csv"'
  }));
  res.end([header.join(','), ...rows].join('\n'));
}

function exportMemberProgressCsv(res) {
  const db = readDb();
  const header = ['id','createdAt','email','name','orderId','weight','waist','bloodPressure','bloodSugar','hunger','mood','energy','sleep','cravings','bowelHabits','symptoms','cyclePregnancyNotes','notes'];
  const rows = (db.progressEntries || []).map(row => header.map(k => csvEscape(row[k])).join(','));
  res.writeHead(200, securityHeaders({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-member-progress.csv"'
  }));
  res.end([header.join(','), ...rows].join('\n'));
}

function exportFoodDiaryCsv(res) {
  const db = readDb();
  const header = ['id','createdAt','email','name','orderId','mealTime','meal','portion','hungerBefore','fullnessAfter','taste','cost','symptomsAfter','dislikedRepeated','replacementRequest'];
  const rows = (db.foodDiary || []).map(row => header.map(k => csvEscape(row[k])).join(','));
  res.writeHead(200, securityHeaders({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-food-diary.csv"'
  }));
  res.end([header.join(','), ...rows].join('\n'));
}

function exportCoachQueueCsv(res) {
  const header = ['email','name','phone','severity','score','latestAt','plan','orderStatus','progressCount','diaryCount','signals'];
  const rows = buildCoachReviewQueue().map(item => {
    const order = item.latestOrder || {};
    const row = {
      email: item.email,
      name: item.name,
      phone: item.phone,
      severity: item.severity,
      score: item.score,
      latestAt: item.latestAt,
      plan: order.packageName || '',
      orderStatus: order.status || '',
      progressCount: item.progressCount,
      diaryCount: item.diaryCount,
      signals: item.signals.map(s => `${s.label}: ${s.detail}`).join(' | ')
    };
    return header.map(k => csvEscape(row[k])).join(',');
  });
  res.writeHead(200, securityHeaders({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="bulamu360-coach-review-queue.csv"'
  }));
  res.end([header.join(','), ...rows].join('\n'));
}

function servePlanByOrder(res, order, download = false, audience = 'patient', pdfUrl = '') {
  if (!order) return sendHtml(res, 404, 'Plan not found');
  // Plans are delivered as real PDFs: the page renders the plan and converts it in the browser
  // (assets/bulamu360/b360-pdf.js). "download" links start the PDF automatically.
  const html = sanitizePlanHtml(planHtmlForOrder(order, { audience }));
  const pdfName = String(planAttachmentFileName(order) || 'Bulamu360_Plan').replace(/\.(html?|pdf)$/i, '') + '.pdf';
  if (pdfUrl && download) { res.writeHead(302, securityHeaders({ Location: pdfUrl })); return res.end(); }
  const tool = `<div data-no-pdf style="position:fixed;right:18px;bottom:18px;z-index:99999;font-family:Outfit,Arial,sans-serif"><button type="button" id="b3-pdf-btn" style="display:inline-flex;align-items:center;gap:8px;background:#17693f;color:#fff;border:0;border-radius:999px;padding:14px 22px;font-size:15px;font-weight:600;cursor:pointer;box-shadow:0 12px 30px rgba(18,53,36,.3)">Download PDF</button></div>
<script src="/assets/bulamu360/b360-pdf.js"></script>
<script>(function(){var b=document.getElementById('b3-pdf-btn');function go(){if(${JSON.stringify(pdfUrl)}){location.href=${JSON.stringify(pdfUrl)};return;}if(!window.B360PDF){alert('The PDF tool could not load. Check your connection and try again.');return;}b.disabled=true;window.B360PDF.fromHtml(document.documentElement.outerHTML, ${JSON.stringify(pdfName)}).catch(function(e){alert(e.message);}).then(function(){b.disabled=false;});}b.addEventListener('click',go);${download ? "window.addEventListener('load',function(){setTimeout(go,500);});" : ''}})();</script>`;
  const out = html.includes('</body>') ? html.replace(/<\/body>(?![\s\S]*<\/body>)/i, tool + '</body>') : html + tool;
  sendHtml(res, 200, out);
}

function isPrivateStaticPath(requested) {
  const clean = String(requested || '').replace(/\\/g, '/').toLowerCase();
  const parts = clean.split('/').filter(Boolean);
  if (parts.some(part => part.startsWith('.'))) return true;
  if (parts.includes('data')) return true;
  if (parts[0] === 'lib') return true;
  if (clean === '/recipes.js') return true;
  if (clean.endsWith('.env') || clean.includes('.env.')) return true;
  if (clean.endsWith('.log') || clean.endsWith('.sql') || clean.endsWith('.yaml') || clean.endsWith('.yml')) return true;
  if (clean.endsWith('.bat') || clean.endsWith('.cmd') || clean.endsWith('.ps1')) return true;
  if (clean === '/server.js' || clean === '/package.json' || clean === '/package-lock.json') return true;
  if (clean === '/admin-dashboard.html' || clean === '/admin-login.html') return true;
  return false;
}

async function serveStatic(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const originalPath = decodeURIComponent(url.pathname);
  let requested = originalPath;
  if (requested === '/') requested = '/bulamu360-source.html';
  if (requested === '/website') requested = '/bulamu360-website.html';
  if (requested === '/app') requested = '/bulamu360-source.html';
  if (requested === '/privacy') requested = '/privacy.html';
  if (requested === '/terms') requested = '/terms.html';
  if (requested === '/disclaimer') requested = '/terms.html';
  if (originalPath === '/bulamu360-source.html') {
    res.writeHead(302, securityHeaders({ Location: '/app' }));
    return res.end();
  }
  if (isPrivateStaticPath(requested)) return sendHtml(res, 403, 'Private file.');
  const fullPath = normalize(join(root, requested));
  if (!fullPath.startsWith(root)) return sendHtml(res, 403, 'Forbidden');
  try {
    const file = await readFile(fullPath);
    const ext = extname(fullPath);
    const isStaticAsset = ['.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg', '.ico', '.css', '.js'].includes(ext);
    res.writeHead(200, securityHeaders({
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-store' : (isStaticAsset ? 'public, max-age=31536000, immutable' : 'public, max-age=300')
    }));
    res.end(file);
  } catch {
    sendHtml(res, 404, 'Not found');
  }
}

/* =====================================================================
   BULAMU360 TRACKER - additive server module
   - Client sharing API (auth = existing approved-order approval code + email)
   - Secure practitioner <-> client messaging
   - Practitioner dashboard (/admin/clients, /admin/groups) behind existing admin auth
   - USDA FoodData Central proxy (optional FDC_API_KEY) and recipe URL import
   Data lives in db.tracker; existing db.orders is only read, never modified.
===================================================================== */
const TRACKER_SESSION_DAYS = 90;
const TRACKER_MAX_SNAPSHOT = 400_000;
const fdcApiKey = process.env.FDC_API_KEY || 'DEMO_KEY';
const fdcCache = new Map();

function trackerState(db) {
  if (!db.tracker || typeof db.tracker !== 'object') db.tracker = {};
  const t = db.tracker;
  if (!t.sessions || typeof t.sessions !== 'object') t.sessions = {};
  if (!t.clients || typeof t.clients !== 'object') t.clients = {};
  if (!t.messages || typeof t.messages !== 'object') t.messages = {};
  if (!t.groups || typeof t.groups !== 'object') t.groups = {};
  if (!t.templates || typeof t.templates !== 'object') t.templates = {};
  if (!Array.isArray(t.audit)) t.audit = [];
  return t;
}
function trackerAudit(db, action, orderId, detail = '') {
  const t = trackerState(db);
  t.audit.unshift({ at: new Date().toISOString(), action, orderId: orderId || '', detail: shortText(detail, 200) });
  if (t.audit.length > 1000) t.audit.length = 1000;
}
function hashToken(token) { return createHash('sha256').update(String(token)).digest('hex'); }
function trackerClientFromToken(db, token) {
  const t = trackerState(db);
  const s = token && t.sessions[hashToken(token)];
  if (!s || s.expiresAt < Date.now()) return null;
  const order = db.orders.find(o => o.id === s.orderId && o.status === 'approved');
  return order ? { order, session: s } : null;
}
/* Deep-sanitise client JSON: finite numbers, short strings, bounded arrays/depth. */
function sanitiseSnapshot(value, depth = 0) {
  if (depth > 7) return null;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') return value.slice(0, 200);
  if (Array.isArray(value)) return value.slice(0, 4000).map(v => sanitiseSnapshot(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 200)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      out[String(k).slice(0, 60)] = sanitiseSnapshot(v, depth + 1);
    }
    return out;
  }
  return null;
}
function clientRecord(db, orderId) {
  const t = trackerState(db);
  if (!t.clients[orderId]) t.clients[orderId] = { orderId, groups: [], assigned: null, snapshot: null, sharedAt: null };
  return t.clients[orderId];
}
function clientMessages(db, orderId) {
  const t = trackerState(db);
  if (!Array.isArray(t.messages[orderId])) t.messages[orderId] = [];
  return t.messages[orderId];
}
function publicMessages(list) {
  return list.slice(-200).map(m => ({ id: m.id, from: m.from, body: m.body, at: m.at, readByPractitioner: Boolean(m.readByPractitioner), readByClient: Boolean(m.readByClient) }));
}
function unreadForClient(db, orderId) { return clientMessages(db, orderId).filter(m => m.from === 'practitioner' && !m.readByClient).length; }
function unreadForPractitioner(db, orderId) { return clientMessages(db, orderId).filter(m => m.from === 'client' && !m.readByPractitioner).length; }

async function handleTrackerApi(req, res, url) {
  const route = url.pathname.replace('/api/tracker/', '');
  const payload = await readRequestJson(req).catch(() => null);
  if (!payload || typeof payload !== 'object') return sendJson(res, 400, { ok: false, error: 'Invalid request.' });
  const db = readDb();
  const t = trackerState(db);
  if (route === 'session') {
    const code = String(payload.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const email = String(payload.email || '').trim().toLowerCase();
    if (!code || !email) return sendJson(res, 400, { ok: false, error: 'Enter your approval code and the email used on your order.' });
    const order = db.orders.find(o => o.status === 'approved' && String(o.approvalCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '') === code);
    if (!order || String(order.email || '').toLowerCase() !== email) {
      return sendJson(res, 404, { ok: false, error: 'No approved plan matches that approval code and email.' });
    }
    const token = randomBytes(32).toString('hex');
    const now = Date.now();
    for (const [h, s] of Object.entries(t.sessions)) if (s.expiresAt < now) delete t.sessions[h];
    const mine = Object.entries(t.sessions).filter(([, s]) => s.orderId === order.id).sort((a, b) => a[1].createdAt - b[1].createdAt);
    while (mine.length >= 5) delete t.sessions[mine.shift()[0]];
    t.sessions[hashToken(token)] = { orderId: order.id, createdAt: now, expiresAt: now + TRACKER_SESSION_DAYS * 864e5 };
    clientRecord(db, order.id);
    trackerAudit(db, 'client-signin', order.id);
    writeDb(db);
    return sendJson(res, 200, { ok: true, token, expiresAt: new Date(now + TRACKER_SESSION_DAYS * 864e5).toISOString(), client: { id: order.id, name: order.name, packageName: order.packageName } });
  }
  const auth = trackerClientFromToken(db, payload.token);
  if (!auth) return sendJson(res, 401, { ok: false, error: 'Session expired. Please sign in again.' });
  const orderId = auth.order.id;
  const rec = clientRecord(db, orderId);
  if (route === 'signout') {
    delete t.sessions[hashToken(payload.token)];
    trackerAudit(db, 'client-signout', orderId);
    writeDb(db);
    return sendJson(res, 200, { ok: true });
  }
  if (route === 'status') return sendJson(res, 200, { ok: true, unread: unreadForClient(db, orderId), assigned: rec.assigned || null });
  if (route === 'sync') {
    const raw = JSON.stringify(payload.snapshot || null);
    if (!payload.snapshot || raw.length > TRACKER_MAX_SNAPSHOT) return sendJson(res, 413, { ok: false, error: 'Shared data is missing or too large.' });
    rec.snapshot = sanitiseSnapshot(payload.snapshot);
    rec.sharedAt = new Date().toISOString();
    trackerAudit(db, 'client-shared', orderId, `${raw.length} bytes`);
    writeDb(db);
    return sendJson(res, 200, { ok: true, sharedAt: rec.sharedAt, assigned: rec.assigned || null, unread: unreadForClient(db, orderId) });
  }
  if (route === 'messages') {
    const list = clientMessages(db, orderId);
    let changed = false;
    for (const m of list) if (m.from === 'practitioner' && !m.readByClient) { m.readByClient = new Date().toISOString(); changed = true; }
    if (changed) writeDb(db);
    return sendJson(res, 200, { ok: true, messages: publicMessages(list), assigned: rec.assigned || null, unread: 0 });
  }
  if (route === 'message') {
    const body = String(payload.body || '').trim().slice(0, 2000);
    if (!body) return sendJson(res, 400, { ok: false, error: 'Message is empty.' });
    const list = clientMessages(db, orderId);
    const recent = list.filter(m => m.from === 'client' && Date.now() - Date.parse(m.at) < 60_000).length;
    if (recent >= 5) return sendJson(res, 429, { ok: false, error: 'Please wait a minute before sending more messages.' });
    list.push({ id: randomUUID(), from: 'client', body, at: new Date().toISOString(), readByPractitioner: false, readByClient: true });
    if (list.length > 500) list.splice(0, list.length - 500);
    trackerAudit(db, 'client-message', orderId);
    writeDb(db);
    if (ownerEmail) {
      // Notification only; the message content stays in the dashboard.
      sendResendEmail({ to: ownerEmail, subject: `New Bulamu360 tracker message - ${auth.order.name}`, html: `<p>${escapeHtml(auth.order.name)} sent you a message in the Bulamu360 tracker.</p><p><a href="${publicBaseUrl}/admin/clients/${encodeURIComponent(orderId)}">Open the client in the practitioner dashboard</a></p>` }).catch(err => console.error('Tracker message email failed:', err.message));
    }
    return sendJson(res, 200, { ok: true, messages: publicMessages(list) });
  }
  return sendJson(res, 404, { ok: false, error: 'Unknown tracker action.' });
}

/* ---------- USDA FoodData Central proxy (keeps the key server-side, caches results) ---------- */
async function fdcFetch(path, params) {
  const qs = new URLSearchParams({ ...params, api_key: fdcApiKey });
  const key = path + '?' + new URLSearchParams(params).toString();
  const hit = fdcCache.get(key);
  if (hit && Date.now() - hit.at < 24 * 3600_000) return hit.data;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12_000);
  try {
    const r = await fetch(`https://api.nal.usda.gov/fdc/v1/${path}?${qs}`, { signal: ctrl.signal });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(r.status === 429 ? 'USDA lookup limit reached; try again later.' : `USDA lookup failed (${r.status}).`); e.status = r.status === 429 ? 429 : 502; throw e; }
    fdcCache.set(key, { at: Date.now(), data });
    if (fdcCache.size > 600) fdcCache.delete(fdcCache.keys().next().value);
    return data;
  } finally { clearTimeout(timer); }
}
function slimFdcFood(f) {
  return {
    fdcId: f.fdcId, description: f.description, dataType: f.dataType, brandOwner: f.brandOwner, brandName: f.brandName,
    foodCategory: typeof f.foodCategory === 'object' && f.foodCategory ? f.foodCategory.description : f.foodCategory,
    gtinUpc: f.gtinUpc, ingredients: f.ingredients, servingSize: f.servingSize, servingSizeUnit: f.servingSizeUnit, householdServingFullText: f.householdServingFullText,
    foodMeasures: (f.foodMeasures || []).slice(0, 10).map(m => ({ disseminationText: m.disseminationText, gramWeight: m.gramWeight })),
    foodPortions: (f.foodPortions || []).slice(0, 10).map(m => ({ amount: m.amount, modifier: m.modifier, portionDescription: m.portionDescription, gramWeight: m.gramWeight, measureUnit: m.measureUnit ? { name: m.measureUnit.name } : undefined })),
    foodNutrients: (f.foodNutrients || []).map(n => ({ nutrientNumber: n.nutrientNumber || (n.nutrient && n.nutrient.number), value: n.value != null ? n.value : n.amount })).filter(n => n.nutrientNumber && n.value != null)
  };
}
async function handleFoodsProxy(req, res, url) {
  try {
    if (url.pathname === '/api/foods/search') {
      const q = String(url.searchParams.get('q') || '').trim().slice(0, 80);
      const page = Math.max(1, Math.min(50, Number(url.searchParams.get('page')) || 1));
      if (q.length < 2) return sendJson(res, 400, { ok: false, error: 'Search needs at least 2 characters.' });
      const data = await fdcFetch('foods/search', { query: q, pageSize: '25', pageNumber: String(page), dataType: 'Foundation,SR Legacy,Survey (FNDDS),Branded' });
      return sendJson(res, 200, { ok: true, totalHits: data.totalHits || 0, totalPages: data.totalPages || 1, foods: (data.foods || []).map(slimFdcFood) });
    }
    const m = url.pathname.match(/^\/api\/foods\/fdc\/(\d{1,10})$/);
    if (m) return sendJson(res, 200, slimFdcFood(await fdcFetch(`food/${m[1]}`, {})));
    return sendJson(res, 404, { ok: false, error: 'Not found' });
  } catch (error) {
    return sendJson(res, error.status || 502, { ok: false, error: error.name === 'AbortError' ? 'USDA lookup timed out.' : error.message });
  }
}

/* ---------- Recipe URL import (schema.org Recipe JSON-LD) with SSRF protection ---------- */
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateAddress(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}
async function assertPublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw Object.assign(new Error('That is not a valid web address.'), { status: 400 }); }
  if (!['http:', 'https:'].includes(u.protocol)) throw Object.assign(new Error('Only http and https addresses are supported.'), { status: 400 });
  if (u.username || u.password) throw Object.assign(new Error('Addresses with credentials are not allowed.'), { status: 400 });
  if (u.port && !['80', '443'].includes(u.port)) throw Object.assign(new Error('That port is not allowed.'), { status: 400 });
  const addrs = await dnsLookup(u.hostname, { all: true }).catch(() => []);
  if (!addrs.length) throw Object.assign(new Error('That website could not be found.'), { status: 400 });
  if (addrs.some(a => isPrivateAddress(a.address))) throw Object.assign(new Error('That address is not allowed.'), { status: 400 });
  return u;
}
function decodeEntities(s) {
  return String(s || '').replace(/<[^>]*>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n))).replace(/\s+/g, ' ').trim();
}
function findRecipeNode(node, depth = 0) {
  if (!node || depth > 6) return null;
  if (Array.isArray(node)) { for (const n of node) { const r = findRecipeNode(n, depth + 1); if (r) return r; } return null; }
  if (typeof node !== 'object') return null;
  const type = node['@type'];
  if (type === 'Recipe' || (Array.isArray(type) && type.includes('Recipe'))) return node;
  if (node['@graph']) return findRecipeNode(node['@graph'], depth + 1);
  if (node.mainEntity) return findRecipeNode(node.mainEntity, depth + 1);
  return null;
}
async function handleRecipeImport(req, res) {
  try {
    const payload = await readRequestJson(req);
    let target = await assertPublicUrl(String(payload.url || '').trim());
    let response;
    for (let hop = 0; hop < 4; hop++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 10_000);
      response = await fetch(target, { redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': 'Bulamu360-RecipeImport/1.0', Accept: 'text/html,application/xhtml+xml' } }).finally(() => clearTimeout(timer));
      if (response.status >= 300 && response.status < 400 && response.headers.get('location')) { target = await assertPublicUrl(new URL(response.headers.get('location'), target).toString()); continue; }
      break;
    }
    if (!response.ok) return sendJson(res, 502, { ok: false, error: `The website responded with ${response.status}.` });
    const reader = response.body.getReader();
    let html = '', size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 3_000_000) { reader.cancel(); break; }
      html += Buffer.from(value).toString('utf8');
    }
    let recipe = null;
    for (const m of html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
      try { recipe = findRecipeNode(JSON.parse(m[1].trim())); } catch { recipe = null; }
      if (recipe) break;
    }
    if (!recipe) return sendJson(res, 422, { ok: false, error: 'No structured recipe data was found on that page.' });
    const yieldRaw = Array.isArray(recipe.recipeYield) ? recipe.recipeYield[0] : recipe.recipeYield;
    const servings = Math.max(1, Math.min(100, parseInt(String(yieldRaw || '').match(/\d+/)?.[0] || '4', 10)));
    const ingredients = (Array.isArray(recipe.recipeIngredient) ? recipe.recipeIngredient : Array.isArray(recipe.ingredients) ? recipe.ingredients : []).slice(0, 80).map(decodeEntities).filter(Boolean).map(s => s.slice(0, 200));
    const nutrition = recipe.nutrition && typeof recipe.nutrition === 'object'
      ? Object.fromEntries(Object.entries(recipe.nutrition).filter(([k, v]) => k !== '@type' && typeof v === 'string').slice(0, 20).map(([k, v]) => [k.slice(0, 40), decodeEntities(v).slice(0, 40)]))
      : null;
    return sendJson(res, 200, { ok: true, name: decodeEntities(recipe.name).slice(0, 120), servings, ingredients, nutrition, source: target.toString() });
  } catch (error) {
    return sendJson(res, error.status || 502, { ok: false, error: error.name === 'AbortError' ? 'The website took too long to respond.' : (error.message || 'Import failed.') });
  }
}

/* Public route dispatcher. Returns true when the request was handled. */
async function handleTrackerPublicRoutes(req, res, url) {
  const p = url.pathname;
  if (req.method === 'GET' && p === '/tracker') { redirect(res, '/app#tracker'); return true; }
  if (req.method === 'GET' && p.startsWith('/api/foods/')) {
    if (!rateLimit(req, res, 'foods', { limit: 60, windowMs: 60_000 })) return true;
    await handleFoodsProxy(req, res, url); return true;
  }
  if (req.method === 'POST' && p === '/api/recipe-import') {
    if (!rateLimit(req, res, 'recipe-import', { limit: 10, windowMs: 60_000 })) return true;
    await handleRecipeImport(req, res); return true;
  }
  if (req.method === 'POST' && p.startsWith('/api/tracker/')) {
    const name = p.endsWith('/session') ? 'tracker-session' : 'tracker';
    if (!rateLimit(req, res, name, { limit: name === 'tracker-session' ? 10 : 120, windowMs: 60_000 })) return true;
    await handleTrackerApi(req, res, url); return true;
  }
  return false;
}

/* ---------- Practitioner dashboard (admin-only; requireAdmin has already run) ---------- */
function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }
function fmt0(v, d = 0) { return v == null || !Number.isFinite(v) ? '–' : Number(v).toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: 0 }); }
function dayKeyAgo(n) { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().slice(0, 10); }
function clientSummary(db, order) {
  const t = trackerState(db);
  const rec = t.clients[order.id] || { groups: [] };
  const snap = rec.snapshot || {};
  const days = Array.isArray(snap.days) ? snap.days : [];
  const since14 = dayKeyAgo(13);
  const recent = days.filter(d => d && d.date >= since14);
  const target = num(snap.targets && snap.targets.energy);
  const assignedEnergy = num(rec.assigned && rec.assigned.energy);
  const goal = assignedEnergy || target;
  const within = goal ? recent.filter(d => num(d.energy) != null && Math.abs(d.energy - goal) / goal <= 0.1).length : null;
  const weights = (Array.isArray(snap.biometrics) ? snap.biometrics : []).filter(b => b && b.metric === 'weight' && num(b.value) != null).sort((a, b) => String(a.date).localeCompare(String(b.date)));
  const w30 = weights.filter(w => w.date >= dayKeyAgo(30));
  return {
    order, rec, snap, days, recent, loggedDays14: recent.length,
    avgKcal14: recent.length ? recent.reduce((s, d) => s + (num(d.energy) || 0), 0) / recent.length : null,
    goal, compliance: goal && recent.length ? within / recent.length : null,
    latestWeight: weights.length ? weights[weights.length - 1] : null,
    weightChange30: w30.length >= 2 ? w30[w30.length - 1].value - w30[0].value : null,
    unread: unreadForPractitioner(db, order.id),
    groups: (rec.groups || []).filter(g => t.groups[g])
  };
}
function trackerClientOrders(db) {
  const t = trackerState(db);
  const ids = new Set([...Object.keys(t.clients), ...Object.keys(t.messages)]);
  return db.orders.filter(o => ids.has(o.id));
}
function trackerAdminShell(title, body, active = 'clients') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · Bulamu360</title><link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
<style>
:root{--forest:#163d2a;--em:#1d7349;--sage:#edf3ee;--line:#dde1da;--ink:#1c2420;--muted:#5f6a64;--bg:#f5f6f3;--warn:#a8671a;--over:#a9492f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,'Segoe UI',Roboto,Arial,sans-serif}
a{color:var(--em)}.wrap{max-width:1320px;margin:0 auto;padding:24px}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:14px}.top h1{margin:0;font-size:24px;color:var(--forest)}.top p{margin:4px 0 0;color:var(--muted)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 16px}.tabs a{padding:7px 12px;border:1px solid var(--line);border-radius:6px;background:#fff;text-decoration:none;color:var(--ink);font-weight:600;font-size:13px}.tabs a.on{background:var(--sage);border-color:var(--em);color:var(--forest)}
.panel{background:#fff;border:1px solid var(--line);border-radius:10px;margin-bottom:16px;overflow:hidden}.panel h2{font-size:15px;margin:0;padding:12px 16px;border-bottom:1px solid var(--line)}.pad{padding:14px 16px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13px}th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:#f0f2ee}.r{text-align:right}
.scroll{overflow:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.btn{display:inline-block;border:1px solid var(--em);background:var(--em);color:#fff;padding:7px 12px;border-radius:6px;font-weight:600;font-size:13px;text-decoration:none;cursor:pointer}.ghost{background:#fff;color:var(--forest);border-color:var(--line)}.danger{background:#fff;color:var(--over);border-color:var(--over)}
input,select,textarea{font:inherit;padding:7px 9px;border:1px solid #c9cfc6;border-radius:6px;background:#fff;max-width:100%}textarea{width:100%;min-height:80px}
label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:8px}label input,label select{display:block;margin-top:3px;width:100%}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:700;background:#e6e9e3;color:var(--muted)}.ok{background:#d9e6dc;color:var(--forest)}.warn{background:#f8eedf;color:var(--warn)}.over{background:#f7e6e0;color:var(--over)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));border-top:1px solid var(--line)}.kpi{padding:10px 14px;border-right:1px solid var(--line)}.kpi span{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:700}.kpi b{font-size:20px}
.msg{max-width:78%;margin:8px 0;padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:#fff}.msg.me{margin-left:auto;background:var(--sage)}.msg small{display:block;color:var(--muted);font-size:11px;margin-top:3px}
.note{font-size:12px;color:var(--muted)}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
@media print{.tabs,.noprint{display:none!important}body{background:#fff}.panel{break-inside:avoid;border-color:#ccc}}
</style></head><body><div class="wrap">
<nav class="tabs noprint" aria-label="Admin navigation"><a href="/admin">Orders</a><a href="/admin/followups">Follow-ups</a><a href="/admin/clients" class="${active === 'clients' ? 'on' : ''}">Tracker clients</a><a href="/admin/groups" class="${active === 'groups' ? 'on' : ''}">Groups &amp; templates</a><a href="/admin/subscribers" class="${active === 'subscribers' ? 'on' : ''}">Accounts &amp; subscribers</a><a href="/admin/logout">Log out</a></nav>
${body}</div></body></html>`;
}
function adminClientsPage(db, url) {
  const t = trackerState(db);
  const q = String(url.searchParams.get('q') || '').trim().toLowerCase();
  const group = String(url.searchParams.get('group') || '');
  const unreadOnly = url.searchParams.get('unread') === '1';
  let rows = trackerClientOrders(db).map(o => clientSummary(db, o));
  if (q) rows = rows.filter(r => `${r.order.name} ${r.order.email} ${r.order.phone}`.toLowerCase().includes(q));
  if (group) rows = rows.filter(r => r.groups.includes(group));
  if (unreadOnly) rows = rows.filter(r => r.unread);
  rows.sort((a, b) => (b.unread - a.unread) || String(b.rec.sharedAt || '').localeCompare(String(a.rec.sharedAt || '')));
  const groupOpts = Object.entries(t.groups).map(([id, g]) => `<option value="${escapeHtml(id)}"${id === group ? ' selected' : ''}>${escapeHtml(g.name)}</option>`).join('');
  const tplOpts = Object.entries(t.templates).map(([id, tp]) => `<option value="${escapeHtml(id)}">${escapeHtml(tp.name)}</option>`).join('');
  const tr = rows.map(r => `<tr>
    <td><input type="checkbox" name="ids" value="${escapeHtml(r.order.id)}" form="batch" aria-label="Select ${escapeHtml(r.order.name)}"></td>
    <td><a href="/admin/clients/${encodeURIComponent(r.order.id)}"><b>${escapeHtml(r.order.name)}</b></a><br><span class="note">${escapeHtml(r.order.email)} · ${escapeHtml(r.order.packageName || '')}</span></td>
    <td>${r.rec.sharedAt ? escapeHtml(new Date(r.rec.sharedAt).toLocaleString()) : '<span class="note">Not shared yet</span>'}</td>
    <td class="r">${r.loggedDays14}/14</td>
    <td class="r">${fmt0(r.avgKcal14)}${r.goal ? ` / ${fmt0(r.goal)}` : ''}</td>
    <td class="r">${r.compliance == null ? '–' : `<span class="badge ${r.compliance >= 0.7 ? 'ok' : r.compliance >= 0.4 ? 'warn' : 'over'}">${Math.round(r.compliance * 100)}%</span>`}</td>
    <td class="r">${r.latestWeight ? `${fmt0(r.latestWeight.value, 1)} kg` : '–'}${r.weightChange30 != null ? `<br><span class="note">${r.weightChange30 >= 0 ? '+' : ''}${fmt0(r.weightChange30, 1)} kg / 30 d</span>` : ''}</td>
    <td>${r.groups.map(g => `<span class="badge">${escapeHtml(t.groups[g].name)}</span>`).join(' ')}</td>
    <td class="r">${r.unread ? `<span class="badge warn">${r.unread} new</span>` : ''}</td></tr>`).join('');
  return trackerAdminShell('Tracker clients', `
  <div class="top"><div><h1>Tracker clients</h1><p>Clients who connected the Bulamu360 tracker with their approval code. Only data each client chose to share is shown.</p></div>
  <div class="row noprint"><a class="btn ghost" href="/admin/clients.csv">Export CSV</a></div></div>
  <form class="panel pad row noprint" method="get" action="/admin/clients" role="search">
    <label style="flex:1;min-width:200px">Search<input name="q" value="${escapeHtml(q)}" placeholder="Name, email or phone"></label>
    <label>Group<select name="group"><option value="">All groups</option>${groupOpts}</select></label>
    <label style="display:flex;gap:6px;align-items:center;margin-bottom:14px"><input type="checkbox" name="unread" value="1" style="width:auto"${unreadOnly ? ' checked' : ''}> Unread only</label>
    <button class="btn" style="margin-bottom:8px">Filter</button></form>
  <div class="panel"><div class="scroll"><table><thead><tr><th></th><th>Client</th><th>Last shared</th><th class="r">Logged (14 d)</th><th class="r">Avg kcal / target</th><th class="r">Energy compliance</th><th class="r">Weight</th><th>Groups</th><th class="r">Messages</th></tr></thead>
  <tbody>${tr || '<tr><td colspan="9" class="note" style="padding:20px">No tracker clients yet. Clients connect from the tracker’s Care team section using their approval code and email.</td></tr>'}</tbody></table></div></div>
  <form id="batch" class="panel pad noprint" method="post" action="/admin/clients/batch"><h2 style="padding:0 0 10px;border:0">Batch actions for selected clients</h2>
    <div class="row">
      <label>Action<select name="action"><option value="group">Add to group</option><option value="ungroup">Remove from group</option><option value="targets">Assign target template</option><option value="mealplan">Assign meal plan note</option></select></label>
      <label>Group<select name="group"><option value="">—</option>${groupOpts}</select></label>
      <label>Target template<select name="template"><option value="">—</option>${tplOpts}</select></label>
      <label style="flex:1;min-width:220px">Meal plan note<input name="mealPlan" maxlength="600" placeholder="e.g. Follow week 2 of your approved plan"></label>
      <button class="btn" style="margin-bottom:8px">Apply to selected</button></div>
    <p class="note">Batch actions change only practitioner-assigned fields. Clients see assigned targets and notes in their tracker; no client can see another client’s data.</p></form>`, 'clients');
}
function sparkBars(values, target, width = 560, height = 90) {
  const vals = values.map(v => (v == null ? null : Number(v)));
  const max = Math.max(1, target || 0, ...vals.filter(v => v != null)) * 1.1;
  const bw = width / Math.max(1, vals.length);
  const bars = vals.map((v, i) => v == null ? '' : `<rect x="${(i * bw + bw * 0.15).toFixed(1)}" y="${(height - v / max * height).toFixed(1)}" width="${(bw * 0.7).toFixed(1)}" height="${(v / max * height).toFixed(1)}" fill="#1d7349" opacity=".85"><title>${fmt0(v)}</title></rect>`).join('');
  const tl = target ? `<line x1="0" x2="${width}" y1="${(height - target / max * height).toFixed(1)}" y2="${(height - target / max * height).toFixed(1)}" stroke="#a9492f" stroke-dasharray="4 3"/>` : '';
  return `<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="Daily energy bars${target ? ' with target line' : ''}">${bars}${tl}</svg>`;
}
const TRACKER_MICRO_LABELS = { protein: 'Protein (g)', fiber: 'Fiber (g)', calcium: 'Calcium (mg)', iron: 'Iron (mg)', magnesium: 'Magnesium (mg)', potassium: 'Potassium (mg)', zinc: 'Zinc (mg)', vitC: 'Vitamin C (mg)', vitD: 'Vitamin D (µg)', folate: 'Folate (µg)', b12: 'Vitamin B12 (µg)', vitA: 'Vitamin A (µg)', sodium: 'Sodium (mg)', satFat: 'Saturated fat (g)', addedSugar: 'Added sugar (g)' };
function adminClientPage(db, orderId, flash = '', printMode = false) {
  const t = trackerState(db);
  const order = db.orders.find(o => o.id === orderId);
  if (!order) return null;
  const s = clientSummary(db, order);
  const snap = s.snap || {};
  const prof = snap.profile || {};
  const consent = snap.consent || {};
  const days30 = [];
  for (let i = 29; i >= 0; i--) { const k = dayKeyAgo(i); days30.push(s.days.find(d => d && d.date === k) || { date: k }); }
  const recent14 = s.days.filter(d => d && d.date >= dayKeyAgo(13));
  const avg = k => { const v = recent14.map(d => num(d[k])).filter(x => x != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : null; };
  const micro = (snap.targets && snap.targets.micro) || {};
  const microRows = Object.keys(TRACKER_MICRO_LABELS).map(k => {
    const a = avg(k); const tv = micro[k] || {}; const ref = num(tv.target) || (k === 'protein' ? num(snap.targets && snap.targets.protein) : null); const max = num(tv.max);
    const pct = a != null && ref ? Math.round(a / ref * 100) : null;
    const cls = max && a > max ? 'over' : pct == null ? '' : pct < 70 ? 'warn' : 'ok';
    return `<tr><td>${TRACKER_MICRO_LABELS[k]}</td><td class="r">${fmt0(a, 1)}</td><td class="r">${ref ? fmt0(ref, 1) : '–'}${max ? ` / max ${fmt0(max)}` : ''}</td><td class="r">${pct == null ? '' : `<span class="badge ${cls}">${pct}%</span>`}</td></tr>`;
  }).join('');
  const bios = Array.isArray(snap.biometrics) ? snap.biometrics : [];
  const metrics = snap.metrics || {};
  const byMetric = {};
  for (const b of bios) { if (!b || !b.metric) continue; (byMetric[b.metric] = byMetric[b.metric] || []).push(b); }
  const bioRows = Object.entries(byMetric).map(([k, list]) => {
    list.sort((a, b) => String(a.date + a.time).localeCompare(String(b.date + b.time)));
    const last = list[list.length - 1], first = list[0], m = metrics[k] || { name: k, unit: '' };
    return `<tr><td>${escapeHtml(m.name)}</td><td class="r">${fmt0(last.value, 1)}${last.value2 != null ? '/' + fmt0(last.value2) : ''} ${escapeHtml(m.unit || '')}</td><td>${escapeHtml(last.date)}</td><td class="r">${list.length}</td><td class="r">${list.length > 1 ? `${last.value - first.value >= 0 ? '+' : ''}${fmt0(last.value - first.value, 1)}` : ''}</td></tr>`;
  }).join('');
  const fasts = Array.isArray(snap.fasting) ? snap.fasting : [];
  const meals = Array.isArray(snap.meals) ? snap.meals.slice(-7).reverse() : [];
  const msgs = clientMessages(db, orderId);
  const a = s.rec.assigned || {};
  const tplOpts = Object.entries(t.templates).map(([id, tp]) => `<option value="${escapeHtml(id)}">${escapeHtml(tp.name)} (${fmt0(tp.energy)} kcal)</option>`).join('');
  const groupChecks = Object.entries(t.groups).map(([id, g]) => `<label style="display:inline-flex;gap:6px;align-items:center;margin-right:14px"><input type="checkbox" name="groups" value="${escapeHtml(id)}" style="width:auto"${s.groups.includes(id) ? ' checked' : ''}> ${escapeHtml(g.name)}</label>`).join('') || '<span class="note">No groups yet — create them under Groups &amp; templates.</span>';
  const exercise = Array.isArray(snap.exercise) ? snap.exercise : [];
  const body = `
  <div class="top"><div><h1>${escapeHtml(order.name)}</h1><p>${escapeHtml(order.email)} · ${escapeHtml(order.phone || '')} · ${escapeHtml(order.packageName || '')} · <a href="/admin/orders/${encodeURIComponent(order.id)}/review" class="noprint">order</a></p></div>
  <div class="row noprint"><a class="btn ghost" href="/admin/clients">All clients</a><a class="btn ghost" href="/admin/clients/${encodeURIComponent(order.id)}/report" target="_blank">Printable report</a><a class="btn ghost" href="/admin/clients/${encodeURIComponent(order.id)}/export.csv">Export CSV</a></div></div>
  ${flash ? `<div class="panel pad" role="status" style="border-color:#1d7349;background:#edf3ee">${escapeHtml(flash)}</div>` : ''}
  <div class="panel"><h2>Overview</h2><div class="kpis">
    <div class="kpi"><span>Last shared</span><b style="font-size:14px">${s.rec.sharedAt ? escapeHtml(new Date(s.rec.sharedAt).toLocaleString()) : 'Not yet'}</b></div>
    <div class="kpi"><span>Logged days (14)</span><b>${s.loggedDays14}</b></div>
    <div class="kpi"><span>Avg energy (14)</span><b>${fmt0(s.avgKcal14)}</b> kcal</div>
    <div class="kpi"><span>Energy target</span><b>${fmt0(s.goal)}</b> kcal</div>
    <div class="kpi"><span>Compliance ±10%</span><b>${s.compliance == null ? '–' : Math.round(s.compliance * 100) + '%'}</b></div>
    <div class="kpi"><span>Weight</span><b>${s.latestWeight ? fmt0(s.latestWeight.value, 1) : '–'}</b> kg ${s.weightChange30 != null ? `<span class="note">(${s.weightChange30 >= 0 ? '+' : ''}${fmt0(s.weightChange30, 1)} / 30 d)</span>` : ''}</div></div>
    <div class="pad note">Profile: ${escapeHtml([prof.sex, prof.age ? prof.age + ' y' : '', prof.heightCm ? prof.heightCm + ' cm' : '', prof.goal ? 'goal: ' + prof.goal : '', prof.goalWeightKg ? 'goal weight ' + prof.goalWeightKg + ' kg' : '', prof.activity ? 'activity: ' + prof.activity : '', prof.pregnancy && prof.pregnancy !== 'none' ? 'pregnancy: ' + prof.pregnancy : '', prof.lactation && prof.lactation !== 'none' ? 'breastfeeding' : ''].filter(Boolean).join(' · ') || 'not shared')}.
    Client’s own targets: ${fmt0(num(snap.targets && snap.targets.energy))} kcal, P ${fmt0(num(snap.targets && snap.targets.protein))} g, C ${fmt0(num(snap.targets && snap.targets.carbs))} g, F ${fmt0(num(snap.targets && snap.targets.fat))} g (${escapeHtml((snap.targets && snap.targets.mode) || '–')}).
    Shared: ${['diary', 'detail', 'biometrics', 'fasting', 'cycle'].map(k => `${k} ${consent[k] ? '✓' : '✗'}`).join(' · ')}</div></div>
  <div class="panel"><h2>Energy — last 30 days</h2><div class="pad">${sparkBars(days30.map(d => num(d.energy)), s.goal)}<p class="note">Bars = logged energy per day (gaps = not logged). Dashed line = ${s.rec.assigned && s.rec.assigned.energy ? 'practitioner-assigned' : 'client'} target.</p></div>
    <div class="scroll"><table><thead><tr><th>Date</th><th class="r">kcal</th><th class="r">Protein</th><th class="r">Carbs</th><th class="r">Fat</th><th class="r">Fiber</th><th class="r">Sodium</th><th class="r">Water (ml)</th></tr></thead><tbody>
    ${s.days.slice(-14).reverse().map(d => `<tr><td>${escapeHtml(d.date)}</td><td class="r">${fmt0(num(d.energy))}</td><td class="r">${fmt0(num(d.protein))}</td><td class="r">${fmt0(num(d.carbs))}</td><td class="r">${fmt0(num(d.fat))}</td><td class="r">${fmt0(num(d.fiber))}</td><td class="r">${fmt0(num(d.sodium))}</td><td class="r">${fmt0(num(d.water))}</td></tr>`).join('') || '<tr><td colspan="8" class="note">No diary data shared.</td></tr>'}</tbody></table></div></div>
  <div class="grid">
    <div class="panel"><h2>Nutrients — 14-day average vs targets</h2><div class="scroll"><table><thead><tr><th>Nutrient</th><th class="r">Avg/day</th><th class="r">Target</th><th class="r">%</th></tr></thead><tbody>${recent14.length ? microRows : '<tr><td colspan="4" class="note">No diary data shared in the last 14 days.</td></tr>'}</tbody></table></div><p class="pad note" style="margin:0">Averages include only foods that report each nutrient; low values may reflect incomplete food data.</p></div>
    <div class="panel"><h2>Biometrics</h2><div class="scroll"><table><thead><tr><th>Measurement</th><th class="r">Latest</th><th>Date</th><th class="r">Readings</th><th class="r">Change</th></tr></thead><tbody>${bioRows || '<tr><td colspan="5" class="note">No biometrics shared.</td></tr>'}</tbody></table></div>
      <div class="pad note">Fasting (90 d): ${fasts.length ? `${fasts.length} fasts, average ${fmt0(fasts.reduce((x, f) => x + (num(f.hours) || 0), 0) / fasts.length, 1)} h, reached target ${Math.round(fasts.filter(f => f.completed).length / fasts.length * 100)}%` : 'none shared'}. Exercise (90 d): ${exercise.length ? `${exercise.length} sessions, ${fmt0(exercise.reduce((x, e) => x + (num(e.kcal) || 0), 0))} kcal` : 'none shared'}.${snap.cycle ? ` Cycle: average length ${fmt0(num(snap.cycle.avgLength))} days.` : ''}</div></div>
  </div>
  ${meals.length ? `<div class="panel"><h2>Food diary (last ${meals.length} logged days)</h2><div class="scroll"><table><thead><tr><th>Date</th><th>Time</th><th>Meal</th><th>Food</th><th>Amount</th><th class="r">kcal</th><th class="r">P / C / F</th></tr></thead><tbody>${meals.map(day => (Array.isArray(day.items) ? day.items : []).map(it => `<tr><td>${escapeHtml(day.date)}</td><td>${escapeHtml(it.time || '')}</td><td>${escapeHtml(it.group || '')}</td><td>${escapeHtml(it.name || '')}${it.estimated ? ' <span class="badge">est.</span>' : ''}</td><td>${escapeHtml(it.amount || '')}</td><td class="r">${fmt0(num(it.kcal))}</td><td class="r">${fmt0(num(it.protein))} / ${fmt0(num(it.carbs))} / ${fmt0(num(it.fat))}</td></tr>`).join('')).join('')}</tbody></table></div></div>` : ''}
  ${printMode ? '' : `<div class="grid noprint">
    <div class="panel"><h2>Messages ${s.unread ? `<span class="badge warn">${s.unread} new</span>` : ''}</h2><div class="pad" style="max-height:420px;overflow:auto">${msgs.length ? msgs.slice(-100).map(m => `<div class="msg${m.from === 'practitioner' ? ' me' : ''}">${escapeHtml(m.body).replace(/\n/g, '<br>')}<small>${m.from === 'practitioner' ? 'You' : escapeHtml(order.name)} · ${escapeHtml(new Date(m.at).toLocaleString())}${m.from === 'practitioner' ? (m.readByClient ? ' · Read' : ' · Delivered') : ''}</small></div>`).join('') : '<p class="note">No messages yet.</p>'}</div>
      <form class="pad" method="post" action="/admin/clients/${encodeURIComponent(order.id)}/message"><label>Reply<textarea name="body" maxlength="2000" required></textarea></label><button class="btn">Send message</button> <span class="note">The client sees it next time they open Care team.</span></form></div>
    <div class="panel"><h2>Assign targets &amp; meal plan</h2><form class="pad" method="post" action="/admin/clients/${encodeURIComponent(order.id)}/assign">
      <label>Start from template<select name="template"><option value="">— none (use values below) —</option>${tplOpts}</select></label>
      <div class="row"><label>Energy (kcal)<input name="energy" type="number" min="800" max="6000" value="${escapeHtml(a.energy || '')}"></label><label>Protein (g)<input name="protein" type="number" min="0" max="500" value="${escapeHtml(a.protein || '')}"></label><label>Carbs (g)<input name="carbs" type="number" min="0" max="900" value="${escapeHtml(a.carbs || '')}"></label><label>Fat (g)<input name="fat" type="number" min="0" max="400" value="${escapeHtml(a.fat || '')}"></label></div>
      <label>Meal plan note<textarea name="mealPlan" maxlength="600">${escapeHtml(a.mealPlan || '')}</textarea></label>
      <label>Note to client<textarea name="notes" maxlength="600">${escapeHtml(a.notes || '')}</textarea></label>
      <button class="btn">Save assignment</button> <button class="btn ghost" name="clear" value="1">Clear</button>
      <p class="note">Assigned targets appear in the client’s tracker; they choose “Practitioner assigned” to use them.</p></form>
      <form class="pad" method="post" action="/admin/clients/${encodeURIComponent(order.id)}/groups" style="border-top:1px solid var(--line)"><div style="margin-bottom:8px">${groupChecks}</div><button class="btn ghost">Save groups</button></form>
      <form class="pad" method="post" action="/admin/clients/${encodeURIComponent(order.id)}/remove" style="border-top:1px solid var(--line)" onsubmit="return confirm('Delete this client’s shared tracker data and messages from the server? Their own device data is not affected.')"><button class="btn danger">Delete shared data</button></form></div>
  </div>`}
  <p class="note">Shared by the client from their own tracker. Values are self-recorded and partly estimated; use clinical judgement. Not a medical record.</p>
  ${printMode ? '<p class="noprint"><button class="btn" onclick="window.print()">Print / Save as PDF</button></p>' : ''}`;
  return trackerAdminShell(`${order.name} · client`, body, 'clients');
}
function adminGroupsPage(db, flash = '') {
  const t = trackerState(db);
  const summaries = trackerClientOrders(db).map(o => clientSummary(db, o));
  const groupRows = Object.entries(t.groups).map(([id, g]) => {
    const members = summaries.filter(s => s.groups.includes(id));
    const comp = members.map(m => m.compliance).filter(v => v != null);
    const wch = members.map(m => m.weightChange30).filter(v => v != null);
    return `<tr><td><b>${escapeHtml(g.name)}</b><br><span class="note">${escapeHtml(g.description || '')}</span></td><td class="r">${members.length}</td><td class="r">${members.length ? fmt0(members.reduce((x, m) => x + m.loggedDays14, 0) / members.length, 1) : '–'}</td><td class="r">${comp.length ? Math.round(comp.reduce((x, v) => x + v, 0) / comp.length * 100) + '%' : '–'}</td><td class="r">${wch.length ? fmt0(wch.reduce((x, v) => x + v, 0) / wch.length, 1) + ' kg' : '–'}</td>
      <td class="r"><a class="btn ghost" href="/admin/clients?group=${encodeURIComponent(id)}">Members</a> <a class="btn ghost" href="/admin/groups/${encodeURIComponent(id)}/report" target="_blank">Report</a>
      <form method="post" action="/admin/groups/${encodeURIComponent(id)}/delete" style="display:inline" onsubmit="return confirm('Delete this group? Clients are not deleted.')"><button class="btn danger">Delete</button></form></td></tr>`;
  }).join('');
  const tplRows = Object.entries(t.templates).map(([id, tp]) => `<tr><td><b>${escapeHtml(tp.name)}</b></td><td class="r">${fmt0(tp.energy)}</td><td class="r">${fmt0(tp.protein)}</td><td class="r">${fmt0(tp.carbs)}</td><td class="r">${fmt0(tp.fat)}</td><td>${escapeHtml(shortText(tp.notes || '', 80))}</td><td class="r"><form method="post" action="/admin/templates/${encodeURIComponent(id)}/delete" onsubmit="return confirm('Delete template?')"><button class="btn danger">Delete</button></form></td></tr>`).join('');
  return trackerAdminShell('Groups & templates', `
  <div class="top"><div><h1>Groups &amp; target templates</h1><p>Organise tracker clients and assign targets in bulk.</p></div></div>
  ${flash ? `<div class="panel pad" role="status">${escapeHtml(flash)}</div>` : ''}
  <div class="panel"><h2>Groups</h2><div class="scroll"><table><thead><tr><th>Group</th><th class="r">Members</th><th class="r">Avg logged days (14)</th><th class="r">Avg compliance</th><th class="r">Avg weight change (30 d)</th><th></th></tr></thead><tbody>${groupRows || '<tr><td colspan="6" class="note">No groups yet.</td></tr>'}</tbody></table></div>
  <form class="pad row" method="post" action="/admin/groups"><label>Name<input name="name" required maxlength="60"></label><label style="flex:1">Description<input name="description" maxlength="160"></label><button class="btn" style="margin-bottom:8px">Create group</button></form></div>
  <div class="panel"><h2>Target templates</h2><div class="scroll"><table><thead><tr><th>Template</th><th class="r">kcal</th><th class="r">Protein</th><th class="r">Carbs</th><th class="r">Fat</th><th>Notes</th><th></th></tr></thead><tbody>${tplRows || '<tr><td colspan="7" class="note">No templates yet.</td></tr>'}</tbody></table></div>
  <form class="pad row" method="post" action="/admin/templates"><label>Name<input name="name" required maxlength="60"></label><label>Energy<input name="energy" type="number" min="800" max="6000" required></label><label>Protein (g)<input name="protein" type="number" min="0" max="500"></label><label>Carbs (g)<input name="carbs" type="number" min="0" max="900"></label><label>Fat (g)<input name="fat" type="number" min="0" max="400"></label><label style="flex:1">Notes<input name="notes" maxlength="300"></label><button class="btn" style="margin-bottom:8px">Save template</button></form></div>
  <div class="panel"><h2>Recent tracker activity</h2><div class="scroll"><table><thead><tr><th>When</th><th>Action</th><th>Client</th><th>Detail</th></tr></thead><tbody>${t.audit.slice(0, 40).map(e => { const o = db.orders.find(x => x.id === e.orderId); return `<tr><td>${escapeHtml(new Date(e.at).toLocaleString())}</td><td>${escapeHtml(e.action)}</td><td>${o ? escapeHtml(o.name) : '<span class="note">–</span>'}</td><td class="note">${escapeHtml(e.detail || '')}</td></tr>`; }).join('') || '<tr><td colspan="4" class="note">No activity yet.</td></tr>'}</tbody></table></div></div>`, 'groups');
}
function adminGroupReport(db, groupId) {
  const t = trackerState(db);
  const g = t.groups[groupId];
  if (!g) return null;
  const members = trackerClientOrders(db).map(o => clientSummary(db, o)).filter(s => s.groups.includes(groupId));
  return trackerAdminShell(`${g.name} · group report`, `<div class="top"><div><h1>${escapeHtml(g.name)} — group report</h1><p>${escapeHtml(g.description || '')} · generated ${escapeHtml(new Date().toLocaleString())} · ${members.length} member(s)</p></div><div class="noprint"><button class="btn" onclick="window.print()">Print / Save as PDF</button></div></div>
  <div class="panel"><div class="scroll"><table><thead><tr><th>Client</th><th class="r">Logged (14 d)</th><th class="r">Avg kcal</th><th class="r">Target</th><th class="r">Compliance</th><th class="r">Weight</th><th class="r">Change 30 d</th><th>Last shared</th></tr></thead><tbody>
  ${members.map(m => `<tr><td>${escapeHtml(m.order.name)}</td><td class="r">${m.loggedDays14}</td><td class="r">${fmt0(m.avgKcal14)}</td><td class="r">${fmt0(m.goal)}</td><td class="r">${m.compliance == null ? '–' : Math.round(m.compliance * 100) + '%'}</td><td class="r">${m.latestWeight ? fmt0(m.latestWeight.value, 1) : '–'}</td><td class="r">${m.weightChange30 == null ? '–' : fmt0(m.weightChange30, 1)}</td><td>${m.rec.sharedAt ? escapeHtml(new Date(m.rec.sharedAt).toLocaleDateString()) : '–'}</td></tr>`).join('') || '<tr><td colspan="8" class="note">No members.</td></tr>'}</tbody></table></div></div>
  <p class="note">Confidential — contains client health information. For practitioner use only.</p>`, 'groups');
}
function csvCell(v) { const s = v == null ? '' : String(v); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
function sendCsv(res, name, rows) {
  res.writeHead(200, securityHeaders({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="${name}"` }));
  res.end(rows.map(r => r.map(csvCell).join(',')).join('\r\n'));
}
function assignedFromForm(db, form) {
  const t = trackerState(db);
  const tp = form.template && t.templates[form.template];
  const pick = (k, max) => { const v = num(tp && tp[k] != null && !form[k] ? tp[k] : form[k]); return v == null ? null : Math.max(0, Math.min(max, Math.round(v))); };
  return {
    energy: pick('energy', 6000), protein: pick('protein', 500), carbs: pick('carbs', 900), fat: pick('fat', 400),
    mealPlan: String(form.mealPlan || '').trim().slice(0, 600), notes: String(form.notes || (tp && tp.notes) || '').trim().slice(0, 600),
    template: tp ? tp.name : '', updatedAt: new Date().toISOString()
  };
}
/* Admin route dispatcher (requireAdmin already passed). Returns true when handled. */
async function handleTrackerAdminRoutes(req, res, url) {
  const p = url.pathname;
  if (!(p === '/admin/clients' || p === '/admin/clients.csv' || p.startsWith('/admin/clients/') || p === '/admin/groups' || p.startsWith('/admin/groups/') || p === '/admin/templates' || p.startsWith('/admin/templates/'))) return false;
  const db = readDb();
  const t = trackerState(db);
  if (req.method === 'GET' && p === '/admin/clients') { sendHtml(res, 200, adminClientsPage(db, url)); return true; }
  if (req.method === 'GET' && p === '/admin/clients.csv') {
    trackerAudit(db, 'export-clients'); writeDb(db);
    sendCsv(res, 'bulamu360-tracker-clients.csv', [['name', 'email', 'phone', 'package', 'last_shared', 'logged_days_14', 'avg_kcal_14', 'energy_target', 'compliance_pct', 'latest_weight_kg', 'weight_change_30d', 'groups', 'unread']]
      .concat(trackerClientOrders(db).map(o => clientSummary(db, o)).map(s => [s.order.name, s.order.email, s.order.phone, s.order.packageName, s.rec.sharedAt || '', s.loggedDays14, s.avgKcal14 == null ? '' : Math.round(s.avgKcal14), s.goal || '', s.compliance == null ? '' : Math.round(s.compliance * 100), s.latestWeight ? s.latestWeight.value : '', s.weightChange30 == null ? '' : s.weightChange30.toFixed(1), s.groups.map(g => t.groups[g].name).join('; '), s.unread])));
    return true;
  }
  if (req.method === 'POST' && p === '/admin/clients/batch') {
    const body = await readRequestBody(req);
    const params = new URLSearchParams(body);
    const ids = params.getAll('ids').filter(id => db.orders.some(o => o.id === id));
    const form = Object.fromEntries(params);
    let n = 0;
    for (const id of ids) {
      const rec = clientRecord(db, id);
      if (form.action === 'group' && t.groups[form.group]) { if (!rec.groups.includes(form.group)) rec.groups.push(form.group); n++; }
      if (form.action === 'ungroup' && form.group) { rec.groups = rec.groups.filter(g => g !== form.group); n++; }
      if (form.action === 'targets' && t.templates[form.template]) { rec.assigned = { ...(rec.assigned || {}), ...assignedFromForm(db, { template: form.template, mealPlan: (rec.assigned && rec.assigned.mealPlan) || '' }) }; n++; }
      if (form.action === 'mealplan' && String(form.mealPlan || '').trim()) { rec.assigned = { ...(rec.assigned || {}), mealPlan: String(form.mealPlan).trim().slice(0, 600), updatedAt: new Date().toISOString() }; n++; }
    }
    trackerAudit(db, 'batch-' + String(form.action || '').slice(0, 20), '', `${n} client(s)`);
    writeDb(db);
    redirect(res, '/admin/clients');
    return true;
  }
  if (p === '/admin/groups' && req.method === 'GET') { sendHtml(res, 200, adminGroupsPage(db)); return true; }
  if (p === '/admin/groups' && req.method === 'POST') {
    const form = await readForm(req);
    const name = String(form.name || '').trim().slice(0, 60);
    if (name) { t.groups[randomUUID()] = { name, description: String(form.description || '').trim().slice(0, 160), createdAt: new Date().toISOString() }; trackerAudit(db, 'group-created', '', name); writeDb(db); }
    redirect(res, '/admin/groups'); return true;
  }
  let m = p.match(/^\/admin\/groups\/([^/]+)\/(delete|report)$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    if (m[2] === 'report' && req.method === 'GET') { const html = adminGroupReport(db, id); if (!html) return sendHtml(res, 404, 'Group not found'), true; trackerAudit(db, 'group-report', '', t.groups[id].name); writeDb(db); sendHtml(res, 200, html); return true; }
    if (m[2] === 'delete' && req.method === 'POST') { delete t.groups[id]; for (const rec of Object.values(t.clients)) rec.groups = (rec.groups || []).filter(g => g !== id); trackerAudit(db, 'group-deleted'); writeDb(db); redirect(res, '/admin/groups'); return true; }
  }
  if (p === '/admin/templates' && req.method === 'POST') {
    const form = await readForm(req);
    const name = String(form.name || '').trim().slice(0, 60);
    const energy = num(form.energy);
    if (name && energy >= 800 && energy <= 6000) { t.templates[randomUUID()] = { name, energy: Math.round(energy), protein: num(form.protein), carbs: num(form.carbs), fat: num(form.fat), notes: String(form.notes || '').trim().slice(0, 300) }; writeDb(db); }
    redirect(res, '/admin/groups'); return true;
  }
  m = p.match(/^\/admin\/templates\/([^/]+)\/delete$/);
  if (m && req.method === 'POST') { delete t.templates[decodeURIComponent(m[1])]; writeDb(db); redirect(res, '/admin/groups'); return true; }
  m = p.match(/^\/admin\/clients\/([^/]+)(?:\/(message|assign|groups|remove|report|export\.csv))?$/);
  if (m) {
    const id = decodeURIComponent(m[1]);
    const order = db.orders.find(o => o.id === id);
    if (!order) { sendHtml(res, 404, 'Client not found'); return true; }
    const action = m[2] || '';
    if (!action && req.method === 'GET') {
      const list = clientMessages(db, id);
      let changed = false;
      for (const msg of list) if (msg.from === 'client' && !msg.readByPractitioner) { msg.readByPractitioner = new Date().toISOString(); changed = true; }
      const html = adminClientPage(db, id, url.searchParams.get('ok') || '');
      trackerAudit(db, 'client-viewed', id);
      writeDb(db);
      sendHtml(res, 200, html);
      return true;
    }
    if (action === 'report' && req.method === 'GET') { trackerAudit(db, 'client-report', id); writeDb(db); sendHtml(res, 200, adminClientPage(db, id, '', true)); return true; }
    if (action === 'export.csv' && req.method === 'GET') {
      const snap = (t.clients[id] && t.clients[id].snapshot) || {};
      trackerAudit(db, 'client-export', id); writeDb(db);
      const keys = ['energy', 'protein', 'carbs', 'fat', 'fiber', 'sugars', 'addedSugar', 'satFat', 'sodium', 'potassium', 'calcium', 'iron', 'magnesium', 'zinc', 'vitC', 'vitD', 'folate', 'b12', 'vitA', 'omega3', 'water'];
      const rows = [['type', 'date', 'time', 'name', 'value', 'value2'].concat(keys)];
      for (const d of (Array.isArray(snap.days) ? snap.days : [])) rows.push(['day', d.date, '', '', '', ''].concat(keys.map(k => d[k] ?? '')));
      for (const b of (Array.isArray(snap.biometrics) ? snap.biometrics : [])) rows.push(['biometric', b.date, b.time, b.metric, b.value, b.value2 ?? ''].concat(keys.map(() => '')));
      for (const f of (Array.isArray(snap.fasting) ? snap.fasting : [])) rows.push(['fast', new Date(f.start).toISOString().slice(0, 10), '', f.preset, f.hours, f.target].concat(keys.map(() => '')));
      sendCsv(res, `bulamu360-client-${id.slice(0, 8)}.csv`, rows);
      return true;
    }
    if (req.method === 'POST') {
      const params = new URLSearchParams(await readRequestBody(req));
      const form = Object.fromEntries(params);
      const rec = clientRecord(db, id);
      let msg = '';
      if (action === 'message') {
        const body = String(form.body || '').trim().slice(0, 2000);
        if (body) { const list = clientMessages(db, id); list.push({ id: randomUUID(), from: 'practitioner', body, at: new Date().toISOString(), readByPractitioner: true, readByClient: false }); if (list.length > 500) list.splice(0, list.length - 500); trackerAudit(db, 'practitioner-message', id); msg = 'Message sent.'; }
      }
      if (action === 'assign') { rec.assigned = form.clear ? null : assignedFromForm(db, form); trackerAudit(db, form.clear ? 'assignment-cleared' : 'assignment-saved', id); msg = form.clear ? 'Assignment cleared.' : 'Assignment saved.'; }
      if (action === 'groups') { rec.groups = params.getAll('groups').filter(g => t.groups[g]); trackerAudit(db, 'groups-updated', id); msg = 'Groups saved.'; }
      if (action === 'remove') { delete t.clients[id]; delete t.messages[id]; for (const [h, s] of Object.entries(t.sessions)) if (s.orderId === id) delete t.sessions[h]; trackerAudit(db, 'client-data-deleted', id); writeDb(db); redirect(res, '/admin/clients'); return true; }
      writeDb(db);
      redirect(res, `/admin/clients/${encodeURIComponent(id)}?ok=${encodeURIComponent(msg || 'Saved.')}`);
      return true;
    }
  }
  return false;
}

/* =====================================================================
   BULAMU360 ACCOUNTS - tracker sign-up / sign-in / password reset / newsletter
   - Passwords: min 8 chars with upper, lower, number and special character; scrypt-hashed
   - Sessions: random token in an HttpOnly cookie (hash stored server-side), 30 days
   - Reset: 6-digit code emailed via Resend, 15-minute expiry, 5 attempts
   - Tracker data saved per account (size-limited)
   Data lives in db.accounts; nothing else in the database is touched.
===================================================================== */
const ACCOUNT_COOKIE = 'b360_session';
const ACCOUNT_SESSION_DAYS = 30;
const ACCOUNT_MAX_TRACKER = 900_000;
function accountsState(db) {
  if (!db.accounts || typeof db.accounts !== 'object') db.accounts = {};
  const a = db.accounts;
  if (!a.users || typeof a.users !== 'object') a.users = {};
  if (!a.byEmail || typeof a.byEmail !== 'object') a.byEmail = {};
  if (!a.sessions || typeof a.sessions !== 'object') a.sessions = {};
  return a;
}
function passwordProblems(pw) {
  const p = String(pw || ''), out = [];
  if (p.length < 8) out.push('at least 8 characters');
  if (!/[A-Z]/.test(p)) out.push('an uppercase letter');
  if (!/[a-z]/.test(p)) out.push('a lowercase letter');
  if (!/[0-9]/.test(p)) out.push('a number');
  if (!/[^A-Za-z0-9]/.test(p)) out.push('a special character');
  if (p.length > 200) out.push('at most 200 characters');
  return out;
}
function hashPassword(pw, salt) {
  return new Promise((resolve, reject) => scryptCb(String(pw), salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => err ? reject(err) : resolve(key.toString('hex'))));
}
async function verifyPassword(pw, user) {
  const h = await hashPassword(pw, user.salt);
  return constantTimeEqual(h, user.passHash);
}
function accountCookie(token, maxAgeSec) {
  const secure = isProduction ? '; Secure' : '';
  return `${ACCOUNT_COOKIE}=${encodeURIComponent(token || '')}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}${secure}`;
}
function publicUser(u, db) { return { id: u.id, name: u.name, email: u.email, newsletter: Boolean(u.newsletter), createdAt: u.createdAt, trackerSavedAt: u.tracker ? u.tracker.savedAt : null, plan: db ? accountPlan(db, u) : undefined }; }
/* B360 PACKAGES */
const TEMPLATE_PRICE = 7000;
const TIER_NAME = { free: 'Free', personal: 'Pantry', specialist: 'Greenwell', advanced: 'Banquet' };
const TIER_RANK = { free: 0, personal: 1, specialist: 2, advanced: 3 };
function accountOrders(db, user) {
  const linked = new Set(Array.isArray(user.linkedOrders) ? user.linkedOrders : []);
  return (db.orders || []).filter(o => o && o.status === 'approved' && ((o.accountId && o.accountId === user.id) || linked.has(o.id)));
}
function accountPlan(db, user) {
  const orders = accountOrders(db, user);
  let best = null;
  for (const o of orders) {
    if (o.kind === 'template') continue;
    const level = memberLevelFromPackage(o.packageName), cyc = memberCycleInfo(o);
    if (level === 'free' || !cyc.active) continue;
    if (!best || TIER_RANK[level] > TIER_RANK[best.level] || (TIER_RANK[level] === TIER_RANK[best.level] && cyc.expiresAt > best.expiresAt)) best = { level, packageName: o.packageName, activeUntil: cyc.activeUntil, expiresAt: cyc.expiresAt, daysRemaining: cyc.daysRemaining };
  }
  const level = best ? best.level : 'free';
  const templates = [...new Set(orders.filter(o => o.kind === 'template' && o.templateId).map(o => o.templateId))];
  return { level, tier: TIER_NAME[level], packageName: best ? best.packageName : '', activeUntil: best ? best.activeUntil : '', daysRemaining: best ? best.daysRemaining : 0, templates, allTemplates: level !== 'free', templateZip: level === 'advanced' };
}
function canDownloadTemplate(plan, id) { const t = TEMPLATES[id]; return !!t && (!t.premium || plan.allTemplates || plan.templates.includes(id)); }
async function handleTemplateRoutes(req, res, url) {
  const m = url.pathname.match(/^\/api\/templates\/([A-Za-z]+)\.(pdf|zip)$/);
  if (!m || req.method !== 'GET') return false;
  const db = readDb(), user = currentAccount(req, db);
  const plan = user ? accountPlan(db, user) : { level: 'free', templates: [], allTemplates: false, templateZip: false };
  const logoPath = join(root, 'bulamu360-logo.png');
  if (m[1] === 'all' && m[2] === 'zip') {
    if (!plan.templateZip) { sendJson(res, 403, { ok: false, error: 'The full template pack comes with the Banquet package.' }); return true; }
    const zip = zipFiles(Object.keys(TEMPLATES).map(id => ({ name: 'Bulamu360 Tracking Templates/Bulamu360_' + TEMPLATES[id].file + '.pdf', data: templatePdf(id, { logoPath }) })));
    res.writeHead(200, securityHeaders({ 'Content-Type': 'application/zip', 'Content-Length': zip.length, 'Content-Disposition': 'attachment; filename="Bulamu360-Tracking-Templates.zip"', 'Cache-Control': 'no-store' }));
    res.end(zip); return true;
  }
  if (m[2] !== 'pdf' || !TEMPLATES[m[1]]) { sendJson(res, 404, { ok: false, error: 'Template not found.' }); return true; }
  if (!canDownloadTemplate(plan, m[1])) { sendJson(res, user ? 402 : 401, { ok: false, error: user ? 'This template costs UGX 7,000, or comes free with any package.' : 'Please sign in to download this template.' }); return true; }
  const pdf = templatePdf(m[1], { logoPath });
  res.writeHead(200, securityHeaders({ 'Content-Type': 'application/pdf', 'Content-Length': pdf.length, 'Content-Disposition': `attachment; filename="Bulamu360_${TEMPLATES[m[1]].file}.pdf"`, 'Cache-Control': 'no-store' }));
  res.end(pdf); return true;
}
function currentAccount(req, db) {
  const tok = getCookie(req, ACCOUNT_COOKIE);
  if (!tok) return null;
  const a = accountsState(db), s = a.sessions[hashToken(tok)];
  if (!s || s.expiresAt < Date.now()) return null;
  return a.users[s.uid] || null;
}
function startAccountSession(res, db, user) {
  const a = accountsState(db), token = randomBytes(32).toString('hex'), now = Date.now();
  for (const [h, s] of Object.entries(a.sessions)) if (s.expiresAt < now) delete a.sessions[h];
  const mine = Object.entries(a.sessions).filter(([, s]) => s.uid === user.id).sort((x, y) => x[1].createdAt - y[1].createdAt);
  while (mine.length >= 10) delete a.sessions[mine.shift()[0]];
  a.sessions[hashToken(token)] = { uid: user.id, createdAt: now, expiresAt: now + ACCOUNT_SESSION_DAYS * 864e5 };
  return accountCookie(token, ACCOUNT_SESSION_DAYS * 86400);
}
function sendJsonWithCookie(res, status, data, cookie) {
  res.writeHead(status, { ...securityHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': cookie });
  res.end(JSON.stringify(data));
}
/* Gentler cleaner for a person's own tracker data (keeps notes and small photo thumbnails). */
function sanitiseAccountData(value, depth = 0) {
  if (depth > 12) return null;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string') return value.length > 60000 ? '' : value;
  if (Array.isArray(value)) return value.slice(0, 20000).map(v => sanitiseAccountData(v, depth + 1));
  if (typeof value === 'object') { const out = {}; for (const [k, v] of Object.entries(value)) { if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue; out[String(k).slice(0, 120)] = sanitiseAccountData(v, depth + 1); } return out; }
  return null;
}
function validEmail(e) { return /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e); }
async function handleAccountApi(req, res, url) {
  const route = url.pathname.replace('/api/account/', '');
  if (!String(req.headers['content-type'] || '').includes('application/json')) return sendJson(res, 415, { ok: false, error: 'Unsupported request.' });
  const body = await readRequestJson(req).catch(() => null);
  if (!body || typeof body !== 'object') return sendJson(res, 400, { ok: false, error: 'Invalid request.' });
  const db = readDb();
  const a = accountsState(db);
  if (route === 'signup') {
    const name = String(body.name || '').trim().slice(0, 80);
    const email = String(body.email || '').trim().toLowerCase();
    const problems = passwordProblems(body.password);
    if (!name) return sendJson(res, 400, { ok: false, error: 'Please enter your name.' });
    if (!validEmail(email)) return sendJson(res, 400, { ok: false, error: 'Please enter a valid email address.' });
    if (problems.length) return sendJson(res, 400, { ok: false, error: 'Your password needs ' + problems.join(', ') + '.' });
    if (a.byEmail[email]) return sendJson(res, 409, { ok: false, error: 'An account with this email already exists. Sign in instead, or reset your password.' });
    const salt = randomBytes(16).toString('hex');
    const user = { id: 'u_' + randomBytes(9).toString('hex'), name, email, salt, passHash: await hashPassword(body.password, salt), newsletter: Boolean(body.newsletter), newsletterAt: body.newsletter ? new Date().toISOString() : null, createdAt: new Date().toISOString(), tracker: null, reset: null };
    a.users[user.id] = user; a.byEmail[email] = user.id;
    const cookie = startAccountSession(res, db, user);
    trackerAudit(db, 'account-created', '', email.replace(/(^.).*(@.*$)/, '$1***$2'));
    writeDb(db);
    return sendJsonWithCookie(res, 200, { ok: true, user: publicUser(user, db) }, cookie);
  }
  if (route === 'login') {
    const email = String(body.email || '').trim().toLowerCase();
    const user = a.users[a.byEmail[email]];
    // Same message and similar timing whether or not the account exists.
    const ok = user ? await verifyPassword(body.password || '', user) : (await hashPassword(body.password || '', 'x'.repeat(32)), false);
    if (!ok) return sendJson(res, 401, { ok: false, error: 'Email or password is incorrect.' });
    const cookie = startAccountSession(res, db, user);
    user.lastLoginAt = new Date().toISOString();
    writeDb(db);
    return sendJsonWithCookie(res, 200, { ok: true, user: publicUser(user, db) }, cookie);
  }
  if (route === 'forgot') {
    const email = String(body.email || '').trim().toLowerCase();
    if (!validEmail(email)) return sendJson(res, 400, { ok: false, error: 'Please enter a valid email address.' });
    if (!apiKey) return sendJson(res, 503, { ok: false, error: 'Password reset emails are not set up yet. Please contact Breyer on WhatsApp to reset your password.' });
    const user = a.users[a.byEmail[email]];
    if (user) {
      if (user.reset && user.reset.sentAt && Date.now() - Date.parse(user.reset.sentAt) < 60_000) return sendJson(res, 429, { ok: false, error: 'A code was just sent. Please wait a minute before asking again.' });
      const code = String(Math.floor(100000 + Math.random() * 900000));
      user.reset = { codeHash: hashToken(user.id + ':' + code), expiresAt: Date.now() + 15 * 60_000, tries: 0, sentAt: new Date().toISOString() };
      writeDb(db);
      try {
        await sendResendEmail({ to: user.email, subject: 'Your Bulamu360 password reset code', html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;color:#123524"><h2 style="margin:0 0 12px">Reset your password</h2><p>Hello ${escapeHtml(user.name)},</p><p>Use this code to reset your Bulamu360 password. It expires in 15 minutes.</p><p style="font-size:34px;letter-spacing:8px;font-weight:bold;background:#e9f7ee;border-radius:14px;padding:16px;text-align:center;color:#123524">${code}</p><p style="color:#5f6f66;font-size:13px">If you didn't ask for this, you can ignore this email; your password stays the same.</p></div>` });
      } catch (err) {
        console.error('Reset email failed:', err.message);
        return sendJson(res, 502, { ok: false, error: 'We could not send the email right now. Please try again in a few minutes.' });
      }
    }
    return sendJson(res, 200, { ok: true, message: 'If an account exists for that email, a 6-digit code is on its way. It expires in 15 minutes.' });
  }
  if (route === 'reset') {
    const email = String(body.email || '').trim().toLowerCase(), code = String(body.code || '').replace(/\D/g, '');
    const user = a.users[a.byEmail[email]];
    const problems = passwordProblems(body.password);
    if (problems.length) return sendJson(res, 400, { ok: false, error: 'Your new password needs ' + problems.join(', ') + '.' });
    if (!user || !user.reset || user.reset.expiresAt < Date.now() || user.reset.tries >= 5) return sendJson(res, 400, { ok: false, error: 'That code has expired or is not valid. Please request a new one.' });
    user.reset.tries += 1;
    if (!constantTimeEqual(hashToken(user.id + ':' + code), user.reset.codeHash)) { writeDb(db); return sendJson(res, 400, { ok: false, error: 'That code is not correct. Please check your email and try again.' }); }
    user.salt = randomBytes(16).toString('hex');
    user.passHash = await hashPassword(body.password, user.salt);
    user.reset = null;
    for (const [h, s] of Object.entries(a.sessions)) if (s.uid === user.id) delete a.sessions[h];
    const cookie = startAccountSession(res, db, user);
    writeDb(db);
    return sendJsonWithCookie(res, 200, { ok: true, user: publicUser(user, db) }, cookie);
  }
  if (route === 'logout') {
    const tok = getCookie(req, ACCOUNT_COOKIE);
    if (tok) { delete a.sessions[hashToken(tok)]; writeDb(db); }
    return sendJsonWithCookie(res, 200, { ok: true }, accountCookie('', 0));
  }
  const user = currentAccount(req, db);
  if (!user) return sendJson(res, 401, { ok: false, error: 'Please sign in.' });
  if (route === 'me') return sendJson(res, 200, { ok: true, user: publicUser(user, db) });
  if (route === 'tracker') return sendJson(res, 200, { ok: true, data: user.tracker ? user.tracker.data : null, savedAt: user.tracker ? user.tracker.savedAt : null });
  if (route === 'tracker/save') {
    const raw = JSON.stringify(body.data || null);
    if (!body.data || raw.length > ACCOUNT_MAX_TRACKER) return sendJson(res, 413, { ok: false, error: 'Your tracker data is too large to save online. Export a backup and clear old entries.' });
    user.tracker = { data: sanitiseAccountData(body.data), savedAt: new Date().toISOString() };
    writeDb(db);
    return sendJson(res, 200, { ok: true, savedAt: user.tracker.savedAt });
  }
  if (route === 'link-order') {
    const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length < 5) return sendJson(res, 400, { ok: false, error: 'Enter the approval code or payment reference from your purchase.' });
    const order = (db.orders || []).find(o => o.status === 'approved' && String(o.email || '').toLowerCase() === user.email && (String(o.approvalCode || '').toUpperCase().replace(/[^A-Z0-9]/g, '') === code || String(o.txRef || '').toUpperCase().replace(/[^A-Z0-9]/g, '') === code));
    if (!order) return sendJson(res, 404, { ok: false, error: 'We could not find an approved purchase with that code for ' + user.email + '.' });
    user.linkedOrders = [...new Set([...(user.linkedOrders || []), order.id])];
    writeDb(db);
    return sendJson(res, 200, { ok: true, user: publicUser(user, db) });
  }
  if (route === 'newsletter') {
    user.newsletter = Boolean(body.subscribe);
    user.newsletterAt = new Date().toISOString();
    writeDb(db);
    return sendJson(res, 200, { ok: true, user: publicUser(user, db) });
  }
  return sendJson(res, 404, { ok: false, error: 'Unknown account action.' });
}
async function handleAccountRoutes(req, res, url) {
  if (!url.pathname.startsWith('/api/account/')) return false;
  if (req.method !== 'POST') { sendJson(res, 405, { ok: false, error: 'Method not allowed' }); return true; }
  const strict = /\/(signup|login|forgot|reset)$/.test(url.pathname);
  if (!rateLimit(req, res, strict ? 'account-auth' : 'account', { limit: strict ? 12 : 120, windowMs: 60_000 })) return true;
  await handleAccountApi(req, res, url);
  return true;
}
/* Admin: newsletter subscribers & account overview (behind existing admin auth). */
async function handleAccountAdminRoutes(req, res, url) {
  if (url.pathname !== '/admin/subscribers' && url.pathname !== '/admin/subscribers.csv') return false;
  const db = readDb(), a = accountsState(db);
  const users = Object.values(a.users).sort((x, y) => String(y.createdAt).localeCompare(String(x.createdAt)));
  const subs = users.filter(u => u.newsletter);
  if (url.pathname === '/admin/subscribers.csv') {
    trackerAudit(db, 'export-subscribers'); writeDb(db);
    sendCsv(res, 'bulamu360-newsletter-subscribers.csv', [['name', 'email', 'subscribed_at', 'account_created']].concat(subs.map(u => [u.name, u.email, u.newsletterAt || '', u.createdAt])));
    return true;
  }
  sendHtml(res, 200, trackerAdminShell('Accounts & subscribers', `<div class="top"><div><h1>Accounts &amp; newsletter</h1><p>${users.length} tracker account(s) · ${subs.length} newsletter subscriber(s)</p></div><div class="row noprint"><a class="btn ghost" href="/admin/subscribers.csv">Export subscribers CSV</a></div></div>
  <div class="panel"><div class="scroll"><table><thead><tr><th>Name</th><th>Email</th><th>Created</th><th>Last sign-in</th><th>Newsletter</th><th>Tracker saved</th></tr></thead><tbody>${users.map(u => `<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.email)}</td><td>${escapeHtml(new Date(u.createdAt).toLocaleDateString())}</td><td>${u.lastLoginAt ? escapeHtml(new Date(u.lastLoginAt).toLocaleString()) : '–'}</td><td>${u.newsletter ? '<span class="badge ok">Subscribed</span>' : '<span class="badge">No</span>'}</td><td>${u.tracker ? escapeHtml(new Date(u.tracker.savedAt).toLocaleString()) : '–'}</td></tr>`).join('') || '<tr><td colspan="6" class="note">No accounts yet.</td></tr>'}</tbody></table></div></div>
  <p class="note">Passwords are stored as salted scrypt hashes; they cannot be viewed. Only people who ticked the newsletter box are included in the export.</p>`, 'subscribers'));
  return true;
}

const server = http.createServer(async (req, res) => {
  try {
    res._corsOrigin = corsOriginForRequest(req);
    if (req.method === 'OPTIONS') return sendJson(res, 204, {});
    const url = new URL(req.url || '/', `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, healthPayload());
    if (req.method === 'GET' && url.pathname === '/api/health') return sendJson(res, 200, healthPayload());
    if (req.method === 'GET' && url.pathname === '/api/member-status') return sendJson(res, 200, memberAccessStatus(req));
    if (req.method === 'POST' && url.pathname === '/api/leads' && !rateLimit(req, res, 'create-lead', { limit: 30, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/orders' && !rateLimit(req, res, 'create-order', { limit: 20, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/unlock-plan' && !rateLimit(req, res, 'unlock-plan', { limit: 20, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/recipe-pool' && !rateLimit(req, res, 'recipe-pool', { limit: 40, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/leads') return handleCreateLead(req, res);
    if (req.method === 'POST' && url.pathname === '/api/orders') return handleCreateOrder(req, res);
    if (req.method === 'POST' && url.pathname === '/api/unlock-plan') return handleUnlockPlan(req, res);
    if (req.method === 'POST' && url.pathname === '/api/recipe-pool') return handleRecipePool(req, res);
    if (await handleTrackerPublicRoutes(req, res, url)) return;
    if (await handleAccountRoutes(req, res, url)) return;
    if (await handleTemplateRoutes(req, res, url)) return;
    if (req.method === 'GET' && (url.pathname === '/member/login' || url.pathname === '/member')) { res.writeHead(302, securityHeaders({ Location: '/?signin=1' })); return res.end(); }
    if (req.method === 'POST' && url.pathname === '/member/login') return handleMemberLogin(req, res);
    if (req.method === 'GET' && url.pathname === '/member/logout') {
      const sid = getCookie(req, 'bulamu_member');
      if (sid) sessions.delete(`member:${sid}`);
      res.writeHead(302, securityHeaders({ Location: '/', 'Set-Cookie': memberSessionCookie('', 0) }));
      return res.end();
    }
    if (req.method === 'GET' && url.pathname === '/member') {
      const member = requireMember(req, res);
      if (!member) return;
      return sendHtml(res, 200, memberDashboardPage(req, member));
    }
    if (req.method === 'POST' && url.pathname === '/member/progress') {
      if (!verifySameOriginPost(req, res)) return;
      const member = requireMember(req, res);
      if (!member) return;
      return handleMemberProgress(req, res, member);
    }
    if (req.method === 'POST' && url.pathname === '/member/food-diary') {
      if (!verifySameOriginPost(req, res)) return;
      const member = requireMember(req, res);
      if (!member) return;
      return handleMemberFoodDiary(req, res, member);
    }
    if (req.method === 'GET' && url.pathname === '/admin/login') return sendHtml(res, 200, adminLoginPage());
    if (req.method === 'POST' && url.pathname === '/admin/login') {
      if (!verifySameOriginPost(req, res)) return;
      return handleAdminLogin(req, res);
    }
    if (req.method === 'GET' && url.pathname === '/admin/logout') {
      res.writeHead(302, securityHeaders({ Location: '/admin/login', 'Set-Cookie': adminSessionCookie('', 0) }));
      return res.end();
    }
    if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
      if (!requireAdmin(req, res)) return;
      if (req.method !== 'GET' && !verifySameOriginPost(req, res)) return;
      if (req.method === 'GET' && url.pathname === '/admin') return sendHtml(res, 200, adminDashboard(req));
      if (req.method === 'GET' && url.pathname === '/admin/system') return sendHtml(res, 200, adminSystemPage());
      if (req.method === 'GET' && url.pathname === '/admin/audit') return sendHtml(res, 200, adminAuditPage());
      if (req.method === 'GET' && url.pathname === '/admin/backup.json') return exportBackupJson(res);
      if (req.method === 'GET' && url.pathname === '/admin/orders.csv') return exportCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/leads.csv') return exportLeadsCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/member-progress.csv') return exportMemberProgressCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/food-diary.csv') return exportFoodDiaryCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/followups') return sendHtml(res, 200, adminFollowupsPage());
      if (req.method === 'GET' && url.pathname === '/admin/followups.csv') return exportFollowupsCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/coach-queue') return sendHtml(res, 200, adminCoachQueuePage());
      if (req.method === 'GET' && url.pathname === '/admin/coach-queue.csv') return exportCoachQueueCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/replacements') return sendHtml(res, 200, adminReplacementQueuePage());
      if (req.method === 'GET' && url.pathname === '/admin/replacements.csv') return exportReplacementQueueCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/plan-fit') return sendHtml(res, 200, adminPlanFitPage());
      if (req.method === 'GET' && url.pathname === '/admin/plan-fit.csv') return exportPlanFitCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/insights') return sendHtml(res, 200, adminInsightsPage());
      if (req.method === 'GET' && url.pathname === '/admin/insights.csv') return exportInsightsCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/recipes') return sendHtml(res, 200, adminRecipeIntelligencePage());
      if (req.method === 'GET' && url.pathname === '/admin/recipes.csv') return exportRecipeIntelligenceCsv(res);
      if (await handleTrackerAdminRoutes(req, res, url)) return;
      if (await handleAccountAdminRoutes(req, res, url)) return;
      const followupMatch = url.pathname.match(/^\/admin\/orders\/([^/]+)\/followups\/([^/]+)$/);
      if (followupMatch) return handleAdminFollowupReview(req, res, followupMatch[1], followupMatch[2]);
      const match = url.pathname.match(/^\/admin\/orders\/([^/]+)\/(approve|reject|resend|plan|download|pdf|review|reminder|delete|edit|content)$/);
      if (match) {
        const [, id, action] = match;
        const db = readDb();
        if (action === 'content') return handlePlanContentEditor(req, res, id);
        if (action === 'edit') return handlePlanEditor(req, res, id);
        if (action === 'delete') return handleDeleteOrder(req, res, id);
        if (action === 'review') return handleReview(req, res, id);
        if (req.method === 'POST' && action === 'approve') return handleApprove(req, res, id);
        if (req.method === 'POST' && action === 'reject') return handleReject(req, res, id);
        if (req.method === 'POST' && action === 'resend') return handleResend(req, res, id);
        if (req.method === 'POST' && action === 'reminder') return handleFollowupReminder(req, res, id);
        if (req.method === 'GET' && action === 'plan') return servePlanByOrder(res, findOrder(db, id), false, 'admin', `/admin/orders/${encodeURIComponent(id)}/pdf`);
        if (req.method === 'GET' && action === 'download') return sendPlanPdf(res, findOrder(db, id), 'admin');
        if (req.method === 'GET' && action === 'pdf') return sendPlanPdf(res, findOrder(db, id), 'admin');
      }
      return sendHtml(res, 404, 'Admin page not found');
    }
    if (req.method === 'GET' && url.pathname.startsWith('/plan/')) {
      const parts = url.pathname.split('/').filter(Boolean);
      const token = parts[1] || '';
      const db = readDb();
      const order = token ? db.orders.find(o => o.status === 'approved' && o.downloadToken === token) : null;
      if (parts[2] === 'pdf') return sendPlanPdf(res, order, 'patient');
      return servePlanByOrder(res, order, false, 'patient', `/plan/${encodeURIComponent(token)}/pdf`);
    }
    if (url.pathname.startsWith('/followup/')) {
      const token = url.pathname.split('/').pop();
      if (req.method === 'POST' && !rateLimit(req, res, 'followup-submit', { limit: 8, windowMs: 60_000 })) return;
      if (req.method === 'GET' || req.method === 'POST') return handleFollowup(req, res, token);
    }
    if (req.method === 'GET') return serveStatic(req, res);
    sendJson(res, 405, { ok: false, error: 'Method not allowed' });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { ok: false, error: isProduction ? 'Server error' : (error.message || 'Server error') });
  }
});

await initialiseStorage();

server.listen(port, () => {
  console.log(`Bulamu360 server running at http://localhost:${port}`);
  console.log(`Admin dashboard: http://localhost:${port}/admin`);
  if (supabaseEnabled()) console.log(`Storage: Supabase table ${supabaseStateTable}/${supabaseStateKey}`);
  else console.log(`Storage: local JSON at ${dbPath}`);
});
