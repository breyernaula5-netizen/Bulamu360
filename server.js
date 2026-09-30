import http from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

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
  '.md': 'text/markdown; charset=utf-8'
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
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store',
    ...extra
  };
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    ...securityHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
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
    emailConfigured: Boolean(apiKey && fromEmail),
    publicBaseUrl,
    time: new Date().toISOString()
  };
}

function validateDbShape(db) {
  if (!db || typeof db !== 'object') return { orders: [] };
  if (!Array.isArray(db.orders)) db.orders = [];
  return db;
}

function renderTemplate(filePath, values = {}) {
  let html = readFileSync(filePath, 'utf8');
  for (const [key, value] of Object.entries(values)) {
    html = html.replaceAll(`{{${key}}}`, String(value ?? ''));
  }
  html = html.replace(/\{\{[A-Z0-9_]+\}\}/g, '0');
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
    return { orders: [] };
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
  return Boolean(session && session.expires > Date.now());
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
    hasDiabetes: conds.includes('diabetes') || text.includes('diabetes'),
    hasHyper: conds.includes('hypertension') || text.includes('hypertension'),
    hasKidney: conds.includes('kidney') || text.includes('kidney'),
    hasGout: conds.includes('gout') || text.includes('gout'),
    hasCholesterol: conds.includes('cholesterol') || text.includes('cholesterol'),
    hasIBS: conds.includes('ibs') || text.includes('ibs') || text.includes('gut'),
    isPrenatal: text.includes('prenatal') || text.includes('pregnan'),
    isChild: text.includes('child'),
    isFamily: text.includes('family'),
    isOver: text.includes('over') || text.includes('obese') || text.includes('weight_loss'),
    isUnder: text.includes('under')
  };
}

function privateRecipeAllowed(recipe, profile) {
  const avoid = Array.isArray(recipe.avoid) ? recipe.avoid.map(x => String(x).toLowerCase()) : [];
  const tags = Array.isArray(recipe.tags) ? recipe.tags.map(x => String(x).toLowerCase()) : [];
  const text = [recipe.name, recipe.method, recipe.why, ...(recipe.ingredients || []), ...tags].join(' ').toLowerCase();
  if (profile.hasDiabetes && (avoid.includes('diabetes') || avoid.includes('diabetes_strict'))) return false;
  if (profile.hasKidney && (avoid.includes('kidney') || avoid.includes('kidney_review'))) return false;
  if (profile.hasGout && avoid.includes('gout')) return false;
  if (profile.hasCholesterol && (avoid.includes('cholesterol') || avoid.includes('cholesterol_strict'))) return false;
  if (profile.hasIBS && (avoid.includes('ibs') || avoid.includes('gut_sensitive'))) return false;
  if (profile.isPrenatal && avoid.includes('pregnancy')) return false;
  if (profile.hasKidney && /avocado|banana|sweet potato|dodo|nakati|sukuma|spinach|beans|lentil|mukene|groundnut/.test(text)) return false;
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
  if (profile.isPrenatal && (tags.includes('pregnancy') || tags.includes('prenatal'))) score += 8;
  if (profile.isChild && (tags.includes('child') || tags.includes('family'))) score += 7;
  if (profile.budget === 'low' && (recipe.cost === 'Low' || tags.includes('budget'))) score += 6;
  if (profile.cooking === 'limited' && Number(recipe.time || 99) <= 15) score += 4;
  if (tags.includes('salad') || tags.includes('smoothie') || tags.includes('soup')) score += 2;
  return score;
}

function limitedRecipePoolForProfile(payload = {}) {
  const { schema, recipes, swaps } = loadPrivateRecipes();
  const profile = profileFromRecipeRequest(payload);
  const limits = { breakfast: 18, lunch: 24, dinner: 24, snack: 18 };
  const selected = [];
  Object.keys(limits).forEach(meal => {
    recipes
      .filter(recipe => recipe.meal === meal && privateRecipeAllowed(recipe, profile))
      .sort((a, b) => privateRecipeScore(b, profile) - privateRecipeScore(a, profile) || String(a.name).localeCompare(String(b.name)))
      .slice(0, limits[meal])
      .forEach(recipe => selected.push(recipe));
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
  const pool = limitedRecipePoolForProfile(payload).recipes;
  const byMeal = { breakfast: [], lunch: [], dinner: [], snack: [] };
  pool.forEach(recipe => {
    if (byMeal[recipe.meal]) byMeal[recipe.meal].push(recipe);
  });
  return byMeal;
}

function pickRecipe(list, index) {
  if (!list || !list.length) return null;
  return list[index % list.length];
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
  if (conds.includes('kidney') && !(profile.labs && (profile.labs.egfr || profile.labs.creatinine))) blockers.push('Kidney condition selected without kidney lab values.');
  if (conds.includes('diabetes') && !(profile.labs && (profile.labs.hba1c || profile.labs.glucose))) blockers.push('Diabetes selected without HbA1c or fasting glucose.');
  if ((conds.includes('hypertension') || String(profile.goal || '').includes('hypertension')) && !(profile.labs && profile.labs.sbp && profile.labs.dbp)) warnings.push('Hypertension selected without current BP readings.');
  if ((String(profile.goal || '').includes('prenatal') || String(profile.lifeStage || '').includes('pregnant')) && !(profile.prenatal && profile.prenatal.trimester)) blockers.push('Pregnancy selected without trimester/status details.');
  const status = blockers.length ? 'review' : warnings.length ? 'caution' : 'safe';
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
    symptoms: profile.symptoms || '',
    allergies: profile.allergies || '',
    customerSource: profile.customerSource || '',
    referralCode: profile.referralCode || '',
    customerType: profile.customerType || '',
    budget: profile.budget || '',
    cooking: profile.cooking || '',
    safetyDecision: {
      status,
      label: status === 'review' ? 'Review required before approval' : status === 'caution' ? 'Caution review recommended' : 'Ready for standard review',
      summary: 'Backend-generated safety summary from submitted customer answers.',
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
    clinicalTargets: [],
    conditionChapters: conds.map(c => ({ title: `${c.charAt(0).toUpperCase()}${c.slice(1)} Support Chapter`, priority: 'review', review: 'Apply customer-specific clinical judgment before final approval.' }))
  };
}

function recipeCardHtml(recipe) {
  if (!recipe) return '';
  const ingredients = (recipe.ingredients || []).join(', ');
  const swaps = (recipe.substitutions || []).slice(0, 2).join(' | ');
  const taste = (recipe.tasteProfile || []).join(', ');
  return `<div class="meal-card">
    <div class="meal-time">${escapeHtml(recipe.meal || 'meal')}</div>
    <div class="meal-name">${escapeHtml(recipe.name || 'Meal')}</div>
    <div class="meal-chips">
      ${recipe.time ? `<span>${escapeHtml(recipe.time)} min</span>` : ''}
      ${recipe.cost ? `<span>${escapeHtml(recipe.cost)}</span>` : ''}
      ${recipe.reviewStatus ? `<span>${escapeHtml(recipe.reviewStatus)}</span>` : ''}
    </div>
    <div class="meal-grid">
      <div class="meal-box"><strong>Ingredients</strong><p>${escapeHtml(ingredients || 'Use listed foods in measured portions.')}</p></div>
      <div class="meal-box"><strong>Preparation</strong><p>${escapeHtml(recipe.method || 'Prepare simply with minimal oil, sugar, and salt.')}</p></div>
      <div class="meal-box"><strong>Portion</strong><p>${escapeHtml(recipe.portion || 'Use a balanced plate: vegetables first, then protein, then measured starch if included.')}</p></div>
      <div class="meal-box"><strong>Food reason</strong><p>${escapeHtml(recipe.why || 'Selected to support the customer profile while keeping the meal practical.')}</p></div>
    </div>
    ${taste ? `<div class="meal-note"><strong>Taste:</strong> ${escapeHtml(taste)}</div>` : ''}
    ${swaps ? `<div class="meal-note"><strong>Smart swaps:</strong> ${escapeHtml(swaps)}</div>` : ''}
  </div>`;
}

function backendPlanHtml(payload = {}, clinicalSummary = {}) {
  const profile = payload.profile && typeof payload.profile === 'object' ? payload.profile : payload;
  const macros = serverMacroSummary(profile);
  const recipes = firstRecipesByMeal(profile);
  const issued = new Date().toLocaleDateString('en-UG', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
  const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
  const conditions = cleanList(profile.conds || payload.conds).join(', ') || 'General nutrition support';
  const rows = [
    ['Name', payload.name || profile.name],
    ['Package', payload.packageName],
    ['Goal', profile.goal || 'General wellness'],
    ['Conditions', conditions],
    ['BMI', payload.bmi || profile.bmi || 'Not captured'],
    ['Budget', profile.budget || 'Not captured'],
    ['Cooking access', profile.cooking || 'Not captured']
  ].filter(([, value]) => String(value || '').trim());
  let html = `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Plan: ${escapeHtml(payload.name || profile.name || 'Client')}</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0;line-height:1.65}
    .page{max-width:880px;margin:0 auto;background:#fff;min-height:100vh}
    .cover{background:#1e3a1a;color:#fff;padding:38px 44px}
    .cover h1{font-family:Georgia,serif;font-size:34px;margin:0 0 8px}
    .cover p{margin:0;color:#dbead5}.body{padding:34px 44px}
    .sec{margin-bottom:28px}.sh{display:flex;align-items:center;gap:10px;border-bottom:2px solid #e2dbcf;padding-bottom:8px;margin-bottom:12px}
    .si{width:30px;height:30px;border-radius:8px;background:#2f6b2b;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px}.si.o{background:#b85c1c}.si.r{background:#8a1010}.si.y{background:#8a6200}
    .st{font-family:Georgia,serif;font-size:18px;font-weight:700;color:#1e3a1a}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.box{background:#faf7f1;border:1px solid #e6dccd;border-radius:8px;padding:10px}.box strong{color:#1e3a1a}
    .macro{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.macro div{background:#ebf7e8;border-radius:8px;padding:10px;text-align:center}.macro b{display:block;font-size:20px;color:#1e3a1a}
    .week-card{border:1px solid #e2dbcf;border-radius:10px;overflow:hidden;margin-bottom:16px}.day-title{background:#f1eadf;padding:10px 12px;font-weight:800;color:#1e3a1a}
    .meal-card{padding:12px;border-top:1px solid #eee6dc}.meal-time{text-transform:uppercase;font-size:10px;font-weight:800;color:#8a7a68}.meal-name{font-weight:800;color:#2a1f14;margin:2px 0 6px}
    .meal-chips{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px}.meal-chips span{font-size:10px;background:#ebf7e8;color:#1e3a1a;border-radius:999px;padding:3px 7px;font-weight:700}
    .meal-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}.meal-box{background:#fffdf8;border-left:3px solid #b85c1c;border-radius:7px;padding:8px}.meal-box strong{display:block;font-size:10px;text-transform:uppercase;color:#7a3c10}.meal-box p{font-size:12px;margin:4px 0 0}
    .meal-note{font-size:11.5px;background:#f7f3ec;border:1px solid #e2dbcf;border-radius:7px;padding:8px;margin-top:7px}
    .note{background:#fff8e8;border-left:4px solid #b85c1c;border-radius:8px;padding:12px}.prtbtn{text-align:center;background:#f7f3ec;padding:18px}@media print{.prtbtn{display:none}.meal-card,.week-card,.sec{page-break-inside:avoid}}@media(max-width:700px){.body,.cover{padding:24px}.grid,.macro,.meal-grid{grid-template-columns:1fr}}
  </style></head><body><div class="page"><div class="cover"><h1>Bulamu360 Personalised Nutrition Plan</h1><p>Prepared privately by the backend plan engine for ${escapeHtml(payload.name || profile.name || 'Client')} on ${escapeHtml(issued)}.</p></div><div class="body">`;
  html += `<div class="sec"><div class="sh"><div class="si">ID</div><div class="st">Client Snapshot</div></div><div class="grid">${rows.map(([label, value]) => `<div class="box"><strong>${escapeHtml(label)}</strong><br>${escapeHtml(value)}</div>`).join('')}</div></div>`;
  html += `<div class="sec"><div class="sh"><div class="si o">NT</div><div class="st">Nutrition Targets</div></div><div class="macro"><div><b>${macros.calories}</b>kcal</div><div><b>${macros.protein}g</b>protein</div><div><b>${macros.carbs}g</b>carbs</div><div><b>${macros.fat}g</b>fat</div><div><b>${macros.water}L</b>water</div></div><p class="note">Targets are starting estimates and should be adjusted using appetite, weight trend, symptoms, glucose/BP/lab readings where relevant, and dietician review.</p></div>`;
  if (clinicalSummary.safetyDecision) {
    const sd = clinicalSummary.safetyDecision;
    html += `<div class="sec"><div class="sh"><div class="si r">SF</div><div class="st">Safety Review</div></div><div class="note"><strong>${escapeHtml(sd.label || 'Safety review')}</strong><br>${escapeHtml(sd.summary || '')}${(sd.review || []).map(x => `<div>${escapeHtml(x)}</div>`).join('')}${(sd.caution || []).map(x => `<div>${escapeHtml(x)}</div>`).join('')}</div></div>`;
  }
  html += `<div class="sec"><div class="sh"><div class="si y">MP</div><div class="st">7-Day Meal Structure</div></div>`;
  days.forEach((day, i) => {
    html += `<div class="week-card"><div class="day-title">${day}</div>`;
    html += recipeCardHtml(pickRecipe(recipes.breakfast, i));
    html += recipeCardHtml(pickRecipe(recipes.snack, i));
    html += recipeCardHtml(pickRecipe(recipes.lunch, i));
    html += recipeCardHtml(pickRecipe(recipes.snack, i + 7));
    html += recipeCardHtml(pickRecipe(recipes.dinner, i));
    html += `</div>`;
  });
  html += `</div><div class="sec"><div class="sh"><div class="si">FU</div><div class="st">Follow-Up</div></div><div class="note">Use the plan for the approved period, then submit progress feedback on taste, cost, symptoms, hunger, disliked meals, repeated meals, and measurements. Severe or worsening symptoms require medical care.</div></div>`;
  html += `</div><div class="prtbtn"><button onclick="window.print()" style="background:#1e3a1a;color:#fff;border:0;border-radius:999px;padding:12px 24px;font-weight:800">Print or Save as PDF</button></div></div></body></html>`;
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
  const link = downloadUrl ? `<p><a href="${escapeHtml(downloadUrl)}" style="background:#1e3a1a;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;display:inline-block">Open approved plan</a></p>` : '';
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
    <p>Your payment reference has been approved. Your printable plan copy is attached.</p>
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

async function sendOrderSubmittedEmails(order) {
  await Promise.allSettled([
    sendResendEmail({
      to: order.email,
      subject: 'Bulamu360 payment reference received',
      html: `<p>Hello ${escapeHtml(order.name)},</p><p>Your payment reference has been received and is pending Breyer's approval.</p><p><strong>Package:</strong> ${escapeHtml(order.packageName)}<br><strong>Amount:</strong> ${escapeHtml(order.amount)}<br><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p>`
    }),
    ownerEmail ? sendResendEmail({
      to: ownerEmail,
      subject: `Pending Bulamu360 order - ${order.name}`,
      html: `<p>A new Bulamu360 order is pending approval.</p><p><strong>Name:</strong> ${escapeHtml(order.name)}<br><strong>Email:</strong> ${escapeHtml(order.email)}<br><strong>Phone:</strong> ${escapeHtml(order.phone)}<br><strong>Package:</strong> ${escapeHtml(order.packageName)}<br><strong>Amount:</strong> ${escapeHtml(order.amount)}<br><strong>Network:</strong> ${escapeHtml(order.network)}<br><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p><p><a href="${publicBaseUrl}/admin">Open admin dashboard</a></p>`
    }) : Promise.resolve()
  ]);
}

async function sendApprovalEmail(order) {
  const safeName = String(order.name || 'Client').replace(/[^\w.-]+/g, '_').slice(0, 80) || 'Client';
  const patientPlanHtml = planHtmlForOrder(order, { audience: 'patient' });
  const attachmentContent = Buffer.from(patientPlanHtml, 'utf8').toString('base64');
  const downloadUrl = `${publicBaseUrl}/plan/${order.downloadToken}`;
  return await sendResendEmail({
    to: order.email,
    subject: `Approved: your Bulamu360 plan - ${order.packageName}`,
    html: planEmailHtml(order, downloadUrl),
    attachments: [{
      filename: `${safeName} - Bulamu360 Plan.html`,
      content: attachmentContent,
      content_type: 'text/html'
    }]
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
  setTimeout(async () => {
    try {
      const result = await task();
      appendEmailLog(orderId, {
        type,
        status: 'sent',
        id: result && result.id ? result.id : '',
        ...extra
      });
    } catch (err) {
      appendEmailLog(orderId, {
        type,
        status: 'failed',
        error: err.message || 'Email sending failed.',
        ...extra
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
  const planEdit = {
    greeting: String(form.planGreeting || '').trim(),
    mealNotes: String(form.planMealNotes || '').trim(),
    ingredients: String(form.planIngredients || '').trim(),
    preparation: String(form.planPreparation || '').trim(),
    portions: String(form.planPortions || '').trim(),
    swaps: String(form.planSwaps || '').trim(),
    shopping: String(form.planShopping || '').trim(),
    exercise: String(form.planExercise || '').trim(),
    followup: String(form.planFollowup || '').trim(),
    extraGuidance: String(form.planExtraGuidance || '').trim(),
    replacements: [1, 2, 3].map(n => ({
      find: String(form[`replaceFind${n}`] || '').trim(),
      with: String(form[`replaceWith${n}`] || '').trim()
    }))
  };
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
    planEdit,
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
    'Condition-Specific Clinical Chapters',
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
    .replace(/<strong>Why selected:<\/strong>/g, '<strong>Food reason:</strong>')
    .replace(/<strong>Taste profile:<\/strong>/g, '<strong>Taste:</strong>')
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
    html: `<p>Hello ${escapeHtml(order.name)},</p><p>Breyer could not approve the payment reference you submitted yet.</p><p><strong>Reference:</strong> ${escapeHtml(order.txRef)}</p><p>${escapeHtml(order.adminNote || 'Please WhatsApp your payment SMS to +256 704 392545 for review.')}</p>`
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
  if (!String(payload.txRef || '').trim() || String(payload.txRef).trim().length < 6) return 'Transaction reference is required.';
  if (!payload.profile || typeof payload.profile !== 'object') return 'Customer profile is required for private plan generation.';
  return '';
}

async function handleCreateOrder(req, res) {
  try {
    const payload = await readRequestJson(req);
    const error = validateOrderPayload(payload);
    if (error) return sendJson(res, 400, { ok: false, error });
    const db = readDb();
    const now = new Date().toISOString();
    const clinicalSummary = serverClinicalSummaryFromPayload(payload);
    const privateHtmlPlan = backendPlanHtml(payload, clinicalSummary);
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
    queueOrderEmail(order, 'order-submitted', () => sendOrderSubmittedEmails(order));
    sendJson(res, 200, { ok: true, orderId: order.id, status: order.status });
  } catch (error) {
    sendJson(res, 500, { ok: false, error: error.message || 'Could not create order.' });
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
    sendJson(res, 200, {
      ok: true,
      order: {
        id: order.id,
        name: order.name,
        packageName: order.packageName,
        amount: order.amount,
        approvalCode: order.approvalCode,
        downloadUrl: `/plan/${order.downloadToken}`
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
  return `<div class="email-status email-ok">Email sent${latest.id ? ` · ${escapeHtml(latest.id)}` : ''}</div>`;
}

function adminDashboard(req) {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const statusFilter = url.searchParams.get('status') || 'all';
  const db = readDb();
  const orders = db.orders.filter(o => statusFilter === 'all' || o.status === statusFilter);
  const counts = db.orders.reduce((acc, o) => (acc[o.status] = (acc[o.status] || 0) + 1, acc), {});
  const followups = allFollowups(db);
  const leadCount = db.orders.filter(o => {
    const cs = o.clinicalSummary || {};
    const status = String(o.status || '').toLowerCase();
    const amount = String(o.amount || '').toLowerCase();
    const source = String(cs.customerSource || cs.customerType || '').toLowerCase();
    return status === 'lead' || amount.includes('free') || source.includes('free');
  }).length;
  const coachQueueCount = followups.filter(({ followup }) => !followup.adminAdjustment || !followup.adminAdjustment.action).length;
  const replacementCount = followups.filter(({ followup }) => {
    return [
      followup.requestedSubstitutions,
      followup.dislikedFoods,
      followup.repeatedMeals,
      followup.hardToCookMeals,
      followup.expensiveMeals,
      followup.foodsCausingSymptoms
    ].some(value => String(value || '').trim());
  }).length;
  const lowFitCount = followups.filter(({ followup }) => {
    const adherence = Number(followup.adherence || 0);
    const taste = Number(followup.tasteSatisfaction || 0);
    const budget = Number(followup.budgetDifficulty || 0);
    const cooking = Number(followup.cookingDifficulty || 0);
    const availability = Number(followup.foodAvailabilityDifficulty || 0);
    return (adherence > 0 && adherence <= 5) || (taste > 0 && taste <= 5) || budget >= 7 || cooking >= 7 || availability >= 7;
  }).length;
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
      : (audit.stats ? `<small>${escapeHtml(audit.stats.uniqueMeals || 0)} unique meals · ${escapeHtml(audit.stats.weeks || 0)} weeks</small>` : '');
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
    const reviewLine2 = review.updatedAt ? `<br><small>Admin review: ${review.checklistComplete ? 'checklist complete' : 'incomplete'} · ${new Date(review.updatedAt).toLocaleString()}</small>` : '<br><small>Admin review not started</small>';
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
      <a class="btn ghost" href="/admin/orders/${o.id}/review">Review</a>
      <a class="btn" href="/admin/orders/${o.id}/review?mode=plan">Edit plan</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/review?mode=html">Edit HTML file</a>
      <a class="btn ghost" href="/admin/orders/${o.id}/download">Download</a>
      ${o.status === 'pending' ? `<form method="post" action="/admin/orders/${o.id}/reject"><input name="note" placeholder="Reason for rejection"><button class="btn reject">Reject</button></form>` : ''}
      ${o.status === 'approved' ? `<form method="post" action="/admin/orders/${o.id}/resend"><button class="btn">Resend email</button></form><form method="post" action="/admin/orders/${o.id}/reminder"><select name="reviewPoint"><option>7-day check-in</option><option>14-day adherence check</option><option>30-day outcome review</option><option>60-day continuation review</option></select><button class="btn ghost">Send reminder</button></form>` : ''}
    </td>
  </tr>`;
  }).join('');
  return renderTemplate(adminDashboardTemplatePath, {
    PENDING_COUNT: counts.pending || 0,
    APPROVED_COUNT: counts.approved || 0,
    REJECTED_COUNT: counts.rejected || 0,
    LEAD_COUNT: leadCount,
    LEADS_COUNT: leadCount,
    FREE_LEAD_COUNT: leadCount,
    FREE_LEADS_COUNT: leadCount,
    COACH_QUEUE_COUNT: coachQueueCount,
    COACH_COUNT: coachQueueCount,
    REPLACEMENT_COUNT: replacementCount,
    REPLACEMENTS_COUNT: replacementCount,
    MEAL_SWAP_COUNT: replacementCount,
    MEAL_SWAPS_COUNT: replacementCount,
    LOW_FIT_COUNT: lowFitCount,
    LOW_FIT_SCORE_COUNT: lowFitCount,
    LOW_FIT_SCORES_COUNT: lowFitCount,
    ROWS_HTML: rows || '<tr class="empty-row"><td colspan="9">No orders yet.</td></tr>'
  });
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 Admin Dashboard</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1480px;margin:0 auto;padding:28px}header{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:20px}.tabs a{display:inline-block;padding:9px 13px;background:#fff;border-radius:999px;text-decoration:none;color:#1e3a1a;margin-right:6px;border:1px solid #e2dbcf}.panel{background:#fff;border-radius:18px;box-shadow:0 10px 35px #0001;overflow:auto}table{width:100%;border-collapse:collapse;min-width:1320px}th,td{text-align:left;vertical-align:top;padding:14px;border-bottom:1px solid #eee6dc;font-size:14px}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;background:#fbf8f3}.badge{padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700}.pending{background:#fff1c7;color:#8a6200}.approved{background:#dff3d8;color:#1e3a1a}.rejected{background:#ffe1dc;color:#8a1010}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:8px 10px;border-radius:8px;text-decoration:none;font-weight:700;cursor:pointer;margin:3px 0}.ghost{background:#ede8df;color:#2a1f14}.approve{background:#1e3a1a}.reject{background:#8a1010}.actions form{margin:6px 0}.actions input{display:block;width:220px;max-width:100%;padding:8px;border:1px solid #ddd;border-radius:8px;margin-bottom:4px}small{color:#6c5b49}code{background:#f1eadf;padding:4px 6px;border-radius:6px}.email-status{margin-top:8px;border-radius:8px;padding:8px;font-size:11px;line-height:1.35;font-weight:700}.email-error{background:#ffe1dc;color:#8a1010}.email-ok{background:#e4f5dd;color:#1e3a1a}.email-queued{background:#fff1c7;color:#8a6200}.safety{border-radius:9px;padding:8px 10px;font-size:12px;font-weight:800;margin-bottom:7px}.safety.safe{background:#e4f5dd;color:#1e3a1a}.safety.caution{background:#fff1c7;color:#8a6200}.safety.review{background:#ffe1dc;color:#8a1010}.safety.not-captured{background:#eee6dc;color:#6c5b49}.risk-list{font-size:11.5px;line-height:1.45;margin-top:6px}.risk-list span{display:block;border-left:3px solid #d8cfbf;padding-left:7px;margin-top:4px}.chips{display:flex;flex-wrap:wrap;gap:5px}.chips span{background:#f1eadf;border:1px solid #e2dbcf;border-radius:999px;padding:5px 8px;font-size:11px;color:#2a1f14}</style></head>
  <body><div class="wrap"><header><div><h1>Bulamu360 Orders</h1><p>Pending: ${counts.pending || 0} · Approved: ${counts.approved || 0} · Rejected: ${counts.rejected || 0}</p></div><div><a class="btn ghost" href="/admin/insights">Insights</a> <a class="btn ghost" href="/admin/orders.csv">Export CSV</a> <a class="btn ghost" href="/admin/logout">Logout</a></div></header>
  <div class="tabs"><a href="/admin">All</a><a href="/admin?status=pending">Pending</a><a href="/admin?status=approved">Approved</a><a href="/admin?status=rejected">Rejected</a><a href="/admin/followups">Progress follow-ups</a><a href="/admin/insights">Insights</a></div>
  <div class="panel"><table><thead><tr><th>Customer</th><th>Plan</th><th>Payment</th><th>Clinical Safety</th><th>Quality Audit</th><th>Chapters</th><th>Status</th><th>Access</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="9">No orders yet.</td></tr>'}</tbody></table></div></div></body></html>`;
}

function adminSystemPage() {
  const db = readDb();
  const counts = db.orders.reduce((acc, o) => (acc[o.status] = (acc[o.status] || 0) + 1, acc), {});
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
    ['Rejected orders', counts.rejected || 0]
  ];
  return `<!doctype html><html><head><meta charset="utf-8"><title>Bulamu360 System Status</title>
  <style>body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:900px;margin:0 auto;padding:28px}.card{background:#fff;border-radius:16px;padding:20px;box-shadow:0 10px 35px #0001}.btn{display:inline-block;background:#ede8df;color:#2a1f14;padding:9px 12px;border-radius:8px;text-decoration:none;font-weight:800}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{text-align:left;border-bottom:1px solid #eee6dc;padding:12px;vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68}code{background:#f1eadf;padding:3px 6px;border-radius:6px}.warn{background:#fff1c7;border-left:4px solid #c06820;padding:12px 14px;border-radius:10px;margin:14px 0}.ok{background:#e4f5dd;border-left:4px solid #1e3a1a;padding:12px 14px;border-radius:10px;margin:14px 0}</style></head>
  <body><div class="wrap"><p><a class="btn" href="/admin">Back to dashboard</a></p><div class="card"><h1>System Status</h1>
  ${supabaseEnabled() ? '<div class="ok">Orders are configured to sync to Supabase.</div>' : '<div class="warn">Orders are using local JSON. This is acceptable for development only, not for the live public app.</div>'}
  <table><thead><tr><th>Setting</th><th>Status</th></tr></thead><tbody>${rows.map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td><code>${escapeHtml(v)}</code></td></tr>`).join('')}</tbody></table>
  <p style="color:#6c5b49;font-size:13px">Secret values are intentionally hidden. This page only shows whether each setting is configured.</p></div></div></body></html>`;
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
    <div class="card metric"><b>${data.orders.length}</b><span>Total orders</span><p class="muted">Approved ${approved} · Pending ${pending} · Rejected ${rejected}</p></div>
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

async function handleAdminLogin(req, res) {
  if (!rateLimit(req, res, 'admin-login', { limit: 8, windowMs: 60_000 })) return;
  const form = await readForm(req);
  if (!constantTimeEqual(form.password || '', adminPassword)) return sendHtml(res, 401, adminLoginPage('Incorrect password.'));
  const sid = randomUUID();
  sessions.set(sid, { createdAt: Date.now(), expires: Date.now() + 1000 * 60 * 60 * 12 });
  res.writeHead(302, securityHeaders({
    Location: '/admin',
    'Set-Cookie': adminSessionCookie(sid)
  }));
  res.end();
}

function findOrder(db, id) {
  return db.orders.find(o => o.id === id);
}

function checked(value) {
  return value ? 'checked' : '';
}

function adminReviewPage(order, message = '', mode = 'plan') {
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
  const editablePlanHtml = order.finalHtmlPlan || applyAdminAmendments(order);
  const planEdit = review.planEdit || {};
  const replacements = Array.isArray(planEdit.replacements) ? planEdit.replacements : [];
  const activeMode = mode === 'html' ? 'html' : 'plan';
  const editablePlanJson = JSON.stringify(editablePlanHtml).replace(/</g, '\\u003c');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Review ${escapeHtml(order.name)} - Bulamu360</title>
  <style>
  body{font-family:Arial,sans-serif;background:#f7f3ec;color:#2a1f14;margin:0}.wrap{max-width:1180px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.btn{display:inline-block;border:0;background:#1e3a1a;color:#fff;padding:10px 13px;border-radius:9px;text-decoration:none;font-weight:700;cursor:pointer}.ghost{background:#ede8df;color:#2a1f14}.danger{background:#8a1010}.panel{background:#fff;border-radius:18px;padding:20px;box-shadow:0 10px 35px #0001;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.edit-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#8a7a68;font-weight:700;margin-bottom:5px}.value{font-size:14px;line-height:1.55}.pill{display:inline-block;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800;margin:3px;background:#f1eadf}.safe{background:#e4f5dd;color:#1e3a1a}.caution{background:#fff1c7;color:#8a6200}.review{background:#ffe1dc;color:#8a1010}.list span{display:block;border-left:3px solid #d8cfbf;padding-left:8px;margin-top:6px;font-size:13px;line-height:1.45}textarea,input[type=text],select{width:100%;box-sizing:border-box;border:1px solid #d8d0c4;border-radius:10px;padding:11px;font:14px Arial,sans-serif;background:#fffdf9}textarea{min-height:86px}.check{display:flex;gap:9px;align-items:flex-start;background:#faf7f1;border:1px solid #e2dbcf;border-radius:10px;padding:10px;margin:8px 0}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.preview{height:520px;border:1px solid #d8d0c4;border-radius:14px;overflow:hidden;background:#fff}.preview iframe{width:100%;height:100%;border:0}.msg{background:#e4f5dd;color:#1e3a1a;border-left:4px solid #1e3a1a;padding:11px 13px;border-radius:10px;margin-bottom:14px}.edit-switch{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0 16px}.edit-switch button{border:0;border-radius:999px;padding:11px 16px;font-weight:800;cursor:pointer;background:#ede8df;color:#2a1f14}.edit-switch button.active{background:#1e3a1a;color:#fff}.editor-panel.hidden{display:none}.hint{color:#6c5b49;font-size:13px;line-height:1.55;margin-top:-6px}.replace-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:9px}@media(max-width:800px){.grid,.edit-grid,.replace-row{grid-template-columns:1fr}}
  </style></head><body><div class="wrap">
  <div class="top"><div><h1>Admin Plan Review</h1><p>${escapeHtml(order.name)} · ${escapeHtml(order.packageName)} · ${escapeHtml(order.amount)}</p></div><div><a class="btn ghost" href="/admin">Back to dashboard</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/plan" target="_blank">Open plan</a></div></div>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <div class="grid">
    <div class="panel"><h2>Customer and Payment</h2>
      <div class="label">Customer</div><div class="value"><strong>${escapeHtml(order.name)}</strong><br>${escapeHtml(order.email)}<br>${escapeHtml(order.phone)}</div><br>
      <div class="label">Payment</div><div class="value">${escapeHtml(order.network)} · ${escapeHtml(order.txRef)}<br>${escapeHtml(order.amount)} · ${escapeHtml(order.status)}</div><br>
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
    <h2>Edit Final Plan Before Sending</h2>
    <div class="edit-switch">
      <button type="button" id="editPlanButton" class="${activeMode === 'plan' ? 'active' : ''}">Edit Plan</button>
      <button type="button" id="editHtmlButton" class="${activeMode === 'html' ? 'active' : ''}">Edit HTML File <span style="font-size:11px;font-weight:700;opacity:.75">(advanced)</span></button>
    </div>
    <div id="planEditorPanel" class="editor-panel ${activeMode === 'html' ? 'hidden' : ''}">
      <p class="hint">Use this simple editor for normal plan improvements. It updates the final HTML file and live preview automatically without requiring you to code.</p>
      <div class="edit-grid">
        <div><div class="label">Client greeting</div><textarea class="simple-plan-field" name="planGreeting" placeholder="Example: Hello Naula, this plan has been adjusted after review...">${escapeHtml(planEdit.greeting || '')}</textarea></div>
        <div><div class="label">Patient-facing guidance</div><textarea class="simple-plan-field" name="planExtraGuidance" placeholder="Any extra patient-facing guidance you want added safely.">${escapeHtml(planEdit.extraGuidance || '')}</textarea></div>
        <div><div class="label">Meal notes</div><textarea class="simple-plan-field" name="planMealNotes" placeholder="Change meal wording, meal flow, or meals to emphasise.">${escapeHtml(planEdit.mealNotes || '')}</textarea></div>
        <div><div class="label">Ingredients notes</div><textarea class="simple-plan-field" name="planIngredients" placeholder="Ingredients to clarify, add, remove, or simplify.">${escapeHtml(planEdit.ingredients || '')}</textarea></div>
        <div><div class="label">Preparation notes</div><textarea class="simple-plan-field" name="planPreparation" placeholder="Cooking or preparation improvements.">${escapeHtml(planEdit.preparation || '')}</textarea></div>
        <div><div class="label">Portion guide notes</div><textarea class="simple-plan-field" name="planPortions" placeholder="Specific cup, fist, palm, spoon, or plate guidance.">${escapeHtml(planEdit.portions || '')}</textarea></div>
        <div><div class="label">Smart swaps</div><textarea class="simple-plan-field" name="planSwaps" placeholder="Food swaps for taste, budget, dislike, allergy, or condition.">${escapeHtml(planEdit.swaps || '')}</textarea></div>
        <div><div class="label">Shopping list notes</div><textarea class="simple-plan-field" name="planShopping" placeholder="Market list changes, quantities, or cheaper alternatives.">${escapeHtml(planEdit.shopping || '')}</textarea></div>
        <div><div class="label">Exercise section</div><textarea class="simple-plan-field" name="planExercise" placeholder="Safe movement guidance for this client only.">${escapeHtml(planEdit.exercise || '')}</textarea></div>
        <div><div class="label">Follow-up notes</div><textarea class="simple-plan-field" name="planFollowup" placeholder="What the client should report back and when.">${escapeHtml(planEdit.followup || '')}</textarea></div>
      </div>
      <h3>Quick wording replacements</h3>
      <p class="hint">Optional: replace exact words or phrases inside the plan. This is useful for correcting a meal name, ingredient, typo, or repeated phrase.</p>
      ${[0, 1, 2].map(i => `<div class="replace-row"><div><div class="label">Find text ${i + 1}</div><input class="simple-plan-field" type="text" name="replaceFind${i + 1}" value="${escapeHtml((replacements[i] && replacements[i].find) || '')}" placeholder="Text currently in the plan"></div><div><div class="label">Replace with ${i + 1}</div><input class="simple-plan-field" type="text" name="replaceWith${i + 1}" value="${escapeHtml((replacements[i] && replacements[i].with) || '')}" placeholder="New text"></div></div>`).join('')}
    </div>
    <div id="htmlEditorPanel" class="editor-panel ${activeMode === 'html' ? '' : 'hidden'}">
      <p class="hint">Advanced editor. Use this only when you need full control over the HTML file. The customer receives this saved final version.</p>
      <textarea id="finalHtmlPlanEditor" name="finalHtmlPlan" style="min-height:340px;font-family:Consolas,monospace;font-size:12px;line-height:1.45;white-space:pre-wrap" spellcheck="false">${escapeHtml(editablePlanHtml)}</textarea>
    </div>
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
  <div class="panel"><h2>Live Plan Preview</h2><p class="hint">This preview updates as you edit. Click save or approve to store the version you want the customer to receive.</p><div class="preview"><iframe id="finalPlanPreview" src="/admin/orders/${escapeHtml(order.id)}/plan"></iframe></div></div>
  <script>
  (function(){
    var basePlanHtml = ${editablePlanJson};
    var editor = document.getElementById('finalHtmlPlanEditor');
    var frame = document.getElementById('finalPlanPreview');
    var planPanel = document.getElementById('planEditorPanel');
    var htmlPanel = document.getElementById('htmlEditorPanel');
    var editPlanButton = document.getElementById('editPlanButton');
    var editHtmlButton = document.getElementById('editHtmlButton');
    var simpleFields = Array.prototype.slice.call(document.querySelectorAll('.simple-plan-field'));
    if (!editor || !frame) return;
    function esc(value){
      return String(value || '').replace(/[&<>"']/g, function(ch){
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
      });
    }
    function field(name){
      var el = document.querySelector('[name="' + name + '"]');
      return el ? el.value.trim() : '';
    }
    function block(title, value){
      if (!value) return '';
      return '<div style="background:#fff;border:1px solid #e2dbcf;border-radius:8px;padding:10px;margin-top:8px"><strong style="color:#1e3a1a">' + esc(title) + '</strong><div style="margin-top:4px;white-space:pre-wrap">' + esc(value) + '</div></div>';
    }
    function buildSimpleSection(){
      var content = [
        block('Client greeting', field('planGreeting')),
        block('Patient-facing guidance', field('planExtraGuidance')),
        block('Meal notes', field('planMealNotes')),
        block('Ingredients notes', field('planIngredients')),
        block('Preparation notes', field('planPreparation')),
        block('Portion guide notes', field('planPortions')),
        block('Smart swaps', field('planSwaps')),
        block('Shopping list notes', field('planShopping')),
        block('Exercise section', field('planExercise')),
        block('Follow-up notes', field('planFollowup'))
      ].filter(Boolean).join('');
      if (!content) return '';
      return '<div class="sec" data-admin-simple-edits="true"><div class="sh"><div class="si o">ED</div><div class="st">Breyer\\'s Plan Edits</div></div><div style="background:linear-gradient(135deg,#fdf8f0,#ede8df);border-radius:9px;padding:14px;border-left:4px solid #1e3a1a;font-size:12.5px;line-height:1.75">' + content + '</div></div>';
    }
    function applyReplacements(html){
      var output = String(html || '');
      [1,2,3].forEach(function(n){
        var find = field('replaceFind' + n);
        var replacement = field('replaceWith' + n);
        if (!find) return;
        output = output.split(find).join(replacement);
      });
      return output;
    }
    function insertSimpleSection(html, section){
      var cleaned = String(html || '').replace(/<div class="sec" data-admin-simple-edits="true">[\\s\\S]*?<\\/div>\\s*<\\/div>/, '');
      if (!section) return cleaned;
      var marker = '<div class="body">';
      if (cleaned.indexOf(marker) >= 0) return cleaned.replace(marker, marker + section);
      return cleaned.replace('</body>', section + '</body>');
    }
    function buildFromSimpleFields(){
      return insertSimpleSection(applyReplacements(basePlanHtml), buildSimpleSection());
    }
    function refreshPreview(){
      frame.srcdoc = editor.value || '<!doctype html><html><body><p>No plan content yet.</p></body></html>';
    }
    function refreshFromSimple(){
      editor.value = buildFromSimpleFields();
      refreshPreview();
    }
    function setMode(mode){
      var useHtml = mode === 'html';
      if (planPanel) planPanel.classList.toggle('hidden', useHtml);
      if (htmlPanel) htmlPanel.classList.toggle('hidden', !useHtml);
      if (editPlanButton) editPlanButton.classList.toggle('active', !useHtml);
      if (editHtmlButton) editHtmlButton.classList.toggle('active', useHtml);
      if (!useHtml) refreshFromSimple();
      else refreshPreview();
    }
    simpleFields.forEach(function(el){ el.addEventListener('input', refreshFromSimple); });
    if (editPlanButton) editPlanButton.addEventListener('click', function(){ setMode('plan'); });
    if (editHtmlButton) editHtmlButton.addEventListener('click', function(){ setMode('html'); });
    editor.addEventListener('input', refreshPreview);
    setMode('${activeMode}');
  })();
  </script>
  </div></body></html>`;
}

function saveAdminReview(order, form) {
  const previous = order.adminReview || {};
  const next = reviewFromForm(form, previous);
  order.reviewHistory = Array.isArray(order.reviewHistory) ? order.reviewHistory : [];
  order.reviewHistory.push({ at: next.updatedAt, type: form.intent || 'save', adminReview: next });
  order.adminReview = next;
  order.adminNote = String(form.note || order.adminNote || '').trim();
  const submittedFinalHtml = String(form.finalHtmlPlan || '').trim();
  order.finalHtmlPlan = submittedFinalHtml || applyAdminAmendments(order);
  order.finalHtmlHash = createHash('sha256').update(order.finalHtmlPlan).digest('hex');
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
  </head><body><div class="wrap"><div class="card"><h1>Bulamu360 Progress Review</h1><p>Hello ${escapeHtml(order.name)}, use this form to tell Breyer how the plan is working in real life.</p><p><strong>Plan:</strong> ${escapeHtml(order.packageName)} · <strong>Approved:</strong> ${escapeHtml(order.approvedAt || '')}</p></div>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <div class="card"><h2>Review Schedule</h2><div class="sched">${followupSchedule().map(s => `<div><strong>${escapeHtml(s.label)}</strong><br>${escapeHtml(s.purpose)}</div>`).join('')}</div></div>
  ${latest ? `<div class="card"><h2>Latest Submission</h2><p>${escapeHtml(new Date(latest.createdAt).toLocaleString())} · ${escapeHtml(latest.reviewPoint || '')}</p><p><strong>Admin response:</strong> ${escapeHtml(latest.adminAdjustment && latest.adminAdjustment.action ? latest.adminAdjustment.action : 'Pending review')}</p></div>` : ''}
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
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const mode = url.searchParams.get('mode') === 'html' ? 'html' : 'plan';
  if (req.method === 'GET') return sendHtml(res, 200, adminReviewPage(order, '', mode));
  const form = await readForm(req);
  saveAdminReview(order, form);
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
      return sendHtml(res, 400, adminReviewPage(order, 'Complete every approval checklist item before approving.', mode));
    }
    approveOrder(db, order, form);
    return redirect(res, '/admin?status=pending');
  }
  writeDb(db);
  return sendHtml(res, 200, adminReviewPage(order, 'Review notes saved.', mode));
}

function approveOrder(db, order, form = {}) {
  order.status = 'approved';
  order.updatedAt = new Date().toISOString();
  order.approvedAt = order.updatedAt;
  order.adminNote = form.note || order.adminNote || '';
  order.approvalCode = order.approvalCode || makeApprovalCode();
  order.downloadToken = order.downloadToken || makeDownloadToken();
  order.followupToken = order.followupToken || makeFollowupToken();
  if (Object.keys(form).length) order.adminReview = reviewFromForm(form, order.adminReview || {});
  const submittedFinalHtml = String(form.finalHtmlPlan || '').trim();
  order.finalHtmlPlan = submittedFinalHtml || applyAdminAmendments(order);
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
      <td><small>Weight: ${escapeHtml(followup.weight || '-')} · Waist: ${escapeHtml(followup.waist || '-')}</small><br><small>Reading: ${escapeHtml(followup.clinicalReading || '-')}</small><br><small>Energy: ${escapeHtml(followup.energy || '-')} · Adherence: ${escapeHtml(followup.adherence || '-')}</small></td>
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
  <body><div class="wrap"><div class="card"><h1>Follow-up Review</h1><p>${escapeHtml(order.name)} · ${escapeHtml(order.packageName)} · ${escapeHtml(followup.reviewPoint)}</p><a class="btn ghost" href="/admin/followups">Back to follow-ups</a> <a class="btn ghost" href="/admin/orders/${escapeHtml(order.id)}/review">Order review</a></div>
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
  if (!(order.adminReview && order.adminReview.checklistComplete)) return redirect(res, `/admin/orders/${encodeURIComponent(id)}/review`);
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
  writeDb(db);
  queueOrderEmail(order, 'rejection', () => sendRejectionEmail(order));
  redirect(res, '/admin?status=pending');
}

async function handleResend(req, res, id) {
  const db = readDb();
  const order = findOrder(db, id);
  if (!order || order.status !== 'approved') return sendHtml(res, 404, 'Approved order not found');
  queueOrderEmail(order, 'resend', () => sendApprovalEmail(order));
  redirect(res, '/admin?status=approved');
}

function csvEscape(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function exportCsv(res) {
  const db = readDb();
  const header = ['id','createdAt','status','name','email','phone','customerSource','customerType','referralCode','packageName','amount','orderType','consultationAddon','network','txRef','approvalCode','riskScore','confidence','safetyStatus','safetyLabel','auditScore','auditStatus','auditLabel','auditBlockers','auditWarnings','auditUniqueMeals','auditWeeks','adminReviewComplete','adminClinicalNote','customerReleaseNote','adminApprovalCondition','adminRequestedLab','adminDietaryCorrection','adminFollowUpInstruction','actualAmountPaid','paymentVerifier','paymentMismatchReason','urgencyLevel','clinicianReferralRecommended','referralReason','redFlagSymptoms','medicationClass','adminOverrideReason','planVersion','rulesEngineVersion','recipeDatabaseVersion','rulesOverall','ruleReview','ruleCaution','contraindications','reviewGates','cautions','conditionChapters','diagnosis','allergies','symptoms','waist','waistRisk','adminNote'];
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
      allergies: cs.allergies || '',
      symptoms: cs.symptoms || '',
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

function servePlanByOrder(res, order, download = false, audience = 'patient') {
  if (!order) return sendHtml(res, 404, 'Plan not found');
  const headers = download ? { 'Content-Disposition': `attachment; filename="Bulamu360_Plan_${order.name.replace(/[^\w.-]+/g, '_')}.html"` } : {};
  sendHtml(res, 200, planHtmlForOrder(order, { audience }), headers);
}

function isPrivateStaticPath(requested) {
  const clean = String(requested || '').replace(/\\/g, '/').toLowerCase();
  const parts = clean.split('/').filter(Boolean);
  if (parts.some(part => part.startsWith('.'))) return true;
  if (parts.includes('data')) return true;
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
  if (requested === '/') requested = '/bulamu360-website.html';
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
    res.writeHead(200, securityHeaders({
      'Content-Type': mimeTypes[extname(fullPath)] || 'application/octet-stream',
      'Cache-Control': extname(fullPath) === '.html' ? 'no-store' : 'public, max-age=300'
    }));
    res.end(file);
  } catch {
    sendHtml(res, 404, 'Not found');
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') return sendJson(res, 204, {});
    const url = new URL(req.url || '/', `http://${req.headers.host}`);
    if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, healthPayload());
    if (req.method === 'GET' && url.pathname === '/api/health') return sendJson(res, 200, healthPayload());
    if (req.method === 'POST' && url.pathname === '/api/orders' && !rateLimit(req, res, 'create-order', { limit: 20, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/unlock-plan' && !rateLimit(req, res, 'unlock-plan', { limit: 20, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/recipe-pool' && !rateLimit(req, res, 'recipe-pool', { limit: 40, windowMs: 60_000 })) return;
    if (req.method === 'POST' && url.pathname === '/api/orders') return handleCreateOrder(req, res);
    if (req.method === 'POST' && url.pathname === '/api/unlock-plan') return handleUnlockPlan(req, res);
    if (req.method === 'POST' && url.pathname === '/api/recipe-pool') return handleRecipePool(req, res);
    if (req.method === 'GET' && url.pathname === '/admin/login') return sendHtml(res, 200, adminLoginPage());
    if (req.method === 'POST' && url.pathname === '/admin/login') return handleAdminLogin(req, res);
    if (req.method === 'GET' && url.pathname === '/admin/logout') {
      res.writeHead(302, securityHeaders({ Location: '/admin/login', 'Set-Cookie': adminSessionCookie('', 0) }));
      return res.end();
    }
    if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
      if (!requireAdmin(req, res)) return;
      if (req.method === 'GET' && url.pathname === '/admin') return sendHtml(res, 200, adminDashboard(req));
      if (req.method === 'GET' && url.pathname === '/admin/system') return sendHtml(res, 200, adminSystemPage());
      if (req.method === 'GET' && url.pathname === '/admin/orders.csv') return exportCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/followups') return sendHtml(res, 200, adminFollowupsPage());
      if (req.method === 'GET' && url.pathname === '/admin/followups.csv') return exportFollowupsCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/insights') return sendHtml(res, 200, adminInsightsPage());
      if (req.method === 'GET' && url.pathname === '/admin/insights.csv') return exportInsightsCsv(res);
      if (req.method === 'GET' && url.pathname === '/admin/recipes') return sendHtml(res, 200, adminRecipeIntelligencePage());
      if (req.method === 'GET' && url.pathname === '/admin/recipes.csv') return exportRecipeIntelligenceCsv(res);
      const followupMatch = url.pathname.match(/^\/admin\/orders\/([^/]+)\/followups\/([^/]+)$/);
      if (followupMatch) return handleAdminFollowupReview(req, res, followupMatch[1], followupMatch[2]);
      const match = url.pathname.match(/^\/admin\/orders\/([^/]+)\/(approve|reject|resend|plan|download|review|reminder)$/);
      if (match) {
        const [, id, action] = match;
        const db = readDb();
        if (action === 'review') return handleReview(req, res, id);
        if (req.method === 'POST' && action === 'approve') return handleApprove(req, res, id);
        if (req.method === 'POST' && action === 'reject') return handleReject(req, res, id);
        if (req.method === 'POST' && action === 'resend') return handleResend(req, res, id);
        if (req.method === 'POST' && action === 'reminder') return handleFollowupReminder(req, res, id);
        if (req.method === 'GET' && action === 'plan') return servePlanByOrder(res, findOrder(db, id), false, 'admin');
        if (req.method === 'GET' && action === 'download') return servePlanByOrder(res, findOrder(db, id), true, 'admin');
      }
      return sendHtml(res, 404, 'Admin page not found');
    }
    if (req.method === 'GET' && url.pathname.startsWith('/plan/')) {
      const token = url.pathname.split('/').pop();
      const db = readDb();
      const order = db.orders.find(o => o.status === 'approved' && o.downloadToken === token);
      return servePlanByOrder(res, order, false, 'patient');
    }
    if (url.pathname.startsWith('/followup/')) {
      const token = url.pathname.split('/').pop();
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
