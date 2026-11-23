require('dotenv').config();
process.env.TZ = process.env.TZ || 'Asia/Kolkata';
const express = require('express'), helmet = require('helmet'), cookieParser = require('cookie-parser'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), multer = require('multer'), Database = require('better-sqlite3'),
  path = require('path'), fs = require('fs'), crypto = require('crypto'), rateLimit = require('express-rate-limit');

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (PROD ? null : crypto.randomBytes(32).toString('hex'));
if (!SECRET) { console.error('JWT_SECRET is required in production'); process.exit(1); }
const MAX = 15, LEAD = 6, MIN = 100;
const STORAGE = path.resolve(process.env.STORAGE_DIR || path.join(__dirname, 'storage'));
fs.mkdirSync(STORAGE, { recursive: true });
const CAPMSG = "We’re currently handling 15 active orders. New orders will open when a slot becomes available.";
const ST = ['New', 'Accepted', 'Waiting List', 'In Progress', 'Completed', 'Cancelled'];
const ACT = ['New', 'Accepted', 'In Progress'], ACTSQL = ACT.map(s => `'${s}'`).join(',');
const NEXT = { New: ['Accepted', 'Waiting List', 'Cancelled'], Accepted: ['In Progress', 'Waiting List', 'Completed', 'Cancelled'],
  'Waiting List': ['Accepted', 'Cancelled'], 'In Progress': ['Completed', 'Waiting List', 'Cancelled'], Completed: [], Cancelled: [] };
const TYPES = ['Record Writing', 'Observation Writing', 'Assignment Writing'];

class AppError extends Error { constructor(m, s = 400) { super(m); this.status = s; } }

// ---------- Database (self-setting-up: creates the file/tables if missing, so a fresh Render deploy just works) ----------
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, 'data.db'));
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8')); // idempotent (create ... if not exists)
db.prepare('insert or ignore into pricing values(1,5,10,10,10,10,25)').run();
// Admin bootstrap from environment variables: creates the admin if missing; RESET_ADMIN_PASSWORD=1 forces the password to match the env value.
const AU = process.env.ADMIN_USERNAME, AP = process.env.ADMIN_PASSWORD;
if (AU && AP) {
  if (AP.length < 8) { console.error('ADMIN_PASSWORD must be at least 8 characters.'); process.exit(1); }
  const ex = db.prepare(`select id from users where username=? and role='admin'`).get(AU);
  if (!ex) { db.prepare(`insert into users(name,username,password_hash,role) values('Admin',?,?, 'admin')`).run(AU, bcrypt.hashSync(AP, 12)); console.log(`Admin "${AU}" created.`); }
  else if (process.env.RESET_ADMIN_PASSWORD === '1') { db.prepare('update users set password_hash=? where id=?').run(bcrypt.hashSync(AP, 12), ex.id); console.log(`Admin "${AU}" password reset from environment.`); }
} else if (!db.prepare(`select 1 from users where role='admin'`).get()) console.warn('No admin exists. Set ADMIN_USERNAME and ADMIN_PASSWORD (and RESET_ADMIN_PASSWORD=1) in the environment.');

// ---------- Helpers ----------
const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);
const pad = n => String(n).padStart(2, '0');
const fmt = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const today = () => { const d = new Date(); return new Date(d.getFullYear(), d.getMonth(), d.getDate()); };
const earliest = () => { const d = today(); d.setDate(d.getDate() + LEAD); return fmt(d); };
const pricing = () => db.prepare('select * from pricing where id=1').get();
const calc = (o, p) => Math.max(MIN, o.pages * p.page + o.drawings * p.drawing + o.tables_n * p.tbl + o.graphs * p.graph +
  o.simple_diagrams * p.simple_diagram + o.detailed_diagrams * p.detailed_diagram);
const cx = o => o.drawings + o.tables_n + o.graphs + o.simple_diagrams + 2 * o.detailed_diagrams;
function autoPriority(o) {
  const days = Math.ceil((new Date(o.due_date + 'T00:00') - today()) / 864e5), price = o.final_price ?? o.estimated;
  const s = (days <= 7 ? 4 : days <= 14 ? 3 : days <= 30 ? 1 : 0) + (o.pages >= 50 ? 2 : o.pages >= 20 ? 1 : 0) +
    (price >= 1000 ? 2 : price >= 500 ? 1 : 0) + (cx(o) >= 15 ? 2 : cx(o) >= 6 ? 1 : 0);
  return s >= 7 ? 'High' : s >= 4 ? 'Medium' : 'Low';
}
const active = () => db.prepare(`select count(*) n from orders where status in (${ACTSQL})`).get().n;
const notify = (uid, m) => db.prepare('insert into notifications(user_id,message) values(?,?)').run(uid, m);
const notifyAdmins = m => db.prepare(`select id from users where role='admin'`).all().forEach(a => notify(a.id, m));
const clientView = ({ admin_notes, priority, priority_manual, ...o }) => o;
const getFiles = id => db.prepare('select id,role,original_name,mime,size from files where order_id=?').all(id);
const magicOk = f => { const fd = fs.openSync(f.path, 'r'), b = Buffer.alloc(4); fs.readSync(fd, b, 0, 4, 0); fs.closeSync(fd);
  return f.mimetype === 'application/pdf' ? b.toString() === '%PDF' : f.mimetype === 'image/png' ? b.toString('hex') === '89504e47' : b.toString('hex').startsWith('ffd8ff'); };

// ---------- App & auth ----------
const app = express();
if (PROD) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { ...helmet.contentSecurityPolicy.getDefaultDirectives(), 'upgrade-insecure-requests': null } } }));
const ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  const o = req.get('Origin'); // CSRF guard: browsers always send Origin on cross-site writes
  if (req.method !== 'GET' && o && o !== ORIGIN) return res.status(403).json({ error: 'Request blocked.' });
  next();
});
app.use(express.json({ limit: '50kb' })); app.use(cookieParser());
app.get('/', (req, res) => res.json({ name: 'TakeHelp? API', ok: true }));
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Please try again later.' } });
const SAMESITE = process.env.COOKIE_SAMESITE || 'strict'; // use 'none' only if frontend and API are on different sites (needs HTTPS)
const COOKIE = { httpOnly: true, sameSite: SAMESITE, secure: PROD || SAMESITE === 'none' };
const setCookie = (res, u) => res.cookie('th_token', jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' }), { ...COOKIE, maxAge: 7 * 864e5 });
const loadUser = req => { const { id } = jwt.verify(req.cookies.th_token, SECRET);
  const u = db.prepare('select id,name,roll_no,username,phone,role from users where id=?').get(id); if (!u) throw 0; return u; };
const auth = (req, res, next) => { try { req.user = loadUser(req); next(); } catch { next(new AppError('Please log in to continue.', 401)); } };
const need = r => (req, res, next) => req.user.role === r ? next() : next(new AppError('Access denied.', 403));
const DUMMY = bcrypt.hashSync('x', 12);
const login = (col, role) => (req, res) => {
  const id = clean(req.body[col === 'roll_no' ? 'rollNo' : 'username'], 60), pw = String(req.body.password || '');
  const u = db.prepare(`select * from users where ${col}=? and role=?`).get(col === 'roll_no' ? id.toUpperCase() : id, role);
  const ok = bcrypt.compareSync(pw, u ? u.password_hash : DUMMY);
  if (!u || !ok) throw new AppError('Invalid login details. Please check and try again.', 401);
  setCookie(res, u); res.json({ user: { id: u.id, name: u.name, role: u.role, roll_no: u.roll_no, username: u.username } });
};
// ---- Client identification: name + roll number + phone (no password / email / OTP) ----
const NOPASS = '!'; // clients have no password; '!' can never match a bcrypt hash
const normName = s => clean(s, 80).replace(/\s+/g, ' ').toLowerCase();
const normRoll = s => clean(s, 30).toUpperCase();
const normPhone = s => { let d = String(s ?? '').replace(/\D/g, ''); if (d.length === 12 && d.startsWith('91')) d = d.slice(2); return d; };
app.post('/api/auth/register', limiter, (req, res) => {
  const name = clean(req.body.name, 80).replace(/\s+/g, ' '), roll = normRoll(req.body.rollNo), phone = normPhone(req.body.phone);
  if (name.length < 3 || !/^[\p{L} .'-]+$/u.test(name)) throw new AppError('Please enter your full real name (letters only).');
  if (!/^[A-Z0-9][A-Z0-9\/-]{2,29}$/.test(roll)) throw new AppError('Please enter a valid roll number.');
  if (!/^\d{10}$/.test(phone)) throw new AppError('Please enter a valid 10-digit phone number.');
  if (db.prepare('select 1 from users where roll_no=?').get(roll)) throw new AppError('This roll number is already registered. Please log in.', 409);
  const r = db.prepare(`insert into users(name,roll_no,phone,password_hash,role) values(?,?,?,?, 'client')`).run(name, roll, phone, NOPASS);
  const u = { id: r.lastInsertRowid }; setCookie(res, u);
  res.status(201).json({ user: { id: u.id, name, role: 'client', roll_no: roll } });
});
const fails = new Map(); // roll number -> { n, until } : locks guessing after 5 wrong tries
app.post('/api/auth/login', limiter, (req, res) => {
  const roll = normRoll(req.body.rollNo), f = fails.get(roll);
  if (f && f.until > Date.now() && f.n >= 5) throw new AppError('Too many failed attempts for this roll number. Please try again in 15 minutes.', 429);
  const u = db.prepare(`select * from users where roll_no=? and role='client'`).get(roll);
  const nameOk = !!u && normName(u.name) === normName(req.body.name), phoneOk = !!u && normPhone(u.phone) === normPhone(req.body.phone);
  if (!(nameOk && phoneOk)) {
    if (fails.size > 5000) fails.clear();
    const cur = f && f.until > Date.now() ? f : { n: 0 }; fails.set(roll, { n: cur.n + 1, until: Date.now() + 15 * 60 * 1000 });
    throw new AppError('These details do not match any account. Please check your name, roll number and phone number.', 401);
  }
  fails.delete(roll); setCookie(res, u);
  res.json({ user: { id: u.id, name: u.name, role: u.role, roll_no: u.roll_no } });
});
app.post('/api/admin/login', limiter, login('username', 'admin'));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('th_token', COOKIE); res.json({ ok: true }); });
app.get('/api/me', (req, res) => { try { res.json({ user: loadUser(req) }); } catch { res.json({ user: null }); } });
app.get('/api/pricing', (req, res) => { const p = pricing(); res.json({ page: p.page, drawing: p.drawing, table: p.tbl, graph: p.graph, simple_diagram: p.simple_diagram, detailed_diagram: p.detailed_diagram, min: MIN, lead: LEAD, earliest: earliest() }); });
app.get('/api/capacity', (req, res) => { const a = active(); res.json({ active: a, max: MAX, available: Math.max(0, MAX - a), full: a >= MAX }); });

// ---------- Uploads ----------
const OK = { '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };
const upload = multer({
  storage: multer.diskStorage({ destination: STORAGE, filename: (r, f, cb) => cb(null, crypto.randomBytes(20).toString('hex')) }),
  limits: { fileSize: 10 * 1024 * 1024, files: 12, fields: 20 },
  fileFilter: (r, f, cb) => { const e = path.extname(f.originalname).toLowerCase();
    cb(OK[e] && OK[e] === f.mimetype && f.originalname.length <= 150 ? null : new AppError('Invalid file. Only PDF, JPG, JPEG and PNG files are allowed.'), true && !!(OK[e] && OK[e] === f.mimetype)); }
}).fields([{ name: 'sample', maxCount: 3 }, { name: 'subject', maxCount: 3 }, { name: 'assignment', maxCount: 3 }, { name: 'reference', maxCount: 6 }]);

const create = db.transaction((o, files) => {
  if (active() >= MAX) throw new AppError(CAPMSG, 409);
  const est = calc(o, pricing());
  const id = Number(db.prepare(`insert into orders(client_id,type,subject,due_date,pages,drawings,tables_n,graphs,simple_diagrams,detailed_diagrams,comments,estimated,priority)
    values(@client_id,@type,@subject,@due_date,@pages,@drawings,@tables_n,@graphs,@simple_diagrams,@detailed_diagrams,@comments,@est,@pr)`)
    .run({ ...o, est, pr: autoPriority({ ...o, estimated: est, final_price: null }) }).lastInsertRowid);
  db.prepare('update orders set code=? where id=?').run('TH-' + (1000 + id), id);
  for (const f of files) db.prepare('insert into files(order_id,role,original_name,stored_name,mime,size) values(?,?,?,?,?,?)')
    .run(id, f.role, clean(path.basename(f.originalname), 150), f.filename, f.mimetype, f.size);
  db.prepare('insert into order_history(order_id,status) values(?,?)').run(id, 'New');
  notifyAdmins(`New order TH-${1000 + id}: ${o.type} – ${o.subject}`);
  return id;
});
app.post('/api/orders', auth, need('client'), (req, res, next) => upload(req, res, e => e ? next(e) : next()), (req, res) => {
  const files = Object.entries(req.files || {}).flatMap(([role, a]) => a.map(f => ({ ...f, role })));
  try {
    const b = req.body, n = (k, max) => { const v = b[k] === undefined || b[k] === '' ? 0 : Number(b[k]);
      if (!Number.isInteger(v) || v < 0 || v > max) throw new AppError(`Invalid value for ${k.replace(/_/g, ' ')}.`); return v; };
    const type = String(b.type || '').trim(), subject = clean(b.subject, 120);
    if (!TYPES.includes(type)) throw new AppError('Please choose a valid work type.');
    if (subject.length < 2) throw new AppError('Please enter the subject name.');
    if (!b.due_date) throw new AppError('Please select a due date.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(b.due_date) || isNaN(new Date(b.due_date + 'T00:00'))) throw new AppError('Invalid due date.');
    if (b.due_date < earliest()) throw new AppError('Orders must be submitted at least 6 days before the required delivery date. Please select a later date.');
    if (!b.pages) throw new AppError('Please enter the number of pages.');
    const pages = n('pages', 1000); if (pages < 1) throw new AppError('Please enter the number of pages.');
    if (!files.length) throw new AppError('Please upload at least one sample or reference file.');
    if (!files.every(magicOk)) throw new AppError('Invalid file. One of the files is not a real PDF/JPG/PNG.');
    const o = { client_id: req.user.id, type, subject, due_date: b.due_date, pages, drawings: n('drawings', 500), tables_n: n('tables_n', 500),
      graphs: n('graphs', 500), simple_diagrams: n('simple_diagrams', 500), detailed_diagrams: n('detailed_diagrams', 500), comments: clean(b.comments, 3000) };
    const id = create(o, files);
    res.status(201).json(clientView(db.prepare('select * from orders where id=?').get(id)));
  } catch (e) { files.forEach(f => fs.unlink(f.path, () => {})); throw e; }
});
app.get('/api/files/:id', auth, (req, res) => {
  const f = db.prepare('select f.*,o.client_id from files f join orders o on o.id=f.order_id where f.id=?').get(req.params.id);
  if (!f || (req.user.role !== 'admin' && f.client_id !== req.user.id)) throw new AppError('File not found.', 404);
  res.set({ 'Content-Type': f.mime, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox',
    'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(f.original_name)}`, 'Cache-Control': 'private, no-store' });
  res.sendFile(path.join(STORAGE, f.stored_name));
});

// ---------- Client ----------
app.get('/api/orders', auth, need('client'), (req, res) =>
  res.json(db.prepare('select * from orders where client_id=? order by id desc').all(req.user.id).map(clientView)));
app.get('/api/orders/:id', auth, need('client'), (req, res) => {
  const o = db.prepare('select * from orders where id=? and client_id=?').get(req.params.id, req.user.id);
  if (!o) throw new AppError('Order not found.', 404);
  res.json({ ...clientView(o), files: getFiles(o.id), history: db.prepare('select status,created_at from order_history where order_id=? order by id').all(o.id) });
});
app.get('/api/notifications', auth, (req, res) => res.json({
  items: db.prepare('select * from notifications where user_id=? order by id desc limit 30').all(req.user.id),
  unread: db.prepare('select count(*) n from notifications where user_id=? and is_read=0').get(req.user.id).n }));
app.post('/api/notifications/read', auth, (req, res) => { db.prepare('update notifications set is_read=1 where user_id=?').run(req.user.id); res.json({ ok: true }); });

// ---------- Admin ----------
const A = [auth, need('admin')];
const withClient = 'select o.*,u.name client_name,u.roll_no,u.phone client_phone from orders o join users u on u.id=o.client_id';
app.get('/api/admin/stats', ...A, (req, res) => {
  const c = s => db.prepare('select count(*) n from orders where status=?').get(s).n, a = active();
  const soon = fmt(new Date(today().getTime() + 10 * 864e5));
  res.json({ active: a, max: MAX, available: Math.max(0, MAX - a), waiting: c('Waiting List'), new: c('New'), accepted: c('Accepted'), inProgress: c('In Progress'),
    completed: c('Completed'), cancelled: c('Cancelled'),
    dueSoon: db.prepare(`select count(*) n from orders where status in (${ACTSQL}) and due_date<=?`).get(soon).n,
    estRevenue: db.prepare(`select coalesce(sum(estimated),0) n from orders where status!='Cancelled'`).get().n,
    finalRevenue: db.prepare(`select coalesce(sum(final_price),0) n from orders where status!='Cancelled'`).get().n });
});
app.get('/api/admin/next', ...A, (req, res) => {
  const R = { High: 0, Medium: 1, Low: 2 };
  res.json(db.prepare(`${withClient} where o.status in (${ACTSQL})`).all().sort((a, b) => a.due_date.localeCompare(b.due_date) ||
    R[a.priority] - R[b.priority] || b.pages - a.pages || cx(b) - cx(a) || (b.final_price ?? b.estimated) - (a.final_price ?? a.estimated)).slice(0, 5));
});
app.get('/api/admin/orders', ...A, (req, res) => {
  const { filter = 'active', q = '', type = '', date = '' } = req.query, w = [], a = [];
  if (filter === 'active') w.push(`o.status in (${ACTSQL})`); else if (filter === 'history') w.push(`o.status in ('Completed','Cancelled')`);
  else if (ST.includes(filter)) { w.push('o.status=?'); a.push(filter); }
  if (q) { w.push('(o.code like ? or u.name like ? or u.roll_no like ? or o.subject like ?)'); const l = `%${String(q).slice(0, 60)}%`; a.push(l, l, l, l); }
  if (TYPES.includes(type)) { w.push('o.type=?'); a.push(type); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(date)) { w.push('date(o.created_at)=?'); a.push(date); }
  res.json(db.prepare(`${withClient} ${w.length ? 'where ' + w.join(' and ') : ''} order by o.due_date`).all(...a));
});
const detail = id => { const o = db.prepare(`${withClient} where o.id=?`).get(id); if (!o) throw new AppError('Order not found.', 404);
  return { ...o, files: getFiles(id), history: db.prepare('select status,created_at from order_history where order_id=? order by id').all(id), allowed: NEXT[o.status] }; };
app.get('/api/admin/orders/:id', ...A, (req, res) => res.json(detail(req.params.id)));
const MSG = { Accepted: 'accepted', 'Waiting List': 'moved to the waiting list', 'In Progress': 'started – work is in progress', Completed: 'completed', Cancelled: 'cancelled' };
app.patch('/api/admin/orders/:id', ...A, (req, res) => {
  const b = req.body;
  db.transaction(() => {
    const o = db.prepare('select * from orders where id=?').get(req.params.id); if (!o) throw new AppError('Order not found.', 404);
    if (b.status !== undefined && b.status !== o.status) {
      if (!NEXT[o.status].includes(b.status)) throw new AppError(`Cannot change from ${o.status} to ${b.status}.`);
      db.prepare(`update orders set status=?,updated_at=datetime('now') where id=?`).run(b.status, o.id);
      db.prepare('insert into order_history(order_id,status) values(?,?)').run(o.id, b.status);
      notify(o.client_id, `Your order ${o.code} (${o.subject}) was ${MSG[b.status]}.`);
    }
    if (b.final_price !== undefined && b.final_price !== null && b.final_price !== '') {
      const f = Number(b.final_price); if (!(f >= MIN) || f > 1e7) throw new AppError('Final price must be at least ₹100.');
      if (f !== o.final_price) { db.prepare(`update orders set final_price=?,updated_at=datetime('now') where id=?`).run(f, o.id);
        notify(o.client_id, `The final price for ${o.code} is now ₹${f}.`); }
    }
    if (b.priority !== undefined) {
      if (b.priority === 'Auto') db.prepare('update orders set priority_manual=0 where id=?').run(o.id);
      else if (['High', 'Medium', 'Low'].includes(b.priority)) db.prepare('update orders set priority=?,priority_manual=1 where id=?').run(b.priority, o.id);
    }
    if (b.admin_notes !== undefined) db.prepare('update orders set admin_notes=? where id=?').run(clean(b.admin_notes, 2000), o.id);
    const n = db.prepare('select * from orders where id=?').get(o.id);
    if (!n.priority_manual) db.prepare('update orders set priority=? where id=?').run(autoPriority(n), o.id);
  })();
  res.json(detail(req.params.id));
});
app.delete('/api/admin/orders/:id', ...A, (req, res) => {
  const o = db.prepare('select * from orders where id=?').get(req.params.id);
  if (!o) throw new AppError('Order not found.', 404);
  if (!['Completed', 'Cancelled'].includes(o.status)) throw new AppError('Only completed or cancelled orders can be deleted.');
  const fl = db.prepare('select stored_name from files where order_id=?').all(o.id);
  db.prepare('delete from orders where id=?').run(o.id);
  fl.forEach(f => fs.unlink(path.join(STORAGE, f.stored_name), () => {})); res.json({ ok: true });
});
app.put('/api/admin/pricing', ...A, (req, res) => {
  const k = ['page', 'drawing', 'table', 'graph', 'simple_diagram', 'detailed_diagram'], v = k.map(x => Number(req.body[x]));
  if (v.some(x => !(x >= 0) || x > 100000)) throw new AppError('Prices must be numbers between 0 and 100000.');
  db.prepare('update pricing set page=?,drawing=?,tbl=?,graph=?,simple_diagram=?,detailed_diagram=? where id=1').run(...v); res.json({ ok: true });
});

// ---------- Errors ----------
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((e, req, res, next) => {
  if (e instanceof AppError) return res.status(e.status).json({ error: e.message });
  if (e.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large. Maximum size is 10 MB per file.' });
  if (String(e.code).startsWith('LIMIT_')) return res.status(400).json({ error: 'Too many files or an unexpected upload field.' });
  if (String(e.message).includes('CAPACITY')) return res.status(409).json({ error: CAPMSG });
  if (e.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request.' });
  console.error(e); res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
app.listen(process.env.PORT || 3000, () => console.log(`TakeHelp? running on http://localhost:${process.env.PORT || 3000}`));
