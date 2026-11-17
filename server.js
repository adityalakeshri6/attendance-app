const express = require('express');
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

types.setTypeParser(20, v => +v); // BIGINT and COUNT come back as numbers
const RADIUS_M = +process.env.RADIUS_M || 100;        // student must be within this distance of teacher
const MAX_ACCURACY = +process.env.MAX_ACCURACY || 100; // reject GPS readings worse than this (metres)
const TZ = process.env.TZ_NAME || 'Asia/Kolkata';
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is missing. See README.md'); process.exit(1); }
if (!process.env.JWT_SECRET) console.warn('JWT_SECRET not set: everyone is logged out whenever the server restarts');
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

const local = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: local ? false : { rejectUnauthorized: false }, max: +process.env.PG_POOL_MAX || 5 });
const q = (sql, p = []) => pool.query(sql, p).then(r => r.rows);
const one = async (sql, p) => (await q(sql, p))[0];
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ });

async function init() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS classes (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL);
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student','teacher','principal')), class_id INTEGER);
  CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY, teacher_id INTEGER, class_id INTEGER, subject TEXT,
    lat DOUBLE PRECISION, lon DOUBLE PRECISION, accuracy DOUBLE PRECISION,
    start_time BIGINT, expires_at BIGINT, status TEXT DEFAULT 'open', photo BYTEA);
  CREATE TABLE IF NOT EXISTS attendance (
    id SERIAL PRIMARY KEY, session_id INTEGER, student_id INTEGER, lat DOUBLE PRECISION, lon DOUBLE PRECISION,
    accuracy DOUBLE PRECISION, distance_m DOUBLE PRECISION, marked_at BIGINT, method TEXT DEFAULT 'gps', UNIQUE (session_id, student_id));
  CREATE TABLE IF NOT EXISTS teacher_attendance (
    id SERIAL PRIMARY KEY, teacher_id INTEGER, date TEXT, lat DOUBLE PRECISION, lon DOUBLE PRECISION,
    check_in BIGINT, UNIQUE (teacher_id, date));
  CREATE INDEX IF NOT EXISTS idx_sessions_class ON sessions(class_id, status);
  ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_phone TEXT;
  ALTER TABLE attendance ADD COLUMN IF NOT EXISTS selfie BYTEA;
  CREATE TABLE IF NOT EXISTS teacher_classes (teacher_id INTEGER, class_id INTEGER, PRIMARY KEY (teacher_id, class_id));
  CREATE TABLE IF NOT EXISTS leaves (id SERIAL PRIMARY KEY, student_id INTEGER, from_date TEXT, to_date TEXT, reason TEXT, status TEXT DEFAULT 'pending', created_at BIGINT);`);
  if (!(await one('SELECT 1 AS x FROM users LIMIT 1'))) {
    const email = (process.env.ADMIN_EMAIL || 'admin@college.com').toLowerCase();
    const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(4).toString('hex');
    await q("INSERT INTO users(name,email,password_hash,role) VALUES ('Principal',$1,$2,'principal')", [email, bcrypt.hashSync(pw, 10)]);
    console.log(`\nFirst run: principal login is ${email} / ${process.env.ADMIN_PASSWORD ? '(your ADMIN_PASSWORD)' : pw}\n`);
  }
}

function distanceM(lat1, lon1, lat2, lon2) { // Haversine
  const R = 6371000, rad = x => x * Math.PI / 180;
  const a = Math.sin(rad(lat2 - lat1) / 2) ** 2 + Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(rad(lon2 - lon1) / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const validGps = b => Number.isFinite(b.lat) && Number.isFinite(b.lon) && Number.isFinite(b.accuracy);
const h = fn => (req, res, next) => fn(req, res).catch(next); // send async errors to the error handler
const dup = e => e.code === '23505';
const digits = s => (s || '').replace(/\D/g, '').slice(0, 15) || null;
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use(express.static('public'));
app.get('/healthz', (_, res) => res.send('ok'));

const auth = (...roles) => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
    next();
  } catch { res.status(401).json({ error: 'Please log in' }); }
};
const getSession = async (req, res) => { // teacher: own sessions only; principal: all
  const s = Number.isInteger(+req.params.id) && await one(
    'SELECT id,teacher_id,class_id,subject,lat,lon,accuracy,start_time,expires_at,status FROM sessions WHERE id=$1', [+req.params.id]);
  if (!s) { res.status(404).json({ error: 'Session not found' }); return null; }
  if (req.user.role !== 'principal' && s.teacher_id !== req.user.id) { res.status(403).json({ error: 'Not allowed' }); return null; }
  return s;
};

const fails = new Map(); // login rate limit: 10 failures per 15 min per IP
app.post('/api/login', h(async (req, res) => {
  const f = fails.get(req.ip);
  if (f && f.n >= 10 && Date.now() < f.until) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes' });
  const u = await one('SELECT * FROM users WHERE email=$1', [(req.body.email || '').trim().toLowerCase()]);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password_hash)) {
    fails.set(req.ip, { n: (f ? f.n : 0) + 1, until: Date.now() + 15 * 60000 });
    return res.status(401).json({ error: 'Wrong email or password' });
  }
  fails.delete(req.ip);
  const user = { id: u.id, name: u.name, role: u.role, class_id: u.class_id };
  res.json({ token: jwt.sign(user, SECRET, { expiresIn: '12h' }), user });
}));
app.post('/api/me/password', auth(), h(async (req, res) => {
  const { old_password, new_password } = req.body, u = await one('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!u || !bcrypt.compareSync(old_password || '', u.password_hash)) return res.status(400).json({ error: 'Current password is wrong' });
  if ((new_password || '').length < 6) return res.status(400).json({ error: 'New password must be 6+ characters' });
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [bcrypt.hashSync(new_password, 10), u.id]);
  res.json({ ok: true });
}));
app.get('/api/classes', auth(), h(async (req, res) => res.json(req.user.role === 'teacher'
  ? await q('SELECT c.* FROM classes c JOIN teacher_classes t ON t.class_id=c.id WHERE t.teacher_id=$1 ORDER BY c.name', [req.user.id])
  : await q('SELECT * FROM classes ORDER BY name'))));
app.get('/api/assignments', auth('principal'), h(async (_, res) => res.json(await q(
  'SELECT t.teacher_id, t.class_id, u.name AS teacher, c.name AS class FROM teacher_classes t JOIN users u ON u.id=t.teacher_id JOIN classes c ON c.id=t.class_id ORDER BY u.name,c.name'))));
app.post('/api/assignments', auth('principal'), h(async (req, res) => {
  const { teacher_id, class_id } = req.body;
  if (!(await one("SELECT 1 AS x FROM users WHERE id=$1 AND role='teacher'", [teacher_id])) || !(await one('SELECT 1 AS x FROM classes WHERE id=$1', [class_id])))
    return res.status(400).json({ error: 'Choose a teacher and a class' });
  await q('INSERT INTO teacher_classes(teacher_id,class_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [teacher_id, class_id]);
  res.json({ ok: true });
}));
app.post('/api/assignments/remove', auth('principal'), h(async (req, res) => {
  await q('DELETE FROM teacher_classes WHERE teacher_id=$1 AND class_id=$2', [+req.body.teacher_id, +req.body.class_id]);
  res.json({ ok: true });
}));

// ---------- Principal ----------
app.post('/api/classes', auth('principal'), h(async (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Class name is required' });
  try { await q('INSERT INTO classes(name) VALUES ($1)', [name]); res.json({ ok: true }); }
  catch (e) { if (!dup(e)) throw e; res.status(409).json({ error: 'That class already exists' }); }
}));
app.get('/api/users', auth('principal'), h(async (_, res) => res.json(await q(
  'SELECT u.id,u.name,u.email,u.role,c.name AS class FROM users u LEFT JOIN classes c ON c.id=u.class_id ORDER BY u.role,u.name'))));
app.post('/api/users', auth('principal'), h(async (req, res) => {
  const { name, password, role, class_id, parent_phone } = req.body, email = (req.body.email || '').trim().toLowerCase();
  if (!name || !email.includes('@') || (password || '').length < 6) return res.status(400).json({ error: 'Name, valid email and a password of 6+ characters are required' });
  if (!['student', 'teacher', 'principal'].includes(role)) return res.status(400).json({ error: 'Choose a role' });
  if (role === 'student' && !(await one('SELECT 1 AS x FROM classes WHERE id=$1', [class_id]))) return res.status(400).json({ error: 'Choose a class for the student' });
  try {
    await q('INSERT INTO users(name,email,password_hash,role,class_id,parent_phone) VALUES ($1,$2,$3,$4,$5,$6)',
      [name.trim(), email, bcrypt.hashSync(password, 10), role, role === 'student' ? class_id : null, role === 'student' ? digits(parent_phone) : null]);
    res.json({ ok: true });
  } catch (e) { if (!dup(e)) throw e; res.status(409).json({ error: 'That email is already registered' }); }
}));
app.post('/api/users/bulk', auth('principal'), h(async (req, res) => { // lines: name, email[, password]
  const { role, class_id, text } = req.body;
  if (!['student', 'teacher'].includes(role)) return res.status(400).json({ error: 'Choose students or teachers' });
  if (role === 'student' && !(await one('SELECT 1 AS x FROM classes WHERE id=$1', [class_id]))) return res.status(400).json({ error: 'Choose a class' });
  const created = [], skipped = [];
  for (const line of String(text || '').split('\n')) {
    const [name, email, phone, pw] = line.split(',').map(s => s.trim());
    if (!name && !email) continue;
    if (!name || !(email || '').includes('@') || (pw && pw.length < 6)) { skipped.push(`${line.trim()} (needs name, email, optional 6+ char password)`); continue; }
    const password = pw || crypto.randomBytes(3).toString('hex');
    try {
      await q('INSERT INTO users(name,email,password_hash,role,class_id,parent_phone) VALUES ($1,$2,$3,$4,$5,$6)',
        [name, email.toLowerCase(), bcrypt.hashSync(password, 10), role, role === 'student' ? class_id : null, role === 'student' ? digits(phone) : null]);
      created.push({ name, email: email.toLowerCase(), password });
    } catch (e) { if (!dup(e)) throw e; skipped.push(`${email} (already registered)`); }
  }
  res.json({ created, skipped });
}));
app.post('/api/users/:id/password', auth('principal'), h(async (req, res) => {
  if ((req.body.password || '').length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [bcrypt.hashSync(req.body.password, 10), +req.params.id]);
  res.json({ ok: true });
}));
app.get('/api/principal/summary', auth('principal'), h(async (_, res) => {
  const students = await q(`SELECT u.name, c.name AS class,
    (SELECT COUNT(*) FROM sessions s WHERE s.class_id=u.class_id) AS total,
    (SELECT COUNT(*) FROM attendance a WHERE a.student_id=u.id) AS present
    FROM users u JOIN classes c ON c.id=u.class_id WHERE u.role='student' ORDER BY c.name,u.name`);
  const teachers = await q(`SELECT u.name, t.check_in FROM users u
    LEFT JOIN teacher_attendance t ON t.teacher_id=u.id AND t.date=$1 WHERE u.role='teacher' ORDER BY u.name`, [today()]);
  res.json({ students, teachers });
}));
app.get('/api/principal/defaulters', auth('principal'), h(async (req, res) => {
  const min = Math.min(Math.max(+req.query.min || 75, 1), 100);
  const rows = await q(`SELECT u.name, c.name AS class, u.parent_phone,
    (SELECT COUNT(*) FROM sessions s WHERE s.class_id=u.class_id) AS total,
    (SELECT COUNT(*) FROM attendance a WHERE a.student_id=u.id) AS present
    FROM users u JOIN classes c ON c.id=u.class_id WHERE u.role='student' ORDER BY c.name,u.name`);
  res.json(rows.filter(r => r.total > 0 && 100 * r.present / r.total < min));
}));
app.get('/api/principal/sessions', auth('principal'), h(async (_, res) => res.json(await q(`
  SELECT s.id, s.subject, s.start_time, c.name AS class, u.name AS teacher,
    (SELECT COUNT(*) FROM attendance a WHERE a.session_id=s.id) AS present,
    (SELECT COUNT(*) FROM users st WHERE st.role='student' AND st.class_id=s.class_id) AS total
  FROM sessions s JOIN classes c ON c.id=s.class_id JOIN users u ON u.id=s.teacher_id ORDER BY s.id DESC LIMIT 30`))));
app.get('/api/principal/export', auth('principal'), h(async (_, res) => {
  const rows = await q(`SELECT u.name AS student, c.name AS class, s.subject, COUNT(DISTINCT s.id) AS total, COUNT(a.id) AS present
    FROM users u JOIN classes c ON c.id=u.class_id JOIN sessions s ON s.class_id=u.class_id
    LEFT JOIN attendance a ON a.session_id=s.id AND a.student_id=u.id
    WHERE u.role='student' GROUP BY u.id,u.name,c.name,s.subject ORDER BY c.name,u.name,s.subject`);
  const cell = v => `"${String(v).replace(/"/g, '""')}"`;
  const csv = ['Student,Class,Subject,Lectures,Present,Percent'].concat(rows.map(r =>
    [r.student, r.class, r.subject, r.total, r.present, Math.round(100 * r.present / r.total) + '%'].map(cell).join(','))).join('\n');
  res.type('text/csv').send(csv);
}));

// ---------- Teacher ----------
app.post('/api/teacher/checkin', auth('teacher'), h(async (req, res) => {
  if (!validGps(req.body)) return res.status(400).json({ error: 'Location is required' });
  await q('INSERT INTO teacher_attendance(teacher_id,date,lat,lon,check_in) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
    [req.user.id, today(), req.body.lat, req.body.lon, Date.now()]);
  res.json({ ok: true });
}));
app.post('/api/sessions/start', auth('teacher'), h(async (req, res) => {
  const { class_id, subject, lat, lon, accuracy, photo, minutes = 10 } = req.body;
  if (!subject || !validGps(req.body) || !(await one('SELECT 1 AS x FROM classes WHERE id=$1', [class_id])))
    return res.status(400).json({ error: 'Class, subject and location are required' });
  if (!(await one('SELECT 1 AS x FROM teacher_classes WHERE teacher_id=$1 AND class_id=$2', [req.user.id, class_id])))
    return res.status(403).json({ error: 'You are not assigned to this class' });
  if (!/^data:image\/jpeg;base64,/.test(photo || '')) return res.status(400).json({ error: 'Take a photo of the class first' });
  if (accuracy > MAX_ACCURACY) return res.status(400).json({ error: `GPS is weak (±${Math.round(accuracy)} m). Move near a window and try again` });
  const img = Buffer.from(photo.split(',')[1], 'base64');
  if (img.length > 3.5e6) return res.status(400).json({ error: 'Photo is too large' });
  await q("UPDATE sessions SET status='closed' WHERE teacher_id=$1 AND status='open'", [req.user.id]);
  const now = Date.now();
  const r = await one('INSERT INTO sessions(teacher_id,class_id,subject,lat,lon,accuracy,start_time,expires_at,photo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
    [req.user.id, class_id, subject.trim(), lat, lon, accuracy, now, now + Math.min(+minutes || 10, 60) * 60000, img]);
  res.json({ session_id: r.id, radius_m: RADIUS_M });
}));
app.post('/api/sessions/:id/close', auth('teacher'), h(async (req, res) => {
  const s = await getSession(req, res); if (!s) return;
  await q("UPDATE sessions SET status='closed' WHERE id=$1", [s.id]);
  res.json({ ok: true });
}));
app.get('/api/sessions/:id/photo', auth('teacher', 'principal'), h(async (req, res) => {
  const s = await getSession(req, res); if (!s) return;
  const r = await one('SELECT photo FROM sessions WHERE id=$1', [s.id]);
  if (!r || !r.photo) return res.status(404).json({ error: 'No photo' });
  res.type('image/jpeg').set('Cache-Control', 'private, max-age=3600').send(r.photo);
}));
app.get('/api/sessions/:id/attendance', auth('teacher', 'principal'), h(async (req, res) => {
  const s = await getSession(req, res); if (!s) return;
  const day = new Date(s.start_time).toLocaleDateString('en-CA', { timeZone: TZ });
  const students = await q(`SELECT u.id, u.name, a.distance_m, a.marked_at, a.method, (a.selfie IS NOT NULL) AS has_selfie,
    EXISTS (SELECT 1 FROM leaves l WHERE l.student_id=u.id AND l.status='approved' AND l.from_date<=$3 AND l.to_date>=$3) AS on_leave
    FROM users u LEFT JOIN attendance a ON a.student_id=u.id AND a.session_id=$1 WHERE u.role='student' AND u.class_id=$2 ORDER BY u.name`, [s.id, s.class_id, day]);
  res.json({ session: s, students });
}));
app.get('/api/sessions/:id/selfie/:student', auth('teacher', 'principal'), h(async (req, res) => {
  const s = await getSession(req, res); if (!s) return;
  const r = await one('SELECT selfie FROM attendance WHERE session_id=$1 AND student_id=$2', [s.id, +req.params.student]);
  if (!r || !r.selfie) return res.status(404).json({ error: 'No selfie' });
  res.type('image/jpeg').set('Cache-Control', 'private, max-age=3600').send(r.selfie);
}));
app.post('/api/sessions/:id/override', auth('teacher', 'principal'), h(async (req, res) => { // cross-check against the class photo
  const s = await getSession(req, res); if (!s) return;
  const { student_id, present } = req.body;
  if (!(await one("SELECT 1 AS x FROM users WHERE id=$1 AND role='student' AND class_id=$2", [student_id, s.class_id])))
    return res.status(400).json({ error: 'Student is not in this class' });
  if (present) await q("INSERT INTO attendance(session_id,student_id,marked_at,method) VALUES ($1,$2,$3,'manual') ON CONFLICT DO NOTHING", [s.id, student_id, Date.now()]);
  else await q('DELETE FROM attendance WHERE session_id=$1 AND student_id=$2', [s.id, student_id]);
  res.json({ ok: true });
}));

// ---------- Student ----------
app.get('/api/sessions/active', auth('student'), h(async (req, res) => {
  const s = await one("SELECT id, subject, expires_at FROM sessions WHERE class_id=$1 AND status='open' AND expires_at>$2 ORDER BY id DESC LIMIT 1", [req.user.class_id, Date.now()]);
  const done = s && await one('SELECT 1 AS x FROM attendance WHERE session_id=$1 AND student_id=$2', [s.id, req.user.id]);
  res.json({ session: s || null, already_marked: !!done });
}));
app.post('/api/attendance/mark', auth('student'), h(async (req, res) => {
  const { session_id, lat, lon, accuracy, selfie } = req.body;
  if (!validGps(req.body)) return res.status(400).json({ error: 'Location is required' });
  const hasSelfie = /^data:image\/jpeg;base64,/.test(selfie || '');
  if (process.env.REQUIRE_SELFIE !== 'false' && !hasSelfie) return res.status(400).json({ error: 'Take a selfie to mark attendance' });
  const selfieImg = hasSelfie ? Buffer.from(selfie.split(',')[1], 'base64') : null;
  if (selfieImg && selfieImg.length > 1.5e6) return res.status(400).json({ error: 'Selfie is too large' });
  const s = await one("SELECT * FROM sessions WHERE id=$1 AND status='open' AND expires_at>$2 AND class_id=$3", [+session_id || 0, Date.now(), req.user.class_id]);
  if (!s) return res.status(400).json({ error: 'No open session for your class' });
  if (accuracy > MAX_ACCURACY) return res.status(400).json({ error: `GPS is weak (±${Math.round(accuracy)} m). Try again` });
  const d = distanceM(s.lat, s.lon, lat, lon);
  if (d > RADIUS_M) return res.status(403).json({ error: `You are ${Math.round(d)} m from the teacher. Move within ${RADIUS_M} m` });
  try {
    await q('INSERT INTO attendance(session_id,student_id,lat,lon,accuracy,distance_m,marked_at,selfie) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [s.id, req.user.id, lat, lon, accuracy, d, Date.now(), selfieImg]);
  } catch (e) { if (!dup(e)) throw e; return res.status(409).json({ error: 'Attendance already marked' }); }
  res.json({ ok: true, distance_m: Math.round(d) });
}));
app.get('/api/student/stats', auth('student'), h(async (req, res) => res.json(await q(
  `SELECT s.subject, COUNT(*) AS total, COUNT(a.id) AS present FROM sessions s
   LEFT JOIN attendance a ON a.session_id=s.id AND a.student_id=$1 WHERE s.class_id=$2 GROUP BY s.subject ORDER BY s.subject`, [req.user.id, req.user.class_id]))));

// ---------- Leave requests ----------
app.post('/api/leaves', auth('student'), h(async (req, res) => {
  const { from_date, to_date, reason } = req.body;
  if (!isDate(from_date) || !isDate(to_date) || from_date > to_date || !(reason || '').trim())
    return res.status(400).json({ error: 'Enter valid dates (from before to) and a reason' });
  await q('INSERT INTO leaves(student_id,from_date,to_date,reason,created_at) VALUES ($1,$2,$3,$4,$5)', [req.user.id, from_date, to_date, reason.trim().slice(0, 300), Date.now()]);
  res.json({ ok: true });
}));
app.get('/api/leaves', auth(), h(async (req, res) => {
  const where = { student: 'WHERE l.student_id=$1', teacher: 'WHERE u.class_id IN (SELECT class_id FROM teacher_classes WHERE teacher_id=$1)', principal: 'WHERE $1 > 0' }[req.user.role];
  res.json(await q(`SELECT l.id,l.from_date,l.to_date,l.reason,l.status,u.name AS student,c.name AS class FROM leaves l
    JOIN users u ON u.id=l.student_id LEFT JOIN classes c ON c.id=u.class_id ${where} ORDER BY l.id DESC LIMIT 50`, [req.user.id]));
}));
app.post('/api/leaves/:id/decision', auth('teacher', 'principal'), h(async (req, res) => {
  const l = await one(`SELECT l.id FROM leaves l JOIN users u ON u.id=l.student_id WHERE l.id=$1
    AND ($2 OR u.class_id IN (SELECT class_id FROM teacher_classes WHERE teacher_id=$3))`, [+req.params.id, req.user.role === 'principal', req.user.id]);
  if (!l) return res.status(404).json({ error: 'Leave request not found' });
  await q('UPDATE leaves SET status=$1 WHERE id=$2', [req.body.approve ? 'approved' : 'rejected', l.id]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  if (err.status === 413) return res.status(413).json({ error: 'Photo is too large' });
  console.error(err); res.status(500).json({ error: 'Server error. Please try again' });
});
init().then(() => app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Running on port ' + (process.env.PORT || 3000))))
  .catch(e => { console.error('Could not start. Check DATABASE_URL:', e.message); process.exit(1); });
