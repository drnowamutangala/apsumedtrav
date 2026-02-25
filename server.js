const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SÉCURITÉ : CLÉ SECRÈTE JWT ====================
const SECRET_KEY = crypto.randomBytes(64).toString('hex');

// ==================== FONCTIONS DE SÉCURITÉ ====================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === verify;
}

function createToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + (8 * 60 * 60 * 1000)
  };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
  return `${data}.${signature}`;
}

function verifyToken(token) {
  try {
    const [data, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET_KEY).update(data).digest('hex');
    if (signature !== expected) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// ==================== MIDDLEWARE ====================

app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'https://apsumedtrav.onrender.com'],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Non authentifié' });
  }
  const token = authHeader.split(' ')[1];
  const user = verifyToken(token);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Token invalide ou expiré' });
  }
  req.user = user;
  next();
}

function adminRequired(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Accès réservé aux administrateurs' });
  }
  next();
}

const loginAttempts = new Map();

function rateLimitLogin(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || [];
  const recent = attempts.filter(t => now - t < 15 * 60 * 1000);
  if (recent.length >= 5) {
    return res.status(429).json({
      success: false,
      message: 'Trop de tentatives. Réessayez dans 15 minutes.'
    });
  }
  loginAttempts.set(ip, [...recent, now]);
  next();
}

// ==================== BASE DE DONNÉES POSTGRESQL ====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDatabase() {
  const client = await pool.connect();
  try {
    // Créer les tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'medecin',
        nom TEXT,
        prenom TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS patients (
        id SERIAL PRIMARY KEY,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        date_naissance TEXT,
        sexe TEXT,
        adresse TEXT,
        telephone TEXT,
        entreprise TEXT,
        poste TEXT,
        numero_securite TEXT,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS consultations (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id),
        date_consultation TEXT,
        type_consultation TEXT,
        motif TEXT,
        examen_clinique TEXT,
        diagnostic TEXT,
        traitement TEXT,
        aptitude TEXT,
        restrictions TEXT,
        prochaine_visite TEXT,
        medecin TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id),
        consultation_id INTEGER,
        type_document TEXT,
        nom_fichier TEXT,
        contenu TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS lab_results (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER,
        patient_nom TEXT,
        patient_prenom TEXT,
        patient_dob TEXT,
        patient_genre TEXT,
        patient_adresse TEXT,
        statut TEXT DEFAULT 'PRIVE',
        numero TEXT,
        preleve_par TEXT,
        valide_par TEXT,
        date_prelevement TEXT,
        heure_prelevement TEXT,
        date_rendu TEXT,
        heure_rendu TEXT,
        hematologie TEXT,
        biochimie TEXT,
        serologie TEXT,
        urines TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        username TEXT,
        action TEXT,
        table_name TEXT,
        record_id INTEGER,
        details TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Tables PostgreSQL créées');

    // Créer le compte admin si inexistant
    const adminResult = await client.query('SELECT * FROM users WHERE username = $1', ['admin']);
    if (adminResult.rows.length === 0) {
      await client.query(
        'INSERT INTO users (username, password, role, nom, prenom) VALUES ($1, $2, $3, $4, $5)',
        ['admin', hashPassword('admin123'), 'admin', 'Administrateur', 'Principal']
      );
      console.log('✅ Compte admin créé (mot de passe hashé)');
    } else if (!adminResult.rows[0].password.includes(':')) {
      const hashed = hashPassword(adminResult.rows[0].password);
      await client.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, adminResult.rows[0].id]);
      console.log('✅ Mot de passe admin migré vers hashé');
    }

    // Créer les utilisateurs par défaut
    const defaultUsers = [
      { username: 'medecin', password: 'Med2024!', role: 'medecin', nom: 'Médecin', prenom: 'Principal' },
      { username: 'medecin1', password: 'Med-2-2024!', role: 'medecin', nom: 'Médecin', prenom: 'Adjoint' },
      { username: 'assistant', password: 'Assist2024!', role: 'assistant', nom: 'Assistant', prenom: 'Principal' },
      { username: 'infirmier', password: 'Infir2024!', role: 'infirmier', nom: 'Infirmier', prenom: 'Principal' },
      { username: 'infirmier-1', password: 'Infir-12024!', role: 'infirmier', nom: 'Infirmier-1', prenom: 'Principal' },
      { username: 'laboratin', password: 'lab2024!', role: 'laboratin', nom: 'Laboratin', prenom: 'Principal' }
    ];

    for (const u of defaultUsers) {
      const exists = await client.query('SELECT id FROM users WHERE username = $1', [u.username]);
      if (exists.rows.length === 0) {
        await client.query(
          'INSERT INTO users (username, password, role, nom, prenom) VALUES ($1, $2, $3, $4, $5)',
          [u.username, hashPassword(u.password), u.role, u.nom, u.prenom]
        );
        console.log(`✅ Utilisateur créé : ${u.username}`);
      }
    }

    console.log('✅ Base de données PostgreSQL initialisée avec succès');

  } catch (err) {
    console.error('❌ Erreur initialisation DB:', err.message);
  } finally {
    client.release();
  }
}

// Lancer l'initialisation
initDatabase();

// ==================== FONCTION AUDIT LOG ====================
async function logAction(req, action, tableName, recordId, details = '') {
  try {
    await pool.query(
      'INSERT INTO audit_log (user_id, username, action, table_name, record_id, details, ip_address) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [req.user?.id || null, req.user?.username || 'anonymous', action, tableName, recordId, details, req.ip]
    );
  } catch (e) {
    console.error('Erreur audit log:', e.message);
  }
}

// ==================== VALIDATION DES ENTRÉES ====================
function validatePatient(p) {
  const errors = [];
  if (!p.nom || p.nom.trim().length < 2) errors.push('Nom requis (min 2 caractères)');
  if (!p.prenom || p.prenom.trim().length < 2) errors.push('Prénom requis (min 2 caractères)');
  if (p.sexe && !['M', 'F'].includes(p.sexe)) errors.push('Sexe invalide');
  if (p.telephone && !/^[\d\s\+\-]{6,20}$/.test(p.telephone)) errors.push('Téléphone invalide');
  return errors;
}

function validateConsultation(c) {
  const errors = [];
  if (!c.patient_id) errors.push('Patient requis');
  if (!c.date_consultation) errors.push('Date requise');
  if (c.aptitude && !['apte', 'inapte', 'apte avec restrictions', 'en attente'].includes(c.aptitude.toLowerCase())) {
    errors.push('Aptitude invalide');
  }
  return errors;
}

// ==================== ROUTES AUTH (publiques) ====================
app.post('/api/login', rateLimitLogin, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Identifiants requis' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (user && verifyPassword(password, user.password)) {
      const token = createToken(user);
      await logAction(req, 'LOGIN', 'users', user.id, 'Connexion réussie');
      res.json({
        success: true,
        token,
        user: { id: user.id, username: user.username, role: user.role, nom: user.nom, prenom: user.prenom }
      });
    } else {
      await logAction(req, 'LOGIN_FAILED', 'users', null, `Tentative: ${username}`);
      res.status(401).json({ success: false, message: 'Identifiants incorrects' });
    }
  } catch (e) {
    console.error('Erreur login:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ==================== ROUTES PATIENTS (protégées) ====================
app.get('/api/patients', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM patients ORDER BY nom, prenom');
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.get('/api/patients/:id', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM patients WHERE id = $1', [req.params.id]);
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).json({ message: 'Patient non trouvé' });
    }
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/api/patients', authRequired, async (req, res) => {
  const errors = validatePatient(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  const p = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO patients (nom, prenom, date_naissance, sexe, adresse, telephone, entreprise, poste, numero_securite, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id',
      [p.nom, p.prenom, p.date_naissance, p.sexe, p.adresse, p.telephone, p.entreprise, p.poste, p.numero_securite, req.user.username]
    );
    const newId = result.rows[0].id;
    await logAction(req, 'CREATE', 'patients', newId, `${p.nom} ${p.prenom}`);
    res.json({ success: true, id: newId });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

app.put('/api/patients/:id', authRequired, async (req, res) => {
  const errors = validatePatient(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  const p = req.body;
  try {
    await pool.query(
      'UPDATE patients SET nom=$1, prenom=$2, date_naissance=$3, sexe=$4, adresse=$5, telephone=$6, entreprise=$7, poste=$8, numero_securite=$9, updated_at=CURRENT_TIMESTAMP WHERE id=$10',
      [p.nom, p.prenom, p.date_naissance, p.sexe, p.adresse, p.telephone, p.entreprise, p.poste, p.numero_securite, req.params.id]
    );
    await logAction(req, 'UPDATE', 'patients', req.params.id, `${p.nom} ${p.prenom}`);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

app.delete('/api/patients/:id', authRequired, adminRequired, async (req, res) => {
  try {
    const patientResult = await pool.query('SELECT nom, prenom FROM patients WHERE id = $1', [req.params.id]);
    const patient = patientResult.rows[0];

    await pool.query('DELETE FROM consultations WHERE patient_id = $1', [req.params.id]);
    await pool.query('DELETE FROM documents WHERE patient_id = $1', [req.params.id]);
    await pool.query('DELETE FROM lab_results WHERE patient_id = $1', [req.params.id]);
    await pool.query('DELETE FROM patients WHERE id = $1', [req.params.id]);

    await logAction(req, 'DELETE', 'patients', req.params.id, `${patient?.nom} ${patient?.prenom}`);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ==================== ROUTES CONSULTATIONS (protégées) ====================
app.get('/api/patients/:id/consultations', authRequired, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM consultations WHERE patient_id = $1 ORDER BY date_consultation DESC',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.get('/api/consultations', authRequired, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, p.nom as patient_nom, p.prenom as patient_prenom
      FROM consultations c
      LEFT JOIN patients p ON c.patient_id = p.id
      ORDER BY c.date_consultation DESC
    `);
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/api/consultations', authRequired, async (req, res) => {
  const errors = validateConsultation(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  const c = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO consultations (patient_id, date_consultation, type_consultation, motif, examen_clinique, diagnostic, traitement, aptitude, restrictions, prochaine_visite, medecin, notes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id',
      [c.patient_id, c.date_consultation, c.type_consultation, c.motif, c.examen_clinique, c.diagnostic, c.traitement, c.aptitude, c.restrictions, c.prochaine_visite, req.user.username, c.notes]
    );
    const newId = result.rows[0].id;
    await logAction(req, 'CREATE', 'consultations', newId, `Patient ID: ${c.patient_id}`);
    res.json({ success: true, id: newId });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

app.put('/api/consultations/:id', authRequired, async (req, res) => {
  const c = req.body;
  try {
    await pool.query(
      'UPDATE consultations SET date_consultation=$1, type_consultation=$2, motif=$3, examen_clinique=$4, diagnostic=$5, traitement=$6, aptitude=$7, restrictions=$8, prochaine_visite=$9, medecin=$10, notes=$11 WHERE id=$12',
      [c.date_consultation, c.type_consultation, c.motif, c.examen_clinique, c.diagnostic, c.traitement, c.aptitude, c.restrictions, c.prochaine_visite, c.medecin, c.notes, req.params.id]
    );
    await logAction(req, 'UPDATE', 'consultations', req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

app.delete('/api/consultations/:id', authRequired, adminRequired, async (req, res) => {
  try {
    await pool.query('DELETE FROM consultations WHERE id = $1', [req.params.id]);
    await logAction(req, 'DELETE', 'consultations', req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ==================== ROUTES UTILISATEURS (admin seulement) ====================
app.get('/api/users', authRequired, adminRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role, nom, prenom, created_at FROM users ORDER BY nom');
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/api/users', authRequired, adminRequired, async (req, res) => {
  const u = req.body;

  if (!u.username || u.username.length < 3) {
    return res.status(400).json({ success: false, message: "Nom d'utilisateur min 3 caractères" });
  }
  if (!u.password || u.password.length < 6) {
    return res.status(400).json({ success: false, message: 'Mot de passe min 6 caractères' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO users (username, password, role, nom, prenom) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [u.username, hashPassword(u.password), u.role || 'medecin', u.nom, u.prenom]
    );
    const newId = result.rows[0].id;
    await logAction(req, 'CREATE', 'users', newId, `${u.username} (${u.role})`);
    res.json({ success: true, id: newId });
  } catch (e) {
    res.status(400).json({ success: false, message: "Ce nom d'utilisateur existe déjà" });
  }
});

app.put('/api/users/:id/password', authRequired, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Non autorisé' });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'Nouveau mot de passe min 6 caractères' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
    }

    if (req.user.role !== 'admin' && !verifyPassword(oldPassword, user.password)) {
      return res.status(400).json({ success: false, message: 'Ancien mot de passe incorrect' });
    }

    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashPassword(newPassword), req.params.id]);
    await logAction(req, 'PASSWORD_CHANGE', 'users', req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ==================== ROUTES LABORATOIRE (protégées) ====================
app.post('/api/lab-results', authRequired, async (req, res) => {
  const d = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO lab_results
      (patient_id, patient_nom, patient_prenom, patient_dob, patient_genre,
       patient_adresse, statut, numero, preleve_par, valide_par,
       date_prelevement, heure_prelevement, date_rendu, heure_rendu,
       hematologie, biochimie, serologie, urines)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id`,
      [
        d.patient_id || null, d.patient_nom, d.patient_prenom, d.patient_dob,
        d.patient_genre, d.patient_adresse, d.statut, d.numero,
        d.preleve_par, d.valide_par, d.date_prelevement, d.heure_prelevement,
        d.date_rendu, d.heure_rendu,
        JSON.stringify(d.hematologie || {}),
        JSON.stringify(d.biochimie || {}),
        JSON.stringify(d.serologie || {}),
        JSON.stringify(d.urines || {})
      ]
    );
    const newId = result.rows[0].id;
    await logAction(req, 'CREATE', 'lab_results', newId, `${d.patient_nom} ${d.patient_prenom}`);
    res.json({ success: true, id: newId });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.get('/api/lab-results', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM lab_results ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.get('/api/lab-results/:id', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM lab_results WHERE id = $1', [req.params.id]);
    if (result.rows.length > 0) {
      const r = result.rows[0];
      r.hematologie = JSON.parse(r.hematologie || '{}');
      r.biochimie = JSON.parse(r.biochimie || '{}');
      r.serologie = JSON.parse(r.serologie || '{}');
      r.urines = JSON.parse(r.urines || '{}');
      res.json(r);
    } else {
      res.status(404).json({ message: 'Non trouvé' });
    }
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.put('/api/lab-results/:id', authRequired, async (req, res) => {
  const d = req.body;
  try {
    await pool.query(
      `UPDATE lab_results SET
      patient_nom=$1, patient_prenom=$2, patient_dob=$3, patient_genre=$4,
      patient_adresse=$5, statut=$6, numero=$7, preleve_par=$8, valide_par=$9,
      date_prelevement=$10, heure_prelevement=$11, date_rendu=$12, heure_rendu=$13,
      hematologie=$14, biochimie=$15, serologie=$16, urines=$17
      WHERE id=$18`,
      [
        d.patient_nom, d.patient_prenom, d.patient_dob, d.patient_genre,
        d.patient_adresse, d.statut, d.numero, d.preleve_par, d.valide_par,
        d.date_prelevement, d.heure_prelevement, d.date_rendu, d.heure_rendu,
        JSON.stringify(d.hematologie || {}),
        JSON.stringify(d.biochimie || {}),
        JSON.stringify(d.serologie || {}),
        JSON.stringify(d.urines || {}),
        req.params.id
      ]
    );
    await logAction(req, 'UPDATE', 'lab_results', req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.delete('/api/lab-results/:id', authRequired, adminRequired, async (req, res) => {
  try {
    await pool.query('DELETE FROM lab_results WHERE id = $1', [req.params.id]);
    await logAction(req, 'DELETE', 'lab_results', req.params.id);
    res.json({ success: true });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ success: false, message: 'Erreur serveur' });
  }
});

// ==================== AUDIT LOG (admin) ====================
app.get('/api/audit-log', authRequired, adminRequired, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const result = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json(result.rows);
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// ==================== STATISTIQUES (protégées) ====================
app.get('/api/stats', authRequired, async (req, res) => {
  try {
    const totalPatients = (await pool.query('SELECT COUNT(*) as count FROM patients')).rows[0].count;
    const totalConsultations = (await pool.query('SELECT COUNT(*) as count FROM consultations')).rows[0].count;
    const today = new Date().toISOString().split('T')[0];
    const consultationsToday = (await pool.query('SELECT COUNT(*) as count FROM consultations WHERE date_consultation = $1', [today])).rows[0].count;
    const totalLabResults = (await pool.query('SELECT COUNT(*) as count FROM lab_results')).rows[0].count;

    res.json({
      totalPatients: parseInt(totalPatients),
      totalConsultations: parseInt(totalConsultations),
      consultationsToday: parseInt(consultationsToday),
      totalLabResults: parseInt(totalLabResults)
    });
  } catch (e) {
    console.error('Erreur:', e.message);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// ==================== PAGES ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/laboratoire', (req, res) => {
  res.sendFile(path.join(__dirname, 'laboratoire.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// ==================== DÉMARRAGE ====================
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║       🏥 APSUMEDTRAV - Serveur Médical          ║');
  console.log('║              🔒 MODE SÉCURISÉ                   ║');
  console.log('║                                                  ║');
  console.log(`║   ✅ Serveur démarré sur le port ${PORT}             ║`);
  console.log(`║   📌 http://localhost:${PORT}                      ║`);
  console.log('║                                                  ║');
  console.log('║   🗄️  Base de données : PostgreSQL               ║');
  console.log('║   🔐 Auth par token obligatoire                 ║');
  console.log('║   🔐 Mots de passe hashés                      ║');
  console.log('║   📋 Audit log activé                          ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});