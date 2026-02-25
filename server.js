const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SÉCURITÉ : CLÉ SECRÈTE JWT ====================
const SECRET_KEY = crypto.randomBytes(64).toString('hex');

// ==================== FONCTIONS DE SÉCURITÉ ====================

// Hashage des mots de passe (SHA-256 avec sel)
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

// Création de token simple (sans dépendance externe)
function createToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role,
    exp: Date.now() + (8 * 60 * 60 * 1000) // expire dans 8h
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
    if (payload.exp < Date.now()) return null; // expiré
    
    return payload;
  } catch {
    return null;
  }
}

// ==================== MIDDLEWARE ====================

// CORS restreint
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname)));

// 🔒 Middleware d'authentification
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

// 🔒 Middleware admin seulement
function adminRequired(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Accès réservé aux administrateurs' });
  }
  next();
}

// 🔒 Rate limiting simple (anti force brute)
const loginAttempts = new Map();

function rateLimitLogin(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || [];
  
  // Garder seulement les tentatives des 15 dernières minutes
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

// ==================== BASE DE DONNÉES ====================
const db = new Database(path.join(__dirname, 'apsumedtrav.db'));
db.pragma('journal_mode = WAL');

// Créer les tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'medecin',
    nom TEXT,
    prenom TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS consultations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
  );

  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    consultation_id INTEGER,
    type_document TEXT,
    nom_fichier TEXT,
    contenu TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
  );

  CREATE TABLE IF NOT EXISTS lab_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT,
    table_name TEXT,
    record_id INTEGER,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// 🔒 Migrer le mot de passe admin s'il est encore en clair
const adminUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminUser) {
  db.prepare('INSERT INTO users (username, password, role, nom, prenom) VALUES (?, ?, ?, ?, ?)')
    .run('admin', hashPassword('admin123'), 'admin', 'Administrateur', 'Principal');
  console.log('✅ Compte admin créé (mot de passe hashé)');
} else if (!adminUser.password.includes(':')) {
  // Le mot de passe est encore en clair → le hasher
  const hashed = hashPassword(adminUser.password);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashed, adminUser.id);
  console.log('✅ Mot de passe admin migré vers hashé');
}
// Créer les utilisateurs par défaut (à exécuter une seule fois)
const defaultUsers = [
  { username: 'medecin', password: 'Med2024!', role: 'medecin', nom: 'Médecin', prenom: 'Principal' },
  { username: 'medecin1', password: 'Med-2-2024!', role: 'medecin', nom: 'Médecin', prenom: 'Adjoint' },
  { username: 'assistant', password: 'Assist2024!', role: 'assistant', nom: 'Assistant', prenom: 'Principal' },
  { username: 'infirmier', password: 'Infir2024!', role: 'infirmier', nom: 'Infirmier', prenom: 'Principal' },
  { username: 'infirmier-1', password: 'Infir-12024!', role: 'infirmier', nom: 'Infirmier-1', prenom: 'Principal' },
  { username: 'laboratin', password: 'lab2024!', role: 'laboratin', nom: 'Laboratin', prenom: 'Principal' }
];

defaultUsers.forEach(u => {
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
  if (!exists) {
    db.prepare('INSERT INTO users (username, password, role, nom, prenom) VALUES (?, ?, ?, ?, ?)')
      .run(u.username, hashPassword(u.password), u.role, u.nom, u.prenom);
    console.log(`✅ Utilisateur créé : ${u.username}`);
  }
});

// ==================== FONCTION AUDIT LOG ====================
function logAction(req, action, tableName, recordId, details = '') {
  try {
    db.prepare(`
      INSERT INTO audit_log (user_id, username, action, table_name, record_id, details, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user?.id || null,
      req.user?.username || 'anonymous',
      action,
      tableName,
      recordId,
      details,
      req.ip
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
app.post('/api/login', rateLimitLogin, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Identifiants requis' });
  }
  
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  
  if (user && verifyPassword(password, user.password)) {
    const token = createToken(user);
    
    logAction(req, 'LOGIN', 'users', user.id, 'Connexion réussie');
    
    res.json({ 
      success: true, 
      token,
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role, 
        nom: user.nom, 
        prenom: user.prenom 
      } 
    });
  } else {
    logAction(req, 'LOGIN_FAILED', 'users', null, `Tentative: ${username}`);
    res.status(401).json({ success: false, message: 'Identifiants incorrects' });
  }
});

// ==================== ROUTES PATIENTS (protégées) ====================
app.get('/api/patients', authRequired, (req, res) => {
  const patients = db.prepare('SELECT * FROM patients ORDER BY nom, prenom').all();
  res.json(patients);
});

app.get('/api/patients/:id', authRequired, (req, res) => {
  const patient = db.prepare('SELECT * FROM patients WHERE id = ?').get(req.params.id);
  if (patient) {
    res.json(patient);
  } else {
    res.status(404).json({ message: 'Patient non trouvé' });
  }
});

app.post('/api/patients', authRequired, (req, res) => {
  const errors = validatePatient(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }
  
  const p = req.body;
  const result = db.prepare(`
    INSERT INTO patients (nom, prenom, date_naissance, sexe, adresse, telephone, entreprise, poste, numero_securite, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(p.nom, p.prenom, p.date_naissance, p.sexe, p.adresse, p.telephone, p.entreprise, p.poste, p.numero_securite, req.user.username);
  
  logAction(req, 'CREATE', 'patients', result.lastInsertRowid, `${p.nom} ${p.prenom}`);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/patients/:id', authRequired, (req, res) => {
  const errors = validatePatient(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }
  
  const p = req.body;
  db.prepare(`
    UPDATE patients SET nom=?, prenom=?, date_naissance=?, sexe=?, adresse=?, telephone=?, entreprise=?, poste=?, numero_securite=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(p.nom, p.prenom, p.date_naissance, p.sexe, p.adresse, p.telephone, p.entreprise, p.poste, p.numero_securite, req.params.id);
  
  logAction(req, 'UPDATE', 'patients', req.params.id, `${p.nom} ${p.prenom}`);
  res.json({ success: true });
});

app.delete('/api/patients/:id', authRequired, adminRequired, (req, res) => {
  const patient = db.prepare('SELECT nom, prenom FROM patients WHERE id = ?').get(req.params.id);
  
  db.prepare('DELETE FROM consultations WHERE patient_id = ?').run(req.params.id);
  db.prepare('DELETE FROM documents WHERE patient_id = ?').run(req.params.id);
  db.prepare('DELETE FROM lab_results WHERE patient_id = ?').run(req.params.id);
  db.prepare('DELETE FROM patients WHERE id = ?').run(req.params.id);
  
  logAction(req, 'DELETE', 'patients', req.params.id, `${patient?.nom} ${patient?.prenom}`);
  res.json({ success: true });
});

// ==================== ROUTES CONSULTATIONS (protégées) ====================
app.get('/api/patients/:id/consultations', authRequired, (req, res) => {
  const consultations = db.prepare('SELECT * FROM consultations WHERE patient_id = ? ORDER BY date_consultation DESC')
    .all(req.params.id);
  res.json(consultations);
});

app.get('/api/consultations', authRequired, (req, res) => {
  const consultations = db.prepare(`
    SELECT c.*, p.nom as patient_nom, p.prenom as patient_prenom 
    FROM consultations c 
    LEFT JOIN patients p ON c.patient_id = p.id 
    ORDER BY c.date_consultation DESC
  `).all();
  res.json(consultations);
});

app.post('/api/consultations', authRequired, (req, res) => {
  const errors = validateConsultation(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }
  
  const c = req.body;
  const result = db.prepare(`
    INSERT INTO consultations (patient_id, date_consultation, type_consultation, motif, examen_clinique, diagnostic, traitement, aptitude, restrictions, prochaine_visite, medecin, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(c.patient_id, c.date_consultation, c.type_consultation, c.motif, c.examen_clinique, c.diagnostic, c.traitement, c.aptitude, c.restrictions, c.prochaine_visite, req.user.username, c.notes);
  
  logAction(req, 'CREATE', 'consultations', result.lastInsertRowid, `Patient ID: ${c.patient_id}`);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.put('/api/consultations/:id', authRequired, (req, res) => {
  const c = req.body;
  db.prepare(`
    UPDATE consultations SET date_consultation=?, type_consultation=?, motif=?, examen_clinique=?, diagnostic=?, traitement=?, aptitude=?, restrictions=?, prochaine_visite=?, medecin=?, notes=?
    WHERE id=?
  `).run(c.date_consultation, c.type_consultation, c.motif, c.examen_clinique, c.diagnostic, c.traitement, c.aptitude, c.restrictions, c.prochaine_visite, c.medecin, c.notes, req.params.id);
  
  logAction(req, 'UPDATE', 'consultations', req.params.id);
  res.json({ success: true });
});

app.delete('/api/consultations/:id', authRequired, adminRequired, (req, res) => {
  db.prepare('DELETE FROM consultations WHERE id = ?').run(req.params.id);
  logAction(req, 'DELETE', 'consultations', req.params.id);
  res.json({ success: true });
});

// ==================== ROUTES UTILISATEURS (admin seulement) ====================
app.get('/api/users', authRequired, adminRequired, (req, res) => {
  const users = db.prepare('SELECT id, username, role, nom, prenom, created_at FROM users ORDER BY nom').all();
  res.json(users);
});

app.post('/api/users', authRequired, adminRequired, (req, res) => {
  const u = req.body;
  
  if (!u.username || u.username.length < 3) {
    return res.status(400).json({ success: false, message: 'Nom d\'utilisateur min 3 caractères' });
  }
  if (!u.password || u.password.length < 6) {
    return res.status(400).json({ success: false, message: 'Mot de passe min 6 caractères' });
  }
  
  try {
    const result = db.prepare('INSERT INTO users (username, password, role, nom, prenom) VALUES (?, ?, ?, ?, ?)')
      .run(u.username, hashPassword(u.password), u.role || 'medecin', u.nom, u.prenom);
    
    logAction(req, 'CREATE', 'users', result.lastInsertRowid, `${u.username} (${u.role})`);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ success: false, message: 'Ce nom d\'utilisateur existe déjà' });
  }
});

// 🔒 Changer mot de passe
app.put('/api/users/:id/password', authRequired, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  
  // Seul l'utilisateur lui-même ou un admin peut changer le mot de passe
  if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Non autorisé' });
  }
  
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'Nouveau mot de passe min 6 caractères' });
  }
  
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) {
    return res.status(404).json({ success: false, message: 'Utilisateur non trouvé' });
  }
  
  // Vérifier l'ancien mot de passe (sauf si admin)
  if (req.user.role !== 'admin' && !verifyPassword(oldPassword, user.password)) {
    return res.status(400).json({ success: false, message: 'Ancien mot de passe incorrect' });
  }
  
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(newPassword), req.params.id);
  logAction(req, 'PASSWORD_CHANGE', 'users', req.params.id);
  res.json({ success: true });
});

// ==================== ROUTES LABORATOIRE (protégées) ====================
app.post('/api/lab-results', authRequired, (req, res) => {
  const d = req.body;
  try {
    const result = db.prepare(`
      INSERT INTO lab_results 
      (patient_id, patient_nom, patient_prenom, patient_dob, patient_genre, 
       patient_adresse, statut, numero, preleve_par, valide_par, 
       date_prelevement, heure_prelevement, date_rendu, heure_rendu,
       hematologie, biochimie, serologie, urines)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      d.patient_id || null, d.patient_nom, d.patient_prenom, d.patient_dob,
      d.patient_genre, d.patient_adresse, d.statut, d.numero,
      d.preleve_par, d.valide_par, d.date_prelevement, d.heure_prelevement,
      d.date_rendu, d.heure_rendu,
      JSON.stringify(d.hematologie || {}),
      JSON.stringify(d.biochimie || {}),
      JSON.stringify(d.serologie || {}),
      JSON.stringify(d.urines || {})
    );
    
    logAction(req, 'CREATE', 'lab_results', result.lastInsertRowid, `${d.patient_nom} ${d.patient_prenom}`);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.get('/api/lab-results', authRequired, (req, res) => {
  const results = db.prepare('SELECT * FROM lab_results ORDER BY created_at DESC').all();
  res.json(results);
});

app.get('/api/lab-results/:id', authRequired, (req, res) => {
  const result = db.prepare('SELECT * FROM lab_results WHERE id = ?').get(req.params.id);
  if (result) {
    result.hematologie = JSON.parse(result.hematologie || '{}');
    result.biochimie = JSON.parse(result.biochimie || '{}');
    result.serologie = JSON.parse(result.serologie || '{}');
    result.urines = JSON.parse(result.urines || '{}');
    res.json(result);
  } else {
    res.status(404).json({ message: 'Non trouvé' });
  }
});

app.put('/api/lab-results/:id', authRequired, (req, res) => {
  const d = req.body;
  try {
    db.prepare(`
      UPDATE lab_results SET
      patient_nom=?, patient_prenom=?, patient_dob=?, patient_genre=?,
      patient_adresse=?, statut=?, numero=?, preleve_par=?, valide_par=?,
      date_prelevement=?, heure_prelevement=?, date_rendu=?, heure_rendu=?,
      hematologie=?, biochimie=?, serologie=?, urines=?
      WHERE id=?
    `).run(
      d.patient_nom, d.patient_prenom, d.patient_dob, d.patient_genre,
      d.patient_adresse, d.statut, d.numero, d.preleve_par, d.valide_par,
      d.date_prelevement, d.heure_prelevement, d.date_rendu, d.heure_rendu,
      JSON.stringify(d.hematologie || {}),
      JSON.stringify(d.biochimie || {}),
      JSON.stringify(d.serologie || {}),
      JSON.stringify(d.urines || {}),
      req.params.id
    );
    
    logAction(req, 'UPDATE', 'lab_results', req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.delete('/api/lab-results/:id', authRequired, adminRequired, (req, res) => {
  db.prepare('DELETE FROM lab_results WHERE id = ?').run(req.params.id);
  logAction(req, 'DELETE', 'lab_results', req.params.id);
  res.json({ success: true });
});

// ==================== AUDIT LOG (admin) ====================
app.get('/api/audit-log', authRequired, adminRequired, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const logs = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?').all(limit);
  res.json(logs);
});

// ==================== STATISTIQUES (protégées) ====================
app.get('/api/stats', authRequired, (req, res) => {
  const totalPatients = db.prepare('SELECT COUNT(*) as count FROM patients').get().count;
  const totalConsultations = db.prepare('SELECT COUNT(*) as count FROM consultations').get().count;
  const today = new Date().toISOString().split('T')[0];
  const consultationsToday = db.prepare('SELECT COUNT(*) as count FROM consultations WHERE date_consultation = ?').get(today).count;
  const totalLabResults = db.prepare('SELECT COUNT(*) as count FROM lab_results').get().count;
  
  res.json({
    totalPatients,
    totalConsultations,
    consultationsToday,
    totalLabResults
  });
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
app.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║       🏥 APSUMEDTRAV - Serveur Médical          ║');
  console.log('║              🔒 MODE SÉCURISÉ                   ║');
  console.log('║                                                  ║');
  console.log(`║   ✅ Serveur démarré sur le port ${PORT}             ║`);
  console.log('║   📌 http://localhost:' + PORT + '                      ║');
  console.log('║                                                  ║');
  console.log('║   🔐 Auth par token obligatoire                 ║');
  console.log('║   🔐 Mots de passe hashés                      ║');
  console.log('║   🔐 Audit log activé                          ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});