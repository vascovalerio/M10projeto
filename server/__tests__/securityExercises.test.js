const request = require('supertest');
const fs = require('fs-extra');
const path = require('path');

// IMPORTANT: set DB path before importing app (app.js reads env + initializes DB)
process.env.DATABASE_URL = './data/test-security.db';
process.env.NODE_ENV = 'test';
process.env.SECRET_ENCRYPTION_KEY = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

const { initializeDatabase, closeDatabase, getDatabase } = require('../src/config/database');
const userModel = require('../src/models/userModel');
const { LOG_FILE } = require('../src/utils/securityLog');

let app;

describe('Security exercises (2.1 RBAC + 2.2 IDOR protection + 3.1 SQLi + 3.2 + 4.x)', () => {
  const dbFile = path.resolve(__dirname, '..', process.env.DATABASE_URL);

  beforeAll(async () => {
    await fs.ensureDir(path.dirname(dbFile));
    await fs.remove(dbFile);
    await initializeDatabase();
    app = require('../src/app');
  });

  afterAll(async () => {
    await closeDatabase();
    await fs.remove(dbFile);
  });

  beforeEach(async () => {
    await fs.remove(LOG_FILE);
  });

  test('2.1 - normal user cannot access GET /system/logs (403)', async () => {
    // Register two users
    await request(app).post('/api/auth/register').send({
      email: 'user@example.com',
      password: 'Password#123'
    });

    await request(app).post('/api/auth/register').send({
      email: 'admin@example.com',
      password: 'Password#123'
    });

    // Promote admin
    const adminRow = await userModel.getUserByEmail('admin@example.com');
    await userModel.setUserRole(adminRow.id, 'admin');

    // Login as normal user
    const loginUser = await request(app).post('/api/auth/login').send({
      email: 'user@example.com',
      password: 'Password#123'
    });
    expect(loginUser.status).toBe(200);
    const userToken = loginUser.body.token;

    const res = await request(app)
      .get('/system/logs')
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty('error', 'Forbidden');
  });

  test('2.1 - admin can access GET /system/logs (200)', async () => {
    const loginAdmin = await request(app).post('/api/auth/login').send({
      email: 'admin@example.com',
      password: 'Password#123'
    });
    expect(loginAdmin.status).toBe(200);
    const adminToken = loginAdmin.body.token;

    const res = await request(app)
      .get('/system/logs')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('logs');
    expect(Array.isArray(res.body.logs)).toBe(true);
  });

  test('2.2 - avoid direct object reference: user A cannot GET /secrets/:id of user B (404)', async () => {
    // Register two users (A and B)
    await request(app).post('/api/auth/register').send({
      email: 'a@example.com',
      password: 'Password#123'
    });
    await request(app).post('/api/auth/register').send({
      email: 'b@example.com',
      password: 'Password#123'
    });

    // Login both
    const loginA = await request(app).post('/api/auth/login').send({
      email: 'a@example.com',
      password: 'Password#123'
    });
    const tokenA = loginA.body.token;

    const loginB = await request(app).post('/api/auth/login').send({
      email: 'b@example.com',
      password: 'Password#123'
    });
    const tokenB = loginB.body.token;

    // User B creates a secret
    const created = await request(app)
      .post('/secrets')
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ name: 'b-secret', value: 'TOP-SECRET' });
    expect(created.status).toBe(201);
    const secretId = created.body.id;

    // User A tries to access B's secret by changing the ID
    const res = await request(app)
      .get(`/secrets/${secretId}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('error', 'Not Found');
  });

  test('3.1 - /secrets?search uses parameterized query and blocks SQL injection payloads', async () => {
    // Register two users and login
    await request(app).post('/api/auth/register').send({
      email: 'search-a@example.com',
      password: 'Password#123'
    });
    await request(app).post('/api/auth/register').send({
      email: 'search-b@example.com',
      password: 'Password#123'
    });

    const loginA = await request(app).post('/api/auth/login').send({
      email: 'search-a@example.com',
      password: 'Password#123'
    });
    const tokenA = loginA.body.token;

    const loginB = await request(app).post('/api/auth/login').send({
      email: 'search-b@example.com',
      password: 'Password#123'
    });
    const tokenB = loginB.body.token;

    // User A stores one secret that should match normal search
    await request(app)
      .post('/secrets')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ name: 'alpha-note', value: 'safe-content' });

    // User B stores a different secret
    await request(app)
      .post('/secrets')
      .set('Authorization', `Bearer ${tokenB}`)
      .send({ name: 'bravo-note', value: 'other-content' });

    // Normal search works
    const normalSearch = await request(app)
      .get('/secrets?search=alpha')
      .set('Authorization', `Bearer ${tokenA}`);

    expect(normalSearch.status).toBe(200);
    expect(Array.isArray(normalSearch.body.data)).toBe(true);
    expect(normalSearch.body.data.length).toBe(1);
    expect(normalSearch.body.data[0]).toHaveProperty('name', 'alpha-note');

    // SQLi payload should be treated as text, not executable SQL
    const sqliAttempt = await request(app)
      .get(`/secrets?search=${encodeURIComponent("' OR '1'='1")}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect(sqliAttempt.status).toBe(200);
    expect(Array.isArray(sqliAttempt.body.data)).toBe(true);
    expect(sqliAttempt.body.data.length).toBe(0);
  });


  test('3.2 - secret content is encrypted at rest and sanitized on output', async () => {
    await request(app).post('/api/auth/register').send({
      email: 'xss@example.com',
      password: 'Password#123'
    });

    const login = await request(app).post('/api/auth/login').send({
      email: 'xss@example.com',
      password: 'Password#123'
    });
    const token = login.body.token;

    const payload = '<script>alert(1)</script>';

    const created = await request(app)
      .post('/secrets')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'xss-note', value: payload });

    expect(created.status).toBe(201);
    expect(created.body.value).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');

    const secretId = created.body.id;

    const db = getDatabase();
    const row = await db.get('SELECT value FROM secrets WHERE id = ?', [secretId]);

    expect(row).toBeTruthy();
    expect(typeof row.value).toBe('string');
    expect(row.value).not.toBe(payload);
    expect(row.value).toMatch(/^enc:v1:/);

    const fetched = await request(app)
      .get(`/secrets/${secretId}`)
      .set('Authorization', `Bearer ${token}`);

    expect(fetched.status).toBe(200);
    expect(fetched.body.value).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  test('4.1 - refresh endpoint issues a new access token via HttpOnly cookie flow', async () => {
    await request(app).post('/api/auth/register').send({
      email: 'refresh@example.com',
      password: 'Password#123'
    });

    const login = await request(app).post('/api/auth/login').send({
      email: 'refresh@example.com',
      password: 'Password#123'
    });

    expect(login.status).toBe(200);
    expect(login.headers['set-cookie']).toBeDefined();
    const refreshCookie = login.headers['set-cookie'].find(c => c.startsWith('refresh_token='));
    expect(refreshCookie).toBeDefined();

    const refresh = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', refreshCookie);

    expect(refresh.status).toBe(200);
    expect(refresh.body).toHaveProperty('accessToken');

    const me = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${refresh.body.accessToken}`);

    expect(me.status).toBe(200);
    expect(me.body).toHaveProperty('user.email', 'refresh@example.com');
  });

  test('4.2 - blocks CORS requests from non-authorized origin', async () => {
    const corsFail = await request(app)
      .get('/health')
      .set('Origin', 'https://evil.example');

    expect(corsFail.status).toBe(403);
    expect(corsFail.body).toHaveProperty('message', 'CORS origin não autorizada');
  });

  test('4.2 - returns security headers', async () => {
    const ok = await request(app).get('/health');
    expect(ok.status).toBe(200);
    expect(ok.headers).toHaveProperty('x-frame-options', 'DENY');
    expect(ok.headers).toHaveProperty('strict-transport-security');
    expect(ok.headers).toHaveProperty('content-security-policy');
  });

  test('5.1 - security logs mask sensitive values (email/password/token)', async () => {
    await request(app).post('/api/auth/login').send({
      email: 'sensitive@example.com',
      password: 'Password#123'
    });

    const logContents = await fs.readFile(LOG_FILE, 'utf8');
    expect(logContents).toContain('se***@example.com');
    expect(logContents).not.toContain('sensitive@example.com');
    expect(logContents).not.toContain('Password#123');
    expect(logContents).not.toContain('Bearer ');
  });

  test('5.1 - audit logs are populated and immutable', async () => {
    await request(app).post('/api/auth/register').send({
      email: 'audit@example.com',
      password: 'Password#123'
    });

    await request(app).post('/api/auth/login').send({
      email: 'audit@example.com',
      password: 'Password#123'
    });

    const db = getDatabase();
    const auditRows = await db.all(`SELECT id, action, result FROM audit_logs ORDER BY id DESC LIMIT 20`);
    expect(auditRows.length).toBeGreaterThan(0);
    expect(auditRows.some(row => row.action === 'AUTH_LOGIN' && row.result === 'SUCCESS')).toBe(true);

    const rowId = auditRows[0].id;
    await expect(db.run(`UPDATE audit_logs SET action = 'HACK' WHERE id = ?`, [rowId]))
      .rejects
      .toThrow(/immutable/i);

    await expect(db.run(`DELETE FROM audit_logs WHERE id = ?`, [rowId]))
      .rejects
      .toThrow(/immutable/i);
  });

  test('5.1 - admin can read audit logs via /system/audit-logs', async () => {
    await request(app).post('/api/auth/register').send({
      email: 'auditadmin@example.com',
      password: 'Password#123'
    });

    const admin = await userModel.getUserByEmail('auditadmin@example.com');
    await userModel.setUserRole(admin.id, 'admin');

    const login = await request(app).post('/api/auth/login').send({
      email: 'auditadmin@example.com',
      password: 'Password#123'
    });

    const res = await request(app)
      .get('/system/audit-logs?limit=5')
      .set('Authorization', `Bearer ${login.body.accessToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.logs)).toBe(true);
    expect(res.body.logs.length).toBeGreaterThan(0);
    expect(res.body.logs[0]).toHaveProperty('action');
  });

});
