const request = require('supertest');
const fs = require('fs-extra');
const path = require('path');

// IMPORTANT: set DB path before importing app (app.js reads env + initializes DB)
process.env.DATABASE_URL = './data/test-security.db';
process.env.NODE_ENV = 'test';

const { initializeDatabase, closeDatabase } = require('../src/config/database');
const userModel = require('../src/models/userModel');

let app;

describe('Security exercises (2.1 RBAC + 2.2 IDOR protection + 3.1 SQLi)', () => {
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

});
