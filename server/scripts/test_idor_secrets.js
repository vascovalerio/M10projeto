/**
 * Exercise 2.2 test script (IDOR)
 *
 * Starts with two users:
 *  - user A authenticates and tries to fetch user B's secret by ID
 * Expected result: 404 Not Found
 *
 * Usage:
 *   1) Start the server: npm start
 *   2) Run: node scripts/test_idor_secrets.js
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

async function http(method, url, body, token) {
  const res = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

async function main() {
  const emailA = 'idor-a@example.com';
  const emailB = 'idor-b@example.com';
  const password = 'Password#123';

  // Register users (ignore if already exists)
  await http('POST', `${BASE_URL}/api/auth/register`, { email: emailA, password });
  await http('POST', `${BASE_URL}/api/auth/register`, { email: emailB, password });

  // Login
  const loginA = await http('POST', `${BASE_URL}/api/auth/login`, { email: emailA, password });
  const loginB = await http('POST', `${BASE_URL}/api/auth/login`, { email: emailB, password });

  const tokenA = loginA.json.token;
  const tokenB = loginB.json.token;

  // User B creates a secret
  const created = await http('POST', `${BASE_URL}/secrets`, { name: 'b-secret', value: 'TOP-SECRET' }, tokenB);
  const secretId = created.json.id;

  // User A attempts to read it by ID
  const attempt = await http('GET', `${BASE_URL}/secrets/${secretId}`, null, tokenA);

  console.log('--- IDOR test report ---');
  console.log('User A email:', emailA);
  console.log('User B email:', emailB);
  console.log('Secret created by B:', { id: secretId });
  console.log('A attempt status:', attempt.status);
  console.log('A attempt body:', attempt.json);
  console.log('Expected: 404 Not Found');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
