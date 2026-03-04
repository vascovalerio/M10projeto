/**
 * Exercise 2.1 test script (RBAC)
 *
 * Logs in as a normal user and calls GET /system/logs.
 * Expected result: 403 Forbidden
 *
 * Usage:
 *   1) Start the server: npm start
 *   2) Run: node scripts/test_rbac_logs.js
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
  const email = 'rbac-user@example.com';
  const password = 'Password#123';

  // Register (ignore if already exists)
  await http('POST', `${BASE_URL}/api/auth/register`, { email, password });

  // Login
  const login = await http('POST', `${BASE_URL}/api/auth/login`, { email, password });
  const token = login.json.token;

  // Attempt admin-only operation
  const res = await http('GET', `${BASE_URL}/system/logs`, null, token);

  console.log('--- RBAC test report ---');
  console.log('User:', email);
  console.log('GET /system/logs status:', res.status);
  console.log('Body:', res.json);
  console.log('Expected: 403 Forbidden');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
