/**
 * End-to-end check of the session token contract between the ACS Lambda
 * (signs, lambda/src/shared/utils/token.ts) and the sso-check CloudFront
 * Function (verifies, functions/sso-check.js).
 *
 *     cd lambda && SAML_HMAC_KEY=... SAML_AUDIENCE=... npm run build && cd ..
 *     SAML_HMAC_KEY=... SAML_AUDIENCE=... node tests/sso-check.test.mjs
 *
 * The function is prepared exactly as main.tf does (full-line comments blanked,
 * sentinels replaced), with only `crypto` mapped to Node's module.
 */

import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { createHmac } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

const KEY = process.env.SAML_HMAC_KEY;
const AUDIENCE = process.env.SAML_AUDIENCE;
assert.ok(KEY && AUDIENCE, 'SAML_HMAC_KEY and SAML_AUDIENCE must match the Lambda build');

const { signToken, verifyToken } = require(path.join(root, 'lambda/dist/shared/utils/token.js'));
const { safeRelay } = require(path.join(root, 'lambda/dist/shared/utils/relay.js'));

function prepare(source, substitutions) {
  let code = source
    .split('\n')
    .map((line) => (/^\s*\/\//.test(line) ? '' : line.trim()))
    .join('\n');
  for (const [sentinel, value] of substitutions) {
    assert.ok(code.includes(sentinel), `sentinel missing: ${sentinel}`);
    code = code.replace(sentinel, JSON.stringify(value));
  }
  return code;
}

async function loadFunction(substitutions) {
  const library = prepare(await readFile(path.join(root, 'functions/sso-check.js'), 'utf8'), substitutions);
  const deployed = [
    "import crypto from 'crypto';",
    library,
    'function handler(event) {',
    '    return ssoCheck(event) || event.request;',
    '}',
    '',
  ].join('\n');
  const runnable = deployed.replace("import crypto from 'crypto';", "import crypto from 'node:crypto';") + '\nexport { handler };\n';
  const url = `data:text/javascript;base64,${Buffer.from(runnable).toString('base64')}`;
  return { handler: (await import(url)).handler, deployed };
}

const SUBSTITUTIONS = [
  ["/*__SSO_HMAC_KEY__*/''", KEY],
  ["/*__SSO_AUDIENCE__*/''", AUDIENCE],
  ["/*__SSO_COOKIE_NAME__*/'sso_auth'", 'sso_auth'],
  ["/*__SSO_LOGIN_PATH__*/'/saml/login'", '/saml/login'],
  ["/*__SSO_LOGOUT_PATH__*/'/saml/logout'", '/saml/logout'],
];

const { handler, deployed } = await loadFunction(SUBSTITUTIONS);

function event({ uri = '/center-booking/complete', cookie, dest, query = {}, headers = {} } = {}) {
  const h = { host: { value: 'www.preprod.example.com' }, ...headers };
  if (dest) h['sec-fetch-dest'] = { value: dest };
  const cookies = {};
  if (cookie !== undefined) cookies.sso_auth = { value: cookie };
  return { request: { method: 'GET', uri, querystring: query, headers: h, cookies } };
}

const now = Math.floor(Date.now() / 1000);
const valid = signToken('jean@example.com', now + 3600);
let passed = 0;
const test = async (name, fn) => {
  await fn();
  passed += 1;
  console.log(`ok - ${name}`);
};

await test('a token signed by the ACS Lambda is accepted and carries the email', () => {
  const e = event({ cookie: valid, dest: 'document' });
  assert.equal(handler(e), e.request);
  assert.equal(e.request.headers['x-sso-user-email'].value, 'jean@example.com');
});

await test('the Lambda verifier agrees with the edge verifier', () => {
  assert.equal(verifyToken(valid).userEmail, 'jean@example.com');
  assert.equal(verifyToken(valid.slice(0, -1) + (valid.endsWith('0') ? '1' : '0')), null);
});

await test('no cookie on a document redirects to /saml/login with path and query', () => {
  const r = handler(event({ dest: 'document', query: { center: { value: 'garde-meuble-libourne.html' }, type: { value: 'q' } } }));
  assert.equal(r.statusCode, 302);
  assert.equal(
    r.headers.location.value,
    '/saml/login?relay=' + encodeURIComponent('/center-booking/complete?center=garde-meuble-libourne.html&type=q'),
  );
  assert.equal(r.headers['cache-control'].value, 'no-cache, no-store, must-revalidate');
});

await test('repeated query parameters are all kept', () => {
  const r = handler(event({ query: { a: { value: '1', multiValue: [{ value: '1' }, { value: '2' }] }, flag: { value: '' } } }));
  assert.equal(decodeURIComponent(r.headers.location.value.split('relay=')[1]), '/center-booking/complete?a=1&a=2&flag');
});

await test('an expired token is refused', () => {
  const r = handler(event({ cookie: signToken('jean@example.com', now - 1), dest: 'document' }));
  assert.equal(r.statusCode, 302);
});

await test('a tampered email is refused', () => {
  const parts = valid.split('.');
  parts[2] = Buffer.from('attacker@example.com').toString('hex');
  assert.equal(handler(event({ cookie: parts.join('.'), dest: 'document' })).statusCode, 302);
});

await test('a token signed for another audience is refused', () => {
  const body = `v1.${now + 3600}.${Buffer.from('jean@example.com').toString('hex')}`;
  const mac = createHmac('sha256', KEY).update(`other-audience|${body}`).digest('hex');
  assert.equal(handler(event({ cookie: `${body}.${mac}`, dest: 'document' })).statusCode, 302);
});

await test('garbage and legacy AES cookies are refused', () => {
  for (const cookie of ['', 'x', 'v1..', 'a'.repeat(96), 'v1.9999999999.zz.00', 'v2.9999999999.00.00']) {
    assert.equal(handler(event({ cookie, dest: 'document' })).statusCode, 302, cookie);
  }
});

await test('fetch/XHR (sec-fetch-dest empty) stays gated', () => {
  assert.equal(handler(event({ dest: 'empty', headers: { rsc: { value: '1' } } })).statusCode, 302);
});

await test('passive sub-resources are served without a session', () => {
  for (const dest of ['image', 'font', 'style', 'script']) {
    const e = event({ uri: '/logo.svg', dest });
    assert.equal(handler(e), e.request, dest);
  }
  const noHeader = event({ uri: '/fonts/a.woff2' });
  assert.equal(handler(noHeader), noHeader.request);
  assert.equal(handler(event({ uri: '/page' })).statusCode, 302);
});

await test('a viewer-supplied identity header is always dropped', () => {
  const e = event({ uri: '/logo.svg', dest: 'image', headers: { 'x-sso-user-email': { value: 'spoof@example.com' } } });
  handler(e);
  assert.equal(e.request.headers['x-sso-user-email'], undefined);
});

await test('logout clears the cookie and goes home', () => {
  const r = handler(event({ uri: '/saml/logout', cookie: valid }));
  assert.equal(r.statusCode, 302);
  assert.equal(r.headers.location.value, '/');
  assert.match(r.cookies.sso_auth.attributes, /Expires=Thu, 01 Jan 1970/);
});

await test('an unsubstituted key fails closed', async () => {
  const { handler: unconfigured } = await loadFunction(SUBSTITUTIONS.slice(1));
  assert.equal(unconfigured(event({ cookie: valid, dest: 'document' })).statusCode, 302);
});

await test('the deployed function fits the 10 KB CloudFront Functions limit with room to compose', () => {
  const size = Buffer.byteLength(deployed);
  console.log(`   deployed size: ${size} bytes`);
  assert.ok(size < 2560, `sso-check is ${size} bytes`);
});

await test('login relay only accepts same-site paths', () => {
  assert.equal(safeRelay('/center-booking/complete?center=x'), '/center-booking/complete?center=x');
  for (const bad of ['https://evil.example', '//evil.example', '/\\evil.example', 'evil', '/a\r\nb', undefined, ['/a']]) {
    assert.equal(safeRelay(bad), '/', String(bad));
  }
});

console.log(`\n${passed} checks passed`);
