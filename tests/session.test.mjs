/**
 * Shared session mode (cookie_domain + auth_host) of the Lambda handlers:
 * cookie attributes, ACS host, RelayState and the ACS redirect validation.
 *
 *     cd lambda && npm run build && cd .. && node tests/session.test.mjs
 *
 * Runs against the built modules; config is switched between modes at runtime.
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

const { config } = require(path.join(root, 'lambda/dist/shared/config.js'));
const session = require(path.join(root, 'lambda/dist/shared/utils/session.js'));
const { readCookieValues } = require(path.join(root, 'lambda/dist/shared/utils/cloudfront.js'));

let passed = 0;
const test = (name, fn) => {
  fn();
  passed += 1;
  console.log(`ok - ${name}`);
};

const perHost = () => Object.assign(config, { cookieDomain: '', authHost: '' });
const shared = () => Object.assign(config, { cookieDomain: '.preprod.example.com', authHost: 'sso.preprod.example.com' });

test('per-host mode: host-only cookie, ACS and relay on the requesting host', () => {
  perHost();
  assert.equal(session.cookieAttributes(), 'Path=/; Secure; HttpOnly; SameSite=Lax');
  assert.equal(session.acsHost('be.preprod.example.com'), 'be.preprod.example.com');
  assert.equal(session.relayStateFor('be.preprod.example.com', '/fr/c?q=1'), '/fr/c?q=1');
  assert.equal(session.redirectTarget('be.preprod.example.com', '/fr/c?q=1'), 'https://be.preprod.example.com/fr/c?q=1');
});

test('per-host mode: the ACS is not an open redirect', () => {
  perHost();
  for (const bad of ['@evil.example/x', '//evil.example', 'https://evil.example', undefined]) {
    assert.equal(session.redirectTarget('be.preprod.example.com', bad), 'https://be.preprod.example.com/', String(bad));
  }
});

test('shared mode: parent-domain cookie, single ACS host, absolute relay', () => {
  shared();
  assert.equal(session.cookieAttributes(), 'Path=/; Secure; HttpOnly; SameSite=Lax; Domain=.preprod.example.com');
  assert.match(session.clearedCookie(), /^sso_auth=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; .*; Domain=\.preprod\.example\.com$/);
  assert.equal(session.acsHost('nl.preprod.example.com'), 'sso.preprod.example.com');
  assert.equal(session.relayStateFor('nl.preprod.example.com', '/nl/c?q=1'), 'https://nl.preprod.example.com/nl/c?q=1');
  assert.equal(session.relayStateFor('nl.preprod.example.com', '//evil.example'), 'https://nl.preprod.example.com/');
});

test('shared mode: the ACS sends the user back to any host under the cookie domain', () => {
  shared();
  for (const target of ['https://nl.preprod.example.com/nl/c?q=1', 'https://preprod.example.com/', 'https://a.b.preprod.example.com/x']) {
    assert.equal(session.redirectTarget('sso.preprod.example.com', target), target);
  }
});

test('shared mode: and nowhere else', () => {
  shared();
  for (const bad of [
    'https://evil.example/',
    'https://preprod.example.com.evil.example/',
    'https://evilpreprod.example.com/',
    'http://nl.preprod.example.com/',
    'https://user@nl.preprod.example.com/',
    'https://nl.preprod.example.com:8443/',
    'javascript:alert(1)',
    '/relative/path',
    undefined,
  ]) {
    assert.equal(session.redirectTarget('sso.preprod.example.com', bad), 'https://sso.preprod.example.com/', String(bad));
  }
});

test('every value of a cookie name is read', () => {
  const cookies = [{ key: 'Cookie', value: 'sso_auth=stale; other=1' }, { key: 'Cookie', value: 'sso_auth=fresh' }];
  assert.deepEqual(readCookieValues(cookies, 'sso_auth'), ['stale', 'fresh']);
  assert.deepEqual(readCookieValues(undefined, 'sso_auth'), []);
});

console.log(`\n${passed} checks passed`);
