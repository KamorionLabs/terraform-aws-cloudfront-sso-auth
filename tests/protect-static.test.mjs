/**
 * Static sub-resource passthrough of the protect Lambda@Edge
 * (lambda/src/handlers/protect.ts): decided on the request line only, never
 * on a client-set header such as Sec-Fetch-Dest.
 *
 *     cd lambda && npm run build && cd .. && node tests/protect-static.test.mjs
 */

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const { isStaticSubresource } = require(path.join(root, 'lambda/dist/handlers/protect.js'));

const cases = [
  ['GET', '/logo.png', true],
  ['HEAD', '/css/site.css', true],
  ['GET', '/fonts/a.woff2', true],
  ['GET', '/admin/console', false],
  ['GET', '/solr/admin/cores', false],
  ['GET', '/app.js', false],
  ['GET', '/data.json', false],
  ['POST', '/upload.png', false],
  ['PUT', '/logo.png', false],
  ['GET', '/admin/console;x.css', false],
  ['GET', '/app;jsessionid=1/logo.png', false],
];

for (const [method, uri, expected] of cases) {
  assert.equal(isStaticSubresource(method, uri), expected, `${method} ${uri}`);
}

console.log(`${cases.length} checks passed`);
process.exit(0);
