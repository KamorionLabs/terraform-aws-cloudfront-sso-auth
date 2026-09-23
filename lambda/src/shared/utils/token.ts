import { createHmac } from 'node:crypto';
import { secrets } from '../config';

// Shared with functions/sso-check.js, which verifies the same token at the
// edge: v1.<expiry epoch seconds>.<hex utf-8 email>.<hex HMAC-SHA256>, the MAC
// covering "<audience>|v1.<expiry>.<email hex>".
const VERSION = 'v1';
const HEX = /^(?:[0-9a-f]{2})*$/;

export interface SessionDetails {
  expiresAt: number;
  userEmail: string;
}

function mac(body: string): string {
  return createHmac('sha256', secrets.hmacKey).update(`${secrets.audience}|${body}`).digest('hex');
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function signToken(userEmail: string, expiresAt: number): string {
  const body = `${VERSION}.${Math.floor(expiresAt)}.${Buffer.from(userEmail, 'utf8').toString('hex')}`;
  return `${body}.${mac(body)}`;
}

export function verifyToken(token: string | undefined): SessionDetails | null {
  if (!token || !secrets.hmacKey) {
    return null;
  }
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION || !/^[0-9]+$/.test(parts[1]) || !HEX.test(parts[2])) {
    return null;
  }
  const expiresAt = Number(parts[1]);
  if (expiresAt <= Math.floor(Date.now() / 1000)) {
    return null;
  }
  if (!safeEqual(mac(`${parts[0]}.${parts[1]}.${parts[2]}`), parts[3])) {
    return null;
  }
  return { expiresAt, userEmail: Buffer.from(parts[2], 'hex').toString('utf8') };
}

export function isValidAudience(audience: string | undefined): boolean {
  return audience === secrets.audience;
}
