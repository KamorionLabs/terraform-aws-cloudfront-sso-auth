import { createCipheriv, createDecipheriv } from 'node:crypto';
import { secrets } from '../config';

const algorithm = 'aes-256-cbc';

export interface AccessDetails {
  audience: string;
  validUntil: number;
  domain: string;
}

/**
 * Encrypt access details for cookie storage
 */
export function encrypt(message: AccessDetails): string {
  const cipher = createCipheriv(
    algorithm,
    Buffer.from(secrets.privateKey),
    Buffer.from(secrets.initVector)
  );
  let encryptedData = cipher.update(JSON.stringify(message), 'utf8', 'hex');
  encryptedData += cipher.final('hex');
  return encryptedData;
}

/**
 * Decrypt access details from cookie
 */
function decrypt(message: string): AccessDetails {
  const cipher = createDecipheriv(
    algorithm,
    Buffer.from(secrets.privateKey),
    Buffer.from(secrets.initVector)
  );
  let decryptedData = cipher.update(message, 'hex', 'utf8');
  decryptedData += cipher.final('utf8');
  return JSON.parse(decryptedData);
}

/**
 * Validate authentication token from cookie
 */
export function isValidToken(token: string | undefined): boolean {
  if (!token) {
    return false;
  }
  try {
    const accessObject = decrypt(token);
    if (!accessObject.audience) {
      return false;
    }
    if (!accessObject.validUntil) {
      return false;
    }
    const now = new Date().getTime();

    return isValidAudience(accessObject.audience) && accessObject.validUntil > now;
  } catch {
    return false;
  }
}

/**
 * Validate SAML audience
 */
export function isValidAudience(audience: string | undefined): boolean {
  try {
    return audience === secrets.audience;
  } catch {
    return false;
  }
}
