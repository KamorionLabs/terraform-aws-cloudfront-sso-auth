import { config } from '../config';
import { safeRelay } from './relay';

/**
 * Shared session mode: with a cookie domain (e.g. ".preprod.example.com") the
 * session cookie covers every host under it, and with an auth host the SAML
 * round-trip goes through that single host, so the Identity Center application
 * needs one ACS URL whatever the number of protected hosts. Both empty keeps
 * the per-host behaviour (host-only cookie, ACS on the requesting host).
 */

/** Attributes of the session cookie (Set-Cookie), Domain included when shared. */
export function cookieAttributes(): string {
  const domain = config.cookieDomain ? `; Domain=${config.cookieDomain}` : '';
  return `Path=/; Secure; HttpOnly; SameSite=Lax${domain}`;
}

/** Set-Cookie value clearing the session cookie, on the same Domain it was set. */
export function clearedCookie(): string {
  return `${config.cookieName}=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; ${cookieAttributes()}`;
}

/** Host whose /saml/acs receives the assertion for a request on requestHost. */
export function acsHost(requestHost: string): string {
  return config.authHost || requestHost;
}

/**
 * RelayState for a login started on requestHost: an absolute URL when the ACS
 * sits on another host (it must send the user back), the path otherwise.
 */
export function relayStateFor(requestHost: string, pathAndQuery: string): string {
  const path = safeRelay(pathAndQuery);
  return config.authHost ? `https://${requestHost}${path}` : path;
}

/** Whether a host is under the shared cookie domain. */
export function isSessionHost(host: string): boolean {
  const domain = config.cookieDomain.toLowerCase();
  const name = host.toLowerCase();
  return domain !== '' && (name === domain.slice(1) || name.endsWith(domain));
}

/**
 * Where the ACS sends the user back. Only a same-host path, or with an auth
 * host an https URL on a host under the cookie domain, is followed: anything
 * else lands on the ACS host's root, so the ACS is never an open redirect.
 */
export function redirectTarget(acsRequestHost: string, relayState: unknown): string {
  const fallback = `https://${acsRequestHost}/`;

  if (!config.authHost) {
    return `https://${acsRequestHost}${safeRelay(relayState)}`;
  }

  if (typeof relayState !== 'string') {
    return fallback;
  }

  try {
    const url = new URL(relayState);
    if (url.protocol !== 'https:' || url.username || url.password || url.port || !isSessionHost(url.hostname)) {
      return fallback;
    }
    return url.href;
  } catch {
    return fallback;
  }
}
