import type { CloudFrontHeaders } from 'aws-lambda';

/**
 * Extract domain from CloudFront request headers
 */
export function getDomain(headers: CloudFrontHeaders): string | undefined {
  if (headers.host && headers.host[0]) {
    return headers.host[0].value;
  }
  return undefined;
}

/**
 * Parse cookies from CloudFront headers
 */
export function parseCookies(cookies: CloudFrontHeaders['cookie']): Record<string, string> {
  const parsedCookies: Record<string, string> = {};
  if (!cookies) {
    return parsedCookies;
  }
  for (const cookie of cookies) {
    cookie.value.split(';').forEach((el) => {
      if (el) {
        const parts = el.split('=');
        if (parts.length >= 2) {
          parsedCookies[parts[0].trim()] = parts.slice(1).join('=').trim();
        }
      }
    });
  }
  return parsedCookies;
}

/**
 * Every value of a cookie name. A parent-domain cookie and a host-only one can
 * share a name, and the browser sends both: callers check them all.
 */
export function readCookieValues(cookies: CloudFrontHeaders['cookie'], name: string): string[] {
  const values: string[] = [];
  for (const cookie of cookies || []) {
    for (const pair of cookie.value.split(';')) {
      const index = pair.indexOf('=');
      if (index > 0 && pair.slice(0, index).trim() === name) {
        values.push(pair.slice(index + 1).trim());
      }
    }
  }
  return values;
}
