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
