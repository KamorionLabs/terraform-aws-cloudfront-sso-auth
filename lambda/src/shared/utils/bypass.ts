import type { CloudFrontHeaders } from 'aws-lambda';

/**
 * Whether the request carries one of the configured bypass headers with its
 * exact value. Header keys are lowercase in Lambda@Edge events.
 */
export function hasBypassHeader(headers: CloudFrontHeaders, bypass: Record<string, string>): boolean {
  return Object.entries(bypass).some(([name, value]) =>
    (headers[name] || []).some((header) => header.value === value),
  );
}
