/**
 * Only same-site, path-absolute targets are accepted as RelayState, so the
 * login endpoint cannot be turned into an open redirect.
 */
export function safeRelay(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.includes('\\') ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    return '/';
  }
  return value;
}
