/**
 * SAML Configuration
 * Values are injected at build time by scripts/inject-config.js
 * Lambda@Edge cannot access environment variables or Secrets Manager at runtime
 */

export const secrets = {
  // SAML audience (EntityID) - must match Identity Center application
  audience: 'PLACEHOLDER_AUDIENCE',

  // HMAC-SHA256 key signing the session cookie (shared with the sso-check
  // CloudFront Function)
  hmacKey: 'PLACEHOLDER_HMAC_KEY',

  // Identity Provider SAML metadata XML
  idpMetadata: 'PLACEHOLDER_IDP_METADATA',

  // SAML signing certificate (PEM format)
  signingCert: 'PLACEHOLDER_SIGNING_CERT',

  // SAML signing private key (PEM format)
  signingPrivateKey: 'PLACEHOLDER_SIGNING_PRIVATE_KEY',

  // Whether to sign SAML AuthnRequests (must match IDP WantAuthnRequestsSigned)
  signAuthnRequests: 'PLACEHOLDER_SIGN_AUTHN_REQUESTS',

  // JSON object { header name: value } letting a request through the protect
  // Lambda without a session (e.g. a WAF-inserted trusted marker)
  bypassHeaders: 'PLACEHOLDER_BYPASS_HEADERS',
};

export const config = {
  acsPath: '/saml/acs',
  metadataPath: '/saml/metadata.xml',
  loginPath: '/saml/login',
  logoutPath: '/saml/logout',
  cookieName: 'sso_auth',

  // Shared session mode, injected at build time (empty = per-host): cookie
  // domain covering every protected host (e.g. '.preprod.example.com') and the
  // single host whose /saml/acs receives the assertion.
  cookieDomain: 'PLACEHOLDER_COOKIE_DOMAIN',
  authHost: 'PLACEHOLDER_AUTH_HOST',

  // Session cookie lifetime in seconds, injected at build time by
  // scripts/inject-config.js. Decoupled from the SAML assertion's short
  // Conditions/notOnOrAfter window so long flows (e.g. multi-step booking
  // tunnels) are not re-prompted mid-session. Falls back to 8h if missing.
  sessionDurationSeconds: Number('PLACEHOLDER_SESSION_DURATION_SECONDS') || 28800,
};

/**
 * Extract the certificate body from PEM format (remove headers and newlines)
 */
function extractCertBody(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\n/g, '')
    .trim();
}

/**
 * Check if AuthnRequests should be signed
 */
export function shouldSignAuthnRequests(): boolean {
  return secrets.signAuthnRequests === 'true';
}

export function spMetadata(domain: string): string {
  const certBody = extractCertBody(secrets.signingCert);
  const signRequests = shouldSignAuthnRequests();
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="${secrets.audience}">
    <md:SPSSODescriptor AuthnRequestsSigned="${signRequests}" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>${certBody}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://${domain}${config.acsPath}"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>`;
}

export const idpMetadata = secrets.idpMetadata;

// Fails closed: an unparsable value grants no bypass.
function parseBypassHeaders(raw: string): Record<string, string> {
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, string>) : {};
  } catch {
    return {};
  }
}

export const bypassHeaders = parseBypassHeaders(secrets.bypassHeaders);
