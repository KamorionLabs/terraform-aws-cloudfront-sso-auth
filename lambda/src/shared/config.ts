/**
 * SAML Configuration
 * Values are injected at build time by scripts/inject-config.js
 * Lambda@Edge cannot access environment variables or Secrets Manager at runtime
 */

export const secrets = {
  // SAML audience (EntityID) - must match Identity Center application
  audience: 'PLACEHOLDER_AUDIENCE',

  // AES encryption initialization vector (16 bytes)
  initVector: 'PLACEHOLDER_IV__',

  // AES encryption private key (32 bytes)
  privateKey: 'PLACEHOLDER_PRIVATE_KEY_32CHARS_',

  // Identity Provider SAML metadata XML
  idpMetadata: 'PLACEHOLDER_IDP_METADATA',

  // SAML signing certificate (PEM format)
  signingCert: 'PLACEHOLDER_SIGNING_CERT',

  // SAML signing private key (PEM format)
  signingPrivateKey: 'PLACEHOLDER_SIGNING_PRIVATE_KEY',
};

export const config = {
  acsPath: '/saml/acs',
  metadataPath: '/saml/metadata.xml',
  cookieName: 'sso_auth',
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
 * Build the Service Provider metadata.xml
 */
export function spMetadata(domain: string): string {
  const certBody = extractCertBody(secrets.signingCert);
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="${secrets.audience}">
    <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
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
