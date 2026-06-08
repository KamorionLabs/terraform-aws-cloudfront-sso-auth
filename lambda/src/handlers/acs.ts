import type {
  CloudFrontRequest,
  CloudFrontRequestHandler,
  CloudFrontRequestResult,
} from 'aws-lambda';

import {
  ServiceProvider as serviceProvider,
  IdentityProvider as identityProvider,
  setSchemaValidator,
} from 'samlify';
import { parse as parseQueryString } from 'node:querystring';
import { spMetadata, idpMetadata, config, secrets } from '../shared/config';
import { encrypt, isValidAudience } from '../shared/utils/crypt';
import { getDomain } from '../shared/utils/cloudfront';

const idp = identityProvider({
  metadata: idpMetadata,
});

const invalidRequest: CloudFrontRequestResult = {
  status: '400',
  statusDescription: 'Invalid SAML Payload',
  body: 'Invalid SAML Payload',
  bodyEncoding: 'text',
  headers: {
    'cache-control': [
      {
        key: 'Cache-Control',
        value: 'no-cache, no-store, must-revalidate',
      },
    ],
  },
};

/**
 * Extract request body as string
 */
function getBody(body: CloudFrontRequest['body']): string | undefined {
  if (!body) {
    return undefined;
  }
  if (body.encoding === 'base64') {
    return Buffer.from(body.data, 'base64').toString('utf-8');
  }
  return body.data;
}

/**
 * ACS (Assertion Consumer Service) Lambda@Edge Handler
 * Handles SAML assertion callback from Identity Center.
 * Validates the assertion and sets authentication cookie.
 */
export const handler: CloudFrontRequestHandler = (event, context, callback) => {
  console.log('ACS handler invoked');
  const method = event.Records[0].cf.request.method || '';
  console.log('Method:', method);

  // ACS endpoint only accepts POST
  if (method.toLowerCase() !== 'post') {
    console.error('Invalid method, expected POST, got:', method);
    callback(null, invalidRequest);
    return;
  }

  const payload = getBody(event.Records[0].cf.request.body);
  if (!payload) {
    console.error('No payload in request body');
    callback(null, invalidRequest);
    return;
  }
  console.log('Payload length:', payload.length);

  const domain = getDomain(event.Records[0].cf.request.headers);
  if (!domain) {
    console.error('Could not extract domain from headers');
    callback(null, invalidRequest);
    return;
  }
  console.log('Domain:', domain);

  try {
    const spMeta = spMetadata(domain);
    console.log('SP Metadata generated for domain:', domain);

    const sp = serviceProvider({
      metadata: spMeta,
      privateKey: secrets.signingPrivateKey,
      authnRequestsSigned: true,
    });
    console.log('ServiceProvider created');

    // Skip XML schema validation (not needed for our use case)
    setSchemaValidator({
      validate: (_response: string) => {
        return Promise.resolve('skipped');
      },
    });

    const payloadAsObject = parseQueryString(payload);
    console.log('Payload keys:', Object.keys(payloadAsObject));
    console.log('SAMLResponse present:', !!payloadAsObject.SAMLResponse);
    console.log('RelayState:', payloadAsObject.RelayState);

    sp.parseLoginResponse(idp, 'post', { body: payloadAsObject })
      .then((parseResult) => {
        console.log('SAML parse successful');
        console.log('Audience:', parseResult.extract.audience);
        console.log('Conditions:', JSON.stringify(parseResult.extract.conditions));
        console.log('NameID:', parseResult.extract.nameID);

        // Assertion freshness: the SAML Conditions/notOnOrAfter window is short
        // (minutes) and is only used here to reject stale/replayed assertions at
        // login time.
        const assertionExpiry = new Date(parseResult.extract.conditions.notOnOrAfter).getTime();
        const now = new Date().getTime();
        console.log('Assertion expiry:', assertionExpiry, 'Now:', now, 'Fresh:', assertionExpiry > now);

        // Session lifetime is decoupled from the (short) assertion window so that
        // long-running flows (e.g. multi-step booking tunnels) are not re-prompted
        // for SSO mid-session.
        const sessionExpiry = now + config.sessionDurationSeconds * 1000;
        console.log('Session expiry:', sessionExpiry, 'Duration (s):', config.sessionDurationSeconds);

        const audienceValid = isValidAudience(parseResult.extract.audience);
        console.log('Audience valid:', audienceValid);

        // Extract user email from SAML nameID
        const userEmail = parseResult.extract.nameID || '';
        console.log('User email extracted:', userEmail);

        if (audienceValid && assertionExpiry > now) {
          // Get original URL from RelayState
          const relayState = (payloadAsObject.RelayState as string) || '/';
          console.log('RelayState for redirect:', relayState);

          // Create encrypted authentication token (includes user email). The
          // token is valid for the whole session, not just the assertion window.
          const encryptedToken = encrypt({
            audience: parseResult.extract.audience,
            validUntil: sessionExpiry,
            domain,
            userEmail,
          });
          console.log('Encrypted token created with user email');

          // Cookie expiry matches the session lifetime.
          const cookieExpiry = new Date(sessionExpiry).toUTCString();

          const response: CloudFrontRequestResult = {
            status: '302',
            statusDescription: 'Found',
            headers: {
              'set-cookie': [
                {
                  key: 'Set-Cookie',
                  value: `${config.cookieName}=${encryptedToken}; Expires=${cookieExpiry}; Path=/; Secure; HttpOnly; SameSite=Lax`,
                },
              ],
              location: [
                {
                  key: 'Location',
                  value: `https://${domain}${relayState}`,
                },
              ],
              'cache-control': [
                {
                  key: 'Cache-Control',
                  value: 'no-cache, no-store, must-revalidate',
                },
              ],
            },
          };
          console.log('Redirecting to:', `https://${domain}${relayState}`);
          callback(null, response);
        } else {
          console.error('Invalid audience or expired assertion. Audience valid:', audienceValid, 'Assertion fresh:', assertionExpiry > now);
          callback(null, invalidRequest);
        }
      })
      .catch((error) => {
        console.error('SAML parsing error:', error);
        console.error('Error message:', error.message);
        console.error('Error stack:', error.stack);
        callback(null, invalidRequest);
      });
  } catch (error) {
    console.error('ACS handler error:', error);
    callback(null, invalidRequest);
  }
};
