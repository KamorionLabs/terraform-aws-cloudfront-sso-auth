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
import { spMetadata, idpMetadata, config } from '../shared/config';
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
  const method = event.Records[0].cf.request.method || '';

  // ACS endpoint only accepts POST
  if (method.toLowerCase() !== 'post') {
    callback(null, invalidRequest);
    return;
  }

  const payload = getBody(event.Records[0].cf.request.body);
  if (!payload) {
    callback(null, invalidRequest);
    return;
  }

  const domain = getDomain(event.Records[0].cf.request.headers);
  if (!domain) {
    callback(null, invalidRequest);
    return;
  }

  try {
    const sp = serviceProvider({
      metadata: spMetadata(domain),
    });

    // Skip XML schema validation (not needed for our use case)
    setSchemaValidator({
      validate: (_response: string) => {
        return Promise.resolve('skipped');
      },
    });

    const payloadAsObject = parseQueryString(payload);

    sp.parseLoginResponse(idp, 'post', { body: payloadAsObject })
      .then((parseResult) => {
        const expiry = new Date(parseResult.extract.conditions.notOnOrAfter).getTime();
        const now = new Date().getTime();

        if (isValidAudience(parseResult.extract.audience) && expiry > now) {
          // Get original URL from RelayState
          const relayState = (payloadAsObject.RelayState as string) || '/';

          // Create encrypted authentication token
          const encryptedToken = encrypt({
            audience: parseResult.extract.audience,
            validUntil: expiry,
            domain,
          });

          // Build cookie expiry date
          const cookieExpiry = new Date(parseResult.extract.conditions.notOnOrAfter).toUTCString();

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
          callback(null, response);
        } else {
          console.error('Invalid audience or expired assertion');
          callback(null, invalidRequest);
        }
      })
      .catch((error) => {
        console.error('SAML parsing error:', error);
        callback(null, invalidRequest);
      });
  } catch (error) {
    console.error('ACS handler error:', error);
    callback(null, invalidRequest);
  }
};
