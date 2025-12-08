import type {
  CloudFrontRequestHandler,
  CloudFrontRequestResult,
} from 'aws-lambda';

import { ServiceProvider as serviceProvider, IdentityProvider as identityProvider } from 'samlify';
import { spMetadata, idpMetadata, config } from '../shared/config';
import { isValidToken } from '../shared/utils/crypt';
import { getDomain, parseCookies } from '../shared/utils/cloudfront';

const idp = identityProvider({
  metadata: idpMetadata,
});

const invalidRequest: CloudFrontRequestResult = {
  status: '403',
  statusDescription: 'Access Forbidden',
  body: 'Access Forbidden',
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
 * Protect Lambda@Edge Handler
 * Validates SSO authentication cookie on each request.
 * Redirects to Identity Center login if not authenticated.
 */
export const handler: CloudFrontRequestHandler = (event, context, callback) => {
  try {
    const request = event.Records[0].cf.request;
    const headers = request.headers;
    const uri = request.uri;

    // Skip auth for SAML endpoints
    if (uri === config.acsPath || uri === config.metadataPath) {
      callback(null, request);
      return;
    }

    const domain = getDomain(headers);
    if (!domain) {
      callback(null, invalidRequest);
      return;
    }

    const sp = serviceProvider({
      metadata: spMetadata(domain),
      // Don't sign AuthnRequest - Identity Center works without it
      authnRequestsSigned: false,
    });

    let accessGranted = false;

    // Check for valid authentication cookie
    if (headers.cookie) {
      const cookies = parseCookies(headers.cookie);
      if (isValidToken(cookies[config.cookieName])) {
        accessGranted = true;
      }
    }

    if (!accessGranted) {
      // Redirect to Identity Center login
      sp.entitySetting.relayState = uri;
      const { context: loginRequestUrl } = sp.createLoginRequest(idp, 'redirect');

      const response: CloudFrontRequestResult = {
        status: '307',
        statusDescription: 'Temporary Redirect',
        headers: {
          location: [
            {
              key: 'Location',
              value: loginRequestUrl,
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
      return;
    }

    // Access granted - forward request to origin
    callback(null, request);
  } catch (error) {
    console.error('Protect handler error:', error);
    callback(null, invalidRequest);
  }
};
