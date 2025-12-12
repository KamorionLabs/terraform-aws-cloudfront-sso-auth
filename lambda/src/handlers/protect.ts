import type {
  CloudFrontRequestHandler,
  CloudFrontRequestResult,
} from 'aws-lambda';

import { ServiceProvider as serviceProvider, IdentityProvider as identityProvider } from 'samlify';
import { spMetadata, idpMetadata, config, secrets, shouldSignAuthnRequests } from '../shared/config';
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
  console.log('Protect handler invoked - v0.1.4');
  try {
    const request = event.Records[0].cf.request;
    const headers = request.headers;
    const uri = request.uri;
    console.log('URI:', uri);
    console.log('Headers host:', headers.host?.[0]?.value);

    // Skip auth for SAML endpoints
    if (uri === config.acsPath || uri === config.metadataPath) {
      console.log('Skipping auth for SAML endpoint');
      callback(null, request);
      return;
    }

    const domain = getDomain(headers);
    console.log('Domain:', domain);
    if (!domain) {
      console.error('Could not extract domain from headers');
      callback(null, invalidRequest);
      return;
    }

    const signRequests = shouldSignAuthnRequests();
    console.log('Creating SP with authnRequestsSigned:', signRequests);
    const sp = serviceProvider({
      metadata: spMetadata(domain),
      privateKey: signRequests ? secrets.signingPrivateKey : undefined,
      authnRequestsSigned: signRequests,
    });
    console.log('SP created successfully');

    let accessGranted = false;

    // Check for valid authentication cookie
    if (headers.cookie) {
      const cookies = parseCookies(headers.cookie);
      console.log('Cookie names:', Object.keys(cookies));
      if (isValidToken(cookies[config.cookieName])) {
        console.log('Valid token found');
        accessGranted = true;
      } else {
        console.log('No valid token in cookies');
      }
    } else {
      console.log('No cookies in request');
    }

    if (!accessGranted) {
      console.log('Access not granted, creating login request');
      // Redirect to Identity Center login
      sp.entitySetting.relayState = uri;
      const { context: loginRequestUrl } = sp.createLoginRequest(idp, 'redirect');
      console.log('Login request URL created:', loginRequestUrl?.substring(0, 100));

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
      console.log('Redirecting to Identity Center');
      callback(null, response);
      return;
    }

    // Access granted - forward request to origin
    console.log('Access granted, forwarding to origin');
    callback(null, request);
  } catch (error) {
    console.error('Protect handler error:', error);
    console.error('Error message:', (error as Error).message);
    console.error('Error stack:', (error as Error).stack);
    callback(null, invalidRequest);
  }
};
