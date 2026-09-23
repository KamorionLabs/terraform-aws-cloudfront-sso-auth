import type {
  CloudFrontRequestHandler,
  CloudFrontRequestResult,
} from 'aws-lambda';

import { ServiceProvider as serviceProvider, IdentityProvider as identityProvider } from 'samlify';
import { parse as parseQueryString } from 'node:querystring';
import { spMetadata, idpMetadata, secrets, shouldSignAuthnRequests } from '../shared/config';
import { getDomain } from '../shared/utils/cloudfront';
import { safeRelay } from '../shared/utils/relay';

const idp = identityProvider({
  metadata: idpMetadata,
});

const noStore = [{ key: 'Cache-Control', value: 'no-cache, no-store, must-revalidate' }];

const invalidRequest: CloudFrontRequestResult = {
  status: '403',
  statusDescription: 'Access Forbidden',
  body: 'Access Forbidden',
  bodyEncoding: 'text',
  headers: { 'cache-control': noStore },
};

/**
 * Login Lambda@Edge Handler (viewer-request on /saml/login)
 * Entry point of the SAML flow when the session is checked by the sso-check
 * CloudFront Function: builds the AuthnRequest and redirects to Identity Center.
 */
export const handler: CloudFrontRequestHandler = (event, context, callback) => {
  try {
    const request = event.Records[0].cf.request;
    const domain = getDomain(request.headers);
    if (!domain) {
      callback(null, invalidRequest);
      return;
    }

    const relay = safeRelay(parseQueryString(request.querystring || '').relay);
    const signRequests = shouldSignAuthnRequests();
    const sp = serviceProvider({
      metadata: spMetadata(domain),
      privateKey: signRequests ? secrets.signingPrivateKey : undefined,
      authnRequestsSigned: signRequests,
    });
    sp.entitySetting.relayState = relay;
    const { context: loginRequestUrl } = sp.createLoginRequest(idp, 'redirect');

    callback(null, {
      status: '302',
      statusDescription: 'Found',
      headers: {
        location: [{ key: 'Location', value: loginRequestUrl }],
        'cache-control': noStore,
      },
    });
  } catch (error) {
    console.error('Login handler error:', (error as Error).message);
    callback(null, invalidRequest);
  }
};
