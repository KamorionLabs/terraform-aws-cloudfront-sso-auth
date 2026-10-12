import type {
  CloudFrontHeaders,
  CloudFrontRequestHandler,
  CloudFrontRequestResult,
} from 'aws-lambda';

import type * as Samlify from 'samlify';
import { spMetadata, idpMetadata, config, secrets, shouldSignAuthnRequests, bypassHeaders } from '../shared/config';
import { verifyToken } from '../shared/utils/token';
import { getDomain, readCookieValues } from '../shared/utils/cloudfront';
import { acsHost, clearedCookie, relayStateFor } from '../shared/utils/session';
import { hasBypassHeader } from '../shared/utils/bypass';

// samlify and the IdP metadata parse are only needed to build a login
// request: loaded on first use, so a cold start serving valid sessions, bypass
// headers or static assets stays light.
let saml: { samlify: typeof Samlify; idp: Samlify.IdentityProviderInstance } | undefined;

function loadSaml() {
  if (!saml) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const samlify: typeof Samlify = require('samlify');
    saml = { samlify, idp: samlify.IdentityProvider({ metadata: idpMetadata }) };
  }
  return saml;
}

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

// File extensions of passive static assets. Intentionally excludes
// .js/.json/.txt/.xml/.html so that data and markup always stay gated.
const STATIC_ASSET_EXTENSIONS =
  /\.(?:svg|ico|png|jpe?g|gif|webp|avif|bmp|woff2?|ttf|otf|eot|css|mp4|webm|ogg|mp3|wav)$/i;

/**
 * Whether a request is a static, non-navigational sub-resource that must be
 * served without an SSO redirect.
 *
 * An SSO gate must never answer an <img>, @font-face, stylesheet or media
 * request with a 307 redirect to the Identity Center HTML portal: the browser
 * cannot render the portal as the requested resource, so the asset silently
 * breaks.
 *
 * Only the request line decides, never a header: Sec-Fetch-Dest is set by the
 * client, so trusting it would let anyone through with
 * "Sec-Fetch-Dest: image" on any path. A request passes only as a GET or HEAD
 * whose path ends with a static asset extension and carries no path parameter
 * (";": Tomcat and Jetty serve "/console;x.css" as "/console").
 */
export function isStaticSubresource(method: string, uri: string): boolean {
  if (method !== 'GET' && method !== 'HEAD') {
    return false;
  }
  if (uri.includes(';')) {
    return false;
  }
  return STATIC_ASSET_EXTENSIONS.test(uri);
}

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

    // Handle logout - clear cookie and redirect to home
    if (uri === config.logoutPath) {
      console.log('Logout requested - clearing cookie');
      const logoutResponse: CloudFrontRequestResult = {
        status: '302',
        statusDescription: 'Found',
        headers: {
          location: [
            {
              key: 'Location',
              value: '/',
            },
          ],
          'set-cookie': [
            {
              key: 'Set-Cookie',
              value: clearedCookie(),
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
      callback(null, logoutResponse);
      return;
    }

    // Never trust an identity header sent by the viewer.
    delete request.headers['x-sso-user-email'];

    // Let through requests carrying a configured bypass header (e.g. the WAF
    // trusted marker): they are already authorised upstream, no session needed.
    if (hasBypassHeader(headers, bypassHeaders)) {
      console.log('Skipping auth for bypass header');
      callback(null, request);
      return;
    }

    // Skip auth for passive static sub-resources so they are never redirected
    // to the HTML login portal. These are public assets (already public in
    // production) with no sensitive data; navigations and XHR/API fetches stay
    // gated. Done before the SAML SP is built to also save work on every asset.
    if (isStaticSubresource(request.method, uri)) {
      console.log('Skipping auth for static sub-resource:', uri);
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


    let accessGranted = false;
    let userEmail: string | undefined;

    // Check for valid authentication cookie (every value of the name: a
    // parent-domain cookie and a host-only one can coexist)
    if (headers.cookie) {
      const tokenDetails = readCookieValues(headers.cookie, config.cookieName)
        .map((token) => verifyToken(token))
        .find((details) => details !== null);
      if (tokenDetails) {
        console.log('Valid token found');
        accessGranted = true;
        userEmail = tokenDetails.userEmail;
        console.log('User email from token:', userEmail);
      } else {
        console.log('No valid token in cookies');
      }
    } else {
      console.log('No cookies in request');
    }

    if (!accessGranted) {
      console.log('Access not granted, creating login request');
      // Preserve querystring across the SAML round-trip: in Lambda@Edge events the
      // querystring lives on request.querystring (raw, no leading '?') separately
      // from request.uri, so it must be concatenated explicitly into RelayState
      // for ACS to redirect back to the original path with its params intact.
      const querystring = request.querystring;
      const relayStateUri = relayStateFor(domain, querystring ? `${uri}?${querystring}` : uri);
      console.log('RelayState:', relayStateUri);
      const { samlify, idp } = loadSaml();
      const signRequests = shouldSignAuthnRequests();
      const sp = samlify.ServiceProvider({
        metadata: spMetadata(acsHost(domain)),
        privateKey: signRequests ? secrets.signingPrivateKey : undefined,
        authnRequestsSigned: signRequests,
      });
      sp.entitySetting.relayState = relayStateUri;
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

    // Access granted - forward request to origin with user identity header
    console.log('Access granted, forwarding to origin');

    // Add user email header if available (for audit/attribution)
    if (userEmail) {
      request.headers['x-sso-user-email'] = [{
        key: 'X-SSO-User-Email',
        value: userEmail,
      }];
      console.log('Added x-sso-user-email header:', userEmail);
    }

    callback(null, request);
  } catch (error) {
    console.error('Protect handler error:', error);
    console.error('Error message:', (error as Error).message);
    console.error('Error stack:', (error as Error).stack);
    callback(null, invalidRequest);
  }
};
