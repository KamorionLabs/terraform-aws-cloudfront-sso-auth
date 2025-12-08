import type { CloudFrontRequestHandler, CloudFrontRequestResult } from 'aws-lambda';

import { ServiceProvider as serviceProvider } from 'samlify';
import { spMetadata } from '../shared/config';
import { getDomain } from '../shared/utils/cloudfront';

const invalidRequest: CloudFrontRequestResult = {
  status: '400',
  statusDescription: 'Invalid Request',
  body: 'Invalid Request',
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
 * Metadata Lambda@Edge Handler
 * Returns the SAML Service Provider metadata.xml
 * This is used by Identity Center to configure the SAML application.
 */
export const handler: CloudFrontRequestHandler = (event, context, callback) => {
  try {
    const domain = getDomain(event.Records[0].cf.request.headers);
    if (!domain) {
      callback(null, invalidRequest);
      return;
    }

    const sp = serviceProvider({
      metadata: spMetadata(domain),
    });

    const response: CloudFrontRequestResult = {
      status: '200',
      statusDescription: 'OK',
      headers: {
        'content-type': [
          {
            key: 'Content-Type',
            value: 'application/xml',
          },
        ],
        'cache-control': [
          {
            key: 'Cache-Control',
            value: 'max-age=86400', // Cache for 1 day
          },
        ],
      },
      body: sp.getMetadata(),
    };

    callback(null, response);
  } catch (error) {
    console.error('Metadata handler error:', error);
    callback(null, invalidRequest);
  }
};
