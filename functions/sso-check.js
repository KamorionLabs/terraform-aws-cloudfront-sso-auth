// CloudFront Function library (cloudfront-js-2.0, viewer-request).
//
// Defines `ssoCheck(event)`: returns a response to send instead of the request
// (login redirect, logout), or undefined when the request may continue.
// Needs `crypto` in scope: the module prepends `import crypto from 'crypto';`.
//
// Token, shared with lambda/src/shared/utils/token.ts:
//   v1.<expiry epoch seconds>.<hex utf-8 email>.<hex HMAC-SHA256>
// the MAC covering "<audience>|v1.<expiry>.<email hex>".
//
// Kept small on purpose: it is composed with other functions under the 10 KB
// CloudFront Functions limit. Terraform blanks full-line comments and strips
// indentation, and replaces each /*__NAME__*/ sentinel together with its
// fallback. The fallbacks fail closed: an empty key accepts no token.
var ssoCheck = (function () {
    var KEY = /*__SSO_HMAC_KEY__*/'';
    var AUD = /*__SSO_AUDIENCE__*/'';
    var COOKIE = /*__SSO_COOKIE_NAME__*/'sso_auth';
    var LOGIN = /*__SSO_LOGIN_PATH__*/'/saml/login';
    var LOGOUT = /*__SSO_LOGOUT_PATH__*/'/saml/logout';
    var DOMAIN = /*__SSO_COOKIE_DOMAIN__*/'';
    var USER = 'x-sso-user-email';
    var ASSET = /\.(?:svg|ico|png|jpe?g|gif|webp|avif|bmp|woff2?|ttf|otf|eot|css|mp4|webm|ogg|mp3|wav)$/i;
    var HEX = /^(?:[0-9a-f]{2})*$/;

    function redirect(location, cookies) {
        var r = { statusCode: 302, statusDescription: 'Found', headers: { location: { value: location }, 'cache-control': { value: 'no-cache, no-store, must-revalidate' } } };
        if (cookies) {
            r.cookies = cookies;
        }
        return r;
    }

    // Returns the session email ('' if none) or null when the token is invalid.
    function verify(t) {
        var p = t ? t.split('.') : [];
        if (!KEY || p.length !== 4 || p[0] !== 'v1' || !/^[0-9]+$/.test(p[1]) || !HEX.test(p[2]) || Number(p[1]) <= Date.now() / 1000) {
            return null;
        }
        var mac = crypto.createHmac('sha256', KEY).update(AUD + '|' + p[0] + '.' + p[1] + '.' + p[2]).digest('hex');
        var diff = mac.length ^ p[3].length;
        for (var i = 0; i < mac.length; i++) {
            diff |= mac.charCodeAt(i) ^ p[3].charCodeAt(i);
        }
        if (diff !== 0) {
            return null;
        }
        try {
            return decodeURIComponent(p[2].replace(/(..)/g, '%$1'));
        } catch (e) {
            return '';
        }
    }

    return function (event) {
        var req = event.request;
        var h = req.headers;
        // Never trust an identity header sent by the viewer.
        delete h[USER];

        if (req.uri === LOGOUT) {
            var c = {};
            c[COOKIE] = { value: '', attributes: 'Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax' + (DOMAIN ? '; Domain=' + DOMAIN : '') };
            return redirect('/', c);
        }

        // Passive sub-resources (img, font, style, media) are never sent to the
        // HTML login portal. Documents, frames and fetch/XHR stay gated.
        var dest = h['sec-fetch-dest'] ? h['sec-fetch-dest'].value : '';
        if (dest ? ['document', 'iframe', 'frame', 'empty'].indexOf(dest) === -1 : ASSET.test(req.uri)) {
            return undefined;
        }

        // Every value of the name: a parent-domain cookie and a host-only one
        // can coexist.
        var ck = req.cookies && req.cookies[COOKIE];
        var tokens = ck ? (ck.multiValue || [ck]) : [];
        var email = null;
        for (var t = 0; t < tokens.length && email === null; t++) {
            email = verify(tokens[t].value ? String(tokens[t].value) : '');
        }
        if (email !== null) {
            if (email) {
                h[USER] = { value: email };
            }
            return undefined;
        }

        var q = [];
        var qs = req.querystring || {};
        for (var k in qs) {
            var vals = qs[k].multiValue || [qs[k]];
            for (var j = 0; j < vals.length; j++) {
                q.push(vals[j].value ? k + '=' + vals[j].value : k);
            }
        }
        return redirect(LOGIN + '?relay=' + encodeURIComponent(req.uri + (q.length ? '?' + q.join('&') : '')));
    };
})();
