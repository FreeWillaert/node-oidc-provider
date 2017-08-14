'use strict';

const _ = require('lodash');
const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

module.exports = function getAccessToken(provider) {
  const BaseToken = provider.BaseToken;
  return class AccessToken extends BaseToken {

    sign(client, options) {
      const opts = options || /* istanbul ignore next */ {};
      // TODO: Is it required/allowed to support access tokens that don't expire?
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;
      opts.noExp = 'noExp' in opts ? opts.noExp : null;

      const expiresIn = (() => {
        if (opts.expiresAt) return opts.expiresAt - epochTime();
        return (this.expiresIn || this.constructor.expiresIn);

      })();

      // Use same signing alg as for id token.
      const alg = client.idTokenSignedResponseAlg;

      // Retrieve any additional claims that need to be passed to the resource server.
      // Note: these claims will also be visible to the client. If that is undesired, use introspection.
      const getResourceClaims = instance(provider).configuration('getResourceClaims');
      const resourceClaimNames = getResourceClaims ? getResourceClaims(options.params.audience) : [];
      const resourceClaims = _.pick(opts.availableClaims, resourceClaimNames);

      // audience request parameter as defined in https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-2.1
      // This must be allowed through config extraParams.
      let requestedTargets = null; // Note: in general, these targets should already be 'consented'
      if (opts.params && opts.params.audience) {
        requestedTargets = opts.params.audience.split(' ');
      }

      const requestedScopes = this.scope.split(' ');

      const payload = _.merge({
        // Note: sub, iss, aud, exp, iat are added via jwt helper/node-jose.
        // TODO: nbf ? (also: can these be passed to node-jose)

        // scp as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.2
        scp: requestedScopes,

        // cid as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.3
        cid: client.clientId,

        jti: this.jti //TODO: For revocation/introspection/... adapt the token lookup (verify jwt signature and use jti from jwt)
      }, resourceClaims);

      return (() => {
        if (alg) {
          const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
          const key = keystore && keystore.get({ alg });

          return JWT.sign(payload, key, alg, {
            audience: requestedTargets,
            expiresIn: opts.noExp ? undefined : expiresIn,
            issuer: provider.issuer,
            subject: this.accountId
          });
        }

        return Promise.resolve(JSON.stringify(payload));
      })();

      // TODO: Do we want/need to support access token encryption?
      const encryption = {
        alg: client.idTokenEncryptedResponseAlg,
        enc: client.idTokenEncryptedResponseEnc,
      };

      if (encryption.enc) {
        return signedTokenPromise.then((signed) => {
          if (client.keystore.stale()) return client.keystore.refresh().then(() => signed);
          return signed;
        })
          .then((signed) => {
            const encryptionKey = client.keystore.get({ alg: encryption.alg });
            if (!encryptionKey) {
              throw new errors.InvalidClientMetadata(
                `no suitable encryption key found (${encryption.alg})`);
            }
            return JWT.encrypt(signed, encryptionKey, encryption.enc, encryption.alg);
          });
      }

      return signedTokenPromise;
    }

  };
};
