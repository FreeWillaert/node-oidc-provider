'use strict';

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

      // resource and audience request parameters as defined in https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-2.1
      // These must be allowed through config extraParams.
      let requestedTargets = null; // Note: in general, these targets should already be 'consented'
      if (opts.params && (opts.params.resource || opts.params.audience)) {
        requestedTargets = [];
        if (opts.params.resource) {
          requestedTargets = requestedTargets.concat(opts.params.resource.split(' '));
        }
        if (opts.params.audience) {
          requestedTargets = requestedTargets.concat(opts.params.audience.split(' '));
        }
      }

      const requestedScopes = this.scope.split(' ');

      // authorizeAccesssTokenTargets/Scopes is optional in config
      const authorizeAccessTokenTargetsFunction = instance(provider).configuration('authorizeAccessTokenTargets') || function () { return Promise.resolve(null) };
      const authorizeAccessTokenScopesFunction = instance(provider).configuration('authorizeAccessTokenScopes') || function () { return Promise.resolve(null) };

      const authorizedPromises = [
        authorizeAccessTokenTargetsFunction.call(this, this.accountId, opts.params.response_type, opts.params.grant_type, client.clientId, requestedTargets),
        authorizeAccessTokenScopesFunction.call(this, this.accountId, opts.params.response_type, opts.params.grant_type, client.clientId, requestedTargets, requestedScopes)
      ];

      const signedTokenPromise = Promise.all(authorizedPromises)
        .then(results => {
          const authorizedTargets = results[0];
          const authorizedScopes = results[1];

          const payload = {
            // Note: sub, iss, aud, exp, iat are added via jwt helper/node-jose.
            // TODO: nbf ? (also: can these be passed to node-jose)

            // Custom claims
            // scp as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.2
            scp: authorizedScopes,

            // cid as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.3
            cid: client.clientId,

            jti: this.jti //TODO: For revocation/introspection/... adapt the token lookup (verify jwt signature and use jti from jwt)
          };

          return (() => {
            if (alg) {
              const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
              const key = keystore && keystore.get({ alg });

              return JWT.sign(payload, key, alg, {
                audience: authorizedTargets,
                expiresIn: opts.noExp ? undefined : expiresIn,
                issuer: provider.issuer,
                subject: this.accountId
              });
            }

            return Promise.resolve(JSON.stringify(payload));
          })();
        }
        )

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
