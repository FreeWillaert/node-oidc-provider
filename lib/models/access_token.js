'use strict';

const _ = require('lodash');
const getMask = require('../helpers/claims');
const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

module.exports = function getAccessToken(provider) {
  const Claims = getMask(instance(provider).configuration());

  const BaseToken = provider.BaseToken;
  return class AccessToken extends BaseToken {

    payload(options, client, extra) {
      const mask = new Claims(options.availableClaims, client.sectorIdentifier);
      mask.scope(options.params.scope);

      return _.merge(mask.result(), extra);
    }

    sign(client, options) {
      const opts = options || /* istanbul ignore next */ {};
      // TODO: Is it required/allowed to support access tokens that don't expire?
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;
      opts.noExp = 'noExp' in opts ? opts.noExp : null;

      const expiresIn = (() => {
        if (opts.expiresAt) return opts.expiresAt - epochTime();
        return (this.expiresIn || this.constructor.expiresIn);
      })();

      // audience request parameter as defined in https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-2.1
      // This must be allowed through config extraParams.
      let requestedAudiences = null;
      if (opts.audience) {
        requestedAudiences = (opts.audience.indexOf(' ') >= 0) ? opts.audience.split(' ') : opts.audience;
      }

      const requestedScopes = this.scope.split(' ');
      const timestamp = Math.floor(Date.now() / 1000);

      // If a getCustomAccessTokenClaims function is found in configuration AND if it returns a result, use that value as atClaims, otherwise use the default atClaims.
      let getCustomAccessTokenClaimsFunc = instance(provider).configuration('getCustomAccessTokenClaims');
      let atClaimsPromise = Promise.resolve(null);
      if (getCustomAccessTokenClaimsFunc) {
        getCustomAccessTokenClaimsFunc = getCustomAccessTokenClaimsFunc.bind(instance(provider).configuration());

        atClaimsPromise = Promise.resolve(getCustomAccessTokenClaimsFunc(client.clientId, requestedAudiences, requestedScopes, this.jti, this.accountId, provider.issuer, options.availableClaims, timestamp, expiresIn));
      }

      return atClaimsPromise
        .then(result => {
          // Setting all claims from here, so that tenant/audience/client-specific claims may be set in full freedom.
          let atClaims = result || {
            iat: timestamp,
            exp: opts.noExp ? undefined : timestamp + expiresIn,
            aud: requestedAudiences || client.clientId,
            iss: provider.issuer,
            sub: this.accountId,
            // scp as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.2
            scp: requestedScopes,
            // cid as defined by https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-09#section-4.3
            cid: client.clientId,
            jti: this.jti
          };

          const payload = this.payload(opts, client, atClaims);

          return (() => {

            let key;
            let alg = client.idTokenSignedResponseAlg; // By default, use same signing alg as for id token.

            let getCustomAccessTokenSigningKeyAndAlgFunc = instance(provider).configuration('getCustomAccessTokenSigningKeyAndAlg');
            if (getCustomAccessTokenSigningKeyAndAlgFunc) {

              getCustomAccessTokenSigningKeyAndAlgFunc = getCustomAccessTokenSigningKeyAndAlgFunc.bind(instance(provider).configuration());

              let keyAndAlg = getCustomAccessTokenSigningKeyAndAlgFunc && getCustomAccessTokenSigningKeyAndAlgFunc(alg, provider, instance(provider), client, requestedAudiences);

              if (keyAndAlg) {
                key = keyAndAlg.key;
                alg = keyAndAlg.alg;
              }
            }

            if (alg) {

              if (!key) { // If key was not set by the custom func.
                const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
                key = keystore && keystore.get({ alg });
              }

              return JWT.sign(payload, key, alg, {});
            }

            return Promise.resolve(JSON.stringify(payload));
          })();
        })


      // // TODO: Do we want/need to support access token encryption?
      // const encryption = {
      //   alg: client.idTokenEncryptedResponseAlg,
      //   enc: client.idTokenEncryptedResponseEnc,
      // };

      // if (encryption.enc) {
      //   return signedTokenPromise.then((signed) => {
      //     if (client.keystore.stale()) return client.keystore.refresh().then(() => signed);
      //     return signed;
      //   })
      //     .then((signed) => {
      //       const encryptionKey = client.keystore.get({ alg: encryption.alg });
      //       if (!encryptionKey) {
      //         throw new errors.InvalidClientMetadata(
      //           `no suitable encryption key found (${encryption.alg})`);
      //       }
      //       return JWT.encrypt(signed, encryptionKey, encryption.enc, encryption.alg);
      //     });
      // }

      // return signedTokenPromise;
    }

  };
};
