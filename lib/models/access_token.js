'use strict';

const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

module.exports = function getAccessToken(provider) {
  const BaseToken = provider.BaseToken;
  return class AccessToken extends BaseToken {

    // TESTING
    sign(client, options) {
      const opts = options || /* istanbul ignore next */ {};
      // opts.use = 'use' in opts ? opts.use : 'idtoken';
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;
      opts.noExp = 'noExp' in opts ? opts.noExp : null;

      const expiresIn = (() => {
        if (opts.expiresAt) return opts.expiresAt - epochTime();
        return undefined;
      })();

      // const alg = opts.use === 'userinfo' ?
      //   client.userinfoSignedResponseAlg : client.idTokenSignedResponseAlg;
      const alg = client.idTokenSignedResponseAlg; // TODO: WHICH ALG TO USE?

      // const payload = this.payload || { sub: "TODO" }; // this.payload();
      const payload = this; // TODO: Can/should payload just be this?

      const promise = (() => {
        if (alg) {
          const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
          const key = keystore && keystore.get({ alg });

          // hashes.forEach((claim) => {
          //   if (payload[claim]) payload[claim] = tokenHash.generate(payload[claim], alg);
          // });

          return JWT.sign(payload, key, alg, {
            audience: client.clientId,
            expiresIn: opts.noExp ? undefined : (this.expiresIn || this.constructor.expiresIn), // (expiresIn || this.constructor.expiresIn),
            issuer: provider.issuer,
            subject: payload.sub,
          });
        }

        return Promise.resolve(JSON.stringify(payload));
      })();

      const encryption = opts.use === 'userinfo' ? {
        alg: client.userinfoEncryptedResponseAlg,
        enc: client.userinfoEncryptedResponseEnc,
      } : {
          alg: client.idTokenEncryptedResponseAlg,
          enc: client.idTokenEncryptedResponseEnc,
        };

      if (encryption.enc) {
        return promise.then((signed) => {
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

      return promise;
    }
    
  };
};