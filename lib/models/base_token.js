'use strict';

const IN_PAYLOAD = [
  'accountId',
  'acr',
  'amr',
  'audience',
  'authTime',
  'claims',
  'clientId',
  'onlyPKCE', // for refresh token
  'codeChallenge', // for authorization code
  'codeChallengeMethod', // for authorization code
  'grantId',
  'jti',
  'kind',
  'nonce',
  'redirectUri',
  'scope',
  'sid',
  'state'
];

const _ = require('lodash');
const constantEquals = require('buffer-equals-constant');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid');

const errors = require('../helpers/errors');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).configuration('adapter'))(obj.name));
    }

    return adapterCache.get(obj);
  }

  function loadClient(clientId) {
    // Validate: client_id param
    return provider.Client
      .find(clientId)
      .then(client => {
        if (!client) throw new errors.InvalidClientError('unrecognized cid claim');
        return client;
      })
  };

  return class BaseToken {

    constructor(payload) {
      Object.assign(this, payload);

      this.jti = this.jti || base64url.encode(uuid());

      this.kind = this.kind || this.constructor.name;
      assert.equal(this.kind, this.constructor.name, 'kind mismatch');
    }

    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }
    get isValid() { return !this.consumed && !this.isExpired; }
    get isExpired() { return this.exp <= epochTime(); }

    save() {
      const key = instance(provider).integrity.get();
      const alg = key.alg;

      const expiresIn = this.expiresIn || this.constructor.expiresIn;

      return JWT.sign(_.pick(this, IN_PAYLOAD), key, alg, {
        expiresIn,
        issuer: provider.issuer,
      }).then((jwt) => {
        const parts = jwt.split('.');

        const upsert = {
          header: parts[0],
          payload: parts[1],
          signature: parts[2],
        };

        if (this.grantId) upsert.grantId = this.grantId;

        return adapter(this).upsert(this.jti, upsert, expiresIn)
          .then(() => `${this.jti}${upsert.signature}`);
      }).then((tokenValue) => {
        provider.emit('token.issued', this);
        return tokenValue;
      });
    }

    destroy() {
      provider.emit('token.revoked', this);
      if (this.grantId) provider.emit('grant.revoked', this.grantId);

      return adapter(this).destroy(this.jti);
    }

    consume() {
      provider.emit('token.consumed', this);
      return adapter(this).consume(this.jti);
    }

    static fromJWT(jwt, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;
      opts.issuer = provider.issuer;

      const keystore = instance(provider).integrity;
      return JWT.verify(jwt, keystore, opts)
        .then(result => new this(Object.assign(result.payload)));
    }

    static find(tokenValue, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;

      let tokenPartsPromise;

      if (opts.jwtat) {

        const clientId = (() => {
          try {
            const jot = JWT.decode(tokenValue);
            return jot.payload.cid;
          } catch (err) {
            throw(new errors.InvalidRequestError(`could not decode jwtat (${err.message})`));
          }
        })();

        tokenPartsPromise = loadClient(clientId)
          .then(client => {
            return provider.IdToken.validate(tokenValue, client)
          })
          .then(decoded => {
            if(!decoded.payload.scp || decoded.payload.scp.indexOf("openid") < 0) throw new Error("jwtat scp does not contain openid"); // TODO: check this?
            return { jti: decoded.payload.jti }
          })
          .catch(err => {
            throw(new errors.InvalidRequestError(`could not validate jwtat (${err.message})`));
          })
      } else {
        try {
          let jti = tokenValue.substring(0, 48);
          let sig = tokenValue.substring(48);
          assert(jti);
          assert(sig);
          tokenPartsPromise = Promise.resolve({ jti, sig });
        } catch (err) {
          return Promise.reject(new errors.InvalidTokenError());
        }
      }

      return tokenPartsPromise
        .then(tokenParts => {
          let jti = tokenParts.jti;
          let sig = tokenParts.sig; // Not relevant in case of jwtat.

          return adapter(this).find(jti).then((token) => {
            if (token) {
              /* istanbul ignore if */
              if (!opts.jwtat) { // if opts.jwtat, the signature check was already done on the jwtat itself.
                if (!constantEquals(new Buffer(sig), new Buffer(token.signature))) {
                  throw new errors.InvalidTokenError();
                }
              }

              const jwt = [token.header, token.payload, token.signature].join('.');
              return this.fromJWT(jwt, opts).then((validated) => {
                const result = validated;
                if (token.consumed !== undefined) result.consumed = token.consumed;

                return result;
              }).catch(() => {
                throw new errors.InvalidTokenError();
              });
            }

            return undefined;
          });
        })

    }
  };
};
