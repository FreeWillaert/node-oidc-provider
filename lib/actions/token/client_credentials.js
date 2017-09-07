'use strict';

const instance = require('../../helpers/weak_cache');

module.exports.handler = function getClientCredentialsHandler(provider) {
  return function* clientCredentialsResponse(next) {
    const ClientCredentials = provider.ClientCredentials;
    const at = new ClientCredentials({
      clientId: this.oidc.client.clientId,
      scope: this.oidc.params.scope,
    });

    // if enabled, return JWT access token
    let token = yield at.save();
    const jwtat = instance(provider).configuration('features.jwtat');

    if (jwtat) {
      token = yield at.sign(this.oidc.client, { params: this.oidc.params, audience: this.oidc.params.audience, availableClaims: {} });
    }

    const tokenType = 'Bearer';
    const expiresIn = ClientCredentials.expiresIn;

    this.body = { access_token: token, expires_in: expiresIn, token_type: tokenType };

    yield next;
  };
};

module.exports.parameters = ['scope'];
