// This original client_credentials handler does not check scopes.
// A custom handler needs to be created instead, but since initialize_app.js loads all files that match a grant type, through
//    const grant = require(`../actions/token/${grantType}`);
// the filename of this handler was changed to avoid it from being loaded.

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
