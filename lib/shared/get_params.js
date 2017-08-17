'use strict';

const assert = require('assert');
const _ = require('lodash');

module.exports = function getParams(whitelist) {
  assert(whitelist, 'whitelist must be present');

  class Params {
    constructor(params) {

      // Clients that don't support custom auth params will pass a special "audience:xxx" scope. 
      // If so, detect it here, assign to audience and remove it from scope.
      if (whitelist.has('audience') && !params.audience && params.scope) {
        const scopes = params.scope.split(' ');
        const audienceScope = scopes.filter(s => s.startsWith('audience:'))[0];
        if (audienceScope) {
          params.audience = audienceScope.substr(9);
          _.pull(scopes, audienceScope);
          params.scope = scopes.join(' ');
        }
      }

      whitelist.forEach((prop) => { this[prop] = params[prop]; });

      Object.seal(this);
    }
  }

  return function* assembleParams(next) {
    const params = this.method === 'POST' ? this.oidc.body : this.query;
    this.oidc.params = new Params(params);
    yield next;
  };
};
