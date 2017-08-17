'use strict';

const assert = require('assert');
const _ = require('lodash');

module.exports = function getParams(whitelist) {
  // NOTE: it appears that whitelist is sometimes an array, sometimes a Set...
  assert(whitelist, 'whitelist must be present');

  class Params {
    constructor(params) {

      // Clients that don't support custom auth params will pass a special "audience:xxx" scope. 
      // If so, detect it here, assign to audience and remove it from scope.
      const whitelistHasAudience = _.isArray(whitelist) ? whitelist.indexOf('audience' >= 0) : whitelist.has('audience');
      if ( whitelistHasAudience && !params.audience && params.scope) {
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
