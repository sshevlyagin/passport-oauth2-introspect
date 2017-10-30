/**
 * Module dependencies.
 */
var passport  = require('passport-strategy'),
    util      = require('util'),
    url       = require('url'),
    request   = require('request');

/**
 * Creates an instance of `Strategy`.
 *
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field.
 *
 * Tokens are validated by querying the Authorization Server introspection
 * endpoint.
 *
 * If the token is not valid, `user` should be set to `false` to indicate an
 * authentication failure.  Additional token `info` can optionally be passed as
 * a third argument, which will be set by Passport at `req.authInfo`, where it
 * can be used by later middleware for access control.  This is typically used
 * to pass any scope associated with the token.
 *
 * Options:
 *
 *   - `realm`          authentication realm, defaults to "Users"
 *   - `introspect_url` AS introspection URL - expected to accept ?token=TOKEN parameter
 *   - `client_id`      client_id to use when authenticating to the introspection service
 *   - `client_secret`  client_secret to use when authenticating to the introspection service
 *   - `scope`          list of scope values required for this authentication strategy
 *   - `cache`          which cache to use - in memory (the default) or Redis
 *   - `redis`          a configuration object for initializing a Redis client
 *
 * Examples:
 *
 *     passport.use(new IntrospectionStrategy({
 *       realm:           'https://authz.example.com/',
 *       introspect_url:  'https://authz.example.com/introspect',
 *       client_id:       'myapp',
 *       client_secret:   'secret',
 *       scope:           'myapp:read myapp:write',
 *     }, function (tokenInfo, done) {
 *       if (tokenInfo.username) {
 *         
 *       }
 *     });
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @constructor
 * @param {Object} [options]
 * @api public
 */
function Strategy(options, verify) {

  if (typeof options === 'function') {
    throw new TypeError('IntrospectStrategy requires options')
  }
  
  if (verify && typeof verify !== 'function') {
    throw new TypeError('IntrospectStrategy requires verify to be a function');
  }
   
  if (!options.client_id || !options.client_secret || !options.introspect_url) {
    throw new TypeError('IntrospectStrategy requires client_id, client_secret, introspect_url')
  }

  this.name = options.name || 'introspect';
  passport.Strategy.call(this);

  this._realm = options.realm;
  this._client_id = options.client_id;
  this._client_secret = options.client_secret;
  this._introspect_url = options.introspect_url;

  if (!this._realm) {
    var parts = url.parse(this._introspect_url);
    this._realm = (parts.protocol || 'https:') + '//' + (parts.host || parts.hostname);
  }

  if (options.redis) {
    this._cache = require('redis').createClient((typeof options.redis === 'boolean') ? {} : options.redis);
  } else {
    // default to cleaning the in-memory cache every 2 hours
    this._cache = require('./cache')(options.cacheCleanup || 7200000);
  }

  // be flexible
  options.scope = options.scope || option.scopes;
  if (Array.isArray(options.scope)) {
    this._scopes = options.scope;
  } else if (typeof options.scope === 'string') {
    this._scopes = options.scope.split(/\s+/);
  } else {
    this._scopes = undefined;
  }

  this._strictSSL = options.strictSSL === undefined ? true : options.strictSSL;

  if (verify) {
    // only use passReqToCallback if using a provided verification function
    this._passReqToCallback = options.passReqToCallback;
    this._verify = verify;
  } else {
    this._verify = function _verify (token, done) {
      done(null, { username: token.username || token.client_id || token.sub || '__UNKNOWN__' }, token);
    }
  } 

  this._errors = {
    'invalid_request': {
      message: 'The request is missing a parameter, or is malformed',
      status: 400,
    },
    'invalid_token': {
      message: 'The token is expired, revoked, malformed or otherwise invald',
      status: 401,
    },
    'insufficient_scope': {
      message: 'The token does not have the correct scope(s) for this request',
      status: 403,
    }
  };

  if (options.error_uris) {
    Object.keys(this._errors).forEach ( function (k) {
      this._errors[k].uri = options.error_uris[k];
    }.bind(this));
  }


}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Bearer authorization
 * header, body parameter, or query parameter.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var token;
  
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length == 2 && /^bearer$/i.test(parts[0])) {
      token = parts[1];
    } else {
      return this._challenge('invalid_request', 'Invalid request');
    }
  }

  if (!token) {
    return this._challenge('invalid_token', 'Token is missing or malformed');
  }
  
  var self = this;

  function verified(err, user, info) {

    if (err) {
      return self.error(err);
    }
    if (!user) {
      if (typeof info == 'string') {
        info = { message: info }
      }
      info = info || {};
      return self._challenge('invalid_token', info.message);
    }
    self.success(user, info);
  }

  // check that every required scope was found
  // in the token
  function checkScopes(tokenScopes) {
    return self._scopes.every(function (scope) {
      return tokenScopes.indexOf(scope) !== -1;
    });
  }

  this._introspect(token, function (err, cached_token) {
    var now = Math.floor(Date.now()/1000),
        error,
        message;

    if (!cached_token) {
      // no token was found
      error = 'invalid_request';
      message = 'No token was found';
    } else if (!cached_token.hasOwnProperty('active')) {
      error = 'invalid_request';
      message = 'The token is malformed';
    } else if (!cached_token.active || !cached_token.exp || cached_token.exp < now) {
      error = 'invalid_token';
      message = 'The token has expired';
    } else if (self._scopes && !checkScopes(cached_token.scopes)) {
      error = 'insufficient_scope';
      message = 'The token did not contain the required scope(s)';
    }
    if (error) {
      return self._challenge(error, message);
    } else if (self._passReqToCallback) {
      self._verify(req, cached_token, verified);
    } else {
      self._verify(cached_token, verified);
    }
  });
};

/**
 * Build authentication challenge.
 *
 * @api private
 */
Strategy.prototype._challenge = function(error, desc, scope) {
  var challenge = 'Bearer realm="' + this._realm + '"',
      uri = this._errors[error] ? this._errors[error].uri : undefined,
      statusCode = this._errors[error] ? this._errors[error].code : 400;

  scope = scope || this._scope;
  desc = desc || this._errors[error].message;

  if (scope) {
    challenge += ', scope="' + scope.join(' ') + '"';
  }
  if (error) {
    challenge += ', error="' + error + '"';
  }
  if (desc && desc.length) {
    challenge += ', error_description="' + desc + '"';
  }
  if (uri && uri.length) {
    challenge += ', error_uri="' + uri + '"';
  }
  
  return this.fail(challenge, statusCode);
};


Strategy.prototype._introspectCallback =  function _introspectCallback (callback, token, err, res, body) {

  var now = Math.floor(Date.now()/1000),
      error;

  if (!res) {
    error = 'Introspection failed spectacularly';
  } else if (res.statusCode !== 200) {
    error = 'Instrospection failed with code ' + res.statusCode;
  }

  if (error) {
    callback(error);
  } else {

    if (body.scope) {
      body.scopes = body.scope.split(/\s+/);
    }

    // cache tokens to minimize introspection calls
    // cache TTL = 2 * time left, or 24 hours.
    this._cache.setex(token,
                      body.exp ? 2 * (body.exp - now) : 86400,
                      JSON.stringify(body),
                      function (err, replies) {
                        callback(err, body);
                      });              
  }
};


Strategy.prototype._introspect = function _introspect (token, callback) {
  var self = this;
  
  self._cache.get(token, function (err, cachedData) {
    var now = Math.floor(Date.now()/1000),
        err,
        cached_token,
        requestCallback = self._introspectCallback.bind(self, callback, token);

    
    // we're just ignoring cache errors, and will re-introspect the token
    if (cachedData && cachedData !== '') {
      try {
        cached_token = JSON.parse(cachedData);
      } catch (ex) {
        err = ex.message;
      }
    }

    if (cached_token && cached_token.active !== undefined) {
      callback(null, cached_token);
    } else if (err) {
      callback(err);
    } else {
      // Introspect the token
      request({
        url: self._introspect_url,
        method: 'POST',
        form: { token: token },
        auth: {
          user: self._client_id,
          pass: self._client_secret
        },
        json: true,
        strictSSL: self._strictSSL,
        callback: requestCallback
      });
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
