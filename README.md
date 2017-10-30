# passport-bearer-introspect

Bearer token introspection authentication strategy for
[Passport](http://passportjs.org/).

This is derived from Jared Hanson's [passport-http-bearer](https://github.com/jaredhanson/passport-http-bearer)

This module lets you authenticate HTTP requests using bearer tokens (as
specified by [RFC 6750](http://tools.ietf.org/html/rfc6750)) issued
from an OAuth 2.0 Authorization Server that supports token
introspection (as specified by [RFC
7662](https://tools.ietf.org/html/rfc7662)) in your Node.js
applications.

By plugging into Passport, bearer token support can be easily and unobtrusively
integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-bearer-introspect

## Usage

#### Configure Strategy

The Bearer Introspection authentication strategy authenticates clients (and users)
using a bearer token.

The strategy requires configuration options to be provided at initialization:

    var passport  = require('passport'),
        IntrospectStrategy  = require('passport-bearer-introspect').Strategy;
  
    passport.use(new IntrospectStrategy({
      client_id:      'myapp.example.com',
      client_secret:  'super_secret',
      introspect_url: 'https://authz.example.com/introspect',
      scope: 'requiredScope1 requiredScope2',
    });

`client_id` and `client_secret` are the *resource* server's client ID
and secret, which are used to authenticate to the OAuth 2.0
Authorization Server (AS) to introspect tokens received from clients.

`introspect_url` is the AS' introspection URL.

`scope` is a space-separate list, or an Array, of scopes that are
required for this resource. Any request with a token which is found to
not contain *all* the required scopes will be rejected.

The strategy supports `verify` callback, which accepts the introspected
token and calls `done` providing a user. Optional `info` can be passed,
typically the introspected token, which will be set by Passport at
`req.authInfo` to be used by later middleware for authorization and
access control.

    passport.use(new IntrospectStrategy(
      options,
      function(token, done) {
        if (token.username) {
          User.findOne(token.username, function (err, user) {
            if (err) { return done(err); }
            if (user) { return done(null, false); }
            return done(null, user, token);
          });
        } else {
          return done(null, {}, token);
        }
      }
    ));

A default `verify` function is used if none is specified, which
populates `req.authInfo` with the token, and sets `req.user.username`
to the first nonempty `username`, `client_id`, or `sub` property in the
token. Additionally, the `scope` property of the token is also broken
out into the `req.authInfo.scopes` Array.

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'bearer'` strategy, to
authenticate requests.  Requests containing bearer tokens do not require session
support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/profile', 
      passport.authenticate('bearer', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

### Variable Scope Requirements

There are two ways to handle different scope requirements across different API endpoints.

The first is to only specify common - or no - scopes in the strategy
options, then check scopes in the endpoint handler:

    app.get('/profile', 
      passport.authenticate('bearer', { session: false }),
      function(req, res) {
        if (req.authInfo.scopes && req.authInfo.scopes.indexOf('requiredScope') === -1) {
          res.status(403).set('WWW-Authenticate','ream="authz.example.com, error="insufficient_scope"').send();
        } else {
          //... process request
        }
      });

Alternatively, the strategy can be used multiple times:

    var passport  = require('passport'),
        IntrospectStrategy  = require('passport-bearer-introspect').Strategy;

    passport.use('read', new IntrospectStrategy({
      client_id:      'myapp.example.com',
      client_secret:  'super_secret',
      introspect_url: 'https://authz.example.com/introspect',
      scope:          'myapp:read'
    });
    passport.use('write', new IntrospectStrategy({
      client_id:      'myapp.example.com',
      client_secret:  'super_secret',
      introspect_url: 'https://authz.example.com/introspect',
      scope:          'myapp:write'
    });

    app.get('/path',
      passport.authenticate('read', { session: false }),
      function(req, res) {
        //... process read request
      }
    );

    app.post('/path',
      passport.authenticate('write', { session: false }),
      function(req, res) {
        //... process write request
      }
    );


