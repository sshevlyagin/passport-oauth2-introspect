const express                = require('express'),
      fs                     = require('fs'),
      passport               = require('passport'),
      IntrospectionStrategy  = require('..').Strategy,
      BasicStrategy          = require('passport-http').BasicStrategy,
      should                 = require('should'),
      shouldHttp             = require('should-http'),
      http                   = require('http'),
      morgan                 = require('morgan'),
      bodyParser             = require('body-parser');
      

morgan.token('log_id', () => {
  return `[${process.pid}]`;
});

morgan.token('client_id', (req) => {
  if (req.authInfo && req.authInfo.client_id) {
    return req.authInfo.client_id;
  } else if (req.user && req.user.id) {
    return req.user.id;
  } else {
    return '-';
  }
});

morgan.token('res_status', (req, res) => {
  return res.statusMessage;
});

describe('Tests', function() {
  
  const clients   = {
    api: {
      id: 'api',
      secret: '1234'
    },
    test: {
      id: 'test',
      secret: '5678'
    }
  };
  const exp = new Date(Date.now() + 3_600_000);
  const tokens = {
    READONLY: {
      active:     true,
      scope:      'read',
      expires_at: exp.toISOString(),
      exp:        Math.floor(exp / 1_000),
      sub:        clients.test.id,
      client_id:  clients.test.id,
      token_type: 'Bearer'
    },
    READWRITE: {
      active:     true,
      scope:      'read write',
      expires_at: exp.toISOString(),
      exp:        Math.floor(exp / 1_000),
      sub:        clients.test.id,
      client_id:  clients.test.id,
      token_type: 'Bearer'
    }
  };

  let app;

  let authz;
  
  let http_opts = {
    protocol: 'http:',
    hostname: 'localhost',
    port: 3000,
  };

  before( (done) => {
    
    passport.use('read', new IntrospectionStrategy({
      introspect_url: 'http://localhost:3001/introspect',
      client_id:      clients.api.id,
      client_secret:  clients.api.secret,
      scope:          'read',
    }));

    passport.use('write', new IntrospectionStrategy({
      introspect_url: 'http://localhost:3001/introspect',
      client_id:      clients.api.id,
      client_secret:  clients.api.secret,
      scope:          'write',
    }));

    passport.use('basic', new BasicStrategy(
      function (id, secret, done) {
        if (id === clients.api.id) {
          if (secret == clients.api.secret) {
            done(null, clients.api);
          } else {
            done(null, new Error('invalid secret'));
          }
        } else {
          done(null, false);
        }
      }
    ));

    app = express();
    authz = express();

    const logFormat = ':date[iso] :remote-addr :client_id :status :res[content-length] :response-time :total-time | :method :url';
    
    app.use(morgan(logFormat, { stream: fs.createWriteStream('test/app.log', { flags: 'a' }) }));
    
    authz.use(morgan(logFormat, { stream: fs.createWriteStream('test/authz.log', { flags: 'a' }) }));

    authz.use(bodyParser.urlencoded());

    authz.all('/introspect',
            passport.authenticate('basic', { session: false }),
            function (req, res) {
              if (req.method !== 'GET' && req.method !== 'POST') {
                res.status(405).end();
              } else {
                const token = req.body && req.body.token ? req.body.token : req.query.token;
                if (token) {
                  if (tokens.hasOwnProperty(token)) {
                    res.json(tokens[token]);
                  } else {
                    res.json({active: false});
                  }
                } else {
                  res.status(400).end();
                }
              }
            });

    app.get('/',
            passport.authenticate('read', { session: false }),
            function(req, res) {
              res.json({ user: req.user, authInfo: req.authInfo });
            }
           );

    app.post('/',
             passport.authenticate('write', { session: false }),
             function(req, res) {
               res.json({ user: req.user, authInfo: req.authInfo });
             }
            );

    app.listen(3000);
    authz.listen(3001);
    done();
  });

  beforeEach( (done) => {
    http_opts.port = 3000;
    done();
  });
  
  it('should allow introspection of a valid TOKEN', function (done) {
    http_opts.port = 3001;
    http_opts.path = '/introspect?token=READONLY';
    http_opts.method = 'GET';
    http_opts.auth = clients.api.id + ':' + clients.api.secret;
    const req = http.request(http_opts, (res) => {
      res.should.have.status(200);
      res.on('data', (chunk) => {
        const now = Math.floor(Date.now()/1_000);
        const info = JSON.parse(chunk.toString());

        [
          'active',
          'scope',
          'expires_at',
          'exp',
          'sub',
          'client_id',
          'token_type'
        ].forEach( (field) => info.should.have.property(field));
        
        info.active.should.equal(true);
        info.token_type.should.equal('Bearer');
        info.sub.should.equal(clients.test.id);
        info.client_id.should.equal(clients.test.id);
        info.scope.should.equal('read');
        info.exp.should.be.greaterThan(now);
        const expAt = Date.parse(info.expires_at);
        expAt.should.be.greaterThan(now);
      });
      res.on('end', done);
    });

    req.end();
  });
    
  it('should correctly introspect an invalid TOKEN', function (done) {
    http_opts.port = 3001;
    http_opts.path = '/introspect?token=INVALID';
    http_opts.method = 'GET';
    http_opts.auth = clients.api.id + ':' + clients.api.secret;
    const req = http.request(http_opts, (res) => {
      res.should.have.status(200);
      res.on('data', (chunk) => {
        const info = JSON.parse(chunk.toString());

        info.should.have.property('active');
        info.active.should.equal(false);
      });
      res.on('end', done);
    });

    req.end();
  });
    

  it('should fail with no token', function (done) {
    http_opts.path = '/';
    http_opts.method = 'GET';
    
    const req = http.request(http_opts, (res) => {
      res.should.have.status(401);
      done();
    });

    req.end();
  });

  it('should successfuly GET with a read token', function (done) {
    http_opts.path = '/';
    http_opts.method = 'GET';
    http_opts.headers = { Authorization: 'Bearer READONLY' };
    
    const req = http.request(http_opts, (res) => {
      res.should.have.status(200);
      done();
    });

    req.end();
  });

  it('should successfuly POST with a write token', function (done) {
    http_opts.path = '/';
    http_opts.method = 'POST';
    http_opts.headers = { Authorization: 'Bearer READWRITE' };
    
    const req = http.request(http_opts, (res) => {
      res.should.have.status(200);
      done();
    });

    req.end();
  });

  it('should fail to POST with a read token', function (done) {
    http_opts.path = '/';
    http_opts.method = 'POST';
    http_opts.headers = { Authorization: 'Bearer READONLY' };
    
    const req = http.request(http_opts, (res) => {
      res.should.have.status(401);
      done();
    });

    req.end();
  });


});

