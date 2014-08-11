var Lab = require('lab');
var Hapi = require('hapi');

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Bearer', function () {

    var defaultHandler = function (request, reply) {
        reply('success');
    }

    var defaultValidateFunc = function(token, callback) {
        return callback(null, token==="12345678",  { token: token });
    }

    var alwaysRejectValidateFunc = function(token, callback) {
        return callback(null, false, { token: token });
    }

    var alwaysErrorValidateFunc = function(token, callback) {
        return callback({'Error':'Error'}, false, null);
    }

    var noCredentialValidateFunc = function(token, callback) {
        return callback(null, true, null);
    }

    var server = new Hapi.Server({debug: false})

    before(function(done){

        server.pack.register(require('../'), function (err) {
            expect(err).to.not.exist;

            server.auth.strategy('default', 'bearer-access-token', true, {
                validateFunc: defaultValidateFunc
            });

            server.auth.strategy('default_named_access_token', 'bearer-access-token', {
                validateFunc: defaultValidateFunc,
                accessTokenName: "my_access_token"
            });

            server.auth.strategy('always_reject', 'bearer-access-token', {
                validateFunc: alwaysRejectValidateFunc
            });

            server.auth.strategy('with_error_strategy', 'bearer-access-token', {
                validateFunc: alwaysErrorValidateFunc
            });

            server.auth.strategy('no_credentials', 'bearer-access-token', {
                validateFunc: noCredentialValidateFunc
            });

            server.auth.strategy('query_token_enabled', 'bearer-access-token', {
                validateFunc: defaultValidateFunc,
                allowQueryToken: true
            });

            server.auth.strategy('query_token_disabled', 'bearer-access-token', {
                validateFunc: defaultValidateFunc,
                allowQueryToken: false
            });

            server.route([
                { method: 'POST', path: '/basic', handler: defaultHandler, config: { auth: 'default' } },
                { method: 'POST', path: '/basic_default_auth', handler: defaultHandler, config: { } },
                { method: 'GET', path: '/basic_named_token', handler: defaultHandler, config: { auth: 'default_named_access_token' } },
                { method: 'GET', path: '/basic_validate_error', handler: defaultHandler, config: { auth: 'with_error_strategy' } },
                { method: 'GET', path: '/always_reject', handler: defaultHandler, config: { auth: 'always_reject' } },
                { method: 'GET', path: '/no_credentials', handler: defaultHandler, config: { auth: 'no_credentials' } },
                { method: 'GET', path: '/query_token_disabled', handler: defaultHandler, config: { auth: 'query_token_disabled' } },
                { method: 'GET', path: '/query_token_enabled', handler: defaultHandler, config: { auth: 'query_token_enabled' } }
            ]);

            done();
        });
    })

    after(function(done) {
        server = null
        done()
    })

    it('returns 200 and success with correct bearer token header set', function (done) {
        var request = { method: 'POST', url: '/basic', headers: { authorization: "Bearer 12345678" } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal('success');
            done();
        });
    });

    it('returns 200 and success with correct bearer token query param set', function (done) {
        var request = { method: 'POST', url: '/basic?access_token=12345678' };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal('success');
            done();
        });
    });

    it('returns 401 error when no bearer token is set when one is required by default', function (done) {
        var request = { method: 'POST', url: '/basic_default_auth' };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns 401 when bearer authorization header is not set', function (done) {
        var request = { method: 'POST', url: '/basic', headers: { authorization: 'definitelynotacorrecttoken' } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns 400 error with incorrect bearer token type', function (done) {
        var request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer {test: 1}' } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('returns 500 when strategy returns an error to validateFunc', function (done) {
        var request = { method: 'GET', url: '/basic_validate_error', headers: { authorization: 'Bearer 12345678' } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(500);
            expect(JSON.stringify(res.result)).to.equal("{\"Error\":\"Error\"}");
            done();
        });
    });

    it('returns 401 handles when isValid false passed to validateFunc', function (done) {
        var request = { method: 'GET', url: '/always_reject', headers: { authorization: 'Bearer 12345678' } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns 500 when no credentials passed to validateFunc', function (done) {
        var request = { method: 'GET', url: '/no_credentials', headers: { authorization: 'Bearer 12345678' } };
        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(500);
            done();
        });
    });

    it('returns a 200 on successful auth with access_token query param renamed and set', function (done) {
        var request_query_token = { method: 'GET', url: '/basic_named_token?my_access_token=12345678' };
        server.inject(request_query_token, function (res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal('success');
            done();
        });
    });

    it('doesn\'t affect header auth and will return 200 and success when specifying custom access_token name', function (done) {
        var request_header_token  = { method: 'GET', url: '/basic_named_token', headers: { authorization: 'Bearer 12345678' } };
        server.inject(request_header_token, function(res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal('success');
            done();
        })
    });

    it('allows you to enable auth by query token', function (done) {
        var request_header_token  = { method: 'GET', url: '/query_token_enabled?access_token=12345678'};
        server.inject(request_header_token, function(res) {
            expect(res.statusCode).to.equal(200);
            expect(res.result).to.equal('success');
            done();
        })
    });

    it('allows you to disable auth by query token', function (done) {
        var request_header_token  = { method: 'GET', url: '/query_token_disabled?access_token=12345678'};
        server.inject(request_header_token, function(res) {
            expect(res.statusCode).to.equal(401);
            done();
        })
    });
});
