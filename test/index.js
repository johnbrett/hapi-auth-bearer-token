var Lab = require('lab');
var Hapi = require('hapi');

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;

describe('Bearer', function () {

    var basicHandler = function (request, reply) {
        reply('ok');
    };

    var server = new Hapi.Server({ debug: false });
    before(function (done) {
        server.pack.register(require('../'), function (err) {
            expect(err).to.not.exist;

            server.auth.strategy('default', 'bearer-access-token', true, {
                validateFunc: function(token, callback) {
                    return callback(null, token==="12345678",  { token: token });
                }
            });

            server.route([
                { method: 'POST', path: '/basic', handler: basicHandler, config: { auth: 'default' } },
                { method: 'POST', path: '/basic_default_auth', handler: basicHandler, config: { } }
            ]);

            done();
        });
    });

    it('returns a reply on successful auth with auth bearer set', function (done) {

        var request = { method: 'POST', url: '/basic', headers: { authorization: "Bearer 12345678" } };

        server.inject(request, function (res) {
            expect(res.result).to.exist;
            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('returns a reply on successful auth with access_token set', function (done) {

        var request = { method: 'POST', url: '/basic?access_token=12345678' };

        server.inject(request, function (res) {
            expect(res.result).to.exist;
            expect(res.result).to.equal('ok');
            done();
        });
    });

    it('returns an error when auth is set to required by default', function (done) {

        var request = { method: 'POST', url: '/basic_default_auth' };

        server.inject(request, function (res) {
            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error with wrong scheme', function (done) {

        var request = { method: 'POST', url: '/basic', headers: { authorization: 'definitelynotacorrecttoken' } };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('returns an error with incorrect strategy', function (done) {

        server.auth.strategy('default_2', 'bearer-access-token', {
            validateFunc: function(token, callback) {
                return callback(null, false, { token: token });
            }
        });

        server.route([
            { method: 'POST', path: '/basic_default_2', handler: basicHandler, config: { auth: 'default_2' } }
        ]);

        var request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer {test: 1}' } };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(400);
            done();
        });
    });

    it('it handles when strategy returns an error to validateFunc', function (done) {

        server.auth.strategy('default_3', 'bearer-access-token', {
            validateFunc: function(token, callback) {
                return callback({'Error':'Error'}, false, null);
            }
        });

        server.route([
            { method: 'GET', path: '/basic_default_3', handler: basicHandler, config: { auth: 'default_3' } }
        ]);

        var request = { method: 'GET', url: '/basic_default_3', headers: { authorization: 'Bearer 12345678' } };

        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(200);
            done();
        });
    });

    it('it handles when isValid is false passed to validateFunc', function (done) {

        server.auth.strategy('default_4', 'bearer-access-token', {
            validateFunc: function(token, callback) {
                return callback(null, false, null);
            }
        });

        server.route([
            { method: 'GET', path: '/basic_default_4', handler: basicHandler, config: { auth: 'default_4' } }
        ]);

        var request = { method: 'GET', url: '/basic_default_4', headers: { authorization: 'Bearer 12345678' } };

        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(401);
            done();
        });
    });

    it('it handles when no credentials passed to validateFunc', function (done) {

        server.auth.strategy('default_5', 'bearer-access-token', {
            validateFunc: function(token, callback) {
                return callback(null, true, null);
            }
        });

        server.route([
            { method: 'GET', path: '/basic_default_5', handler: basicHandler, config: { auth: 'default_5' } }
        ]);

        var request = { method: 'GET', url: '/basic_default_5', headers: { authorization: 'Bearer 12345678' } };

        server.inject(request, function (res) {
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});
