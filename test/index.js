'use strict';

const Lab = require('lab');
const Code = require('code');
const Hapi = require('hapi');
const Boom = require('boom');
const lab = exports.lab = Lab.script();

const expect = Code.expect;
const before = lab.before;
const after = lab.after;
const it = lab.it;


const defaultHandler = (request, reply) => {

    reply('success');
};


const defaultValidateFunc = (token, callback) => {

    return callback(null, token === '12345678',  { token });
};


const alwaysRejectValidateFunc = (token, callback) => {

    return callback(null, false, { token });
};


const alwaysErrorValidateFunc = (token, callback) => {

    return callback({ Error:'Error' }, false, null);
};


const boomErrorValidateFunc = (token, callback) => {

    return callback(Boom.badImplementation('test info'), false, null);
};


const noCredentialValidateFunc = (token, callback) => {

    return callback(null, true, null);
};

const artifactsValidateFunc = (token, callback) => {

    return callback(null, true, { token }, { sampleArtifact: 'artifact' });
};

let server = new Hapi.Server({ debug: false });
server.connection();


before((done) => {

    server.register(require('../'), (err) => {

        expect(err).to.not.exist();

        server.auth.strategy('default', 'bearer-access-token', true, {
            validateFunc: defaultValidateFunc
        });

        server.auth.strategy('default_named_access_token', 'bearer-access-token', {
            validateFunc: defaultValidateFunc,
            accessTokenName: 'my_access_token'
        });

        server.auth.strategy('always_reject', 'bearer-access-token', {
            validateFunc: alwaysRejectValidateFunc
        });

        server.auth.strategy('with_error_strategy', 'bearer-access-token', {
            validateFunc: alwaysErrorValidateFunc
        });

        server.auth.strategy('boom_error_strategy', 'bearer-access-token', {
            validateFunc: boomErrorValidateFunc
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

        server.auth.strategy('cookie_token_disabled', 'bearer-access-token', {
            validateFunc: defaultValidateFunc,
            allowCookieToken: false
        });

        server.auth.strategy('cookie_token_enabled', 'bearer-access-token', {
            validateFunc: defaultValidateFunc,
            allowCookieToken: true
        });

        server.auth.strategy('multiple_headers', 'bearer-access-token', {
            validateFunc: defaultValidateFunc,
            allowMultipleHeaders: true,
            tokenType: 'TestToken'
        });

        server.auth.strategy('custom_token_type', 'bearer-access-token', {
            validateFunc: defaultValidateFunc,
            tokenType: 'Basic'
        });

        server.auth.strategy('artifact_test', 'bearer-access-token', {
            validateFunc: artifactsValidateFunc
        });

        server.auth.strategy('reject_with_chain', 'bearer-access-token', {
            validateFunc: alwaysRejectValidateFunc,
            allowChaining: true
        });

        server.route([
            { method: 'POST', path: '/basic', handler: defaultHandler, config: { auth: 'default' } },
            { method: 'POST', path: '/basic_default_auth', handler: defaultHandler, config: { } },
            { method: 'GET', path: '/basic_named_token', handler: defaultHandler, config: { auth: 'default_named_access_token' } },
            { method: 'GET', path: '/basic_validate_error', handler: defaultHandler, config: { auth: 'with_error_strategy' } },
            { method: 'GET', path: '/boom_validate_error', handler: defaultHandler, config: { auth: 'boom_error_strategy' } },
            { method: 'GET', path: '/always_reject', handler: defaultHandler, config: { auth: 'always_reject' } },
            { method: 'GET', path: '/no_credentials', handler: defaultHandler, config: { auth: 'no_credentials' } },
            { method: 'GET', path: '/query_token_disabled', handler: defaultHandler, config: { auth: 'query_token_disabled' } },
            { method: 'GET', path: '/query_token_enabled', handler: defaultHandler, config: { auth: 'query_token_enabled' } },
            { method: 'GET', path: '/cookie_token_disabled', handler: defaultHandler, config: { auth: 'cookie_token_disabled' } },
            { method: 'GET', path: '/cookie_token_enabled', handler: defaultHandler, config: { auth: 'cookie_token_enabled' } },
            { method: 'GET', path: '/multiple_headers_enabled', handler: defaultHandler, config: { auth: 'multiple_headers' } },
            { method: 'GET', path: '/custom_token_type', handler: defaultHandler, config: { auth: 'custom_token_type' } },
            { method: 'GET', path: '/artifacts', handler: defaultHandler, config: { auth: 'artifact_test' } },
            { method: 'GET', path: '/chain', handler: defaultHandler, config: { auth: { strategies: ['reject_with_chain', 'default'] } } }
        ]);

        done();
    });
});


after((done) => {

    server = null;
    done();
});

it('throws when no bearer options provided', (done) => {

    try {
        server.auth.strategy('no_options', 'bearer-access-token', true);
    }
    catch (e) {
        expect(e.message).to.equal('Missing bearer auth strategy options');
        done();
    }
});

it('throws when validateFunc is not provided', (done) => {

    try {
        server.auth.strategy('no_options', 'bearer-access-token', true, { validateFunc: 'string' });
    }
    catch (e) {
        expect(e.details[0].message).to.equal('"validateFunc" must be a Function');
        done();
    }
});

it('returns 200 and success with correct bearer token header set', (done) => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer 12345678' } };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('returns 200 and success with correct bearer token header set in multiple authorization header', (done) => {

    const request = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'TestToken 12345678; FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018' } };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('returns 200 and success with correct bearer token header set in multiple places of the authorization header', (done) => {

    const request = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018; TestToken 12345678' } };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('returns 200 and success with correct bearer token query param set', (done) => {

    const request = { method: 'POST', url: '/basic?access_token=12345678' };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('returns 401 error when no bearer token is set when one is required by default', (done) => {

    const request = { method: 'POST', url: '/basic_default_auth' };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('returns 401 when bearer authorization header is not set', (done) => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'definitelynotacorrecttoken' } };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('returns 401 error with bearer token type of object (invalid token)', (done) => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer {test: 1}' } };

    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('returns 500 when strategy returns a regular object to validateFunc', (done) => {

    const request = { method: 'GET', url: '/basic_validate_error', headers: { authorization: 'Bearer 12345678' } };
    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(JSON.stringify(res.result)).to.equal('{\"Error\":\"Error\"}');
        done();
    });
});


it('returns 500 when strategy returns a Boom error to validateFunc', (done) => {

    const request = { method: 'GET', url: '/boom_validate_error', headers: { authorization: 'Bearer 12345678' } };
    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(500);
        expect(JSON.stringify(res.result)).to.equal('{\"statusCode\":500,\"error\":\"Internal Server Error\",\"message\":\"An internal server error occurred\"}');
        done();
    });
});


it('returns 401 handles when isValid false passed to validateFunc', (done) => {

    const request = { method: 'GET', url: '/always_reject', headers: { authorization: 'Bearer 12345678' } };
    server.inject(request, (res) => {

        expect(res.result).to.equal({
            statusCode: 401,
            error: 'Unauthorized',
            message: 'Bad token',
            attributes: {
                error: 'Bad token'
            }
        });
        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('returns 500 when no credentials passed to validateFunc', (done) => {

    const request = { method: 'GET', url: '/no_credentials', headers: { authorization: 'Bearer 12345678' } };
    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(500);
        done();
    });
});


it('returns a 200 on successful auth with access_token query param renamed and set', (done) => {

    const requestQueryToken = { method: 'GET', url: '/basic_named_token?my_access_token=12345678' };
    server.inject(requestQueryToken, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('doesn\'t affect header auth and will return 200 and success when specifying custom access_token name', (done) => {

    const requestQueryToken = { method: 'GET', url: '/basic_named_token', headers: { authorization: 'Bearer 12345678' } };
    server.inject(requestQueryToken, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('allows you to enable auth by query token', (done) => {

    const requestQueryToken = { method: 'GET', url: '/query_token_enabled?access_token=12345678' };
    server.inject(requestQueryToken, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});


it('allows you to disable auth by query token', (done) => {

    const requestHeaderToken  = { method: 'GET', url: '/query_token_disabled?access_token=12345678' };
    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('disables multiple auth headers by default', (done) => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'RandomAuthHeader 1234; TestToken 12345678' } };
    server.inject(request, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('allows you to enable multiple auth headers', (done) => {

    const requestHeaderToken = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'RandomAuthHeader 1234; TestToken 12345678' } };
    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(200);
        done();
    });
});


it('return unauthorized when no auth info and multiple headers disabled', (done) => {

    const requestHeaderToken = { method: 'POST', url: '/basic', headers: { authorization: 'x' } };
    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('return unauthorized when no auth info and multiple headers enabled', (done) => {

    const requestHeaderToken = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'x' } };
    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('return unauthorized when different token type is used', (done) => {

    const requestHeaderToken = { method: 'GET', url: '/custom_token_type', headers: { authorization: 'Bearer 12345678' } };

    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});


it('return 200 when correct token type is used', (done) => {

    const requestHeaderToken  = { method: 'GET', url: '/custom_token_type', headers: { authorization: 'Basic 12345678' } };

    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(200);
        done();
    });
});


it('accepts artifacts with credentials', (done) => {

    const requestHeaderToken  = { method: 'GET', url: '/artifacts', headers: { authorization: 'Bearer 12345678' } };

    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.request.auth.artifacts.sampleArtifact).equal('artifact');
        done();
    });
});

it('allows chaining of strategies', (done) => {

    const requestHeaderToken  = { method: 'GET', url: '/chain', headers: { authorization: 'Bearer 12345678' } };

    server.inject(requestHeaderToken, (res) => {

        expect(res.statusCode).to.equal(200);
        done();
    });
});

it('does not allow an auth cookie by default', (done) => {

    const cookie = 'my_access_token=12345678';
    const requestCookieToken = { method: 'GET', url: '/basic_named_token', headers: { cookie } };

    server.inject(requestCookieToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('allows you to enable auth by cookie token', (done) => {

    const cookie = 'access_token=12345678';
    const requestCookieToken = { method: 'GET', url: '/cookie_token_enabled', headers: { cookie }  };
    server.inject(requestCookieToken, (res) => {

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('success');
        done();
    });
});

it('will ignore cookie value if header auth provided', (done) => {

    const cookie = 'my_access_token=12345678';
    const authorization = 'Bearer 12345678';
    const requestCookieToken = { method: 'GET', url: '/cookie_token_enabled', headers: { authorization, cookie } };

    server.inject(requestCookieToken, (res) => {

        expect(res.statusCode).to.equal(200);
        done();
    });
});

it('allows you to disable auth by cookie token', (done) => {

    const cookie = 'access_token=12345678';
    const requestCookieToken  = { method: 'GET', url: '/cookie_token_disabled', headers: { cookie }  };
    server.inject(requestCookieToken, (res) => {

        expect(res.statusCode).to.equal(401);
        done();
    });
});
