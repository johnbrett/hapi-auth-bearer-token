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


const defaultHandler = (request, h) => {

    return 'success';
};


const defaultValidateFunc = (request, token) => {

    return {
        isValid: token === '12345678',
        credentials: { token }
    };
};


const alwaysRejectValidateFunc = (request, token) => {

    return {
        isValid: false,
        credentials: { token }
    };
};


const alwaysErrorValidateFunc = (request, token) => {

    throw new Error('Error');
};


const boomErrorValidateFunc = (request, token) => {

    throw Boom.badImplementation('test info');
};


const noCredentialValidateFunc = (request, token, callback) => {

    return {
        isValid: true,
        credentials: null
    };
};

const artifactsValidateFunc = (request, token, callback) => {

    return {
        isValid: true,
        credentials: { token },
        artifacts: {
            sampleArtifact: 'artifact'
        }
    };
};

let server = Hapi.server({ debug: false });

before(async () => {

    try {
        await server.register(require('../'));
    }
    catch (err){
        expect(err).to.not.exist();
    }

    server.auth.strategy('default', 'bearer-access-token', {
        validate: defaultValidateFunc
    });
    server.auth.default('default');

    server.auth.strategy('default_named_access_token', 'bearer-access-token', {
        validate: defaultValidateFunc,
        accessTokenName: 'my_access_token'
    });

    server.auth.strategy('always_reject', 'bearer-access-token', {
        validate: alwaysRejectValidateFunc
    });

    server.auth.strategy('with_error_strategy', 'bearer-access-token', {
        validate: alwaysErrorValidateFunc
    });

    server.auth.strategy('boom_error_strategy', 'bearer-access-token', {
        validate: boomErrorValidateFunc
    });

    server.auth.strategy('no_credentials', 'bearer-access-token', {
        validate: noCredentialValidateFunc
    });

    server.auth.strategy('query_token_enabled', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowQueryToken: true
    });

    server.auth.strategy('query_token_enabled_renamed', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowQueryToken: true,
        accessTokenName: 'my_access_token'
    });

    server.auth.strategy('query_token_disabled', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowQueryToken: false
    });

    server.auth.strategy('cookie_token_disabled', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowCookieToken: false
    });

    server.auth.strategy('cookie_token_enabled', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowCookieToken: true
    });

    server.auth.strategy('multiple_headers', 'bearer-access-token', {
        validate: defaultValidateFunc,
        allowMultipleHeaders: true,
        tokenType: 'TestToken'
    });

    server.auth.strategy('custom_token_type', 'bearer-access-token', {
        validate: defaultValidateFunc,
        tokenType: 'Basic'
    });

    server.auth.strategy('artifact_test', 'bearer-access-token', {
        validate: artifactsValidateFunc
    });

    server.auth.strategy('reject_with_chain', 'bearer-access-token', {
        validate: alwaysRejectValidateFunc,
        allowChaining: true
    });

    server.auth.strategy('custom_unauthorized_func', 'bearer-access-token', {
        validate: alwaysRejectValidateFunc,
        unauthorized: (message, schema, attributed) => Boom.notFound(),
        allowChaining: true
    });

    server.route([
        { method: 'POST', path: '/basic', handler: defaultHandler, options: { auth: 'default' } },
        { method: 'POST', path: '/basic_default_auth', handler: defaultHandler, options: { } },
        { method: 'GET', path: '/basic_named_token', handler: defaultHandler, options: { auth: 'default_named_access_token' } },
        { method: 'GET', path: '/basic_validate_error', handler: defaultHandler, options: { auth: 'with_error_strategy' } },
        { method: 'GET', path: '/boom_validate_error', handler: defaultHandler, options: { auth: 'boom_error_strategy' } },
        { method: 'GET', path: '/always_reject', handler: defaultHandler, options: { auth: 'always_reject' } },
        { method: 'GET', path: '/no_credentials', handler: defaultHandler, options: { auth: 'no_credentials' } },
        { method: 'GET', path: '/query_token_disabled', handler: defaultHandler, options: { auth: 'query_token_disabled' } },
        { method: 'GET', path: '/query_token_enabled', handler: defaultHandler, options: { auth: 'query_token_enabled' } },
        { method: 'GET', path: '/query_token_enabled_renamed', handler: defaultHandler, options: { auth: 'query_token_enabled_renamed' } },
        { method: 'GET', path: '/cookie_token_disabled', handler: defaultHandler, options: { auth: 'cookie_token_disabled' } },
        { method: 'GET', path: '/cookie_token_enabled', handler: defaultHandler, options: { auth: 'cookie_token_enabled' } },
        { method: 'GET', path: '/multiple_headers_enabled', handler: defaultHandler, options: { auth: 'multiple_headers' } },
        { method: 'GET', path: '/custom_token_type', handler: defaultHandler, options: { auth: 'custom_token_type' } },
        { method: 'GET', path: '/custom_unauthorized_func', handler: defaultHandler, options: { auth: 'custom_unauthorized_func' } },
        { method: 'GET', path: '/artifacts', handler: defaultHandler, options: { auth: 'artifact_test' } },
        { method: 'GET', path: '/chain', handler: defaultHandler, options: { auth: { strategies: ['reject_with_chain', 'default'] } } }
    ]);

    return;
});


after(() => {

    server = null;
    return;
});

it('throws when no bearer options provided', () => {

    try {
        server.auth.strategy('no_options', 'bearer-access-token', null);
    }
    catch (e) {
        expect(e.message).to.equal('Missing bearer auth strategy options');
    }
});

it('throws when validateFunc is not provided', () => {

    try {
        server.auth.strategy('no_options', 'bearer-access-token', { validate: 'string' });
    }
    catch (e) {
        expect(e.details[0].message).to.equal('"validate" must be a Function');
    }
});

it('returns 200 and success with correct bearer token header set', async () => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer 12345678' } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});


it('returns 200 and success with correct bearer token header set in multiple authorization header', async () => {

    const request = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'TestToken 12345678; FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018' } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});


it('returns 200 and success with correct bearer token header set in multiple places of the authorization header', async () => {

    const request = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018; TestToken 12345678' } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});


it('returns 401 error with bearer token query param set by default', async () => {

    const request = { method: 'POST', url: '/basic?access_token=12345678' };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(401);
});


it('returns 401 error when no bearer token is set when one is required by default', async () => {

    const request = { method: 'POST', url: '/basic_default_auth' };

    const res = await server.inject(request);
    expect(res.statusCode).to.equal(401);
});


it('returns 401 when bearer authorization header is not set', async () => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'definitelynotacorrecttoken' } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(401);
});


it('returns 401 error with bearer token type of object (invalid token)', async () => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'Bearer {test: 1}' } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(401);
});


it('returns 500 when strategy returns a regular object to validateFunc', async () => {

    const request = { method: 'GET', url: '/basic_validate_error', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(request);

    expect(res.statusCode).to.equal(500);
    expect(JSON.stringify(res.result)).to.equal('{\"statusCode\":500,\"error\":\"Internal Server Error\",\"message\":\"An internal server error occurred\"}');
});


it('returns 500 when strategy returns a Boom error to validateFunc', async () => {

    const request = { method: 'GET', url: '/boom_validate_error', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(request);

    expect(res.statusCode).to.equal(500);
    expect(JSON.stringify(res.result)).to.equal('{\"statusCode\":500,\"error\":\"Internal Server Error\",\"message\":\"An internal server error occurred\"}');
});


it('returns 401 handles when isValid false passed to validateFunc', async () => {

    const request = { method: 'GET', url: '/always_reject', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(request);

    expect(res.result).to.equal({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Bad token',
        attributes: {
            error: 'Bad token'
        }
    });
    expect(res.statusCode).to.equal(401);
});


it('returns 500 when no credentials passed to validateFunc', async () => {

    const request = { method: 'GET', url: '/no_credentials', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(request);

    expect(res.statusCode).to.equal(500);
});


it('returns a 401 on default auth with access_token query param renamed and set', async () => {

    const requestQueryToken = { method: 'GET', url: '/basic_named_token?my_access_token=12345678' };
    const res = await server.inject(requestQueryToken);

    expect(res.statusCode).to.equal(401);
});


it('doesn\'t affect header auth and will return 200 and success when specifying custom access_token name', async () => {

    const requestQueryToken = { method: 'GET', url: '/basic_named_token', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(requestQueryToken);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});


it('allows you to enable auth by query token', async () => {

    const requestQueryToken = { method: 'GET', url: '/query_token_enabled?access_token=12345678' };
    const res = await server.inject(requestQueryToken);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});

it('allows you to enable auth by query token and rename the query param', async () => {

    const requestQueryToken = { method: 'GET', url: '/query_token_enabled_renamed?my_access_token=12345678' };
    const res = await server.inject(requestQueryToken);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});

it('allows you to enable auth by query token and still use header', async () => {

    const requestQueryToken = { method: 'GET', url: '/query_token_enabled_renamed', headers: { authorization: 'Bearer 12345678' } };
    const res = await server.inject(requestQueryToken);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});


it('allows you to disable auth by query token', async () => {

    const requestHeaderToken  = { method: 'GET', url: '/query_token_disabled?access_token=12345678' };
    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(401);
});


it('disables multiple auth headers by default', async () => {

    const request = { method: 'POST', url: '/basic', headers: { authorization: 'RandomAuthHeader 1234; TestToken 12345678' } };
    const res = await server.inject(request);

    expect(res.statusCode).to.equal(401);
});

it('allows you to enable multiple auth headers', async () => {

    const requestHeaderToken = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'RandomAuthHeader 1234; TestToken 12345678' } };
    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(200);
});


it('return unauthorized when no auth info and multiple headers disabled', async () => {

    const requestHeaderToken = { method: 'POST', url: '/basic', headers: { authorization: 'x' } };
    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(401);
});


it('return unauthorized when no auth info and multiple headers enabled', async () => {

    const requestHeaderToken = { method: 'GET', url: '/multiple_headers_enabled', headers: { authorization: 'x' } };
    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(401);
});


it('return unauthorized when different token type is used', async () => {

    const requestHeaderToken = { method: 'GET', url: '/custom_token_type', headers: { authorization: 'Bearer 12345678' } };

    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(401);
});


it('return 200 when correct token type is used', async () => {

    const requestHeaderToken  = { method: 'GET', url: '/custom_token_type', headers: { authorization: 'Basic 12345678' } };

    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(200);
});


it('accepts artifacts with credentials', async () => {

    const requestHeaderToken  = { method: 'GET', url: '/artifacts', headers: { authorization: 'Bearer 12345678' } };

    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(200);
    expect(res.request.auth.artifacts.sampleArtifact).equal('artifact');
});

it('allows chaining of strategies', async () => {

    const requestHeaderToken  = { method: 'GET', url: '/chain', headers: { authorization: 'Bearer 12345678' } };

    const res = await server.inject(requestHeaderToken);

    expect(res.statusCode).to.equal(200);
});

it('does not allow an auth cookie by default', async () => {

    const cookie = 'my_access_token=12345678';
    const requestCookieToken = { method: 'GET', url: '/basic_named_token', headers: { cookie } };

    const res = await server.inject(requestCookieToken);

    expect(res.statusCode).to.equal(401);
});

it('allows you to enable auth by cookie token', async () => {

    const cookie = 'access_token=12345678';
    const requestCookieToken = { method: 'GET', url: '/cookie_token_enabled', headers: { cookie }  };
    const res = await server.inject(requestCookieToken);

    expect(res.statusCode).to.equal(200);
    expect(res.result).to.equal('success');
});

it('will ignore cookie value if header auth provided', async () => {

    const cookie = 'my_access_token=12345678';
    const authorization = 'Bearer 12345678';
    const requestCookieToken = { method: 'GET', url: '/cookie_token_enabled', headers: { authorization, cookie } };

    const res = await server.inject(requestCookieToken);

    expect(res.statusCode).to.equal(200);
});

it('allows you to disable auth by cookie token', async () => {

    const cookie = 'access_token=12345678';
    const requestCookieToken  = { method: 'GET', url: '/cookie_token_disabled', headers: { cookie }  };
    const res = await server.inject(requestCookieToken);

    expect(res.statusCode).to.equal(401);
});

it('allows you to use a custom unauthrozied function', async () => {

    const request = {
        method: 'GET', url: '/custom_unauthorized_func',
        headers: { authorization: 'definitelynotacorrecttoken' }
    };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(404);
});

