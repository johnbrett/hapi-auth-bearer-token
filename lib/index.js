'use strict';

const Boom = require('@hapi/boom');
const Hoek = require('@hapi/hoek');
const Joi = require('joi');

// Declare Internals

const internals = {};

internals.defaults = {
    accessTokenName: 'access_token',
    allowQueryToken: false,
    allowCookieToken: false,
    allowMultipleHeaders: false,
    allowChaining: false,
    tokenType: 'Bearer',
    unauthorized: Boom.unauthorized
};

internals.schema = Joi.object().keys({
    validate: Joi.func().required(),
    accessTokenName: Joi.alternatives().try(
        Joi.string().required(),
        Joi.array().items(Joi.string().required())
    ).required(),
    allowQueryToken: Joi.boolean(),
    allowCookieToken: Joi.boolean(),
    allowMultipleHeaders: Joi.boolean(),
    allowChaining: Joi.boolean(),
    tokenType: Joi.alternatives().try(
        Joi.string().required(),
        Joi.array().items(Joi.string().required())
    ).required(),
    unauthorized: Joi.func()
});

// Look the first token in object
const getTokenFromObject = function (object, tokenTypes) {

    for (const type of tokenTypes) {
        if (object[ type ]) {
            return { tokenType: type, token: object[ type ] };
        }
    }

    return null;
};

const getToken = function (request, settings) {

    const tokenTypes = Array.isArray(settings.tokenType) ? settings.tokenType : [settings.tokenType];

    const headerTokens = typeof (request.raw.req.headers.authorization) === 'string' ? request.raw.req.headers.authorization.split(';') : [];

    const regExps = tokenTypes.map( (type) => {

        return { type, regexp: new RegExp(type + '\\s+([^;$]+)','i') };
    });

    for (const possibleToken of headerTokens) {
        for (const regxp of regExps) {
            const test = possibleToken.match(regxp.regexp);

            if (test) {
                return { tokenType: regxp.type, token: test[1] };
            }
        }
    }

    const accessTokenTypes = Array.isArray(settings.accessTokenName) ? settings.accessTokenName : [settings.accessTokenName];

    if (settings.allowCookieToken) {
        const token = getTokenFromObject(request.state, accessTokenTypes);
        if (token) {
            return token;
        }
    }

    if (settings.allowQueryToken) {
        const token = getTokenFromObject(request.query, accessTokenTypes);

        if (token) {
            return token;
        }
    }

    return null;
};

internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing bearer auth strategy options');

    const settings = Hoek.applyToDefaults(internals.defaults, options);
    Joi.assert(settings, internals.schema);

    const scheme = {
        authenticate: async (request, h) => {

            const accessToken = getToken(request, settings);

            if (!accessToken) {
                throw settings.unauthorized(null, settings.tokenType);
            }

            const { isValid, credentials, artifacts } = await settings.validate(request, accessToken.token, h);

            if (!isValid) {
                let message = 'Bad token';
                if (settings.allowChaining) {
                    const routeSettings = request.route.settings.auth;
                    const auth = routeSettings || request.server.auth.lookup(request.route);
                    if (auth.strategies.length > 1) {
                        message = null;
                    }
                }

                return h.unauthenticated(settings.unauthorized(message, accessToken.tokenType), { credentials: credentials || {}, artifacts });
            }

            if (!credentials
                || typeof credentials !== 'object') {
                return h.unauthenticated(Boom.badImplementation('Bad token string received for Bearer auth validation'), { credentials: {} });
            }

            return h.authenticated({ credentials, artifacts });
        }
    };

    return scheme;
};

exports.plugin = {
    pkg: require('../package.json'),
    register: (server, options) => server.auth.scheme('bearer-access-token', internals.implementation)
};
