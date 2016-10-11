'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');

// Declare Internals

const internals = {};

internals.defaults = {
    accessTokenName: 'access_token',
    allowQueryToken: true,
    allowCookieToken: false,
    allowMultipleHeaders: false,
    allowChaining: false,
    tokenType: 'Bearer'
};

internals.schema = Joi.object().keys({
    validateFunc: Joi.func().required(),
    accessTokenName: Joi.string().required(),
    allowQueryToken: Joi.boolean(),
    allowCookieToken: Joi.boolean(),
    allowMultipleHeaders: Joi.boolean(),
    allowChaining: Joi.boolean(),
    tokenType: Joi.string().required()
});

internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing bearer auth strategy options');

    const settings = Hoek.applyToDefaults(internals.defaults, options);

    Joi.assert(settings, internals.schema);

    const headerRegExp = new RegExp(settings.tokenType + '\\s+([^;$]+)','i');

    const scheme = {
        authenticate: (request, reply) => {

            let authorization = request.raw.req.headers.authorization;

            if (settings.allowCookieToken
                && !authorization
                && request.state[settings.accessTokenName] ) {
                authorization = settings.tokenType + ' ' + request.state[settings.accessTokenName];
            }

            if (settings.allowQueryToken
                && !authorization
                && request.query[settings.accessTokenName] ) {
                authorization = settings.tokenType + ' ' + request.query[settings.accessTokenName];
                delete request.query[settings.accessTokenName];
            }

            if (!authorization) {
                return reply(Boom.unauthorized(null, settings.tokenType));
            }

            if (settings.allowMultipleHeaders) {
                const headers = authorization.match(headerRegExp);
                if (headers !== null) {
                    authorization = headers[0];
                }
            }

            const parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== settings.tokenType.toLowerCase()) {
                return reply(Boom.unauthorized(null, settings.tokenType));
            }

            const token = parts[1];

            settings.validateFunc.call(request, token, (err, isValid, credentials, artifacts) => {

                if (err) {
                    return reply(err, { credentials, log: { tags: ['auth', 'bearer'], data: err } });
                }

                if (!isValid) {
                    const message = (settings.allowChaining && request.route.settings.auth.strategies.length > 1) ? null : 'Bad token';

                    return reply(Boom.unauthorized(message, settings.tokenType), { credentials, artifacts });
                }

                if (!credentials
                    || typeof credentials !== 'object') {
                    return reply(Boom.badImplementation('Bad token string received for Bearer auth validation'), { log: { tags: 'token' } });
                }

                return reply.continue({ credentials, artifacts });
            });
        }
    };

    return scheme;
};

exports.register = (server, options, next) => {

    server.auth.scheme('bearer-access-token', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};
