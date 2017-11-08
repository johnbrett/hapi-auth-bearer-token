'use strict';

const Boom = require('boom');
const Bounce = require('bounce');
const Hoek = require('hoek');
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
    unauthorizedFunc: Boom.unauthorized
};

internals.schema = Joi.object().keys({
    validateFunc: Joi.func().required(),
    accessTokenName: Joi.string().required(),
    allowQueryToken: Joi.boolean(),
    allowCookieToken: Joi.boolean(),
    allowMultipleHeaders: Joi.boolean(),
    allowChaining: Joi.boolean(),
    tokenType: Joi.string().required(),
    unauthorizedFunc: Joi.func()
});

internals.implementation = (server, options) => {

    Hoek.assert(options, new Error('Missing bearer auth strategy options'));
    const settings = Hoek.applyToDefaults(internals.defaults, options);

    Joi.assert(settings, internals.schema);

    const headerRegExp = new RegExp(settings.tokenType + '\\s+([^;$]+)','i');

    const scheme = {
        authenticate: async (request, h) => {

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
                return settings.unauthorizedFunc(null, settings.tokenType);
            }

            if (settings.allowMultipleHeaders) {
                const headers = authorization.match(headerRegExp);
                if (headers !== null) {
                    authorization = headers[0];
                }
            }

            const parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== settings.tokenType.toLowerCase()) {
                return settings.unauthorizedFunc(null, settings.tokenType);
            }

            const token = parts[1];

            let validationResult;
            try {
                validationResult = await settings.validateFunc.call(request, token);
            }
            catch (err) {
                Bounce.rethrow(err, 'system');  // Rethrows system errors and ignores application errors
                if (err.isBoom) {
                    return err;
                }
                return err;
            }

            if (!validationResult.isValid) {
                const message = (settings.allowChaining && request.route.settings.auth.strategies.length > 1) ? null : 'Bad token';
                return h.unauthenticated(settings.unauthorizedFunc(message, settings.tokenType), {
                    credentials: validationResult.credentials,
                    artifacts: validationResult.artifacts
                });
            }

            if (!validationResult.credentials
                || typeof validationResult.credentials !== 'object') {
                return h.unauthenticated(Boom.badImplementation('Bad token string received for Bearer auth validation'), { credentials: {} });
            }

            return h.authenticated({
                credentials: validationResult.credentials,
                artifacts: validationResult.artifacts
            });
        }
    };

    return scheme;
};

exports.plugin = {
    pkg: require('../package.json'),
    register: function (server, options) {

        return server.auth.scheme('bearer-access-token', internals.implementation);
    }
};
