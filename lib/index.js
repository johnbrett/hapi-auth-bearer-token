'use strict';

const Boom = require('boom');
const Hoek = require('hoek');

// Declare Internals

const internals = {};

exports.register = (server, options, next) => {

    server.auth.scheme('bearer-access-token', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing bearer auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in bearer scheme');

    options.accessTokenName = options.accessTokenName || 'access_token';
    options.allowQueryToken = options.allowQueryToken === false ? false : true;
    options.allowMultipleHeaders = options.allowMultipleHeaders === true ? true : false;
    options.tokenType = options.tokenType || 'Bearer';

    const settings = Hoek.clone(options);

    settings.headerRegExp = new RegExp(options.tokenType + '\\s+([^;$]+)','i');

    const scheme = {
        authenticate: (request, reply) => {

            const req = request.raw.req;
            let authorization = req.headers.authorization;

            if (settings.allowQueryToken
                && !authorization
                && request.query[settings.accessTokenName] ) {
                authorization = options.tokenType + ' ' + request.query[settings.accessTokenName];
                delete request.query[settings.accessTokenName];
            }

            if (!authorization) {
                return reply(Boom.unauthorized(null, options.tokenType));
            }

            if (settings.allowMultipleHeaders) {
                const headers = authorization.match(settings.headerRegExp);
                if (headers !== null) {
                    authorization = headers[0];
                }
            }

            const parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== options.tokenType.toLowerCase()) {
                return reply(Boom.unauthorized(null, options.tokenType));
            }

            const token = parts[1];

            settings.validateFunc.call(request, token, (err, isValid, credentials, artifacts) => {

                if (err) {
                    return reply(err, { credentials, log: { tags: ['auth', 'bearer'], data: err } });
                }

                if (!isValid) {
                    const message = (options.allowChaining && request.route.settings.auth.strategies.length > 1) ? null : 'Bad token';

                    return reply(Boom.unauthorized(message, options.tokenType), { credentials, artifacts });
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
