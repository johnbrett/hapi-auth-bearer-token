var Boom = require('boom');
var Hoek = require('hoek');

exports.register = function (plugin, options, next) {

    plugin.auth.scheme('bearer-access-token', function (server, options) {

        Hoek.assert(options, 'Missing bearer auth strategy options');
        Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in bearer scheme');

        options.accessTokenName = options.accessTokenName || "access_token";
        options.allowQueryToken = options.allowQueryToken === false ? false : true;

        var settings = Hoek.clone(options);

        var scheme = {
            authenticate: function (request, reply) {

                var req = request.raw.req;
                var authorization = req.headers.authorization;

                if(settings.allowQueryToken
                    && !authorization
                    && request.query[settings.accessTokenName]){
                    authorization = "Bearer " + request.query[settings.accessTokenName];
                    delete request.query[settings.accessTokenName];
                }
                if (!authorization) {
                    return reply(Boom.unauthorized(null, 'Bearer'));
                }

                // find bearer in any part of the Authorization header
                // e.g
                // Authorization: Bearer 12345678
                // Authorization: Bearer 12345678; FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018
                // Authorization: FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018; Bearer 12345678
                var parts = authorization.match(/Bearer\s+([^;$]+)/i);

                if (!parts) {
                    return reply(Boom.unauthorized(null, 'Bearer'));
                }

                if (parts.length !== 2 || parts[1].length < 1) {
                    return reply(Boom.badRequest('Bad HTTP authentication header format', 'Bearer'));
                }

                var token = parts[1];

                settings.validateFunc.call(request, token, function (err, isValid, credentials) {

                    if (err) {
                        return reply(err, { credentials: credentials, log: { tags: ['auth', 'bearer'], data: err } }).code(500);
                    }

                    if (!isValid) {
                        return reply(Boom.unauthorized('Bad token', 'Bearer'), { credentials: credentials });
                    }

                    if (!credentials
                        || typeof credentials !== 'object') {
                        return reply(Boom.badImplementation('Bad token string received for Bearer auth validation'), { log: { tags: 'token' } });
                    }

                    return reply(null, { credentials: credentials });
                });
            }
        };

        return scheme;
    });

    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};
