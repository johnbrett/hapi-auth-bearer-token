var Boom = require('boom');
var Hoek = require('hoek');

exports.register = function (server, options, next) {

    server.auth.scheme('bearer-access-token', function (server, options) {

        Hoek.assert(options, 'Missing bearer auth strategy options');
        Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in bearer scheme');

        options.accessTokenName = options.accessTokenName || "access_token";
        options.allowQueryToken = options.allowQueryToken === false ? false : true;
        options.allowMultipleHeaders = options.allowMultipleHeaders === true ? true : false;
        options.tokenType = options.tokenType || 'Bearer';

        var settings = Hoek.clone(options);

        var scheme = {
            authenticate: function (request, reply) {

                var req = request.raw.req;
                var authorization = req.headers.authorization;

                if(settings.allowQueryToken
                    && !authorization
                    && request.query[settings.accessTokenName]){
                    authorization = options.tokenType + " " + request.query[settings.accessTokenName];
                    delete request.query[settings.accessTokenName];
                }
                
                if (!authorization) {
                    return reply(Boom.unauthorized(null, options.tokenType));
                }

                if(settings.allowMultipleHeaders) {
                    var headers = authorization.match(/Bearer\s+([^;$]+)/i);
                    if(headers !== null) {
                        authorization = headers[0];
                    }
                }

                var parts = authorization.split(/\s+/);

                if (parts[0].toLowerCase() !== options.tokenType.toLowerCase()) {
                    return reply(Boom.unauthorized(null, options.tokenType));
                }

                var token = parts[1];

                settings.validateFunc.call(request, token, function (err, isValid, credentials) {

                    if (err) {
                        return reply(err, { credentials: credentials, log: { tags: ['auth', 'bearer'], data: err } });
                    }

                    if (!isValid) {
                        return reply(Boom.unauthorized('Bad token', options.tokenType), { credentials: credentials });
                    }

                    if (!credentials
                        || typeof credentials !== 'object') {
                        return reply(Boom.badImplementation('Bad token string received for Bearer auth validation'), { log: { tags: 'token' } });
                    }
                    
                    return reply.continue({ credentials: credentials });
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
