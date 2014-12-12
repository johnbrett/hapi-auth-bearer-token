# Hapi auth bearer token
[![Build Status](https://travis-ci.org/johnbrett/hapi-auth-bearer-token.svg?branch=master)](https://travis-ci.org/johnbrett/hapi-auth-bearer-token) [![Dependency Status](https://david-dm.org/johnbrett/hapi-auth-bearer-token.svg)](https://david-dm.org/johnbrett/hapi-auth-bearer-token) [![Test Coverage](https://codeclimate.com/github/johnbrett/hapi-auth-bearer-token/badges/coverage.svg)](https://codeclimate.com/github/johnbrett/hapi-auth-bearer-token)

[**hapi**](https://github.com/spumko/hapi) Bearer and Access Token authentication scheme

This project is actively maintained and has 100% unit test coverage. If you have any problems using it or have any feature requests, please raise an issue. Please star if using, so I know where to focus time spent on open source work.

Bearer authentication requires validating a token passed in by either the bearer authorization header, or by an access_token query parameter. The `'bearer-access-token'` scheme takes the following options:

- `validateFunc` - (required) a token lookup and validation function with the signature `function(token, callback)` where:
    - `token` - the auth token received from the client.
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - an internal error.
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Typically, `credentials` are only
          included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails
          (e.g. with authentication mode `'try'`).
- `options` - (optional) 
    - `accessTokenName` (Default: 'access_token') - Rename the token query parameter key e.g. 'sample_token_name' would rename the token query parameter to /route1?sample_token_name=12345678.
    - `allowQueryToken` (Default: true) - Disable accepting token by query parameter, forcing token to be passed in through authorization header.
    - `allowMultipleHeaders` (Default: false) - Allow multiple authorization headers in request, e.g. `Authorization: FD AF6C74D1-BBB2-4171-8EE3-7BE9356EB018; Bearer 12345678`
    - `tokenType` (Default: 'Bearer') - Allow custom token type, e.g. `Authorization: Basic 12345678`

For convenience, the `request` object can be accessed from `this` within validateFunc. This allows some greater flexibility with authentication, such different authentication checks for different routes.

```javascript
var Hapi = require('hapi');

var server = new Hapi.Server();
server.connection({ port: 8080 });

server.register(require('hapi-auth-bearer-token'), function (err) {

    server.auth.strategy('simple', 'bearer-access-token', {
        allowQueryToken: true,              // optional, true by default
        allowMultipleHeaders: false,        // optional, false by default
        accessTokenName: 'access_token',    // optional, 'access_token' by default
        validateFunc: function( token, callback ) {
        
            // For convenience, the request object can be accessed 
            // from `this` within validateFunc.
            var request = this;  
        
            // Use a real strategy here, 
            // comparing with a token from your database for example
            if(token === "1234"){
                callback(null, true, { token: token })
            } else {
                callback(null, false, { token: token })
            }
        }
    });
});

server.route({ 
    method: 'GET', 
    path: '/', 
    handler: function (request, reply) {
        reply('success');
    }, 
    config: { auth: 'simple' } 
});

server.start(function () {
    console.log('Server started at: ' + server.info.uri);
})
```

License MIT @ John Brett 2014
