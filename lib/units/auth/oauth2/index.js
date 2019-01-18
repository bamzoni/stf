var http = require('http')

var URI = require('urijs');
var ClientOAuth2 = require('client-oauth2')
var request = require('request');

var express = require('express')
var passport = require('passport')

var logger = require('../../../util/logger')
var urlutil = require('../../../util/urlutil')
var jwtutil = require('../../../util/jwtutil')
var Strategy = require('./strategy')

module.exports = function(options) {
  var log = logger.createLogger('auth-oauth2')
  var app = express()
  var server = http.createServer(app)

  var auth = new ClientOAuth2({
    clientId: options.oauth.clientID,
    clientSecret: options.oauth.clientSecret,
    accessTokenUri: options.oauth.tokenURL,
    authorizationUri: options.oauth.authorizationURL,
    redirectUri: options.oauth.callbackURL,
    scopes: options.oauth.scope})
  
    app.get("/auth/oauth", function (req, res) {
            var uri = URI(auth.code.getUri())
            var uri = uri.addSearch("hd", options.domain)
            res.redirect(uri)
    });
  
  app.get(
    '/auth/oauth/callback'
  , function(req, res) {
    request.post(options.oauth.tokenURL, 
      { form: 
        {
          code: req.query.code, 
          client_id: options.oauth.clientID,
          client_secret: options.oauth.clientSecret,
          redirect_uri: options.oauth.callbackURL,
          grant_type: "authorization_code"
        }
      }, function (error, response, body) {
      console.log('error:', error); // Print the error if one occurred
      console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received

      if (!error && response.statusCode == 200) {

        const info = JSON.parse(body);
        
        request(options.oauth.userinfoURL,
          {
            'auth': {
              'bearer': info.access_token
            }
          },
          function (error2, response2, body2) {
          console.log('error2:', error2); // Print the error if one occurred
          console.log('statusCode2:', response2 && response2.statusCode); // Print the response status code if a response was received
          console.log('body2:', body2);
          if (!error2 && response2.statusCode == 200) {
            const info2 = JSON.parse(body2);
            res.redirect(urlutil.addParams(options.appUrl, {
              jwt: jwtutil.encode({
                payload: {
                  email: info2.email
                , name: info2.email.split('@', 1).join('')
                }
              , secret: options.secret
              , header: {
                  exp: Date.now() + 24 * 3600
                }
              })
            }))
          }
          
        });

        
      
      }
      console.log('body:', body);
    });
        

        
    }
  )

  server.listen(options.port)
  log.info('Listening on port %d', options.port)
}
