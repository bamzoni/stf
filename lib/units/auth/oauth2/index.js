var http = require('http')

var URI = require('urijs');
var ClientOAuth2 = require('client-oauth2')

var express = require('express')
var passport = require('passport')

var logger = require('../../../util/logger')
var urlutil = require('../../../util/urlutil')
var jwtutil = require('../../../util/jwtutil')
var Strategy = require('./strategy')

module.exports = function(options) {

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
        res.redirect(urlutil.addParams(options.appUrl, {
          jwt: jwtutil.encode({
            payload: {
              email: req.user.email
            , name: req.user.email.split('@', 1).join('')
            }
          , secret: options.secret
          , header: {
              exp: Date.now() + 24 * 3600
            }
          })
        }))
    }
  )

  server.listen(options.port)
  log.info('Listening on port %d', options.port)
}
