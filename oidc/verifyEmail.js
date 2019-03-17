/**
 * Module dependencies
 */

var settings = require('../boot/settings')
var User = require('../models/User')
var OneTimeToken = require('../models/OneTimeToken')
var url = require('url')

/**
 * Verify Email
 *
 * verifyEmail is a route handler that takes an email
 * verification request and matches a token parameter
 * to a OneTimeToken. Assuming there is a valid OneTimeToken
 * instance matching the token, it updates the user's
 * emailVerified claim to true along with a timestamp.
 *
 * This handler requires oidc.selectConnectParams and
 * oidc.verifyRedirectURI middleware upstream.
 */

function verifyEmail (req, res, next) {
  // ensure there's a token in the request params
  if (!req.query.token) {
    return res.render('verifyEmail', {
      error: 'Missing verification code.'
    })
  }

  // consume the token
  OneTimeToken.consume(req.query.token, function (err, token) {
    if (err) { return next(err) }

    // Invalid or expired token
    if (!token || token.use !== 'emailVerification') {
      return res.render('verifyEmail', {
        error: 'Invalid or expired verification code.'
      })
    }

    // Update the user
    User.patch(token.sub, {
      dateEmailVerified: Date.now(),
      emailVerified: true
    }, function (err, user) {
      if (err) { return next(err) }

      // unknown user
      if (!user) {
        return res.render('verifyEmail', {
          error: 'Unable to verify email for this user.'
        })
      }

      // check that the redirect uri is valid and safe to use
      if (req.client && req.connectParams.redirect_uri) {
        var continueURL = new url.URL(settings.issuer)

        continueURL.pathname = 'signin'
        continueURL.query = {
          redirect_uri: req.connectParams.redirect_uri,
          client_id: req.connectParams.client_id,
          response_type: req.connectParams.response_type,
          scope: req.connectParams.scope,
          nonce: req.connectParams.nonce
        }

        res.render('verifyEmail', {
          signin: {
            url: url.format(continueURL),
            client: req.client
          }
        })
      } else {
        res.render('verifyEmail')
      }
    })
  })
}

/**
 * Exports
 */

module.exports = verifyEmail
