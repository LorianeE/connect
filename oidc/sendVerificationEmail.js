/**
 * Module dependencies
 */
var { URL } = require('url')
var mailer = require('../boot/mailer')
var settings = require('../boot/settings')
var OneTimeToken = require('../models/OneTimeToken')

/**
 * Send verification email middleware
 */

function sendVerificationEmail (req, res, next) {
  // skip if we don't need to send the email
  if (!req.sendVerificationEmail) {
    next()

    // send the email
  } else {
    var user = req.user

    var ttl = (settings.emailVerification &&
      settings.emailVerification.tokenTTL) ||
      (3600 * 24 * 7)

    OneTimeToken.issue({
      ttl: ttl,
      sub: user._id,
      use: 'emailVerification'
    }, function (err, token) {
      if (err) { return next(err) }

      // build email link
      var verifyURL = new URL(settings.issuer)
      verifyURL.pathname = 'email/verify'
      verifyURL.searchParams.set('token', token._id)
      ;['redirect_uri', 'client_id', 'response_type', 'scope', 'nonce']
        .forEach(function (key) {
          var value = req.connectParams[key]
          if (value) {
            verifyURL.searchParams.set(key, value)
          }
        })

      // email template data
      var locals = {
        email: user.email,
        name: {
          first: user.givenName,
          last: user.familyName
        },
        verifyURL: verifyURL.toString()
      }

      // Send verification email
      mailer.getMailer().sendMail('verifyEmail', locals, {
        to: user.email,
        subject: 'Verify your e-mail address'
      }, function (err, responseStatus) {
        if (err) { }
        // TODO: REQUIRES REFACTOR TO MAIL QUEUE
        next()
      })
    })
  }
}

/**
 * Export
 */

module.exports = sendVerificationEmail
