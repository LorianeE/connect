/**
 * Middleware dependencies
 *
 * This middleware depends on the following to be run first:
 *
 *   -  req.login() (passport)
 *   -  determineProvider
 */

/**
 * Module dependencies
 */

var Role = require('../models/Role')
var mailer = require('../boot/mailer').getMailer()
var settings = require('../boot/settings')
var { URL } = require('url')

/**
 * Require verified email middleware
 */

module.exports = function (options) {
  options = options || {}

  options = {
    force: options.force || false,
    view: options.view || 'requireVerifiedEmail',
    locals: options.locals || {}
  }

  return function requireVerifiedEmail (req, res, next) {
    Role.listByUsers(req.user, function (err, roles) {
      if (err) { return next(err) }

      var isAuthority = roles && roles.some(function (role) {
        return role && role.name && role.name === 'authority'
      })

      if (req.user.emailVerified || isAuthority) {
        next()
      } else if (!req.provider.emailVerification.enable) {
        next()
      } else if (!options.force && !req.provider.emailVerification.require) {
        next()
      } else {
        var resendURL = new URL(settings.issuer)

        resendURL.pathname = 'email/resend'
        resendURL.searchParams.set('email', req.user.email)
        if (req.connectParams) {
          resendURL.searchParams.set('redirect_uri', req.connectParams.redirect_uri)
          resendURL.searchParams.set('client_id', req.connectParams.client_id)
          resendURL.searchParams.set('response_type', req.connectParams.response_type)
          resendURL.searchParams.set('scope', req.connectParams.scope)
        }

        var existingUserMsg = 'E-mail verification is required to proceed'
        var newUserMsg = 'Congratulations on creating your user account! ' +
          'All that\'s left now is to verify your e-mail.'

        var isNewUser = req.flash('isNewUser').indexOf(true) !== -1

        var locals = {
          error: options.locals.error === undefined
            ? (!isNewUser ? existingUserMsg : undefined) : options.locals.error,
          message: options.locals.message === undefined
            ? (isNewUser ? newUserMsg : undefined) : options.locals.message,
          from: options.locals.from || mailer.from,
          resendURL: options.locals.resendURL || resendURL.toString()
        }
        res.render(options.view, locals)
      }
    })
  }
}
