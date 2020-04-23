/**
 * Module dependencies
 */

var settings = require('../boot/settings')
const { JWT } = require('jose')
var UnauthorizedError = require('../errors/UnauthorizedError')

/**
 * Client Bearer Token Authentication Middleware
 */

function verifyClientToken (req, res, next) {
  var header = req.headers.authorization

  // missing header
  if (!header) {
    return next(new UnauthorizedError({
      realm: 'client',
      error: 'unauthorized_client',
      error_description: 'Missing authorization header',
      statusCode: 403
    }))

    // header found
  } else {
    var jwt = header.replace('Bearer ', '')
    var token
    try {
      token = JWT.verify(jwt, settings.keys.sig.pub) && JWT.decode(jwt, { complete: true })
    } catch (err) {
      token = err
    }

    // failed to decode
    if (!token || token instanceof Error) {
      next(new UnauthorizedError({
        realm: 'client',
        error: 'unauthorized_client',
        error_description: 'Invalid access token',
        statusCode: 403
      }))

      // decoded successfully
    } else {
      // validate token
      req.token = token
      next()
    }
  }
}

/**
 * Exports
 */

module.exports = verifyClientToken
