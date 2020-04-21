chai = require 'chai'
sinon = require 'sinon'
sinonChai = require 'sinon-chai'
expect = chai.expect
proxyquire = require('proxyquire').noCallThru()

chai.use sinonChai
chai.should()


settings = require '../../../boot/settings'
AccessToken = proxyquire('../../../models/AccessToken', {
  '../boot/redis': {
    getClient: () => {}
  }
})
verifyClientReg = proxyquire('../../../oidc/verifyClientRegistration', {
  '../models/AccessToken': AccessToken
})

clientRegType = settings.client_registration
trustedRegScope = settings.trusted_registration_scope
regScope = settings.registration_scope


describe 'Verify Scoped Client Registration', ->
  before ->
    settings.client_registration = 'scoped'
    settings.trusted_registration_scope = 'realm'
    settings.registration_scope = 'developer'

  after ->
    settings.client_registration = clientRegType
    settings.trusted_registration_scope = trustedRegScope
    settings.registration_scope = 'developer'


  { req, res, next, err } = {}


  describe 'with missing bearer token', ->
    before (done) ->
      req = { headers: {}, body: {} }
      res = {}

      verifyClientReg req, res, (error) ->
        err = error
        done()

    it 'should provide an UnauthorizedError', ->
      err.name.should.equal 'UnauthorizedError'

    it 'should provide a realm', ->
      err.realm.should.equal 'user'

    it 'should provide an error code', ->
      err.error.should.equal 'invalid_request'

    it 'should provide an error description', ->
      err.error_description.should.equal 'Missing access token'

    it 'should provide a status code', ->
      err.statusCode.should.equal 400


  describe 'with insufficient trusted scope', ->
    before (done) ->
      req =
        bearer: 'valid.jwt'
        claims:
          sub: 'uuid1'
        body: { trusted: true }

      res = {}

      verifyClientReg req, res, (error) ->
        err = error
        done()

    it 'should provide an UnauthorizedError', ->
      err.name.should.equal 'UnauthorizedError'

    it 'should provide a realm', ->
      err.realm.should.equal 'user'

    it 'should provide an error code', ->
      err.error.should.equal 'insufficient_scope'

    it 'should provide an error description', ->
      err.error_description.should.equal 'User does not have permission'

    it 'should provide a status code', ->
      err.statusCode.should.equal 403


  describe 'with insufficient scope', ->
    before (done) ->
      req =
        bearer: 'valid.jwt'
        claims:
          sub: 'uuid1'
          scope: 'other'
        body: { trusted: false }


      res = {}

      verifyClientReg req, res, (error) ->
        err = error
        done()

    it 'should provide an UnauthorizedError', ->
      err.name.should.equal 'UnauthorizedError'

    it 'should provide a realm', ->
      err.realm.should.equal 'user'

    it 'should provide an error code', ->
      err.error.should.equal 'insufficient_scope'

    it 'should provide an error description', ->
      err.error_description.should.equal 'User does not have permission'

    it 'should provide a status code', ->
      err.statusCode.should.equal 403


  describe 'with sufficient trusted scope', ->
    before (done) ->
      req =
        bearer: 'valid.jwt'
        claims:
          sub: 'uuid1'
          scope: 'realm'
        body: { trusted: true }

      res = {}
      next = sinon.spy (error) ->
        err = error
        done()

      verifyClientReg req, res, next

    it 'should not provide an error', ->
      expect(err).to.be.undefined

    it 'should continue', ->
      next.should.have.been.called


  describe 'with sufficient scope', ->
    before (done) ->
      req =
        bearer: 'valid.jwt'
        claims:
          sub: 'uuid1'
          scope: 'developer'
        body: {}

      res = {}
      next = sinon.spy (error) ->
        err = error
        done()

      verifyClientReg req, res, next

    it 'should not provide an error', ->
      expect(err).to.be.undefined

    it 'should continue', ->
      next.should.have.been.called




