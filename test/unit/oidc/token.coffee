chai = require 'chai'
sinon = require 'sinon'
sinonChai = require 'sinon-chai'
expect = chai.expect
proxyquire = require('proxyquire').noCallThru()


chai.use sinonChai
chai.should()


settings = require '../../../boot/settings'
ClientToken = require '../../../models/ClientToken'
IDToken = require '../../../models/IDToken'

AuthorizationCode = proxyquire('../../../models/AuthorizationCode', {
  '../boot/redis': {
    getClient: () => {}
  }
})
AccessToken = proxyquire('../../../models/AccessToken', {
  '../boot/redis': {
    getClient: () => {}
  }
})
token = proxyquire('../../../oidc/token', {
  '../models/AccessToken': AccessToken
})

describe 'Token response', ->
  { req, res, next, err } = {}


  describe 'authorization code grant with no nonce', ->
    { at } = {}

    before (done) ->
      at = AccessToken.initialize()
      sinon.stub(AccessToken, 'exchange').callsArgWith(1, null, at)
      sinon.spy(IDToken.prototype, 'initializePayload')

      req =
        body:
          grant_type: 'authorization_code'
          state: 'st4t3'
        code:
          user_id: 'uuid1'
          client_id: 'uuid2'
        client:
          access_token_type: 'random'
        session:
          opbs: 'h4sh'
          amr: ['pwd']
      res =
        set: sinon.spy()
        json: sinon.spy()
      next = sinon.spy (error) ->
        err = error
        done()

      token req, res, next
      done()

    after ->
      AccessToken.exchange.restore()
      IDToken.prototype.initializePayload.restore()

    it 'should respond with access_token', ->
      res.json.should.have.been.calledWith sinon.match({ access_token: at.at })

    it 'should respond with token_type', ->
      res.json.should.have.been.calledWith sinon.match({ token_type: 'Bearer' })

    it 'should respond with expires_in', ->
      res.json.should.have.been.calledWith sinon.match({ expires_in: 3600 })

    it 'should respond with id_token', ->
      res.json.should.have.been.calledWith sinon.match({
        id_token: sinon.match.string
      })

    it 'should respond with state', ->
      res.json.should.have.been.calledWith sinon.match({ state: 'st4t3' })

    it 'should not have nonce', ->
      jwt = IDToken.decode(res.json.firstCall.args[0].id_token, settings.keys.sig.pub)
      expect(jwt.payload.nonce).to.be.undefined

    it 'should respond with session_state', ->
      res.json.should.have.been.calledWith sinon.match({
        session_state: sinon.match.string
      })

    it 'should include `amr` claim in id_token', ->
      IDToken.prototype.initializePayload.should.have.been.calledWith(
        sinon.match amr: req.session.amr
      )


  describe 'authorization code grant with optional nonce', ->
    { at } = {}

    before (done) ->
      at = AccessToken.initialize()
      sinon.stub(AccessToken, 'exchange').callsArgWith(1, null, at)

      req =
        body:
          grant_type: 'authorization_code'
          state: 'st4t3'
        code:
          user_id: 'uuid1'
          client_id: 'uuid2'
          nonce: 'noncf7'
        client:
          access_token_type: 'random'
        session:
          opbs: 'h4sh'
      res =
        set: sinon.spy()
        json: sinon.spy()
      next = sinon.spy (error) ->
        err = error
        done()

      token req, res, next
      done()

    after ->
      AccessToken.exchange.restore()

    it 'should have nonce', ->
      jwt = IDToken.decode(res.json.firstCall.args[0].id_token, settings.keys.sig.pub)
      jwt.payload.nonce.should.equal 'noncf7'


  describe 'refresh grant', ->
    { at } = {}

    before (done) ->
      at = AccessToken.initialize({ cid: 'uuid2', uid: 'uuid1' })
      sinon.stub(AccessToken, 'refresh').callsArgWith(2, null, at)
      sinon.spy(IDToken.prototype, 'initializePayload')

      req =
        body:
          grant_type: 'refresh_token'
          state: 'st4t3'
        client:
          _id: 'uuid2'
          access_token_type: 'random'
        session:
          opbs: 'h4sh'
          amr: ['otp']
      res =
        set: sinon.spy()
        json: sinon.spy()
      next = sinon.spy (error) ->
        err = error
        done()

      token req, res, next
      done()

    after ->
      IDToken.prototype.initializePayload.restore()


    it 'should respond with access_token', ->
      res.json.should.have.been.calledWith sinon.match({ access_token: at.at })

    it 'should respond with token_type', ->
      res.json.should.have.been.calledWith sinon.match({ token_type: 'Bearer' })

    it 'should respond with expires_in', ->
      res.json.should.have.been.calledWith sinon.match({ expires_in: 3600 })

    it 'should respond with id_token', ->
      res.json.should.have.been.calledWith sinon.match({
        id_token: sinon.match.string
      })

    it 'should respond with state', ->
      res.json.should.have.been.calledWith sinon.match({ state: 'st4t3' })

    it 'should respond with session_state', ->
      res.json.should.have.been.calledWith sinon.match({
        session_state: sinon.match.string
      })

    it 'should include `amr` claim in id_token', ->
      IDToken.prototype.initializePayload.should.have.been.calledWith(
        sinon.match amr: req.session.amr
      )


  describe 'client credentials grant', ->
    before (done) ->
      sinon.spy(ClientToken, 'issue')

      req =
        body:
          grant_type: 'client_credentials'
        client:
          _id: 'uuid3'
          default_max_age: 3600
        scope: 'register other'
      res =
        set: sinon.spy()
        json: sinon.spy()
      next = sinon.spy (error) ->
        err = error
        done()

      token req, res, next
      done()

    after ->
      ClientToken.issue.restore()

    it 'should issue a client token with client_id as sub', ->
      ClientToken.issue.should.have.been.calledWith sinon.match({
        sub: 'uuid3'
      })

    it 'should issue a client token with client_id as aud', ->
      ClientToken.issue.should.have.been.calledWith sinon.match({
        aud: 'uuid3'
      })

    it 'should issue a client token with authorized client scope', ->
      ClientToken.issue.should.have.been.calledWith sinon.match({
        scope: 'register other'
      })

    it 'should respond with access_token', ->
      res.json.should.have.been.calledWith sinon.match({
        access_token: sinon.match('eyJhbGciOiJSUzI1NiJ9.')
      })

    it 'should respond with token_type', ->
      res.json.should.have.been.calledWith sinon.match({
        token_type: 'Bearer'
      })

    it 'should respond with expires_in', ->
      res.json.should.have.been.calledWith sinon.match({
        expires_in: 3600
      })
