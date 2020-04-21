chai      = require 'chai'
sinon     = require 'sinon'
sinonChai = require 'sinon-chai'
expect = chai.expect
proxyquire = require('proxyquire').noCallThru()


chai.use sinonChai
chai.should()


mailer = require '../../../boot/mailer'
fakeMailer =
  sendMail: (tmpl, loc, opts, cb) ->
    cb()

OneTimeToken = proxyquire('../../../models/OneTimeToken', {
  '../boot/redis': {
    getClient: () => {}
  }
})
sendVerificationEmail = proxyquire('../../../oidc/sendVerificationEmail', {
  '../models/OneTimeToken': OneTimeToken
})


describe 'Send Verification Email', ->
  before ->
    sinon.stub(mailer, 'getMailer').returns(fakeMailer)

  after ->
    mailer.getMailer.restore()


  {req,res,next} = {}


  describe 'when not requested', ->

    before ->
      req =
        provider:
          emailVerification:
            enable: false
        sendVerificationEmail: false
      res = {}
      next = sinon.spy()

      sinon.spy(OneTimeToken, 'issue')
      sinon.spy(fakeMailer, 'sendMail')

      sendVerificationEmail req, res, next

    after ->
      OneTimeToken.issue.restore()
      fakeMailer.sendMail.restore()

    it 'should continue', ->
      next.should.have.been.called

    it 'should not issue a OneTimeToken', ->
      OneTimeToken.issue.should.not.have.been.called

    it 'should not send an email', ->
      fakeMailer.sendMail.should.not.have.been.called



  describe 'when requested', ->

    before ->
      req =
        connectParams:
          redirect_uri:  'https://example.com/callback'
          client_id:     'client-uuid'
          response_type: 'id_token token'
          scope:         'openid profile'
        provider:
          emailVerification:
            enable: true
        sendVerificationEmail: true
        user:
          _id: 'uuid'
          email: 'joe@example.com'
          givenName: 'joe'
          familyName: 'johnson'
      res = {}
      next = sinon.spy()

      sinon.stub(OneTimeToken, 'issue')
        .callsArgWith(1, null, new OneTimeToken {
          sub: req.user._id
          ttl: 3600 * 24 * 7
          use: 'emailVerification'
        })
      sinon.stub(fakeMailer, 'sendMail').callsArgWith 3, null, null

      sendVerificationEmail req, res, next

    after ->
      OneTimeToken.issue.restore()
      fakeMailer.sendMail.restore()

    it 'should issue a token to the user', ->
      OneTimeToken.issue.should.have.been.calledWith sinon.match({
        sub: req.user._id
      })

    it 'should issue an expiring token', ->
      OneTimeToken.issue.should.have.been.calledWith sinon.match({
        ttl: sinon.match.number
      })

    it 'should issue a token for email verification', ->
      OneTimeToken.issue.should.have.been.calledWith sinon.match({
        use: 'emailVerification'
      })

    it 'should send to the user', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match.object, sinon.match({
          to: req.user.email
        })

    it 'should provide a subject', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match.object, sinon.match({
          subject: sinon.match.string
        })

    it 'should render with the user email', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match({
          email: req.user.email
        })

    it 'should render with the user given name', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match({
          name: {
            first: req.user.givenName
          }
        })

    it 'should render with the user family name', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match({
          name: {
            last: req.user.familyName
          }
        })

    it 'should render with the verification url', ->
      fakeMailer.sendMail.should.have.been
        .calledWith 'verifyEmail', sinon.match({
          verifyURL: sinon.match.string
        })

    it 'should continue', ->
      next.should.have.been.called
      next.should.not.have.been.calledWith sinon.match.any


