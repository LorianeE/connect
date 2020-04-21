# Test dependencies
cwd       = process.cwd()
path      = require 'path'
faker     = require 'faker'
chai      = require 'chai'
sinon     = require 'sinon'
sinonChai = require 'sinon-chai'
mockMulti = require '../lib/multi'
qs        = require 'qs'
expect = chai.expect
proxyquire = require('proxyquire').noCallThru()


# Configure Chai and Sinon
chai.use sinonChai
chai.should()


# Code under test
Modinha = require 'modinha'
Role = proxyquire(path.join(cwd, 'models/Role'), {
  '../boot/redis': {
    getClient: () => {}
  }
})
User = proxyquire(path.join(cwd, 'models/User'), {
  '../boot/redis': {
    getClient: () => {}
  }
})
settings = require path.join(cwd, 'boot/settings')


# Redis lib for spying and stubbing
Redis = require('redis-mock')
rclient = Redis.prototype
{ client, multi } = {}


describe 'User', ->

  before ->
    client = Redis.createClient()
    multi = mockMulti(client)
    User.__client = client
    Role.__client = client

  after ->
    multi.restore()


  {data,user,users,role,roles,jsonUsers} = {}
  {err,validation,instance,instances,update,deleted,original,ids} = {}
  {stat,info,options,userInfo} = {}


  before ->

    # Mock data
    data = []

    for i in [0..9]
      data.push
        name:     "#{faker.name.firstName()} #{faker.name.lastName()}"
        email:    faker.internet.email()
        hash:     'private'
        password: 'secret1337'

    users = User.initialize(data, { private: true })
    jsonUsers = users.map (d) ->
      User.serialize(d)
    ids = users.map (d) ->
      d._id


  describe 'schema', ->

    beforeEach ->
      user = new User
      validation = user.validate()

    it 'should have unique identifier', ->
      User.schema[User.uniqueId].should.be.a('object')


    # STANDARD CLAIMS

    it 'should have name', ->
      User.schema.name.type.should.equal 'string'

    it 'should have given name', ->
      User.schema.givenName.type.should.equal 'string'

    it 'should have family name', ->
      User.schema.familyName.type.should.equal 'string'

    it 'should have middle name', ->
      User.schema.middleName.type.should.equal 'string'

    it 'should have nickname', ->
      User.schema.nickname.type.should.equal 'string'

    it 'should have perferredUsername', ->
      User.schema.preferredUsername.type.should.equal 'string'

    it 'should have profile', ->
      User.schema.profile.type.should.equal 'string'

    it 'should have picture', ->
      User.schema.picture.type.should.equal 'string'

    it 'should have website', ->
      User.schema.website.type.should.equal 'string'

    it 'should have email', ->
      User.schema.email.type.should.equal 'string'

    # Currently email is not required
    it 'should not require email', ->
      validation = (new User email: undefined).validate()
      validation.valid.should.be.true

    ###
    # If email is required
    it 'should require email', ->
      validation.errors.email.attribute.should.equal 'required'
    ###

    it 'should require email to be valid', ->
      validation = (new User email: 'not-valid').validate()
      validation.errors.email.attribute.should.equal 'format'

    it 'should have email verified', ->
      User.schema.emailVerified.type.should.equal 'boolean'

    it 'should have gender', ->
      User.schema.gender.type.should.equal 'string'

    it 'should have birthdate', ->
      User.schema.birthdate.type.should.equal 'string'

    it 'should have zoneinfo', ->
      User.schema.zoneinfo.type.should.equal 'string'

    it 'should have locale', ->
      User.schema.locale.type.should.equal 'string'

    it 'should have phone number', ->
      User.schema.phoneNumber.type.should.equal 'string'

    it 'should have phone number verified', ->
      User.schema.phoneNumberVerified.type.should.equal 'boolean'

    it 'should have address', ->
      User.schema.address.type.should.equal 'object'


    # HASHED PASSWORD

    it 'should have hash', ->
      User.schema.hash.type.should.equal 'string'

    it 'should hash a password', ->
      user = new User { password: 'secret1337' }, { private: true }
      expect(typeof user.hash).equals 'string'

    it 'should protect hash', ->
      User.schema.hash.private.should.equal true


    # TIMESTAMPS

    it 'should have "created" timestamp', ->
      User.schema.created.default.should.equal Modinha.defaults.timestamp

    it 'should have "modified" timestamp', ->
      User.schema.modified.default.should.equal Modinha.defaults.timestamp




  describe 'insert', ->

    describe 'with valid data', ->

      beforeEach (done) ->
        sinon.spy multi, 'hset'
        sinon.spy multi, 'zadd'
        sinon.spy User, 'index'
        sinon.stub(User, 'enforceUnique').callsArgWith(1, null)
        sinon.stub(multi, 'exec').callsArgWith 0, null

        User.insert data[0], (error, result) ->
          err = error
          instance = result
          done()

      afterEach ->
        multi.hset.restore()
        multi.zadd.restore()
        User.index.restore()
        User.enforceUnique.restore()
        multi.exec.restore()

      it 'should provide a null error', ->
        expect(err).to.be.null

      it 'should provide the inserted instance', ->
        expect(instance).to.be.instanceof User

      it 'should not provide private properties', ->
        expect(instance.hash).to.be.undefined

      it 'should store the hashed password', ->
        multi.hset.should.have.been.calledWith 'users', instance._id, sinon.match('"hash":"')

      it 'should discard the password', ->
        expect(instance.password).to.be.undefined
        multi.hset.should.not.have.been.calledWith 'users', instance._id, sinon.match('password')

      it 'should store the serialized instance by unique id', ->
        multi.hset.should.have.been.calledWith 'users', instance._id, sinon.match('"name":"' + instance.name + '"')

      it 'should index the instance', ->
        User.index.should.have.been.calledWith sinon.match.object, sinon.match(instance)


    describe 'with invalid data', ->

      before (done) ->
        sinon.spy multi, 'hset'
        sinon.spy multi, 'zadd'
        sinon.spy User, 'index'

        User.insert { email: 'not-valid', password: 'secret1337' }, (error, result) ->
          err = error
          instance = result
          done()

      after ->
        multi.hset.restore()
        multi.zadd.restore()
        User.index.restore()

      it 'should provide a validation error', ->
        err.should.be.instanceof Modinha.ValidationError

      it 'should not provide an instance', ->
        expect(instance).to.be.undefined

      it 'should not store the data', ->
        multi.hset.should.not.have.been.called

      it 'should not index the data', ->
        User.index.should.not.have.been.called


    describe 'with a weak password', ->

      before (done) ->
        User.insert { email: 'valid@example.com', password: 'secret' }, (error, result) ->
          err = error
          instance = result
          done()

      it 'should provide an error', ->
        err.name.should.equal 'InsecurePasswordError'

      it 'should not provide an instance', ->
        expect(instance).to.be.undefined


    describe 'without a password', ->

      before (done) ->
        User.insert { email: 'valid@example.com' }, (error, instance) ->
          err = error
          user = instance
          done()

      it 'should provide an error', ->
        err.name.should.equal 'PasswordRequiredError'

      it 'should not provide an instance', ->
        expect(user).to.be.undefined


    describe 'with private values option', ->

      beforeEach (done) ->
        sinon.spy multi, 'hset'
        sinon.spy multi, 'zadd'
        sinon.spy User, 'index'
        sinon.stub(User, 'enforceUnique').callsArgWith(1, null)
        sinon.stub(multi, 'exec').callsArgWith 0, null, []

        User.insert data[0], { private: true }, (error, result) ->
          err = error
          instance = result
          done()

      afterEach ->
        multi.hset.restore()
        multi.zadd.restore()
        multi.exec.restore()
        User.index.restore()
        User.enforceUnique.restore()

      it 'should provide a null error', ->
        expect(err).to.be.null

      it 'should provide the inserted instance', ->
        expect(instance).to.be.instanceof User

      it 'should provide private properties', ->
        expect(instance.hash).to.be.a.string


    describe 'with duplicate email', ->

      beforeEach (done) ->
        sinon.spy multi, 'hset'
        sinon.spy multi, 'zadd'
        sinon.spy User, 'index'
        sinon.stub(User, 'getByEmail')
          .callsArgWith 1, null, users[0]

        User.insert data[0], (error, result) ->
          err = error
          instance = result
          done()

      afterEach ->
        multi.hset.restore()
        multi.zadd.restore()
        User.index.restore()
        User.getByEmail.restore()

      it 'should provide a unique value error', ->
        expect(err).to.be.instanceof User.UniqueValueError

      it 'should not provide an instance', ->
        expect(instance).to.be.undefined




  describe 'password verification', ->

    before ->
      src  = email: faker.internet.email(), password: 'secret1337'
      user = new User src, { private: true }


    it 'should verify a correct password', (done) ->
      user.verifyPassword 'secret1337', (err, match) ->
        match.should.be.true
        done()

    it 'should not verify an incorrect password', (done) ->
      user.verifyPassword 'wrong', (err, match) ->
        match.should.be.false
        done()

    it 'should not verify against an undefined hash', (done) ->
      user = new User
      expect(user.hash).to.be.undefined
      user.verifyPassword 'secret', (err, match) ->
        match.should.be.false
        done()



  describe 'password strength validation', ->

    describe 'with a weak password', ->

      it 'should return false', ->
        User.verifyPasswordStrength('password').should.equal false

    describe 'with a strong password', ->

      it 'should return true', ->
        User.verifyPasswordStrength('_u247c^c5u4@$324v23').should.equal true




  describe 'change password', ->

    before ->
      sinon.stub(User, 'patch').callsFake((id, data, opts, cb) ->
        cb null, { _id: id, hash: 'fakehash' })

    after ->
      User.patch.restore()

    describe 'without a password', ->

      {err,user} = {}

      before ->
        User.changePassword 'someid', null, (error, userObj) ->
          err = error
          user = userObj

      it 'should provide a PasswordRequiredError', ->
        err.name.should.equal 'PasswordRequiredError'

      it 'should not return a user', ->
        expect(user).to.not.be.ok

    describe 'with a weak password', ->

      {err,user} = {}

      before ->
        User.changePassword 'someid', 'password', (error, userObj) ->
          err = error
          user = userObj

      it 'should provide a InsecurePasswordError', ->
        err.name.should.equal 'InsecurePasswordError'

      it 'should not return a user', ->
        expect(user).to.not.be.ok

    describe 'with a strong password', ->

      {err,user} = {}

      before ->
        User.changePassword 'someid', '91385m%@%##$G.', (error, userObj) ->
          err = error
          user = userObj

      it 'should provide a null error', ->
        expect(err).to.not.be.ok

      it 'should return a user instance', ->
        expect(user).to.be.an 'object'
        user._id.should.equal 'someid'
        user.hash.should.be.a 'string'




  describe 'authentication', ->

    describe 'with valid email and password credentials', ->

      before (done) ->
        {email,password} = data[0]
        sinon.stub(User, 'getByEmail').callsArgWith(2, null, users[0])
        sinon.stub(User.prototype, 'verifyPassword').callsArgWith(1, null, true)
        User.authenticate email, password, (error, instance, information) ->
          err = error
          user = instance
          info = information
          done()

      after ->
        User.getByEmail.restore()
        User.prototype.verifyPassword.restore()

      it 'should provide a null error', ->
        expect(err).to.be.null

      it 'should provide an User instance', ->
        expect(user).to.be.instanceof User

      it 'should provide a message', ->
        info.message.should.equal 'Authenticated successfully!'


    describe 'with unknown user', ->

      before (done) ->
        {email,password} = data[0]
        sinon.stub(User, 'getByEmail').callsArgWith(2, null, null)
        User.authenticate email, password, (error, instance, information) ->
          err = error
          user = instance
          info = information
          done()

      after ->
        User.getByEmail.restore()

      it 'should provide a null error', ->
        expect(err).to.be.null

      it 'should provide a false user', ->
        expect(user).to.be.false

      it 'should provide a message', ->
        info.message.should.equal 'Unknown user.'


    describe 'with incorrect password', ->

      before (done) ->
        {email} = data[0]
        sinon.stub(User, 'getByEmail').callsArgWith(2, null, users[0])
        sinon.stub(User.prototype, 'verifyPassword').callsArgWith(1, null, false)

        User.authenticate email, 'wrong', (error, instance, information) ->
          err = error
          user = instance
          info = information
          done()

      after ->
        User.getByEmail.restore()
        User.prototype.verifyPassword.restore()

      it 'should provide a null error', ->
        expect(err).to.be.null

      it 'should provide a false user', ->
        expect(user).to.be.false

      it 'should provide a message', ->
        info.message.should.equal 'Invalid password.'




  describe 'password reset', ->




  describe 'user verification', ->


  #


  describe 'add roles', ->

    before (done) ->
      user = users[0]
      role = new Role

      sinon.stub(multi, 'exec').callsArgWith 0, null, []
      sinon.spy multi, 'zadd'
      User.addRoles user, role, done

    after ->
      multi.exec.restore()
      multi.zadd.restore()

    it 'should index the role by the user', ->
      multi.zadd.should.have.been.calledWith "users:#{user._id}:roles", role.created, role._id

    it 'should index the user by the role', ->
      multi.zadd.should.have.been.calledWith "roles:#{role._id}:users", user.created, user._id



  describe 'remove roles', ->

    before (done) ->
      user = users[1]
      role = new Role

      sinon.stub(multi, 'exec').callsArgWith 0, null, []
      sinon.spy multi, 'zrem'
      User.removeRoles user, role, done

    after ->
      multi.exec.restore()
      multi.zrem.restore()

    it 'should deindex the role by the user', ->
      multi.zrem.should.have.been.calledWith "users:#{user._id}:roles", role._id

    it 'should deindex the user by the role', ->
      multi.zrem.should.have.been.calledWith "roles:#{role._id}:users", user._id



  describe 'list by roles', ->

    before (done) ->
      role = new Role name: 'authority'
      sinon.stub(User, 'list').callsArgWith 1, null, []
      User.listByRoles role.name, done

    after ->
      User.list.restore()

    it 'should look in the users index', ->
      User.list.should.have.been.calledWith(
        sinon.match({ index: "roles:#{role.name}:users" })
      )



  describe 'lookup with authenticated user', ->

    {authenticated} = {}

    before (done) ->
      authenticated = new User _id: 'r4nd0m'
      req = user: authenticated
      info = id: '1234'
      User.lookup req, info, (error, instance) ->
        err = error
        user = instance
        done()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide the authenticated user', ->
      user.should.equal authenticated



  describe 'lookup with unauthenticated known user', ->

    it 'should provide a null error'
    it 'should provide the user'



  describe 'lookup with unknown user', ->

    it 'should provide a null error'
    it 'should provide a null user'




  describe 'connect with authenticated user', ->

    before (done) ->
      user = new User()

      req =
        params:
          provider: 'google'
        user: user
      auth =
        access_token: 'b34r3r'
      info =
        id: 'g00gl3'

      sinon.stub(User, 'patch').callsArgWith(2, null, user)

      User.connect req, auth, info, (error, instance) ->
        err = error
        user = instance
        done()

    after ->
      User.patch.restore()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide a user', ->
      user.should.be.instanceof User

    it 'should update the provider id', ->
      User.patch.should.have.been.calledWith user._id, {
        lastProvider: 'google',
        providers: {
          google: {
            provider: 'google',
            protocol: 'OAuth2',
            auth: { access_token: 'b34r3r' },
            info: { id: 'g00gl3' }
          }
        }
      }




  describe 'connect with unauthenticated existing user', ->

    before (done) ->
      user = new User()

      req =
        params:
          provider: 'google'
      auth =
        access_token: 'b34r3r'
      info =
        id: 'g00gl3_2'

      sinon.stub(User, 'lookup').callsArgWith(2, null, user)
      sinon.stub(User, 'patch').callsArgWith(2, null, user)

      User.connect req, auth, info, (error, instance) ->
        err = error
        user = instance
        done()

    after ->
      User.lookup.restore()
      User.patch.restore()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide a user', ->
      user.should.be.instanceof User

    it 'should update the provider id', ->
      User.patch.should.have.been.calledWith user._id, {
        lastProvider: 'google',
        providers: {
          google: {
            provider: 'google',
            protocol: 'OAuth2',
            auth: { access_token: 'b34r3r' },
            info: { id: 'g00gl3_2' }
          }
        }
      }




  describe 'connect with new user and existing email', ->

    before (done) ->
      user = new User()

      req =
        params:
          provider: 'google'
      auth =
        access_token: 'b34r3r'
      userInfo =
        id: 'g00gl3_3'
        email: 'john@smith.com'
        given_name: 'John'
        family_name: 'Smith'
      user =
        _id: 'uuid'
        email: 'john@smith.com'
        providers:
          github: {}

      uniqueError = new Error 'email must be unique'

      sinon.stub(User, 'lookup').callsArgWith(2, null, null)
      sinon.stub(User, 'insert').callsArgWith(2, uniqueError)
      sinon.stub(User, 'getByEmail').callsArgWith(1, null, user)

      User.connect req, auth, userInfo, (error, _instance, information) ->
        err = error
        instance = _instance
        info = information
        done()

    after ->
      User.lookup.restore()
      User.insert.restore()
      User.getByEmail.restore()

    it 'should not provide an error', ->
      expect(err).to.be.null

    it 'should not provide a user', ->
      expect(instance).to.be.false

    it 'should provide a message', ->
      info.message.should.equal 'email must be unique'

    it 'should provide providers', ->
      info.providers.should.equal user.providers




  describe 'connect with new user', ->

    before (done) ->
      user = new User()

      req =
        params:
          provider: 'google'
        connectParams:
          redirect_uri: 'https://app.example.com/callback'
          client_id: 'uuid'
          response_type: 'id_token token'
          scope: 'openid profile'
        flash: sinon.spy()
        provider:
          emailVerification:
            enable: false
      auth =
        access_token: 'b34r3r'
      info =
        id: 'g00gl3_3'
        given_name: 'John'
        family_name: 'Smith'

      sinon.stub(User, 'lookup').callsArgWith(2, null, null)
      sinon.stub(User, 'insert').callsArgWith(2, null, user)

      User.connect req, auth, info, (error, instance) ->
        err = error
        user = instance
        done()

    after ->
      User.lookup.restore()
      User.insert.restore()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide a user', ->
      user.should.be.instanceof User

    it 'should insert the user profile', ->
      User.insert.should.have.been.calledWith sinon.match({
        givenName: 'John'
        familyName: 'Smith'
        providers:
          google:
            provider: 'google'
            protocol: 'OAuth2'
            auth: { access_token: 'b34r3r' }
            info:
              id: 'g00gl3_3'
              given_name: 'John'
              family_name: 'Smith'
      })

    #it 'should include a mapping in the options', ->
    #  User.insert.should.have.been.calledWith sinon.match.object, sinon.match({
    #    mapping: 'google'
    #  })

    it 'should disable the password requirement', ->
      User.insert.should.have.been.calledWith sinon.match.object, sinon.match({
        password: false
      })




  describe 'connect existing user with refreshed userinfo', ->

    before (done) ->
      settings.refresh_userinfo = true
      user = new User email: 'initial@example.com'

      req =
        params:
          provider: 'google'
      auth =
        access_token: 'b34r3r'
      info =
        id: 'g00gl3_2'
        email: 'updated@example.com'

      sinon.stub(User, 'lookup').callsArgWith(2, null, user)
      sinon.stub(User, 'patch').callsArgWith(2, null, user)
      sinon.spy(Modinha, 'map')

      User.connect req, auth, info, (error, instance) ->
        err = error
        user = instance
        done()

    after ->
      delete settings.refresh_userinfo
      User.lookup.restore()
      User.patch.restore()
      Modinha.map.restore()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide a user', ->
      user.should.be.instanceof User

    it 'should update user claims from provider info', ->
      Modinha.map.should.have.been.called




  describe 'connect existing user without refreshed userinfo', ->

    before (done) ->
      user = new User email: 'initial@example.com'

      req =
        params:
          provider: 'google'
      auth =
        access_token: 'b34r3r'
      info =
        id: 'g00gl3_2'
        email: 'updated@example.com'

      sinon.stub(User, 'lookup').callsArgWith(2, null, user)
      sinon.stub(User, 'patch').callsArgWith(2, null, user)
      sinon.spy(Modinha, 'map')

      User.connect req, auth, info, (error, instance) ->
        err = error
        user = instance
        done()

    after ->
      User.lookup.restore()
      User.patch.restore()
      Modinha.map.restore()

    it 'should provide a null error', ->
      expect(err).to.be.null

    it 'should provide a user', ->
      user.should.be.instanceof User

    it 'should update user claims from provider info', ->
      Modinha.map.should.not.have.been.called




