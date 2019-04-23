# Test dependencies
cwd       = process.cwd()
path      = require 'path'
faker     = require 'faker'
chai      = require 'chai'
sinon     = require 'sinon'
sinonChai = require 'sinon-chai'
mockMulti = require '../lib/multi'
expect    = chai.expect




# Configure Chai and Sinon
chai.use sinonChai
chai.should()




# Code under test
userApplications = require path.join(cwd, 'models/UserApplications')
User = require path.join(cwd, 'models/User')
Client = require path.join(cwd, 'models/Client')




# Redis lib for spying and stubbing
Redis   = require('redis-mock')
{client,multi} = {}




describe 'User Applications', ->

  before ->
    client = Redis.createClient()
    multi = mockMulti(client)
    Client.__client = client

  after ->
    client.multi.restore()

  {err,res,clients} = {}

  # Mock data
  data = []

  for i in [0..9]
    data.push
      _id: "uuid-#{i}"
      client_name: faker.company.companyName()
      client_uri: "http://#{faker.internet.domainName()}"
      application_type: 'web'
      logo_uri: faker.image.imageUrl()
      trusted: true

  data[1].scopes = ['n0p3']
  data[2].scopes = ['a', 'b', 'c']

  clients = Client.initialize(data)
  jsonClients = clients.map (d) ->
    Client.serialize(d)
  ids = clients.map (d) -> d._id
  scopes = ['openid', 'profile', 'a', 'b', 'c']
  visited = ids.slice(4)


  before (done) ->
    user = new User
    sinon.stub(User.prototype, 'authorizedScope').callsArgWith(0, null, scopes)
    sinon.stub(client, 'hmget').callsArgWith(2, null, jsonClients)
    sinon.stub(client, 'zrevrange').callsArgWith(3, null, visited)
    userApplications user, (error, results) ->
      err = error
      res = results
      done()

  after ->
    User.prototype.authorizedScope.restore()
    client.hmget.restore()
    client.zrevrange.restore()

  it 'should include client id', ->
    res.forEach (client) ->
      expect(client._id).to.not.be.undefined

  it 'should include client name', ->
    res.forEach (client) ->
      expect(client.client_name).to.not.be.undefined

  it 'should include client uri', ->
    res.forEach (client) ->
      expect(client.client_uri).to.not.be.undefined

  it 'should include application_type', ->
    res.forEach (client) ->
      expect(client.application_type).to.not.be.undefined

  it 'should include logo_uri', ->
    res.forEach (client) ->
      expect(client.logo_uri).to.not.be.undefined

  it 'should include scopes', ->
    res.forEach (client) ->
      expect(client.scopes).to.not.be.undefined

  it 'should include created', ->
    res.forEach (client) ->
      expect(client.created).to.not.be.undefined

  it 'should include modified', ->
    res.forEach (client) ->
      expect(client.modified).to.not.be.undefined

  it 'should include visited', ->
    res.forEach (client) ->
      expect(client.visited).to.not.be.undefined

  it 'should not include client secret', ->
    res.forEach (client) ->
      expect(client.client_secret).to.be.undefined

  it 'should not include unauthorized clients', ->
    res.forEach (client) ->
      client.scopes.should.not.contain 'w00t'




