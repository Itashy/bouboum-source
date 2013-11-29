#!/usr/bin/env python
# coding: utf-8

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol

import packets.general
import packets.protocol
import packets.opcodes
from packets.bytearray import ByteArray

import sys
import struct
import json

import MySQLdb
import random
import MySQLdb.cursors

import threading
 
database = MySQLdb.connect(host="localhost", user="root", passwd="123qaz123", db="bouboum", cursorclass=MySQLdb.cursors.DictCursor)
cursor = database.cursor()

def _(text):
	print "[Main]", text

_("Server starting")

class BouboumClient(packets.protocol.TFMClientProtocol):
	def __init__(self, serveur):
		self.serveur = serveur
		self.versionValidated = False
		self.community = "EN"

		self.Database = self.serveur.Database
		self.Cursor = self.Database.cursor()

		self.frooze = False

		self.username = ""
		self.playerCode = 0
		self.isDead = False
		self.look = 0
		self.shopitems = []
		self.score = 0
		self.room = None

	def connectionMade(self):
		if sys.platform.startswith('win'):
			self.address = self.transport.getPeer()
			self.address = [self.address.host]
		else:
			self.address = self.transport.getHandle().getpeername()

		_("Connection"+" "+str(self.address))
		self.serveur.clients.append(self)
		pass

	def inforequestReceived(self, string):
		if string == '<policy-file-request/>\x00':
			# policy request
			self.transport.write(packets.general.PolicyRequestGenerator(self.serveur.policyData))
			self.transport.loseConnection()

	def connectionLost(self, reason):
		self.serveur.clients.remove(self)
		if self.room:
			self.room.removeClient(self)
		pass

	def parseUTFData(self, values):
		eventTokens = struct.unpack('!bb', values.pop(0))
		eventToken1, eventToken2 = eventTokens

		print eventTokens, values

		if eventToken1 == 26:
			if eventToken2 == 4:
				# log in
				username, passwordHash, startRoom, loaderURL, base64Hash = values
				if username == "" and passwordHash == "": username = "Hamster"
				if passwordHash == "": username = '*%s'%username
				actionCode = self.authenticate(username, passwordHash)
				if actionCode == True:
					self.sendLogInData()
					self.enterRoom(startRoom)
				else:
					self.frooze = True
					threading.Timer(2.0, self.sendIncorrectPassword, [actionCode]).start()

	def stringReceived(self, data):
		p = ByteArray(data)
		fingerPrint, packetCodes = p.readInt(), [p.readByte(), p.readByte()]

		eventToken1, eventToken2 = packetCodes

		if not self.checkFingerPrint(fingerPrint):
			_("Invalid fingerprint on"+" "+str(self.address))
			self.transport.loseConnection()


		if not self.versionValidated:
			if eventToken1 == 28:
				if eventToken2 == 1:
					# key
					protocolVersion, connectionKey = p.readShort(), p.readUTF()
					#print 'connect', '-', protocolVersion, '-', connectionKey
					if packets.opcodes.opcodes.general.protocolVersion == protocolVersion:
						if packets.opcodes.opcodes.general.connectionKey == connectionKey:
							self.versionValidated = True
							self.sendInitialPacket()

		elif eventToken1 == packets.opcodes.opcodes.general.old_protocol:
			if eventToken2 == packets.opcodes.opcodes.general.old_protocol:
				# old protocol
				self.parseUTFData(p.readUTF().split('\x01'))
				return

		elif eventToken1 == packets.opcodes.opcodes.player.player:
			if eventToken2 == packets.opcodes.opcodes.player.community:
				# old protocol
				cid = p.readByte()
				self.community = packets.opcodes.communites[cid]

		elif eventToken1 == packets.opcodes.opcodes.system.system:
			if eventToken2 == packets.opcodes.opcodes.system.system_info:
				clientLangue, clientOS, clientFlashV = p.readUTF(), p.readUTF(), p.readUTF()
				_("New client at {community}. Used Flash {flashV} at {system}".format(community=clientLangue, flashV=clientFlashV, system=clientOS))

		elif eventToken1 == packets.opcodes.opcodes.shop.shop:
			if eventToken2 == packets.opcodes.opcodes.shop.shop_req:
				p = ByteArray()
				p.writeByte(102)
				p.writeByte(70)

				p.writeInt(self.nutsCount)
				p.writeByte(self.look) # current fur
				shopList = '0,0;17,50;3,100;4,200;6,400;19,500;2,800;7,1000;9,1000;8,1500;5,2000'.split(';')#{0: 0, 1: 0, 2: 17, 3: 50, 4: 3, 5: 100, 6: 4, 7: 200, 8: 6, 9: 400, 10: 19, 11: 500, 12: 2, 13: 800, 14: 7, 15: 1000, 16: 9, 17: 1000, 18: 8, 19: 1500, 20: 5, 21: 2000} #[0, 0, 17, 0, 3, 100, 4, 200, 6, 400, 19, 500, 2, 800, 7, 1000, 9, 1000, 8, 1500, 5, 2000]

				p.writeByte(len(shopList)*2)

				for x in shopList:
					item, cost = map(int, x.split(','))
					if item in self.shopitems: cost = 0
					p.writeByte(item)
					p.writeShort(cost)
				self.sendBData(p)

		print packetCodes, repr(p.toString())

	def sendData(self, tokens, values):
		p = ByteArray("\x01\x01")
		p.writeUTF('\x01'.join([''.join([struct.pack('!b', x) for x in tokens]), '\x01'.join([str(x) for x in values])]))
		print repr(p.toPack())
		self.transport.write(p.toPack())

	def sendBData(self, p):
		self.transport.write(p.toPack())

	def sendInitialPacket(self):
		self.sendData((26, 27), [len(self.serveur.clients), '4932176805', '1973', 'ru'])

	def checkFingerPrint(self, fingerprint):
		#print fingerprint
		return True

	def authenticate(self, username, passwordHash):
		username = username.lower().capitalize()
		while self.frooze: pass
		if username.startswith("*"):
			self.username = username
			self.playerCode = self.serveur.generatePlayerCode()
			self.nutsCount = 0
			self.shopitems = []
			self.look = 0
			return True
		self.Cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
		row = self.Cursor.fetchone()
		if row is None or row['password'] != passwordHash:
			return 'WRONGPW'
		else:
			self.username = row['username']
			self.playerCode = row['id']
			self.nutsCount = row['shopnuts']
			self.shopitems = json.loads(row['shopitems'])
			self.look = int(row['look'])
			return True

	def enterRoom(self, roomName):
		room = self.serveur.addClientToRoom(self, roomName)

		if room:
			self.room = room

			self.sendEnterRoom(roomName)
	#   /$$$$$$$                      /$$                   /$$              
	#  | $$__  $$                    | $$                  | $$              
	#  | $$  \ $$  /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$  /$$$$$$    /$$$$$$$
	#  | $$$$$$$/ |____  $$ /$$_____/| $$  /$$/ /$$__  $$|_  $$_/   /$$_____/
	#  | $$____/   /$$$$$$$| $$      | $$$$$$/ | $$$$$$$$  | $$    |  $$$$$$ 
	#  | $$       /$$__  $$| $$      | $$_  $$ | $$_____/  | $$ /$$ \____  $$
	#  | $$      |  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/ /$$$$$$$/
	#  |__/       \_______/ \_______/|__/  \__/ \_______/   \___/  |_______/ 
	#                                                                        
	#                                                                        
	#        

	def sendEnterRoom(self, roomName):
		self.sendData((5, 21), ['ru-'+str(roomName)])                                                                

	def sendIncorrectPassword(self, reason):
		self.frooze = False
		if reason == 'WRONGPW':
			self.sendData((26, 3), [])
		else:
			self.sendData((26, 3), [1])

	def sendSkills(self):
		p = ByteArray()
		p.writeByte(8)
		p.writeByte(22)

		p.writeByte(0)
		self.sendBData(p)


		p = ByteArray()
		p.writeByte(8)
		p.writeByte(8)

		p.writeByte(0) # level
		p.writeInt(0) # exp
		p.writeInt(0) # exp_for_levelup
		self.sendBData(p)

	def sendGameMode(self, gameMode=2):
		p = ByteArray()
		p.writeByte(7)
		p.writeByte(1)

		p.writeByte(gameMode)
		self.sendBData(p)

	def sendLogInData(self):
		self.sendSkills()
		self.sendData((26, 8), [self.username, self.playerCode, 1, 0, 0]) # logon data

		p = ByteArray()
		p.writeByte(26)
		p.writeByte(2)

		p.writeInt(self.playerCode)
		p.writeUTF(self.username)
		self.sendBData(p)

		self.sendGameMode()
		#reactor.callLater(3, self.sendInjectionSWF)

	def sendInjectionSWF(self):
		swf = open('Injection.swf', 'rb')
		swf = swf.read()
		self.sendData((28, 1), [swf])

	def sendNewRound(self, currentWorld):
		p = ByteArray()
		p.writeByte(102)
		p.writeByte(53)

		p.writeShort(23)
		p.writeInt(currentWorld[0]) # fond
		p.writeByte(currentWorld[1])
		p.writeByte(6)

		for x in currentWorld[2]: p.writeByte(x)

		#p.writeBytes('\x00\x10\x00\x00\x00\x06\x0e\x0b\x01\x01\x01\x01\x00\x01\x01\x00\x02\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x02\x00\x01\x00\x01\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x02\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x00\x01\x00\x01\x01\x01\x02\x01\x00\x01\x00\x01\x00\x01\x01\x01\x01\x00\x01\x00\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x02\x01\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x01\x01\x02\x01\x02\x00\x01\x00\x00\x01\x01\x01\x00\x01\x00\x01\x00\x00\x01\x01\x01\x02\x01\x00\x00\x00\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x02\x00\x00\x01\x01\x01\x01\x01\x00\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x00\x01\x00\x01\x00\x01\x00\x01\x01\x01\x01\x01\x02\x01\x01\x01\x00\x01\x01\x00\x01\x00\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x02\x02\x02\x01\x01\x02\x01\x00\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x02\x02\x02\x01\x01\x00\x00\x00\x01\x01\x01\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x02\x02\x02\x01\x01\x01\x00\x01\x01\x00\x00\x01\x00\x00\x02\x01\x01\x01\x01\x01\x00\x01\x00\x01\x01\x00\x01\x00\x00\x00\x00\x02\x01\x01\x00\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x00\x01\x01\x00\x01\x01\x01\x02\x01\x01\x01\x01\x01\x00\x01\x01\x00\x00\x01\x00\x01\x00\x01\x01\x01\x00\x02\x01\x00\x01\x00\x00\x01\x01\x00\x01\x01\x00\x02\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x00\x02\x01\x01\x00\x01\x01\x00\x01\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x02\x00\x00\x01\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x02\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x01\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x00\x01\x00\x01\x01\x01\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x00\x00\x01\x00\x00\x01\x01\x01\x01\x00\x01\x01\x01\x01\x00\x02\x01\x01\x01\x01\x00\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x02\x01\x01\x00\x01\x00\x00\x01\x00\x01\x01\x01\x01\x01\x01\x00\x01\x01\x02\x01\x01\x00\x01\x01\x00\x01\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x02\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x00\x01\x00\x01\x01\x00\x02\x01\x01\x00\x01\x01\x01\x00\x00')
		self.sendBData(p)

	def sendPlayerList(self, clients, one=False):
		p = ByteArray()
		p.writeByte(102)
		if not one: p.writeByte(50)
		else: p.writeByte(51)

		if not one: p.writeShort(len(clients))
		if one: clients = {clients.username:clients}
		for client in clients.values():
			p.writeUTF(client.username)
			p.writeShort(28634) #28634
			p.writeBoolean(client.isDead) # is dead (???)
			p.writeByte(client.look) # skin ID
			p.writeShort(client.score) # score
			p.writeShort(1250) # rang
			p.writeByte(25) # x
			p.writeByte(3) # y

		#p.writeBytes('\x00\x01\x00\x06SpaowiTU\x01\x00\x00\x00\x04\xe2\x00\x00')
		self.sendBData(p)

	def sendRoundTime(self, s=120):
		p = ByteArray()
		p.writeByte(5)
		p.writeByte(22)

		p.writeShort(s)
		self.sendBData(p)

	def sendBombCount(self):#, bc, ec):
		p = ByteArray()
		p.writeByte(20)
		p.writeByte(4)

		p.writeBytes('\x01\x00')
		self.sendBData(p)

	def sendPlayerJoined(self, client):
		self.sendPlayerList(client, one=True)

	def sendPlayerLeaved(self, client):
		p = ByteArray()
		p.writeByte(102)
		p.writeByte(69)

		p.writeUTF(client.username)

		#p.writeBytes('\x00\x0c*Hamster_lbc')
		self.sendBData(p)

	def startPlay(self):
		self.isDead = False
		self.score = 0
		self.sendRoundTime()

		p = ByteArray()
		p.writeByte(102)
		p.writeByte(67)

		p.writeBytes('\x00')
		self.sendBData(p)

		p = ByteArray()
		p.writeByte(102)
		p.writeByte(68)

		p.writeBytes('\x01')
		self.sendBData(p)

		p = ByteArray()
		p.writeByte(102)
		p.writeByte(52)

		p.writeBytes('TU\t\x00\x08\x00\t\x01')
		self.sendBData(p)

		p = ByteArray()
		p.writeByte(102)
		p.writeByte(13)

		p.writeBytes('TU\x00')
		self.sendBData(p)

		p = ByteArray()
		p.writeByte(28)
		p.writeByte(2)

		p.writeBytes('R\x93\x86\x80')
		self.sendBData(p)

class BouboumRoom(object):

	def __init__(self, serveur, roomName):
		self.Clients = {} # username: BouboumClient
		self.name = roomName

		self.currentWorld = [1, 1, []] # [world, blocks, [block positions]]

		self.positions = []

		self.newRoundTimer = reactor.callLater(0.2, self.newRound)

	def addClient(self, client):
		self.Clients[client.username] = client
		for player in self.Clients.values():
			if not player == client:
				player.sendPlayerJoined(client)

	def removeClient(self, client):
		if client.username in self.Clients:
			del self.Clients[client.username]
			for player in self.Clients.values():
				if not player == client:
					player.sendPlayerLeaved(client)

	def generateWorld(self):
		world = [random.choice([0, 1, 1, 0, 0, 1, 0, 0, 2]) for x in range(702)]
		self.currentWorld[2] = world

	def newRound(self):
		self.newRoundTimer = None
		self.generateWorld()

		for client in self.Clients.values():
			client.sendPlayerList(self.Clients)
			client.sendNewRound(self.currentWorld)
			client.startPlay()

		self.newRoundTimer = reactor.callLater(120, self.newRound)
		

class BouboumServeur(Factory):
	protocol = BouboumClient

	def __init__(self):
		self.policyData = {
			'*':[443, 44444, 44440, 5555, 3724, 6112]
		}

		self.clients = []
		self.rooms = {}
		self.lastPlayerCode = 30000

		self.Database = database
		self.Cursor = self.Database.cursor()

	def buildProtocol(self, addr):
		client = BouboumClient(self)
		return client

	def addClientToRoom(self, client, roomName):
		roomName = str(roomName)
		if roomName in self.rooms:
			self.rooms[roomName].addClient(client)
		else:
			self.rooms[roomName] = BouboumRoom(self, roomName)
			self.rooms[roomName].addClient(client)
		return self.rooms[roomName]

	def generatePlayerCode(self):
		self.lastPlayerCode += 1
		return self.lastPlayerCode


if __name__ == "__main__":
	f = BouboumServeur()

	for p in [443, 44444, 44440, 5555, 3724, 6112]:
		reactor.listenTCP(p, f)

	reactor.run()
