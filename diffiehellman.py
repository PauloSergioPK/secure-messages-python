from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import requests
import secrets

primeNumber = 2**2048 - 2**1984 - 1 + 2**64 * ((2**1918) + 124476)
generatorNumber = 2

class DHParams:
  def __init__(self, privateKey, publicKey, data, signedPublicKeyAndData, username):
    self.privateKey = privateKey
    self.publicKey = publicKey
    self.data = data
    self.signedPublicKeyAndData = signedPublicKeyAndData
    self.username = username

def generateDHParams(privateKey, username):
  dhPrivateKey = secrets.randbelow(primeNumber)
  dhPublicKey = pow(generatorNumber, dhPrivateKey, primeNumber)
  dhData = str(dhPublicKey).encode() + username.encode()
  signedPublicKeyAndData = privateKey.sign(
    dhData,
    ec.ECDSA(hashes.SHA256())
  )

  return DHParams(
    privateKey = dhPrivateKey,
    publicKey = dhPublicKey,
    data = dhData,
    signedPublicKeyAndData = signedPublicKeyAndData,
    username = username
  )

def sendDhParams(socket, dhparams, username):
  socket.send(str(dhparams.publicKey).encode())
  socket.send(len(dhparams.signedPublicKeyAndData).to_bytes(2,'big'))
  socket.send(dhparams.signedPublicKeyAndData)
  socket.send(username.encode())

def receiveDhParams(socket):
  dhPublicKey = int(socket.recv(4096).decode())
  signedPublicKeyAndData = readRemoteSignedPublicKeyAndData(socket)
  username = socket.recv(4096).decode()
  dhData = str(dhPublicKey).encode() + username.encode()

  return DHParams(
    publicKey = dhPublicKey,
    data = dhData,
    signedPublicKeyAndData = signedPublicKeyAndData,
    username = username,
    privateKey = "any"
  )

def readRemoteSignedPublicKeyAndData(socket):
  dhSignedPublicKeyAndDataBytes = socket.recv(2)
  dhSignedPublicKeyAndDataLen = int.from_bytes(dhSignedPublicKeyAndDataBytes,'big')
  dhSignedPublicKeyAndData = b''

  while len(dhSignedPublicKeyAndData) < dhSignedPublicKeyAndDataLen:
    part = socket.recv(dhSignedPublicKeyAndDataLen - len(dhSignedPublicKeyAndData))
    if not part:
      raise ConnectionError("Connection lost while reading signature")
    dhSignedPublicKeyAndData += part

  return dhSignedPublicKeyAndData
  
  
def verifyRemoteKey(githubUsername, remoteDHSignedPublicKeyAndData, remoteDHdata):
  response = requests.get(f'https://github.com/{githubUsername}.keys')
  publicKey = serialization.load_ssh_public_key(response.text.encode())
  publicKey.verify(remoteDHSignedPublicKeyAndData, remoteDHdata, ec.ECDSA(hashes.SHA256()))