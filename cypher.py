from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

iterations = 100_000

class CypherKeys:
  def __init__(self, aesKey, hmacKey):
    self.aesKey = aesKey
    self.hmacKey = hmacKey

def loadPrivateKey(keyName):
  fileName = keyName + ".pem"
  with open(fileName, "rb") as f:
      return serialization.load_pem_private_key(
          f.read(),
          password=None, 
          backend=default_backend()
      )
  
def createCypherKeysFromSecret(secret, salt):
  secretBytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
  kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32+32, salt=salt, iterations=iterations)
  derived = kdf.derive(secretBytes)
  aesKey = derived[:32]
  hmacKey = derived[32:]

  return CypherKeys(aesKey,hmacKey)
