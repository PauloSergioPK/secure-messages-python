import socket
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sockets import serverHost, serverPort
from diffiehellman import primeNumber, receiveDhParams, verifyRemoteKey, generateDHParams, sendDhParams
from cypher import loadPrivateKey, createCypherKeysFromSecret

def dhHandshake(privateKey, username):
    localDHParams = generateDHParams(privateKey = privateKey, username = username)
    sendDhParams(socket = client,dhparams = localDHParams,username = username)

    remoteDhParams = receiveDhParams(client)
    verifyRemoteKey(
        githubUsername = remoteDhParams.username,
        remoteDHSignedPublicKeyAndData = remoteDhParams.signedPublicKeyAndData, 
        remoteDHdata = remoteDhParams.data
    )

    return pow(remoteDhParams.publicKey, localDHParams.privateKey, primeNumber)

def getCypherAlgorithmKeys():
    privateKey = loadPrivateKey("client_ecdsa_private_key")
    secret = dhHandshake(
        privateKey = privateKey,
        username = "PauloSergioPKClienteCadeiraUFC"
    )

    salt = client.recv(16)

    return createCypherKeysFromSecret(secret=secret, salt=salt)

def encyptMessage(cypherKeys, message):
    padded_msg = message + b'\x00' * (16 - len(message) % 16)

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(cypherKeys.aesKey), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()

    h = hmac.new(cypherKeys.hmacKey, iv + ciphertext, hashlib.sha256)
    hmacTag = h.digest()

    return hmacTag + iv + ciphertext


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((serverHost, serverPort))

cypherKeys = getCypherAlgorithmKeys()

while True:
    try:
        userInput = input("Digite sua mensagem (ou 'exit' para sair): ")
        if userInput.lower() == 'exit':
            print("[*] Encerrando conexão.")
            break
        message = userInput.encode()

        cryptedMessage = encyptMessage(
            cypherKeys = cypherKeys,
            message = message
        )
        client.send(cryptedMessage)

        print("[+] Mensagem criptografada e enviada com sucesso.", cryptedMessage)
    except Exception as e:
        print(f"[!] Erro ao enviar mensagem: {e}")
        break

client.close()