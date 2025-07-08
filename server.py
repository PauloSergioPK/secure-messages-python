import socket
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sockets import serverHost, serverPort
from diffiehellman import primeNumber, receiveDhParams, verifyRemoteKey, generateDHParams, sendDhParams
from cypher import loadPrivateKey, createCypherKeysFromSecret

def dhHandshake(privateKey, username):
    remoteDhParams = receiveDhParams(conn)
    verifyRemoteKey(
        githubUsername = remoteDhParams.username,
        remoteDHSignedPublicKeyAndData = remoteDhParams.signedPublicKeyAndData, 
        remoteDHdata = remoteDhParams.data
    )

    localDHParams = generateDHParams(privateKey = privateKey, username = username)
    sendDhParams(socket = conn,dhparams = localDHParams,username = username)

    return pow(remoteDhParams.publicKey, localDHParams.privateKey, primeNumber)

def getCypherAlgorithmKeys():
    privateKey = loadPrivateKey("server_ecdsa_private_key")
    secret = dhHandshake(privateKey,"PauloSergioPKServidorCadeiraUFC")

    salt = secrets.token_bytes(16)
    conn.send(salt)

    return createCypherKeysFromSecret(secret=secret, salt=salt)

def decryptMessage(cypherKeys, data):
    hmacTag = data[:32]
    iv = data[32:48]
    ciphertext = data[48:]

    h = hmac.new(cypherKeys.hmacKey, iv + ciphertext, hashlib.sha256)
    if not hmac.compare_digest(h.digest(), hmacTag):
        print('[!] HMAC inválido. Mensagem rejeitada.')
        exit()

    cipher = Cipher(algorithms.AES(cypherKeys.aesKey), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    return padded_msg.rstrip(b'\x00')

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((serverHost, serverPort))
server.listen(1)
print('[*] Aguardando conexão...')
conn, _ = server.accept()
print('[*] Cliente conectado')

cypherKeys = getCypherAlgorithmKeys()

try:
    while True:
        data = conn.recv(4096)
        if not data:
            print("[*] Cliente desconectado.")
            break
        print('[+] Mensagem recebida:', data)
        try:
            message = decryptMessage(cypherKeys, data)
            print('[+] Mensagem decifrada:', message.decode())
        except Exception as e:
            print(f'[!] Erro ao decifrar mensagem: {e}')
except KeyboardInterrupt:
    print("\n[*] Encerrando servidor.")
finally:
    conn.close()
    server.close()