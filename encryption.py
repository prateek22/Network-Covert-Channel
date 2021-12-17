from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import  hashlib

def decryptMessage(message):
  keyFile = open("rsa_priv.pem", 'rb')
  data = keyFile.read()
  privKey = RSA.import_key(data)
  messageDecryptor = PKCS1_OAEP.new(privKey)
  decryptedMessage = messageDecryptor.decrypt(message)
  print(decryptedMessage.decode())

def msgHash(encryptedMessage):
  m = hashlib.sha512()
  m.update(encryptedMessage)
  return m.digest()

def encryptMessage(path):
  keyFile = open("rsa.pub", 'rb')
  data = keyFile.read()
  keyString = open(path,"rb")
  pubKey = RSA.import_key(data)
  messageEncryptor = PKCS1_OAEP.new(pubKey)
  encryptedMessage = messageEncryptor.encrypt(keyString.read())
  return encryptedMessage