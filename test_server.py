import logging
import  hashlib
import base64
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import msgdef_pb2 as msg
# don't output warnings from scapy, kthx
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sniff
import argparse

# globals
maxPort = 65535
message = ""
response = msg.ExpressionResponse()
length = 0
# parsePacket - takes in a packet that passes our sniff filter
# Gets the difference between 65535 and the source port field in the packet,
# then gets the binary value of that difference.  If the length of the binary
# string is greater than 8, then we parse 2 characters from the string, otherwise
# the string only contains one character.  We convert the binary string to an
# ASCII character.  You'll notice that we open and close the output file within
# this function, that's because pythons file library requires the file to be closed
# for the data from our write calls to actually be written to the file.
def parsePacket(packet):
  global message
  global length
  global response
  sport = packet.sport
  difference = maxPort - sport
  binVal = bin(difference)[2:]
  binLen = len(binVal)
  if binLen > 8 and packet["TCP"].flags == 0x40:
    # binary string contains two ascii characters
    # the last 8 characters in the string are always the 2nd character
    binChar2 = binVal[-8:]
    # python trims leading zeroes at the start of our concatenated binary string
    binChar1 = binVal[0:binLen - 8]
    char1 = chr(int(binChar1, 2))
    char2 = chr(int(binChar2, 2))
    if (char1.strip() != "" or char2.strip() != "") and (char1 in string.printable and char2 in string.printable):
      message += char1
      message += char2
    #print("Received: " + char1 + char2)

  else:
    # binary string contains one ascii character
    char = chr(int(binVal, 2))
    if char.strip() != "" and char in string.printable:
      message += char
    #print("Received: " + char)

  if message[-1]=="\n":
    length = int(message[:-1])
    message = ""
    print(length)
    
  if length == len(message):
    decodedMessage = base64.b64decode(message)
    response.ParseFromString(decodedMessage)
    if response.hash == msgHash(response.encrypt):
      decryptMessage(response.encrypt)
    length = 0
    message = ""

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

# start of execution
parser = argparse.ArgumentParser(description="Covert Channel Server")
parser.add_argument('-o'
                   , '--output'
                   , dest='filePath'
                   , help='Absolute path to where you would like to save packets sent to the server.'
                   , required=True)
args = parser.parse_args()
# sniff for tcp packets with a destination port of 80, send them to parsePacket
sniff(filter="tcp and (dst port 80)", prn=parsePacket)
