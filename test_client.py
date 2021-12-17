import logging
import base64
import string

import binascii
import msgdef_pb2 as msg
# don't output warnings from scapy, kthx
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sniff
from manipulate_packets import *
from encryption import *
import argparse

# globals
maxPort = 65535
message = ""
response = msg.Message()
length = 0



def parsePacket(packet):
  global message
  global length
  global response
  sport = packet.sport
  difference = maxPort - sport
  binVal = bin(difference)[2:]
  binLen = len(binVal)
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


if __name__=="__main__":
  # Parse the command line arguments
  parser = argparse.ArgumentParser(description="Covert Channel Server")
  parser.add_argument('-o'
                    , '--output'
                    , dest='filePath'
                    , help='Absolute path to where you would like to save packets sent to the server.'
                    , required=True)
  parser.add_argument('-d'
                    , '--destination'
                    , dest='serverIp'
                    , help='IP address to covertly send data to.'
                    , required=True)
  args = parser.parse_args()

  # Send Hello message to the server
  print("Sending hello to the server...\n")
  hello_message = msg.Message()
  hello_message.hello.text = "Hi!! I am active!!"
  message_string = hello_message.SerializeToString()
  message_string = base64.b64encode(message_string)
  fileSize = len(message_string)
  print(args.serverIp)
  sendPackets(str(fileSize)+"\n",args.serverIp)
  lastPosition = 0
  #sendPackets(message_string.decode(), args.serverIp)

  # sniff for tcp packets with a destination port of 80, send them to parsePacket
  sniff(filter="tcp and (dst port 80)", prn=parsePacket)
