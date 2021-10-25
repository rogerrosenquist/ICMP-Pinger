from socket import *
import os
import sys
import struct
import time
import select
import binascii
ICMP_ECHO_REQUEST = 8

def checksum(string):
    # In this function we make the checksum of our packet 
    string = bytearray(string)
    csum = 0
    countTo = (len(string) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(string):
        csum = csum + string[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    # Make global so we can do the calculations
    global RTT_MIN, RTT_MAX, RTT_SUM, RTT_COUNT
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fetch the ICMP header from the IP packet
        type, code, checksum, id, seq = struct.unpack('bbHHh', recPacket[20:28])
        if type != 0:
            return 'expected type=0, but got {}'.format(type)
        if code != 0:
            return 'expected code=0, but got {}'.format(code)
        if ID != id:
            return 'expected ID={}, but got {}'.format(ID, id)
        send_time,  = struct.unpack('d', recPacket[28:])
        
        # Setting up the math for the Round Trip Times
        rtt = (timeReceived - send_time) * 1000
        RTT_COUNT += 1
        RTT_SUM += rtt
        RTT_MIN = min(RTT_MIN, rtt)
        RTT_MAX = max(RTT_MAX, rtt)

        ip_header = struct.unpack('!BBHHHBBH4s4s' , recPacket[:20])
        ttl = ip_header[5]
        saddr = inet_ntoa(ip_header[8])
        length = len(recPacket) - 20

        # For the CMD line printing
        return '{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms'.format(length, saddr, seq, ttl, rtt)

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    # Convert 16-bit integers from host to network byte order
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object

def doOnePing(destAddr, timeout):         
    icmp = getprotobyname("icmp") 
    # Socket made here
    # Using SOCK_RAW for lower level network access compared to SOCK_STREAM
    mySocket = socket(AF_INET, SOCK_RAW, icmp) 

    myID = os.getpid() & 0xFFFF  #Return the current process i     
    sendOnePing(mySocket, destAddr, myID) 
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)          

    mySocket.close()         
    return delay  

def ping(host, timeout=1):
    global RTT_MIN, RTT_MAX, RTT_SUM, RTT_COUNT
    RTT_MIN = float('+inf')
    RTT_MAX = float('-inf')
    RTT_SUM = 0
    RTT_COUNT = 0
    count = 0
    # Timeout=1 means: If 1 second goes by without a reply from the server, then
    # the client assumes that either ping or the reply was lost along the way
    dest = gethostbyname(host)
    print( "Pinging " + dest + " using Python:")
    # Send ping requests to a server separated by about 1 second
    try:
        while True:
            count += 1
            print (doOnePing(dest, timeout))
            time.sleep(1)
    # Once the user interrupts, we stop pinging and do all of 
    # the calculations based on our global variables
    except KeyboardInterrupt:
        if count != 0:
            print ('--- {} Ping statistics ---'.format(host))
            print ('{} Packets transmitted, {} Packets received, {:.1f}% Packet loss'.format(count, RTT_COUNT, 100.0 - RTT_COUNT * 100.0 / count))
            # If we made at least 1 round trip
            if RTT_COUNT != 0:
                print ('Round-Trip Min/Avg/Max {:.3f}/{:.3f}/{:.3f} ms'.format(RTT_MIN, RTT_SUM / RTT_COUNT, RTT_MAX))

ping("219.99.166.50")