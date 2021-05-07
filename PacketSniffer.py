#Importing the necessary modules
import logging
from datetime import datetime
import subprocess
import sys

#This will supress all messages that have less significance
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()
    
#Printing a message to the user; always use "sudo scapy" in Linux!
print("\n! Make sure to run this program as ROOT !\n")

#Asking the user for some parameters: interface on which sniff, the number of packets to sniff, the time interval to sniff, the protocol

#Asking the user for input - the interface on which to run the sniffer
net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")

#Setting network interface in promiscuous mode
'''
Wikipedia: In computer  networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network 
interface controller (NIC) or wireless network interface controller (WNIC) that causes the controller to
pass all traffic it receives to the central processing unit (CPU) rather than passing only the frames 
that the controller is interned to receive.
This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.
'''
try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)
 
except:
    print("\nFailed to configure interface as promiscuous.\n")

else:
    #Executed if the try clause does not raise an exception
    print("\nInterface %s was set to PROMISC mode.\n" % net_iface)
    
#APPLICATION #Part 2
    
#Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")

#Consider the case when user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))
    
elif int(pkt_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")
    
#Asking the user for the time interval to sniff (the "timeout" paramter)
time_to_sniff = input("* Enter the number of seconds to run the capture: ")

#Handling the value entered by the user
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))
    
#Asking the user for any protocol filter he might want to apply to the sniffing process
#For this example I chose three protocols: ARP, BOOTP, ICMP
#You can customize this to add your own desired protocols
proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

#Considering the case when the user enters 0 (meaning all protocols)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
   
elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")

#Asking the user to enter the name and path of the log file to be created
file_name = input("* Please give a name to the log file: ")

#Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending
sniffer_log = open(file_name, "a")


#APPLICATION #Part 3
#This is the function that will be called for each captured packet
#The function will extract parameters from the packet and then log each packet to the log file
def packet_log(packet):
    
    #Getting the current timestamp
    now = datetime.now()
    
    #Writing the packet information to the log file, also considering the protocol or 0 fo all protocols
    if proto_sniff == "0":
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)
        
    elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
        #Writing the data to the log file
        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)

#Printing an informational message to the screen
print("\n* Starting the capture...")

#Running the sniffing process (with or without a filter)
if proto_sniff == "0":
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
else:
    print("\nCould not identify the protocol.\n")
    sys.exit()

#Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % file_name)

#Closing the log file
sniffer_log.close()

#End of the program