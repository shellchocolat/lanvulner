
#!/usr/bin/env python3
import sys
import os
import time
import argparse
import socket
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
import scapy.sendrecv

parser = argparse.ArgumentParser()
parser.add_argument('-n', '--TTL', help="Time To Live")
parser.add_argument('-I', '--INTERFACE', help="renseigner l'interface utilisee : eth0, wlan0, ...")
parser.add_argument('-v', '--IP_VICTIME', help="renseigner l'adresse ip de la victime")
parser.add_argument('-t', '--TIMEOUT', help="renseigner le timeout")
parser.add_argument('-p', '--PROTOCOL', help="renseigner le protocol: ICMP/TCP/UDP")
args = parser.parse_args()


ttl = int(args.TTL)
timeout = int(args.TIMEOUT)
interface = args.INTERFACE
ip_victime = args.IP_VICTIME
protocol = args.PROTOCOL

def main():

	try:
		dest = socket.gethostbyname(ip_victime)
	except Exception as e:
		dest = ip_victime
		print(str(e))
		sys.exit(1)	

	for i in range(1, ttl+1):
		if protocol == "TCP":
			packet = IP(dst=dest, ttl=i)/TCP(dport=53, flags="S")
		elif protocol == "UDP":
			packet = IP(dst=dest, ttl=i)/UDP(dport=34334)
		elif protocol == "ICMP":
			packet = IP(dst=dest, ttl=i)/ICMP(type='echo-request')
		else:
			packet = IP(dst=dest, ttl=i)/ICMP(type='echo-request')

		packets = scapy.sendrecv.sr1(packet, verbose=False, timeout=timeout)
		if packets:
			try:
				hostname = socket.gethostbyaddr(packets[0].src)[0]
			except:
				hostname = "* * *"

			print('[{:02d}] {:s} ({:s})'.format(i, packets[0].src, hostname))

			if packets[0].src == dest:
				break
		
		else:
			print('[{:02d}] Timeout'.format(i))

	sys.exit(1)

if __name__ == "__main__":
	main()
