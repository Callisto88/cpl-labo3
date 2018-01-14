#! /usr/bin/env python3

# Set log level to benefit from Scapy warnings
import logging

# debug on os x
# import os
# print(os.sys.path)
logging.getLogger("scapy").setLevel(1)

# Import all modules
from scapy.all import *

import crc8
hash = crc8.crc8()
hash.update(b'123')
assert hash.hexdigest() == 'c0'

print(hash)

def CreateLPDU(dst,src,type,payload):
    name = "Gros protocole de sa raclette de mes 2"
    champs = [ ShortField("dst", 4),
               ShortField("src", 3),
               ShortField("type", 1),
               ShortField("frag", 3) ]


def make_test():
    return Ether()/IP()/CreateLPDU(dst="1101",src="011",type="1",payload="110")

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="CPL Labo")
