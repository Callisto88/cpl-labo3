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

def CreateLPDU(dst,src,type,frag):
    name = "Gros protocole de sa raclette de mes 2"
    champs = [ ShortField("dst", 4),
               ShortField("src", 3),
               ShortField("type", 1),
               ShortField("frag", 3) ]
    print(dst)

def SendPPDU(LPDU):
    src = '00:00:00:00:00:00'
    dst = 'FF:FF:FF:FF:FF:FF'

    # Here scapy cmd effectiv send

def CreateLSDU():
    name = "error check"
    # lookup for any error
    # //

    # check if had an error but were fixed meantime
    # //

    # detect rafales de 2 ou 3 erreurs < 8
    # //

def ReceivePPDU():
    name = "reveive PPDU"
    # But de la fonction: Filtrer les PPDU qui nous sont destinés et les stocker dans un tableau.
    # Fonction complémentaire du script SendPPDU

def Fragment():
    name = "expect frags"
    # But de la fonction: fragmenter un NPDUs de maximum 50 octets en fragments de longueur d’au maximum 21 octets.
    # Arguments d’entrée : Une suite d’octets ascii représentant les bits de la NPDU. Donnée par le personnel enseignant.

    # Sortie : Fragments d’au plus 21 octets.

def Defragment():
    name = "complement frag"
    # complement fragment fn

def make_test():
    return Ether()/IP()/CreateLPDU(dst="1101",src="011",type="1",frag="110")

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="CPL Labo")
