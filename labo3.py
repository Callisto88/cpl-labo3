#! /usr/bin/env python
# coding: utf-8

# This script requires the following module to be installed :
# - crc8
# - pcapy
# - netifaces
#
# - you may install them using pip install [module_name]

'''
Imports
'''
# Import all modules
#from scapy.all import *
#import logging
import crc8
import binascii
import math

# Set log level to benefit from Scapy warnings
#logging.getLogger("scapy").setLevel(1)

# Test CRC8
hash = crc8.crc8()

# Constantes
MAX_SIZE_PAYLOAD = 28

# myvar = input("Entrez une chaîne pour générer son CRC8 : ")
# hash.update(str(myvar))
# print("CRC calculated for [ " + str(myvar) + " ] is => " + str(hash.hexdigest()))
# assert hash.hexdigest() == 'c0'

# Manual input
# seq = input("Entrez la suite de bits de la séquence : ")

# print("Séquence reçue : " + str(seq))
# print("Découpage de la séquence selon custom protocole : \n")

'''
Définition des fonctions
- CreateLPDU
- SendPPDU
- CreateLSDU
- ReceivePPDU
- Fragment
- Defragment
'''

class trame:
    def __init__(self):
        self.dst = 0
        self.src = 0
        self.type = 0
        self.frag = 0
        self.sn = 0
        self.size = 0
        self.payload = 0
        self.crc = 0

# variable globales SN (sequence number), receivedWindows, sendWindows
sn = 0
lpduRec = []
lpduSent = [ [ None for y in range( 1 ) ] for x in range( 8 ) ]

# Basic function to display packet fields
def DisplayPacket(trm):
    print("---------------------")
    trm.show()    # Packet summary

    print("---------------------")
    print("Splitting frame's load\n")
    print("Destination : " + trm.dst[0:4] + "[" + trm.dst[4:5] + "]")
    print("Source : " + trm.src[0:3] + "[" + trm.src[3:4] + "]")
    print("Type : " + trm.type[0:1] + "[" + trm.type[1:2] + "]")
    print("Fragment : " + trm.frag[0:1] + "[" + trm.frag[1:2] + "]")
    print("Séquence No : " + trm.sn[0:3] + "[" + trm.sn[3:4] + "]")
    print("Taille : " + trm.size[0:5] + "[" + trm.size[5:6] + "]")
    print("Payload : " + trm.payload)
    print("FCS-CRC : " + trm.crc[0:8] + "[" + trm.crc[8:9] + "]")
    print("---------------------")


#fct parité paire : Retourne le bit de parité du champ
def Parity(field):
    count = 0
    for c in field:
        if(c == '1'):
            count += 1

    return str(count % 2)

# data max length 27 bits
def CreateLPDU(dst, src, type, data):
    print("\n\n====================")
    print("Function : CreateLPDU ")
    print("======================")
    print("Received from NPDU : " + str(data));

    global sn
    global lpduSent
    slpdu = []
    output = []

    fragNo = 1

    # Return a fragments list
    Fragment(data, output)

    # Consider each fragment
    for fragData in output:

        print("Considering frag #" + str(fragNo) + " => " + str(fragData))

        # FCS-CRC
        hash.update(fragData)
        size = len(fragData)

        lpdu = []
        lpdu.append(dst)
        lpdu.append(Parity(dst))
        lpdu.append(src)
        lpdu.append(Parity(src))
        lpdu.append(type)
        lpdu.append(Parity(type))
        lpdu.append(str(fragNo))
        lpdu.append(Parity(str(fragNo)))
        lpdu.append(str("{0:b}".format(sn).zfill(3)))
        lpdu.append(Parity(str("{0:b}".format(sn))))
        lpdu.append(str("{0:b}".format(size).zfill(4)))
        lpdu.append(Parity(str("{0:b}".format(size))))
        lpdu.append(fragData)
        lpdu.append(str(bin(int(hash.hexdigest(), 16))[2:].zfill(8)))
        lpdu.append(Parity(str(bin(int(hash.hexdigest(), 16))[2:])))

        fragNo = fragNo + 1
        slpdu = ''.join(lpdu)

        # Debug
        print("Sequence #" + str(sn) + " output SLPDU : " + slpdu)

        lpduSent[sn] = slpdu

        # Update sequence number
        if sn != 0 and (sn % 7) == 0:
            sn = 0
        else:
            sn += 1

    return slpdu

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

'''
But de la fonction: Filtrer les PPDU qui nous sont destines et les stocker dans un tableau
Fonction complementaire du script SendPPDU
'''
def ReceivePPDU(p):

    if hasattr(p, 'load'):

        trm = trame();

        # Spliting the load
        trm.dst = p.load[0:5]

        if trm.dst == "00011" and trm.dst[-1] == Parity(trm.dst):

            trm.src = p.load[5:9]
            trm.type = p.load[9:11]
            trm.frag = p.load[11:13]
            trm.sn = p.load[13:17]
            trm.size = p.load[17:23]

            length = int(trm.size[0:5], 2)

            trm.payload = p.load[23:23+length]
            trm.crc = p.load[23+length:23+length+8]

            # Verifiy parity bit for every field, if any is incorrect return
            if trm.src[-1] != Parity(trm.src) or \
                trm.type[-1] != Parity(trm.type) or \
                trm.frag[-1] != Parity(trm.frag) or \
                trm.sn[-1] != Parity(trm.sn) or \
                trm.size[-1] != Parity(trm.size):

                print("Parity check failed");
                return

            tabFrame = []
            tabFrame.append(trm)

            DisplayPacket(trm)


'''
But de la fonction: fragmenter un NPDUs de maximum 60 bits en fragments de longueur d'au maximum 27 bits
Arguments d'entree : Une suite d'octets ascii representant les bits de la NPDU. Donnee par le personnel enseignant
Sortie : Fragments d'au plus 27 bits
'''


def Fragment(NPDU, output):
    # assert we have max. 60 bits
    # max payload size is defined as constants in the header

    print("\n\n====================")
    print("Function : Fragment ")
    print("======================")

    lengthNPDU = len(NPDU)
    print("NPUD received : " + NPDU + " [ length = " + str(lengthNPDU) + " ]")

    nbFrag = int(math.ceil(float(lengthNPDU) / MAX_SIZE_PAYLOAD))
    print("Nombres de fragments : " + str(nbFrag))

    i = 0
    while nbFrag > 1:
        payloadRange = NPDU[i * MAX_SIZE_PAYLOAD:(i + 1) * MAX_SIZE_PAYLOAD]
        print("Fragment #" + str(i) + " : [ " + str((i * MAX_SIZE_PAYLOAD)) + " : " + str(
            ((i + 1) * MAX_SIZE_PAYLOAD)) + " ] => " + str(payloadRange))
        output.append(payloadRange)
        del payloadRange

        i = i + 1
        nbFrag = nbFrag - 1

    print("Fragment #" + str(i) + " : [ " + str((i * MAX_SIZE_PAYLOAD)) + " : " + str(len(NPDU)) + " ] => " + str(
        NPDU[i * MAX_SIZE_PAYLOAD:(i + 1) * MAX_SIZE_PAYLOAD]))
    output.append(NPDU[i * MAX_SIZE_PAYLOAD:(i + 1) * MAX_SIZE_PAYLOAD])

def Defragment():
    name = "complement frag"
    # complement fragment fn

# reçoit tout le traffic et l'envoi en paramètre à ReceivePPDU
# a = sniff(filter="ether dst ffffffffffff", prn=ReceivePPDU)
# a = sniff(filter="ether dst ffffffffffff", prn=ReceivePPDU)

#----------------------- Scapy CPL -----------------------
# Envoyer des paquets avec payload
if __name__ == '__main__':
    dst = "0100"
    src = "001"

    NPDU = "00010101000101010010101010010010010000111010100010110100111"  # 59 bits
    # Fragment(NPDU)

    CreateLPDU(dst, src, "0", NPDU)

'''
    PPDUtoSend = "00010101000101010010101010010010010000111010100010110100111"  # 59 bits
    lengthPPDU = len(PPDUtoSend)
    print(PPDUtoSend + " [ length = " + str(lengthPPDU) + " ]")

    nbFrag = int(math.ceil(float(lengthPPDU) / MAX_SIZE_PAYLOAD))
    print("Nombres de fragments : " + str(nbFrag))

    i = 0
    while nbFrag > 1:
        print("Fragment #" + str(nbFrag) + ", with payload range as : [ " + str((i * MAX_SIZE_PAYLOAD)) + " : " + str(((i + 1) * MAX_SIZE_PAYLOAD)) + " ]" )
        payloadRange = PPDUtoSend[i * MAX_SIZE_PAYLOAD:(i + 1) * MAX_SIZE_PAYLOAD]
        CreateLPDU(dst, src, "0", "0", payloadRange)
        del payloadRange
        i = i+1
        nbFrag = nbFrag-1

    print("Last fragment : [ " + str((i * MAX_SIZE_PAYLOAD)) + " : " + str(len(PPDUtoSend)) + " ]")
    CreateLPDU(dst, src, "0", "1", PPDUtoSend[i * MAX_SIZE_PAYLOAD:(i + 1) * MAX_SIZE_PAYLOAD])

    # CreateLPDU("0001", "010", "0", "1", "010101")
'''

'''
sendp(Ether()/"Hello World")
a = Ether()
data = "100110"
sendp(a/data)

# Paramètres de trames Ethernet
Ether(src = "11:22:33:44:55:66", dst = "ff:ff:ff:ff:ff:ff", type = 0x0801)

# Sniffer des paquets (ctrl+c pour arrêter)
a = sniff(filter = "ether src 000000000000") # avec adresse de source 00:00:00:00:00:00
a = sniff(filter = "ether dst ffffffffffff") # avec adresse de destination ff:ff:ff:ff:ff:ff
a = sniff(filter = "ether proto 0x0801") # avec type de trame 0x0801

# En travaillant directement sur les datas (l'adresse source est du 6 au 12ème octet dans une trame Ethernet):
a = sniff(filter = "ether[6:4] == 0x34363bd3 and ether[10:2] == 0xea14") # avec adresse de source 34:36:3b:d3:ea:14

# Affichage du tableau des trames reçues
a.show()

# Affichage d'une des trames reçues
a[1].show()

#------------------ Exemples avec python ------------------
# N'affiche que les paquets avec une certaine adresse de destination (si pas filtré avant)
for p in a:
    if p.dst == "ff:ff:ff:ff:ff:ff":
        p.show()
        print("--------------------------------")

# N'affiche que les paquets contenant une certaine séquence dans le payload
if p.load.__contains__('100001'):   # Pourrait être un flag
    print("salut")

# N'affiche que les paquets dont le payload commence par une certaine la séquence
# Pourrait être une adresse de destination

if p.load[1:4] == "1101":
    print(p.load)

# Lancer une foncton pour chaque paquet sniffé, ici affiche les paquets au fur et à mesure qu'ils arrivent
def customAction(packet):
    packet.show()
    print("--------------------------------")

sniff(filter = "ether src 000000000000 and ether dst = ffffffffffff", prn = customAction)
'''