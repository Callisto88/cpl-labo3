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

# Set log level to benefit from Scapy warnings
#logging.getLogger("scapy").setLevel(1)

# Test CRC8
hash = crc8.crc8()

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

    # TODO : Découpage du payload selon la taille
    # TODO : Découpage des 8 derniers bits de FCS-CRC
    # print("Payload : " + sn[0:3] + "[" + sn[3:4] + "]")
    # print("FCS-CRC : " + sn[0:3] + "[" + sn[3:4] + "]")
    print("---------------------")

	
#fct parité paire : Retourne le bit de parité du champ
def Parity(field):
	count = 0
	for c in field:
		if(c == '1'):
			count += 1
	
	return str(count % 2)
	
# data max length 27 bits
def CreateLPDU(dst,src,type,frag,data):
	global sn
	global lpduSent
	
	hash.update(data)
	size = len(data)
	
	if sn != 0 and (sn % 7) == 0 :
		sn = 0
	else :
		sn += 1
	
	lpdu = []
	lpdu.append(dst)
	lpdu.append(Parity(dst))
	lpdu.append(src)
	lpdu.append(Parity(src))
	lpdu.append(type)
	lpdu.append(Parity(type))
	lpdu.append(frag)
	lpdu.append(Parity(frag))
	lpdu.append(str(sn))
	lpdu.append(Parity(str(sn)))
	lpdu.append(str("{0:b}".format(size).zfill(4)))
	lpdu.append(Parity(str("{0:b}".format(size))))
	lpdu.append(data)
	lpdu.append(str(bin(int(hash.hexdigest(), 16))[2:].zfill(8)))
	lpdu.append(Parity(str(bin(int(hash.hexdigest(), 16))[2:])))
	
	# lpdu = ""
	# lpdu += dst
	# lpdu += Parity(dst)
	# lpdu += src
	# lpdu += Parity(src)
	# lpdu += type
	# lpdu += Parity(type)
	# lpdu += frag
	# lpdu += Parity(frag)
	# lpdu += str(sn)
	# lpdu += Parity(str(sn))
	# lpdu += "{0:b}".format(size)
	# lpdu += Parity("{0:b}".format(size))
	# lpdu += data
	# lpdu += (str(hash.hexdigest()))
	# lpdu += Parity(str(hash.hexdigest()))
	
	slpdu = ''.join(lpdu)
	
	print(slpdu)
	
	lpduSent[sn] = slpdu
	
	
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

        if trm.dst == "00011":

            trm.src = p.load[5:9]
            trm.type = p.load[9:11]
            trm.frag = p.load[11:13]
            trm.sn = p.load[13:17]
            trm.size = p.load[17:23]

            tabFrame = []
            tabFrame.append(trm)

            DisplayPacket(trm)


'''
But de la fonction: fragmenter un NPDUs de maximum 50 octets en fragments de longueur d'au maximum 21 octets.
Arguments d'entree : Une suite d'octets ascii representant les bits de la NPDU. Donnee par le personnel enseignant
'''
def Fragment():
    name = "expect frags"

    # Sortie : Fragments d'au plus 21 octets.

def Defragment():
    name = "complement frag"
    # complement fragment fn

def make_test():
    return Ether()/IP()/CreateLPDU("1101","011","1","0")


# reçoit tout le traffic et l'envoi en paramètre à ReceivePPDU
# a = sniff(filter="ether dst ffffffffffff", prn=ReceivePPDU)
# a = sniff(filter="ether dst ffffffffffff", prn=ReceivePPDU)

#----------------------- Scapy CPL -----------------------
# Envoyer des paquets avec payload
if __name__ == '__main__':
	CreateLPDU("0001", "010", "0", "1", "010101")
	
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