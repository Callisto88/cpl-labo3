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
from scapy.all import *
import logging
import crc8

# Set log level to benefit from Scapy warnings
logging.getLogger("scapy").setLevel(1)

# Test CRC8
hash = crc8.crc8()

# myvar = input("Entrez une chaîne pour générer son CRC8 : ")
# hash.update(str(myvar))
# print("CRC calculated for [ " + str(myvar) + " ] is => " + str(hash.hexdigest()))
# assert hash.hexdigest() == 'c0'

# Manual input
# seq = input("Entrez la suite de bits de la séquence : ")

# Ecoute de paquets broadcast
a = sniff(filter = "ether dst ffffffffffff") # avec adresse de destination ff:ff:ff:ff:ff:ff
for p in a:
    if p.dst == "ff:ff:ff:ff:ff:ff":
        p.show()
        print("--------------------------------")

# print("Séquence reçue : " + str(seq))
# print("Découpage de la séquence selon custom protocole : \n")

dst = p.load[0:5]
src = p.load[5:9]
type = p.load[9:11]
frag = p.load[11:13]
sn = p.load[12:14]

print("Destination : " + dst)
print("Source : " + src)
print("Type : " + type)
print("Fragment : " + frag)
print("Séquence No : " + sn)

'''
Définition des fonctions
- CreateLPDU
- SendPPDU
- CreateLSDU
- ReceivePPDU
- Fragment
- Defragment
'''
def CreateLPDU(dst,src,type,frag):
    name = "CPL_Ansermoz_deBourgues"
    champs = [ ShortField("dst","1111"),
               ShortField("src","101"),
               ShortField("type","1"),
               ShortField("frag","0") ]
    print("Destination : " + dst)
    print("Source : " + src)
    print("Type : " + type)
    print("Fragment : " + frag)

    return champs

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

    ## But de la fonction: Filtrer les PPDU qui nous sont destines et les stocker dans un tableau
    #     ## Fonction complementaire du script SendPPDU

def Fragment():
    name = "expect frags"
    # But de la fonction: fragmenter un NPDUs de maximum 50 octets en fragments de longueur d'au maximum 21 octets.
    # Arguments d'entree : Une suite d'octets ascii representant les bits de la NPDU. Donnee par le personnel enseignant

    # Sortie : Fragments d'au plus 21 octets.

def Defragment():
    name = "complement frag"
    # complement fragment fn

def make_test():
    return Ether()/IP()/CreateLPDU("1101","011","1","0")

#----------------------- Scapy CPL -----------------------
# Envoyer des paquets avec payload
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