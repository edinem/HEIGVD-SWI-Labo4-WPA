#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""


__author__      = "Edin Mujkanovic et Daniel Oliveira Paiva"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "edin.mujkanovic@heig-vd.ch"
__status__ 		= "Prototype"

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
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

ssid        = wpa[0].info # On récupère le SSID contenu dans la trame 1 dans l'info
APmac       = a2b_hex(str.replace(wpa[5].addr2, ":", "")) # Récupération de l'adresse MAC de l'AP dans la 6ème trame. On enlève les ":".
Clientmac   = a2b_hex(str.replace(wpa[5].addr1, ":", "")) # Récupération de l'adresse MAC du client dans la 6ème trame. On enlève les ":".

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90]) # Récupèration de l'Authenticator Nonce
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90]) # Récupèration du Supplicant Nonce

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[8].load.hex()[-36:-4] # Récuperation du MIC envoyé par le client



B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

ea = wpa[8][EAPOL] # On recupere la couche EAPOL de la trame

data =  hex(ea.version)[2:].zfill(2) # On récupère le numéro de version
data += hex(ea.type)[2:].zfill(2) # On récupère le type
data += hex(ea.len)[2:].zfill(4) # On récupère la longueur des données de la trame
data += (wpa[8].load[:-18]).hex() # On récupère toutes les données sauf le MIC et la longueur de la clé WPA
data += '0' * 32 # On remplace le MIC par des 0
data += (wpa[8].load[-2:]).hex() # On récupère la longueur de la clé WPA
data = a2b_hex(data) # Transformation en données binaires
print("Data :" + data.hex()) # On imprime le data créé avec les données récupérées dans la trames


print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
