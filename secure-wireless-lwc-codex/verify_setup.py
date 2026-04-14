import os
import socket
import struct
import tracemalloc
import time

import ascon
import matplotlib
import numpy
import pandas
import scapy.all
from Crypto.Cipher import AES


# Quick ASCON smoke test
key = os.urandom(16)
nonce = os.urandom(16)
plaintext = b"Hello, Lightweight Crypto!"

ciphertext = ascon.encrypt(key, nonce, b"", plaintext)
decrypted = ascon.decrypt(key, nonce, b"", ciphertext)

assert decrypted == plaintext, "ASCON FAILED!"
print("ALL IMPORTS OK. ASCON encrypt/decrypt VERIFIED.")
