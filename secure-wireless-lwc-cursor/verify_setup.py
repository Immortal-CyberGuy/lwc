"""Phase 1: verify dependencies and ASCON encrypt/decrypt round-trip."""

import importlib
import os

import ascon

# Verify remaining requirements resolve (no unused-import noise).
for _name in ("Crypto.Cipher", "scapy.all", "matplotlib", "pandas", "numpy", "psutil"):
    importlib.import_module(_name)

# Quick ASCON smoke test
key = os.urandom(16)
nonce = os.urandom(16)
plaintext = b"Hello, Lightweight Crypto!"
ciphertext = ascon.encrypt(key, nonce, b"", plaintext)
decrypted = ascon.decrypt(key, nonce, b"", ciphertext)
assert decrypted == plaintext, "ASCON FAILED!"

print("ALL IMPORTS OK. ASCON encrypt/decrypt VERIFIED.")
