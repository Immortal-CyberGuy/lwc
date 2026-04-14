import ascon as _ascon

from .base_engine import CryptoEngine


class AsconEngine(CryptoEngine):
    def encrypt(self, key, nonce, ad, plaintext):
        ct_tag = _ascon.encrypt(key, nonce, ad, plaintext)
        return ct_tag[:-16], ct_tag[-16:]

    def decrypt(self, key, nonce, ad, ciphertext, tag):
        return _ascon.decrypt(key, nonce, ad, ciphertext + tag)

    def name(self):
        return "ASCON-AEAD128"

    @property
    def algo_id(self):
        return 1
