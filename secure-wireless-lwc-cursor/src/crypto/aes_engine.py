from Crypto.Cipher import AES

from .base_engine import CryptoEngine


class AESEngine(CryptoEngine):
    def encrypt(self, key, nonce, ad, plaintext):
        cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce[:12])
        cipher.update(ad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct, tag

    def decrypt(self, key, nonce, ad, ciphertext, tag):
        try:
            cipher = AES.new(key[:16], AES.MODE_GCM, nonce=nonce[:12])
            cipher.update(ad)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            return None

    def name(self):
        return "AES-128-GCM"

    @property
    def algo_id(self):
        return 2
