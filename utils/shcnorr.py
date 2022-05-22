import hashlib
import random

import settings


def sign(sk, message):
    k = random.getrandbits(10)  # ephemeral private key
    h = hashlib.sha256()
    h.update(bytes(message, 'utf-8') + bytes(hex(settings.g*k), 'utf-8'))  # hash
    signature = k - sk * int.from_bytes(h.digest(), 'big')
    print("sign")
    print(signature)
    print(int.from_bytes(h.digest(), 'big'))
    return signature, int.from_bytes(h.digest(), 'big')


def verify(pk, signature, h, message):
    gk = (settings.g ** signature) * (pk ** h)# public ephemeral key
    hash_result = hashlib.sha256()
    hash_result.update(bytes(hex(gk), 'utf-8') + bytes(message, 'utf-8'))
    print("verify")
    print(hash_result)
    print(h)




if __name__ == "__main__":
    s, h = sign(1, "Hello")
    verify(2, s, h, "Hello")
