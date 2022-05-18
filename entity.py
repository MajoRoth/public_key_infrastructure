import math

from settings import g


class Entity:
    def __init__(self):
        pass

    """
    Schnorr signatures
    """
    def sign(self, secret_key, message):
        public_key = math.pow(g, secret_key)  # public key calc
        ephemeral_k = 1  # choose random k
        ephemeral_public_key = math.pow(g, ephemeral_k) # ephemeral public
        hash_message = 1  # Hash(ephemeral_public_key + message)
        sigma =  ephemeral_k - secret_key * hash_message # Fixed sized output. sign arbitrarily long messages by hashing
        return sigma, hash_message
