import math

from settings import g


class Validator:

    def __init__(self):
        pass

    def validate(self, sigma, hashed, public_key, message):
        ephemeral_public_key = math.pow(g, sigma) * math.pow(public_key, hashed)
        # check if the hash of ephemeral_public_key || message == hashed