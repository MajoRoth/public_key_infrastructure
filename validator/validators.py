from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import math

from ca.certificate import Certificate

class Validator:

    def __init__(self):
        pass

    @staticmethod
    def validate(public_key: rsa.RSAPublicKey, certificate: Certificate):
        return public_key.verify(
            certificate.get_signature(),
            certificate.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )