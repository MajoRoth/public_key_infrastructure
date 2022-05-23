from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import pickle

from ca.certificate import Certificate


class CA:

    def __init__(self, name, sk: rsa.RSAPrivateKey):
        self.name = name
        self.sk = sk

    def generate_certificate(self):
        pass

    def sign(self, certificate: Certificate):
        print(certificate)
        signature = self.sk.sign(
            bytes(str(certificate), 'utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        certificate.signer_signature = signature
        return signature



