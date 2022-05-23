from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ca.ca import CA


class Entity:
    def __init__(self, name, sk, certificate=None):
        self.name = name
        self.sk = sk
        self.pk = sk.public_key()
        self.certificate = certificate

    """
    Schnorr signatures
    """
    def sign(self, message):
        signature = self.sk.sign(
            bytes(message, 'utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def request_cert(self, ca: CA):
        self.certificate = ca.generate_certificate(self.name, self.pk)
