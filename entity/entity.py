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
        self.ca = None

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

    def request_cert(self, ca: CA, is_ca=False):
        if type(ca) == Entity:
            if ca.ca is None:
                raise "entity is not a ca"
            ca = ca.ca
        self.certificate = ca.generate_certificate(self.name, self.pk, is_ca=is_ca)
        if is_ca:
            self.ca = CA(self.name, self.sk)

        ca.sign(self.certificate)
        print(self.certificate)
