from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import pickle

from certificate import Certificate


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
        # certificate.signer_signature = signature
        return signature


if __name__ == '__main__':
    rsa_sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    rsa_pk = rsa_sk.public_key()
    cert = Certificate("google", rsa_pk, "root_ca", "01.01.2020", "01.01.2023")
    print(cert)
    ca = CA("root_ca", rsa_sk)
    signa = ca.sign(cert)
    print(signa)
    print(validate(rsa_pk, cert, signa))
