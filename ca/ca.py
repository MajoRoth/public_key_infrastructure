from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from datetime import date

from ca.certificate import Certificate


class CA:

    def __init__(self, name, sk: rsa.RSAPrivateKey):
        self.name = name
        self.sk = sk
        self.pk = sk.public_key()
        self.revocation_list = list()  # list of invalid certs

    def generate_certificate(self, name, public_key, is_ca=False):
        date_from = date.today()
        date_to = date.today()
        date_to = date_to.replace(year=date_from.year + 1)
        cert = Certificate(name=name, public_key=public_key, signer=self,
                           validity_date_from=date_from, validity_date_to=date_to, is_ca=is_ca)
        return cert

    def sign(self, certificate: Certificate):
        signature = self.sk.sign(
            certificate.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        certificate.signer_signature = signature
        return signature

    def get_public_key(self):
        return self.pk

    def revocate(self, certificate: Certificate):
        self.revocation_list.append(certificate)

    def check_if_revocated(self, certificate: Certificate):
        return certificate in self.revocation_list



