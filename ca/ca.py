from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from datetime import date

from ca.certificate import Certificate
from utils.logs import log
from utils import settings


class CA:

    def __init__(self, name, sk: rsa.RSAPrivateKey):
        self.name = name
        self.sk = sk
        self.pk = sk.public_key()
        self.revocation_list = list()  # list of invalid certs

    def generate_certificate(self, name, public_key, ca_address, ca_port, is_ca=False):
        date_from = date.today()
        date_to = date.today()
        date_to = date_to.replace(year=date_from.year + 1)
        cert = Certificate(name=name, public_key=public_key, signer_name=self.name, signers_entity_port=ca_port,
                           signers_entity_address=ca_address,
                           validity_date_from=date_from, validity_date_to=date_to, is_ca=is_ca)

        self.sign(cert)
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
        self.update_revocation_list()
        self.revocation_list.append(certificate)

    def check_if_revocated(self, certificate: Certificate):
        self.update_revocation_list()
        return certificate in self.revocation_list

    def update_revocation_list(self):
        d = date.today()
        new_list = list()
        for cert in self.revocation_list:
            if cert.validity_date_to >= d:
                new_list.append(cert)

        self.revocation_list = new_list
        log("{}".format(self.revocation_list), settings.LOG.Debug)




