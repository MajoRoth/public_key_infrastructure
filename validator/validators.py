from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import math

from ca.certificate import Certificate
from ca.ca import CA


class Validator:

    class RevocedCertificateError(Exception):
        """raised when the certificate has been revoced by the specific ca"""

    class SignerNotCaError(Exception):
        """raised when the signer is not a root ca or authorized by another authorized ca"""
        pass

    def __init__(self):
        self.root_ca_dict = dict()

    def add_root_ca(self, name: str, pk: rsa.RSAPublicKey):
        self.root_ca_dict[name] = pk

    def validate(self, certificate: Certificate):
        if certificate.get_signer_name() in self.root_ca_dict.keys():
            self.root_ca_dict[certificate.get_signer_name()].verify(
                certificate.get_signature(),
                certificate.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            if certificate.is_ca:
                self.add_root_ca(certificate.name, certificate.public_key)

            if certificate.signer.check_if_revocated(certificate):
                raise self.RevocedCertificateError(certificate.name)

            return True
        raise self.SignerNotCaError(certificate.signer_name)
