import pickle

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import date
import math
import socket

import ca.ca
import entity.entity
import settings
from ca.certificate import Certificate
from ca.ca import CA
from cryptography.hazmat.primitives.serialization import load_pem_public_key



class Validator:

    class RevocedCertificateError(Exception):
        """raised when the certificate has been revoced by the specific ca"""

    class SignerNotCaError(Exception):
        """raised when the signer is not a root ca or authorized by another authorized ca"""
        pass

    class ExpiredDate(Exception):
        """raised when the date is of the cert is expired"""
        pass

    def __init__(self):
        self.root_ca_dict = dict()

    def verify(self, pk: rsa.RSAPublicKey, message, signature):
        pk.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    def add_root_ca(self, root_address, root_port, pk: rsa.RSAPublicKey):
        self.root_ca_dict[(root_address, root_port)] = pk

    def validate(self, certificate: Certificate):
        if self.is_ca(certificate.signers_entity_address, certificate.signers_entity_port):
            soc = socket.socket()

            print('Waiting for connectionn')

            try:
                soc.connect((certificate.signers_entity_address, int(certificate.signers_entity_port)))
            except socket.error as e:
                print(str(e))
            print(soc.recv(settings.RECEIVE_BYTES))
            print("get here")

            soc.send(str.encode("pk"))

            pk_data = soc.recv(settings.RECEIVE_BYTES)
            pk = load_pem_public_key(pk_data)

            try:
                pk.verify(
                    certificate.get_signature(),
                    certificate.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception:
                return False

            if settings.LOG.value >= settings.Log.Results.value:
                print("{}Results: pk verified {}".format('\033[92m', '\033[0m'))


            if self.revocated(certificate):
                return False

            if certificate.validity_date_to < date.today():
                return False

            print("Passed all")
            return True

        return False

    def passive_validate(self, certificate: Certificate, pk: rsa.RSAPublicKey):
        pk.verify(
            certificate.get_signature(),
            certificate.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        return True

    def is_ca(self, address, port):
        soc = socket.socket()

        print('Waiting for connection')
        try:
            soc.connect((address, int(port)))
        except socket.error as e:
            print(str(e))

        print(soc.recv(settings.RECEIVE_BYTES))

        print((address, int(port)) in self.root_ca_dict)
        if (address, int(port)) in self.root_ca_dict:
            return True

        soc.send(str.encode("get_cert"))
        cert = soc.recv(settings.RECEIVE_BYTES)
        cert = pickle.loads(cert)
        print(cert)
        if cert == settings.BAD:
            return False


        signer_soc = socket.socket()
        try:
            signer_soc.connect((cert.signers_entity_address, int(cert.signers_entity_port)))
        except socket.error as e:
            print(str(e))

        print(signer_soc.recv(settings.RECEIVE_BYTES))
        signer_soc.send(str.encode("pk"))

        pk_data = signer_soc.recv(settings.RECEIVE_BYTES)
        pk = load_pem_public_key(pk_data)


        if cert.is_ca and self.passive_validate(cert, pk):
            return self.is_ca(cert.signers_entity_address, int(cert.signers_entity_port))

        print("NOT A CA - RETURNED FALSE")
        return False


    def revocated(self, certificate: Certificate):
        soc = socket.socket()

        try:
            soc.connect((certificate.signers_entity_address, int(certificate.signers_entity_port)))
        except socket.error as e:
            print(str(e))
        print(soc.recv(settings.RECEIVE_BYTES))

        print("REVOCATING")
        soc.send(str.encode("check_if_revocated"))
        soc.recv(settings.RECEIVE_BYTES)
        soc.send(pickle.dumps(certificate))
        print("REVOCATING")

        answer = soc.recv(settings.RECEIVE_BYTES)
        print(answer)
        print(answer==settings.OK)
        if answer == settings.OK:
            return True

        print("wew")

        soc.send(str.encode("is_root_ca"))
        if soc.recv(settings.RECEIVE_BYTES) == settings.OK:
            return False

        soc.send(str.encode("get_cert"))
        signer_cert = pickle.loads(soc.recv(settings.RECEIVE_BYTES))
        return self.revocated(signer_cert)



