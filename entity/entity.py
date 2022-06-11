import pickle
import socket

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


from ca.ca import CA
import settings


class Entity:

    class NotCaError(Exception):
        """raised when the entity is not a ca"""

    def __init__(self, name, sk, certificate=None):
        self.name = name
        self.sk = sk
        self.pk = sk.public_key()
        self.certificate = certificate
        self.ca = None
        self.root_ca = False

    def sign(self, message):
        signature = self.sk.sign(
            bytes(str(message), 'utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    def request_cert(self, ca_address, ca_port, pk, is_ca=False):
        print("REQUEST CERT")

        soc = socket.socket()

        print('Waiting for connection')
        try:
            soc.connect((ca_address, int(ca_port)))
        except socket.error as e:
            print(str(e))

        print(soc.recv(1024))


        soc.send(bytes("is_ca ", settings.FORMAT))
        is_signer_ca = soc.recv(settings.RECEIVE_BYTES)
        print("IS_CA {}".format(is_ca))
        if is_signer_ca == settings.BAD:
            raise self.NotCaError()

        if is_signer_ca == settings.OK:
            self.ca = CA(self.name, self.sk)

        serialized_pk = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print(serialized_pk)


        soc.send(bytes("generate_cert {} {} {} {} {}".format(self.name, serialized_pk, ca_address, ca_port, is_ca), settings.FORMAT))
        pickled_cert = soc.recv(settings.RECEIVE_BYTES)
        return pickled_cert
        # self.certificate = ca_entity.ca.generate_certificate(self.name, self.pk, ca_entity, is_ca=is_ca)
        # if is_ca:
        #     self.ca = CA(self.name, self.sk)
        #
        # ca_entity.ca.sign(self.certificate)

    def make_root_ca(self):
        self.root_ca = True
        self.ca = CA(self.name, self.sk)

    def is_ca(self):
        return self.ca is not None

    def get_cert(self):
        return self.certificate



    """
        CA methods
    """





