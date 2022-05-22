from Crypto.PublicKey import RSA

from certificate import Certificate

class CA:

    def __init__(self, name, sk):
        self.name = name
        self.sk = sk


    def generate_certificate(self):
        pass


    def sign(self, certificate: Certificate):
        empheral_private_key =
        pass


if __name__ == '__main__':
    key = RSA.generate(2048)
    c = CA("google", key)