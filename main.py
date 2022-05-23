from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ca.certificate import Certificate
from ca.ca import CA
from validators import Validator



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
    print(Validator.validate(rsa_pk, cert, signa))