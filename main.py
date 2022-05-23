from cryptography.hazmat.primitives.asymmetric import rsa

from ca.ca import CA
from validator.validators import Validator



if __name__ == '__main__':
    rsa_sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    ca = CA("root_ca", rsa_sk)
    cert1 = ca.generate_certificate("google", 1)
    cert2 = ca.generate_certificate("microsoft", 2)
    print(cert)
    signa = ca.sign(cert)
    print(signa)
    print(Validator.validate(ca.get_public_key(), cert))