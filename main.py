from cryptography.hazmat.primitives.asymmetric import rsa

from ca.ca import CA
from validator.validators import Validator
from entity.entity import Entity



if __name__ == '__main__':
    rsa_root_ca = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    rsa_usa_ca = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    rsa_il_ca = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    rsa_google = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    rsa_microsoft = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    rsa_wix = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    root_ca = CA("root_ca", rsa_root_ca)

    usa = Entity("usa_ca", rsa_usa_ca)
    usa.request_cert(root_ca, True)

    il = Entity("il_ca", rsa_il_ca)
    il.request_cert(root_ca, True)

    google = Entity("google", rsa_google)
    google.request_cert(usa)

    microsoft = Entity("microsoft", rsa_microsoft)
    microsoft.request_cert(usa)

    wix = Entity("wix", rsa_wix)
    wix.request_cert(il)

    v = Validator()
    v.add_root_ca(root_ca.name, root_ca.pk)
    v.validate(il.certificate)
    il.ca.revocate(wix.certificate)
    v.validate(wix.certificate)



