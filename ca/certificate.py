

class Certificate:

    def __init__(self, name, public_key, signer_name, signer_signature, validity_date_from, validity_date_to, is_ca = False):
        self.name = name
        self.public_key = public_key
        self.signer_name = signer_name
        self.signer_signature = signer_signature
        self.validity_date_from = validity_date_from
        self.validity_date_to = validity_date_to
        self.is_ca = is_ca





