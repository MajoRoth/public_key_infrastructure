

class Certificate:

    def __init__(self, name, public_key, signer_name, validity_date_from, validity_date_to,
                 signers_entity_address, signers_entity_port, signer_signature=None, is_ca=False):
        self.name = name
        self.public_key = public_key
        self.signer_name = signer_name
        self.signer_signature = signer_signature
        self.validity_date_from = validity_date_from
        self.validity_date_to = validity_date_to
        self.is_ca = is_ca
        self.signers_entity_address = signers_entity_address
        self.signers_entity_port = signers_entity_port

    def __str__(self):
        return "name: {name}\n" \
               "signer_name: {signer_name}\n" \
               "validity_date_from: {validity_date_from}\n" \
               "validity_date_to: {validity_date_to}\n" \
               "public_key: {public_key}\n" \
               "signer_signature: {signer_signature}\n" \
               "is_ca: {is_ca}\n".format(
                name=self.name,
                signer_name=self.signer_name,
                validity_date_from=self.validity_date_from,
                validity_date_to=self.validity_date_to,
                public_key=self.public_key,
                signer_signature=self.signer_signature,
                is_ca=self.is_ca
        )

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return (self.name == other.name and self.signer_name == other.signer_name
                and self.public_key == other.public_key and self.signer_signature == other.signer_signature
                and self.validity_date_from == other.validity_date_from and self.validity_date_to == other.validity_date_to)



    def encode(self):
        str_output = "{name}{signer_name}{validity_date_from}{validity_date_to}{public_key}{is_ca}".format(
            name=self.name,
            signer_name=self.signer_name,
            validity_date_from=self.validity_date_from,
            validity_date_to=self.validity_date_to,
            public_key=self.public_key,
            signer_signature=self.signer_signature,
            is_ca=self.is_ca
        )
        return bytes(str_output, 'utf-8')

    def get_signature(self):
        if self.signer_signature is None:
            raise "cert does not signed"
        return self.signer_signature

    def get_signer_name(self):
        return self.signer_name





