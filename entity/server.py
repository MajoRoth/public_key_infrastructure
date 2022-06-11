import pickle
import socket
import re
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from entity import Entity
import settings

from _thread import *

entity = None


def run(PORT):
    ServerSocket = socket.socket()
    ThreadCount = 0
    try:
        ServerSocket.bind((settings.SERVER_HOST, PORT))
    except socket.error as e:
        print(str(e))

    print('Waitiing for a Connection..')
    ServerSocket.listen(5)

    while True:
        Client, address = ServerSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(threaded_client, (Client,))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSocket.close()


def threaded_client(connection):
    global entity
    connection.send(str.encode('Welcome to the Server'))
    while True:
        data = connection.recv(settings.RECEIVE_BYTES)
        if data:
            data = data.decode(settings.FORMAT)
            print(data)

            if re.findall("^create_entity ", data):
                entity = Entity(data.split()[1], rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                ))
                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: created entity {} {}".format('\033[92m', data.split()[1], '\033[0m'))

                connection.sendall(settings.OK)


            elif re.findall("^sign ", data):
                signature = entity.sign(data.split()[1])
                connection.sendall(signature)
                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: signing {} size {}, {} {}".format('\033[92m', data.split()[1], len(signature),
                                                                        signature, '\033[0m'))


            elif re.findall("^request_cert ", data):
                ca_address = data.split()[1]
                ca_port = data.split()[2]
                is_ca = data.split()[3]

                # soc = socket.socket()
                #
                # print('Waiting for connection')
                # try:
                #     soc.connect((ca_address, int(ca_port)))
                # except socket.error as e:
                #     print(str(e))

                pickled_cert = entity.request_cert(ca_address, int(ca_port), entity.pk, is_ca)
                entity.certificate = pickle.loads(pickled_cert)

                print(entity.certificate)

                connection.sendall(settings.OK)
                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: requesting cert from {}:{} {}".format('\033[92m', ca_address, ca_port, '\033[0m'))

            elif re.findall("^make_root_ca", data):
                entity.make_root_ca()
                connection.sendall(settings.OK)
                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: making root ca {}".format('\033[92m', '\033[0m'))

            elif re.findall("^is_ca", data):
                if entity.is_ca():
                    connection.sendall(settings.OK)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: is ca {}".format('\033[92m', '\033[0m'))
                else:
                    connection.sendall(settings.BAD)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: not a ca {}".format('\033[92m', '\033[0m'))

            elif re.findall("^get_cert", data):
                if entity.get_cert() is None:
                    connection.sendall(settings.BAD)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: cert is None {}".format('\033[92m', '\033[0m'))
                else:
                    pickled_cert = pickle.dumps(entity.get_cert())
                    connection.sendall(pickled_cert)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: sent cert {}".format('\033[92m', '\033[0m'))


            elif re.findall("^pk", data):
                pk = entity.pk.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                print("PKKKPKPKPKP")
                print(pk)
                print(type(pk))
                print(load_pem_public_key(pk))
                connection.sendall(pk)

            elif re.findall("^generate_cert ", data):
                name = data.split()[1]
                print(name)
                pk = data.split()[2] + " " + data.split()[3] + " " + data.split()[4] + " " + data.split()[5] + " " + \
                     data.split()[6]
                print(pk)
                ca_address = data.split()[7]
                print(ca_address)
                ca_port = data.split()[8]
                print(ca_port)
                is_ca = int(data.split()[9]) == 1
                print(is_ca)

                cert = entity.ca.generate_certificate(name, pk, ca_address, ca_port, is_ca)
                pickled_cert = pickle.dumps(cert)
                connection.sendall(pickled_cert)

                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: signed the cert {}".format('\033[92m', '\033[0m'))

            elif re.findall("^revocate", data):
                connection.sendall(settings.OK)
                cert = connection.recv(settings.RECEIVE_BYTES)
                cert = pickle.loads(cert)
                entity.ca.revocate(cert)

                if settings.LOG.value >= settings.Log.Results.value:
                    print("{}Results: revocated {} {}".format('\033[92m', pickle.dumps(cert), '\033[0m'))

                connection.sendall(settings.OK)

            elif re.findall("^check_if_revocated", data):
                connection.sendall(settings.OK)
                cert = connection.recv(settings.RECEIVE_BYTES)
                cert = pickle.loads(cert)
                print("{}cert{}".format('\033[92m', '\033[0m'))
                print(entity.ca.revocation_list)
                print(cert)
                print(entity.ca.check_if_revocated(cert))
                if entity.ca.check_if_revocated(cert):
                    connection.sendall(settings.OK)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: cert is revocated {}".format('\033[92m', '\033[0m'))

                else:
                    connection.sendall(settings.BAD)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: cert is not revocated {}".format('\033[92m', '\033[0m'))


            elif re.findall("^is_root_ca", data):
                if entity.root_ca:
                    connection.sendall(settings.OK)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: is root ca {}".format('\033[92m', '\033[0m'))

                else:
                    connection.sendall(settings.BAD)
                    if settings.LOG.value >= settings.Log.Results.value:
                        print("{}Results: not a root ca {}".format('\033[92m', '\033[0m'))

    connection.close()


if __name__ == "__main__":
    run(int(sys.argv[1]))
