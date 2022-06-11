import pickle
import socket
import re
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from entity import Entity
from utils import settings
from utils.logs import log

from _thread import *

entity = None


def run(PORT):
    ServerSocket = socket.socket()
    ThreadCount = 0
    try:
        ServerSocket.bind((settings.SERVER_HOST, PORT))
    except socket.error as e:
        log("{}".format(e), settings.Log.Errors)

    log("waiting for connection", settings.Log.Results)
    ServerSocket.listen(5)

    while True:
        Client, address = ServerSocket.accept()
        log("connected to {}:{}".format(address[0], address[1]), settings.Log.Results)
        start_new_thread(threaded_client, (Client,))
        ThreadCount += 1
        log("thread number {}".format(ThreadCount), settings.Log.Results)
    ServerSocket.close()


def threaded_client(connection):
    global entity
    connection.send(str.encode('Welcome to the Server'))
    while True:
        data = connection.recv(settings.RECEIVE_BYTES)
        if data:
            data = data.decode(settings.FORMAT)
            log("data {}".format(data), settings.Log.Debug)

            if re.findall("^create_entity ", data):
                entity = Entity(data.split()[1], rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                ))

                log("created entity {}".format(data.split()[1]), settings.Log.Results)
                connection.sendall(settings.OK)

            elif re.findall("^sign ", data):
                signature = entity.sign(data.split()[1])
                connection.sendall(signature)
                log("signing {} -> {}".format(data.split()[1], signature), settings.Log.Results)

            elif re.findall("^request_cert ", data):
                ca_address = data.split()[1]
                ca_port = data.split()[2]
                is_ca = data.split()[3]

                pickled_cert = entity.request_cert(ca_address, int(ca_port), entity.pk, is_ca)
                entity.certificate = pickle.loads(pickled_cert)

                log("{}".format(entity.certificate), settings.Log.Debug)
                connection.sendall(settings.OK)
                log("requesting cert from {}:{}".format(ca_address, ca_port), settings.Log.Results)

            elif re.findall("^make_root_ca", data):
                entity.make_root_ca()
                connection.sendall(settings.OK)
                log("making root ca", settings.Log.Results)

            elif re.findall("^is_ca", data):
                if entity.is_ca():
                    connection.sendall(settings.OK)
                    log("is_ca", settings.Log.Results)
                else:
                    connection.sendall(settings.BAD)
                    log("not a ca", settings.Log.Warnings)

            elif re.findall("^get_cert", data):
                if entity.get_cert() is None:
                    connection.sendall(settings.BAD)
                    log("cert is None", settings.Log.Warning)

                else:
                    pickled_cert = pickle.dumps(entity.get_cert())
                    connection.sendall(pickled_cert)
                    log("returned cert", settings.Log.Results)



            elif re.findall("^pk", data):
                pk = entity.pk.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                log("pk -> {}".format(pk), settings.Log.Debug)
                connection.sendall(pk)

            elif re.findall("^generate_cert ", data):
                name = data.split()[1]
                pk = data.split()[2] + " " + data.split()[3] + " " + data.split()[4] + " " + data.split()[5] + " " + \
                     data.split()[6]
                ca_address = data.split()[7]
                ca_port = data.split()[8]
                is_ca = int(data.split()[9]) == 1

                cert = entity.ca.generate_certificate(name, pk, ca_address, ca_port, is_ca)
                pickled_cert = pickle.dumps(cert)
                connection.sendall(pickled_cert)
                log("generated ans signed the cert", settings.Log.Results)


            elif re.findall("^revocate", data):
                connection.sendall(settings.OK)
                cert = connection.recv(settings.RECEIVE_BYTES)
                cert = pickle.loads(cert)
                entity.ca.revocate(cert)

                log("revocated cert", settings.Log.Results)

                connection.sendall(settings.OK)

            elif re.findall("^check_if_revocated", data):
                connection.sendall(settings.OK)
                cert = connection.recv(settings.RECEIVE_BYTES)
                cert = pickle.loads(cert)
                if entity.ca.check_if_revocated(cert):
                    connection.sendall(settings.OK)
                    log("cert is revocated", settings.Log.Results)

                else:
                    connection.sendall(settings.BAD)
                    log("cert is not revocated", settings.Log.Results)



            elif re.findall("^is_root_ca", data):
                if entity.root_ca:
                    connection.sendall(settings.OK)
                    log("is root ca", settings.Log.Results)

                else:
                    connection.sendall(settings.BAD)
                    log("is not a root ca", settings.Log.Results)

    connection.close()


if __name__ == "__main__":
    run(int(sys.argv[1]))
