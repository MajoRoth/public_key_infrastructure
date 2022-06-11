import pickle
import socket
import re
import sys

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from validator import Validator
from utils import settings
from utils.logs import log

from _thread import *


validator = None


def run(PORT):
    ServerSocket = socket.socket()
    ThreadCount = 0
    try:
        ServerSocket.bind((settings.SERVER_HOST, PORT))
    except socket.error as e:
        log("connected to {}".format(e), settings.Log.Errors)

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
    global validator
    connection.send(str.encode('Welcome to the Server'))
    while True:
        data = connection.recv(settings.RECEIVE_BYTES)
        if data:
            data = data.decode(settings.FORMAT)
            log("data {}".format(data), settings.Log.Debug)

            if re.findall("^create_validator ", data):
                validator = Validator()
                log("created validator", settings.Log.Results)
                connection.sendall(settings.OK)

            if re.findall("^verify ", data):
                message = data.split()[1]
                connection.sendall(settings.OK)
                pk_data = connection.recv(settings.RECEIVE_BYTES)
                connection.sendall(settings.OK)
                signature = connection.recv(settings.RECEIVE_BYTES)
                pk = load_pem_public_key(pk_data)

                try:
                    if validator.verify(pk, bytes(message, settings.FORMAT), signature):
                        connection.sendall(settings.OK)
                        log("verified {}".format(message), settings.Log.Results)

                except Exception as e:
                    log("{}".format(e), settings.Log.Errors)
                    connection.sendall(settings.BAD)

            if re.findall("^add_root_ca ", data):
                address = data.split()[1]
                port = int(data.split()[2])
                connection.sendall(settings.OK)
                pk_data = connection.recv(settings.RECEIVE_BYTES)
                pk = load_pem_public_key(pk_data)
                validator.add_root_ca(address, port, pk)
                log("added {}:{} as root".format(address, port), settings.Log.Results)
                connection.sendall(settings.OK)


            if re.findall("^validate", data):
                connection.sendall(settings.OK)
                cert_data = connection.recv(settings.RECEIVE_BYTES)
                cert = pickle.loads(cert_data)

                if validator.validate(cert):
                    log("cert is validated", settings.Log.Results)
                    connection.sendall(settings.OK)

                else:
                    if settings.LOG.value >= settings.Log.Results.value:
                        log("cert is invalid", settings.Log.Warnings)
                    connection.sendall(settings.BAD)

    connection.close()









if __name__ == "__main__":
    run(int(sys.argv[1]))