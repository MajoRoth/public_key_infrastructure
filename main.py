from cryptography.hazmat.primitives.asymmetric import rsa
import socket
import pickle

import settings


def establish_connection():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((settings.CLIENT_HOST, settings.PORT))
    return server


if __name__ == '__main__':
    # rsa_root_ca = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_usa_ca = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_il_ca = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_uk_ca = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_huji = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_cs_school = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_math_school = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_physics_school = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_google = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_microsoft = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # rsa_wix = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    #
    # server = establish_connection()
    #
    # server.sendall(bytes("create_entity {}".format("root"), settings.FORMAT))
    # recv = server.recv(settings.RECEIVE_BYTES)
    #
    # server.sendall(bytes("sign {}".format("message"), settings.FORMAT))
    # signature = server.recv(settings.RECEIVE_BYTES)
    # pickled_bucket = pickle.dumps(bucket)

    # root = Entity("root", rsa_root_ca)
    # root.make_root_ca()
    #
    # usa = Entity("usa", rsa_usa_ca)
    # usa.request_cert(root, True)
    #
    # il = Entity("il", rsa_il_ca)
    # il.request_cert(root, True)
    #
    # uk = Entity("uk", rsa_uk_ca)
    # uk.request_cert(root, True)
    #
    # huji = Entity("huji", rsa_uk_ca)
    # huji.request_cert(il, True)
    #
    # cs = Entity("cs", rsa_cs_school)
    # cs.request_cert(huji, True)
    #
    # math = Entity("math", rsa_math_school)
    # math.request_cert(huji, True)
    #
    # physics = Entity("physics", rsa_physics_school)
    # physics.request_cert(huji, True)
    #
    # google = Entity("google", rsa_google)
    # google.request_cert(usa)
    #
    # microsoft = Entity("microsoft", rsa_microsoft)
    # microsoft.request_cert(usa)
    #
    # wix = Entity("wix", rsa_wix)
    # wix.request_cert(il)
    #
    # v = Validator()
    # v.add_root_ca(root, root.pk)
    # v.validate(huji.certificate)
    # message = "huji mail"
    # sign = huji.sign(message)
    # v.verify(huji.pk, bytes(message, 'utf-8'), sign)

    import socket

    ClientSocketRoot = socket.socket()

    print('Waiting for connection')
    try:
        ClientSocketRoot.connect((settings.CLIENT_HOST, settings.ROOT_PORT))
    except socket.error as e:
        print(str(e))

    ClientSocketIl = socket.socket()

    print('Waiting for connection')
    try:
        ClientSocketIl.connect((settings.CLIENT_HOST, settings.IL_PORT))
    except socket.error as e:
        print(str(e))

    ClientSocketHuji = socket.socket()

    print('Waiting for connection')
    try:
        ClientSocketHuji.connect((settings.CLIENT_HOST, settings.HUJI_PORT))
    except socket.error as e:
        print(str(e))

    ValidatorSocket = socket.socket()

    print('Waiting for connection')
    try:
        ValidatorSocket.connect((settings.CLIENT_HOST, settings.VALIDATOR_PORT))
    except socket.error as e:
        print(str(e))


    Response = ClientSocketRoot.recv(1024)
    Response = ClientSocketHuji.recv(1024)
    Response = ClientSocketIl.recv(1024)
    Response = ValidatorSocket.recv(1024)
    print(Response)
    print("Starting sending")

    ClientSocketRoot.send(str.encode("create_entity root"))
    print(ClientSocketRoot.recv(1024))

    ClientSocketIl.send(str.encode("create_entity il"))
    print(ClientSocketIl.recv(1024))

    ClientSocketHuji.send(str.encode("create_entity huji"))
    print(ClientSocketHuji.recv(1024))

    ClientSocketRoot.send(str.encode("make_root_ca "))
    print("response {}".format(ClientSocketRoot.recv(1024)))


    ClientSocketIl.send(str.encode("request_cert {} {} 1".format(settings.CLIENT_HOST, settings.ROOT_PORT)))
    print("response {}".format(ClientSocketIl.recv(1024)))

    ClientSocketIl.send(str.encode("get_cert"))
    il_cert = ClientSocketIl.recv(1024)
    il_cert = pickle.loads(il_cert)
    print(il_cert)


    ClientSocketHuji.send(str.encode("request_cert {} {} 0".format(settings.CLIENT_HOST, settings.IL_PORT)))
    print("response {}".format(ClientSocketHuji.recv(1024)))

    ClientSocketHuji.send(str.encode("get_cert"))
    huji_cert = ClientSocketHuji.recv(1024)
    huji_cert = pickle.loads(huji_cert)
    print(huji_cert)

    ClientSocketRoot.send(str.encode("sign This_is_the_message"))
    signature = ClientSocketRoot.recv(1024)
    print("response {}".format(signature))

    ValidatorSocket.send(str.encode("create_validator "))
    print(ValidatorSocket.recv(1024))

    ClientSocketRoot.send(str.encode("pk "))
    root_pk = ClientSocketRoot.recv(1024)
    print("root pk {}".format(root_pk))

    ValidatorSocket.send(str.encode("verify {}".format("This_is_the_message")))
    print(ValidatorSocket.recv(1024))
    ValidatorSocket.send(root_pk)
    print(ValidatorSocket.recv(1024))
    ValidatorSocket.send(signature)
    print(ValidatorSocket.recv(1024))

    ValidatorSocket.send(str.encode("add_root_ca {} {}".format(settings.SERVER_HOST, settings.ROOT_PORT)))
    print(ValidatorSocket.recv(1024))
    ValidatorSocket.send(root_pk)
    print(ValidatorSocket.recv(1024))

    # print("revocating")
    # ClientSocketRoot.send(str.encode("revocate"))
    # print(ClientSocketRoot.recv(1024))
    # ClientSocketRoot.send(pickle.dumps(il_cert))
    # print(ClientSocketRoot.recv(1024))

    print("VALIDATING")
    ValidatorSocket.send(str.encode("validate "))
    print(ValidatorSocket.recv(1024))
    ValidatorSocket.send(pickle.dumps(il_cert))
    print(ValidatorSocket.recv(1024))

    print("VALIDATING")
    ValidatorSocket.send(str.encode("validate "))
    print(ValidatorSocket.recv(1024))
    ValidatorSocket.send(pickle.dumps(huji_cert))
    print(ValidatorSocket.recv(1024))

    # while True:
    #     Input = input('Say Something: ')
    #     ClientSocket.send(str.encode(Input))
    #     Response = ClientSocket.recv(1024)
    #     print(Response.decode('utf-8'))

    ClientSocketRoot.close()
    print("END")




