from enum import Enum

RECEIVE_BYTES = 4096
SERVER_HOST = "127.0.0.1"
CLIENT_HOST = "127.0.0.1"
FORMAT = 'utf-8'
OK = b'\x01'
BAD = b'\x00'


class Log(Enum):
    Errors = 1
    Warnings = 2
    Results = 3
    Debug = 4


LOG = Log.Warnings


ROOT_PORT = 5401
IL_PORT = 5402
HUJI_PORT = 5403
VALIDATOR_PORT = 5406
