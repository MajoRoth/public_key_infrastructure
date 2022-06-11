from utils import settings


def log(message, priority: settings.LOG):
    if settings.LOG.value >= priority.value:
        if priority.value == 1:
            print('\033[91m' + message + '\033[0m')
        if priority.value == 2:
            print('\033[93m' + message + '\033[0m')
        if priority.value == 3:
            print('\033[92m' + message + '\033[0m')
        if priority.value == 4:
            print('\033[96m' + message + '\033[0m')


