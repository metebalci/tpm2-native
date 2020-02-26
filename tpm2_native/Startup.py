import struct
import sys
from tpm2_native.common import *


def _startup(true_if_clear):
    req = struct.pack('!HIH',
            TPM_ST['NO_SESSIONS'],
            TPM_CC['Startup'],
            TPM_SU['CLEAR'] if true_if_clear else TPM_SU['STATE'])
    tpm2_xmit(req)


def _help():
    print('tpm2_Startup clear|state')
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        _help()
    elif sys.argv[1] == 'clear':
        _startup(True)
    elif sys.argv[1] == 'state':
        _startup(False)
    else:
        help()
