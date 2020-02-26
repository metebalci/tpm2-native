import struct
import sys
from tpm2_native.common import *


def _shutdown(true_if_clear):
    req = struct.pack('!HIH',
            TPM_ST['NO_SESSIONS'],
            TPM_CC['Shutdown'],
            TPM_SU['CLEAR'] if true_if_clear else TPM_SU['STATE'])
    (res, tag, rs, rc) = tpm2_xmit(req)
    if tag == TPM_ST['SESSIONS']:
        print('Info: An audit session is present (since it returned TPM_ST_SESSIONS).')


def _help():
    print('tpm2_Shutdown clear|state')
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        _help()
    elif sys.argv[1] == 'clear':
        _shutdown(True)
    elif sys.argv[1] == 'state':
        _shutdown(False)
    else:
        help()
