import struct
import sys
from tpm2_native.common import *


def _self_test(true_if_sessions, true_if_fulltest):
    req = struct.pack('!HIB',
            TPM_ST['SESSIONS'] if true_if_sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['SelfTest'],
            1 if true_if_fulltest else 0)
    tpm2_xmit(req)


def _help():
    print('tpm2_SelfTest no_sessions|sessions yes|no')
    print('yes: perform full test, no: test only untested functions')
    sys.exit(1)


def main():
    if len(sys.argv) < 3:
        _help()
    else:
        sessions = False
        fulltest = False
        if sys.argv[1] == 'no_sessions':
            sessions = False
        elif sys.argv[1] == 'sessions':
            sessions = True
        else:
            _help()
        if sys.argv[2] == 'yes':
            fulltest = True
        elif sys.argv[2] == 'no':
            fulltest = False
        else:
            _help()
        _self_test(sessions, fulltest)
