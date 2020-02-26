import struct
import sys
from tpm2_native.common import *


def _stir_random(true_if_sessions, inData):
    print('len(inData):'.rjust(20) + ' 0x%x [%d]' % (len(inData), len(inData)))
    req = struct.pack('!HIH%ds' % len(inData),
            TPM_ST['SESSIONS'] if true_if_sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['StirRandom'],
            len(inData),
            inData)
    tpm2_xmit(req)


def _help():
    print('tpm2_StirRandom no_sessions|sessions indata_filename')
    sys.exit(1)


def main():
    if len(sys.argv) < 3:
        _help()
    else:
        sessions = False
        if sys.argv[1] == 'no_sessions':
            sessions = False
        elif sys.argv[1] == 'sessions':
            sessions = True
        else:
            _help()
        with open(sys.argv[2], 'rb') as f:
            inData = f.read()
        if len(inData) > 128:
            print('inData is too bit, >128 bytes')
            sys.exit(1)
        _stir_random(sessions, inData)
