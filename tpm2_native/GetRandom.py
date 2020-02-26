import struct
import sys
from tpm2_native.common import *


def _get_random(bytesRequested):
    req = struct.pack('!HIH',
            TPM_ST['NO_SESSIONS'],
            TPM_CC['GetRandom'],
            bytesRequested)
    (res, tag, rs, rc) = tpm2_xmit(req)
    if rc == TPM_RC['SUCCESS']:
        (randomBytesSize,) = struct.unpack('!H', res[0:2])
        print('randomBytesSize:'.rjust(20) + ' 0x%x [%d]' % (randomBytesSize, 
            randomBytesSize))
        randomBytes = res[2:2+randomBytesSize]
        print('randomBytes:'.rjust(20) + ' ' + bytes2hex(randomBytes))


def _help():
    print('tpm2_GetRandom bytesRequested')


def main():
    if len(sys.argv) < 2:
        _help()
    else:
        bytesRequested = int(sys.argv[1])
        _get_random(bytesRequested)
