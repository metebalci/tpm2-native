import struct
import sys
from tpm2_native.common import *


def _incremental_self_test(true_if_sessions, toTest):
    req = struct.pack('!HII',
            TPM_ST['SESSIONS'] if true_if_sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['IncrementalSelfTest'],
            len(toTest))
    for algId in toTest:
        req = req + struct.pack('!H', algId)
    (res, tag, rs, rc) = tpm2_xmit(req)
    if rc == TPM_RC['SUCCESS']:
        (count,) = struct.unpack('!I', res[0:4])
        print('toDoList:'.rjust(20))
        for i in range(0, count):
            (algId,) = struct.unpack('!H', res[4+2*i:4+2*i+2])
            alg = TPM_ALGrev.get(algId, "UNKNOWN")
            print(''.rjust(20) + ' %s [0x%x]' % (alg, algId))


def _help():
    print('tpm2_IncrementalSelfTest no_sessions|sessions algorithm1ToTest algorithm2ToTest ...')
    print('tpm2_IncrementalSelfTest ? lists all algorithms')
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        _help()
    else:
        sessions = False
        fulltest = False
        if sys.argv[1] == 'no_sessions':
            sessions = False
        elif sys.argv[1] == 'sessions':
            sessions = True
        elif sys.argv[1] == '?':
            for k in TPM_ALG.keys():
                print(k)
            sys.exit(0)
        else:
            _help()
        toTest = []
        print('toTest:'.rjust(20))
        for alg in sys.argv[2:]:
            algId = TPM_ALG.get(alg, None)
            if algId is None:
                print('ALG name: %s is invalid, check the list of algorithms' % alg)
                sys.exit(1)
            print(''.rjust(20) + ' %s [0x%x]' % (alg, algId))
            toTest.append(algId)
        _incremental_self_test(sessions, toTest)
