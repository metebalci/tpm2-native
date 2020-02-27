import struct
import sys
from tpm2_native.common import *


def _test_parms(true_if_sessions, parameters):
    req = struct.pack('!HII',
            TPM_ST['SESSIONS'] if true_if_sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['TestParms'],
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
    print('tpm2_TestParms no_sessions|sessions parameter1 parameter2 ...')
    print('tpm2_TestParms ? lists all parameters')
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
        parameters = []
        print('parameters:'.rjust(20))
        for parameter in sys.argv[2:]:
            algId = TPM_ALG.get(alg, None)
            if algId is None:
                print('ALG name: %s is invalid, check the list of algorithms' % alg)
                sys.exit(1)
            print(''.rjust(20) + ' %s [0x%x]' % (alg, algId))
            toTest.append(algId)
        _test_parms(sessions, parameters)
