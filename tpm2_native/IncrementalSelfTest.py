import struct
import sys
from tpm2_native.common import *


def _incremental_self_test(sessions, toTest):
    info0('<<< Command >>>')
    info0('toTest', [(algId, TPM_ALGrev[algId]) for algId in toTest])
    req = struct.pack('!HII',
            TPM_ST['SESSIONS'] if sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['IncrementalSelfTest'],
            len(toTest))
    for algId in toTest:
        req = req + struct.pack('!H', algId)
    (res, tag, rs, rc) = tpm2_xmit(req)
    if rc == TPM_RC['SUCCESS']:
        (count,) = struct.unpack('!I', res[0:4])
        toDoList = []
        for i in range(0, count):
            (algId,) = struct.unpack('!H', res[4+2*i:4+2*i+2])
            toDoList.append(algId)
        info0('toDoList', [(algId, TPM_ALGrev[algId]) for algId in toDoList])


def main():
    parser = argparse.ArgumentParser()
    add_tpm_st(parser)
    for alg in TPM_ALG.keys():
        parser.add_argument('--%s' % alg, action='append_const', dest='to_test', const=TPM_ALG[alg])
    args = run(parser)
    _incremental_self_test(args.sessions == 'yes', args.to_test)
