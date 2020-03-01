import struct
import sys
from tpm2_native.common import *


def _self_test(sessions, full):
    info0('<<< Command >>>')
    info0('fullTest', full)
    req = struct.pack('!HIB',
            TPM_ST['SESSIONS'] if sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['SelfTest'],
            1 if full else 0)
    tpm2_xmit(req)


def main():
    parser = argparse.ArgumentParser()
    add_tpm_st(parser)
    parser.add_argument('--test-type', choices=['full', 'only-untested'], required=True)
    args = run(parser)
    _self_test(args.sessions == 'yes', args.test_type == 'full')
