import struct
import sys
import argparse
from tpm2_native.common import *


def _startup(clear):
    info0('<<< Command >>>')
    su = TPM_SU['CLEAR' if clear else 'STATE']
    info0('startupType', (su, TPM_SUrev.get(su, 'UNKNOWN')))
    req = struct.pack('!HIH',
            TPM_ST['NO_SESSIONS'],
            TPM_CC['Startup'],
            TPM_SU['CLEAR'] if clear else TPM_SU['STATE'])
    tpm2_xmit(req)

    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--startup-type', choices=['clear', 'state'], required=True)
    args = run(parser)
    _startup(args.startup_type == 'clear')
