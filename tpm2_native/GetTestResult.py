import struct
import sys
from tpm2_native.common import *


def _get_test_result():
    req = struct.pack('!HI',
            TPM_ST['NO_SESSIONS'],
            TPM_CC['GetTestResult'])
    (res, tag, rs, rc) = tpm2_xmit(req)
    (outDataSize,) = struct.unpack('!H', res[0:2])
    print("outDataSize:".rjust(20) + " 0x%x [%d]" % (outDataSize, outDataSize)) 
    outData = res[2:2+outDataSize]
    print("outData:".rjust(20) + " %s" % bytes2hex(outData))
    (testResult,) = struct.unpack('!H', res[2+outDataSize:2+outDataSize+2])
    print("testResult:".rjust(20) + " 0x%x [%s]" % (testResult,
        TPM_RCrev.get(testResult, "UNKNOWN")));


def main():
    _get_test_result()
