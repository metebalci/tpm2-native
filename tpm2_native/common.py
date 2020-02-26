import struct
import os


def bytes2hex(b):
    return ' '.join([b[i:i+1].hex() for i in range(0, len(b))]).strip()


def tpm2_xmit(b):
    # append size to [2:6]
    bws = struct.pack('!2sI', b[0:2], len(b)+4)[:] + b[2:]
    if len(bws) < 10:
        raise Error('request is too small, <10 bytes')
    (tag, rs, cc) = struct.unpack("!HII", bws[0:10])
    print("tag:".rjust(20) + " 0x%x [%s]" % (tag, TPM_STrev.get(tag, "UNKNOWN")))
    print("requestSize:".rjust(20) + " 0x%x [%d]" % (rs, rs))
    print("commandCode:".rjust(20) + " 0x%x [%s]" % (cc, TPM_CCrev.get(cc, "UNKNOWN")))
    if len(bws) > 1024:
        raise Error('request is too big, >1024 bytes')
    print('req: %s' % bytes2hex(bws))
    dev = None
    try:
        dev = os.open('/dev/tpm0', os.O_RDWR)
        status = os.write(dev, bws)
        if status != len(bws):
            raise Error('request cannot be transmitted')
        out = os.read(dev, 4096)
        print('res: %s' % bytes2hex(out))
        if len(out) < 10:
            raise Error('response is too small, <10 bytes')
        # this is common to all responses
        (tag, rs, rc) = struct.unpack("!HII", out[0:10])
        print("tag:".rjust(20) + " 0x%x [%s]" % (tag, TPM_STrev.get(tag, "UNKNOWN")))
        print("responseSize:".rjust(20) + " 0x%x [%d]" % (rs, rs))
        print("responseCode:".rjust(20) + " 0x%x [%s]" % (rc, TPM_RCrev.get(rc, "UNKNOWN")))
        return (out[10:], tag, rs, rc)
    finally:
        if dev is not None:
            os.close(dev)

def _set_members(prefix, d):
    for (k, v) in d.items():
        setattr(common, "%s_%s" % (prefix, d), v) 

def _reverse_dict(prefix, d):
    rd = {}
    for (k, v) in d.items():
        rd[v] = '%s_%s' % (prefix, k)
    return rd

TPM_CC = {}
TPM_CC["IncrementalSelfTest"]   = 0x00000142
TPM_CC["SelfTest"]              = 0x00000143
TPM_CC["Startup"]               = 0x00000144
TPM_CC["Shutdown"]              = 0x00000145
TPM_CC["StirRandom"]            = 0x00000146
TPM_CC["GetTime"]               = 0x0000014C
TPM_CC["GetCapability"]         = 0x0000017A
TPM_CC["GetRandom"]             = 0x0000017B
TPM_CC["GetTestResult"]         = 0x0000017C
TPM_CCrev = _reverse_dict('TPM_CC', TPM_CC)

TPM_SU = {}
TPM_SU["CLEAR"] = 0x0000
TPM_SU["STATE"] = 0x0001
TPM_SUrev = _reverse_dict('TPM_SU', TPM_SU)
 
TPM_ST = {}
TPM_ST["NO_SESSIONS"]   = 0x8001
TPM_ST["SESSIONS"]      = 0x8002
TPM_STrev = _reverse_dict('TPM_ST', TPM_ST)

TPM_ALG = {}
TPM_ALG["RSA"]          = 0x0001
TPM_ALG["SHA"]          = 0x0004 
TPM_ALG["SHA1"]         = 0x0004 
TPM_ALG["HMAC"]         = 0x0005 
TPM_ALG["AES"]          = 0x0006
TPM_ALG["MGF1"]         = 0x0007
TPM_ALG["KEYEDHASH"]    = 0x0008
TPM_ALG["XOR"]          = 0x000A
TPM_ALG["SHA256"]       = 0x000B
TPM_ALG["SHA384"]       = 0x000C
TPM_ALG["SHA512"]       = 0x000D
TPM_ALG["NULL"]         = 0x0010
TPM_ALG["SM3_256"]      = 0x0012
TPM_ALG["SM4"]          = 0x0013
TPM_ALG["RSASSA"]       = 0x0014
TPM_ALG["RSAES"]        = 0x0015
TPM_ALG["RSAPSS"]       = 0x0016
TPM_ALG["OAEP"]         = 0x0017
TPM_ALG["ECDSA"]        = 0x0018
TPM_ALG["ECDH"]         = 0x0019
TPM_ALG["ECDAA"]        = 0x001A
TPM_ALG["SM2"]          = 0x001B
TPM_ALG["ECSCHNORR"]    = 0x001C
TPM_ALG["ECMQV"]        = 0x001D
TPM_ALG["KDF1_SP800_56A"] = 0x0020
TPM_ALG["KDF2"]         = 0x0021
TPM_ALG["KDF1_SP800_108"] = 0x0022
TPM_ALG["ECC"]          = 0x0023
TPM_ALG["SYMCIPHER"]    = 0x0025
TPM_ALG["CAMELLIA"]     = 0x0026
TPM_ALG["CTR"]          = 0x0040
TPM_ALG["OFB"]          = 0x0041
TPM_ALG["CBC"]          = 0x0042
TPM_ALG["CFB"]          = 0x0043
TPM_ALG["ECB"]          = 0x0044
TPM_ALGrev = _reverse_dict('TPM_ALG', TPM_ALG)
 
TPM_RC = {}
TPM_RC["SUCCESS"]       = 0x000
TPM_RC["INITIALIZE"]    = 0x100
TPM_RC["FAILURE"]       = 0x101
TPM_RC["NEEDS_TEST"]    = 0x153
TPM_RC["TESTING"]       = 0x90A
TPM_RCrev = _reverse_dict('TPM_RC', TPM_RC)
