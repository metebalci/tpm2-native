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
 
TPM_RC = {}
TPM_RC["SUCCESS"]       = 0x000
TPM_RC["INITIALIZE"]    = 0x100
TPM_RC["FAILURE"]       = 0x101
TPM_RC["NEEDS_TEST"]    = 0x153
TPM_RC["TESTING"]       = 0x90A
TPM_RCrev = _reverse_dict('TPM_RC', TPM_RC)
