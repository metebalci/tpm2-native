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
TPM_CC["NV_UndefineSpaceSpecial"]   = 0x0000011F
TPM_CC["EvictControl"]              = 0x00000120
TPM_CC["HierarchyControl"]          = 0x00000121
TPM_CC["NV_UndefineSpace"]          = 0x00000122
TPM_CC["ChangeEPS"]                 = 0x00000124
TPM_CC["ChangePPS"]                 = 0x00000125
TPM_CC["Clear"]                     = 0x00000126
TPM_CC["ClearControl"]              = 0x00000127
TPM_CC["ClockSet"]                  = 0x00000128
TPM_CC["HierarchyChangeAuth"]       = 0x00000129
TPM_CC["NV_DefineSpace"]            = 0x0000012A
TPM_CC["PCR_Allocate"]              = 0x0000012B
TPM_CC["PCR_SetAuthPolicy"]         = 0x0000012C
TPM_CC["PP_Commands"]               = 0x0000012D
TPM_CC["SetPrimaryPolicy"]          = 0x0000012E
TPM_CC["FieldUpgradeStart"]         = 0x0000012F

TPM_CC["ClockRateAdjust"]           = 0x00000130
TPM_CC["CreatePrimary"]             = 0x00000131
TPM_CC["NV_GlobalWriteLock"]        = 0x00000132
TPM_CC["GetCommandAuditDigest"]     = 0x00000133
TPM_CC["NV_Increment"]              = 0x00000134
TPM_CC["NV_SetBits"]                = 0x00000135
TPM_CC["NV_Extend"]                 = 0x00000136
TPM_CC["NV_Write"]                  = 0x00000137
TPM_CC["NV_WriteLock"]              = 0x00000138
TPM_CC["DictionaryAttackLockReset"]     = 0x00000139
TPM_CC["DictionaryAttackParameters"]    = 0x0000013A
TPM_CC["NV_ChangeAuth"]             = 0x0000013B
TPM_CC["PCR_Event"]                 = 0x0000013C
TPM_CC["PCR_Reset"]                 = 0x0000013D
TPM_CC["SequenceComplete"]          = 0x0000013E
TPM_CC["SetAlgorithmSet"]           = 0x0000013F

TPM_CC["SetCommandCodeAuditStatus"] = 0x00000140
TPM_CC["FieldUpgradeData"]          = 0x00000141
TPM_CC["IncrementalSelfTest"]       = 0x00000142
TPM_CC["SelfTest"]                  = 0x00000143
TPM_CC["Startup"]                   = 0x00000144
TPM_CC["Shutdown"]                  = 0x00000145
TPM_CC["StirRandom"]                = 0x00000146
TPM_CC["ActivateCredential"]        = 0x00000147
TPM_CC["Certify"]                   = 0x00000148
TPM_CC["PolicyNV"]                  = 0x00000149
TPM_CC["CertifyCreation"]           = 0x0000014A
TPM_CC["Duplicate"]                 = 0x0000014B
TPM_CC["GetTime"]                   = 0x0000014C
TPM_CC["GetSessionAuditDigest"]     = 0x0000014D
TPM_CC["NV_Read"]                   = 0x0000014E
TPM_CC["NV_ReadLock"]               = 0x0000014F

TPM_CC["ObjectChangeAuth"]          = 0x00000150
TPM_CC["PolicySecret"]              = 0x00000151
TPM_CC["Rewrap"]                    = 0x00000152
TPM_CC["Create"]                    = 0x00000153
TPM_CC["ECDH_ZGen"]                 = 0x00000154
TPM_CC["HMAC"]                      = 0x00000155
TPM_CC["Import"]                    = 0x00000156
TPM_CC["Load"]                      = 0x00000157
TPM_CC["Quote"]                     = 0x00000158
TPM_CC["RSA_Decrypt"]               = 0x00000159
TPM_CC["HMAC_Start"]                = 0x0000015A
TPM_CC["SequenceUpdate"]            = 0x0000015B
TPM_CC["Sign"]                      = 0x0000015C
TPM_CC["Unseal"]                    = 0x0000015D
TPM_CC["NV_ReadLock"]               = 0x0000015E

TPM_CC["Policy_Signed"]             = 0x00000160
TPM_CC["ContextLoad"]               = 0x00000161
TPM_CC["ContextSave"]               = 0x00000162
TPM_CC["ECDH_KeyGen"]               = 0x00000163
TPM_CC["EncryptDecrypt"]            = 0x00000164
TPM_CC["FlushContext"]              = 0x00000165
TPM_CC["LoadExternal"]              = 0x00000167
TPM_CC["MakeCredential"]            = 0x00000168
TPM_CC["NV_ReadPublic"]             = 0x00000169
TPM_CC["PolicyAuthorize"]           = 0x0000016A
TPM_CC["PolicyAuthValue"]           = 0x0000016B
TPM_CC["PolicyCommandCode"]         = 0x0000016C
TPM_CC["PolicyCounterTimer"]        = 0x0000016D
TPM_CC["PolicyCpHash"]              = 0x0000016E
TPM_CC["PolicyLocality"]            = 0x0000016F

TPM_CC["PolicyNameHash"]            = 0x00000170
TPM_CC["PolicyOR"]                  = 0x00000171
TPM_CC["PolicyTicket"]              = 0x00000172
TPM_CC["ReadPublic"]                = 0x00000173
TPM_CC["RSA_Encrypt"]               = 0x00000174
TPM_CC["StartAuthSession"]          = 0x00000176
TPM_CC["VerifySignature"]           = 0x00000177
TPM_CC["ECC_Parameters"]            = 0x00000178
TPM_CC["FirmwareRead"]              = 0x00000179
TPM_CC["GetCapability"]             = 0x0000017A
TPM_CC["GetRandom"]                 = 0x0000017B
TPM_CC["GetTestResult"]             = 0x0000017C
TPM_CC["Hash"]                      = 0x0000017D
TPM_CC["PCR_Read"]                  = 0x0000017E
TPM_CC["PolicyPCR"]                 = 0x0000017F

TPM_CC["PolicyRestart"]             = 0x00000180
TPM_CC["ReadClock"]                 = 0x00000181
TPM_CC["PCR_Extend"]                = 0x00000182
TPM_CC["PCR_SetAuthValue"]          = 0x00000183
TPM_CC["NV_Certify"]                = 0x00000184
TPM_CC["EventSequenceComplete"]     = 0x00000185
TPM_CC["HashSequenceStart"]         = 0x00000186
TPM_CC["PolicyPhysicalPresence"]    = 0x00000187
TPM_CC["PolicyDuplicationSelect"]   = 0x00000188
TPM_CC["PolicyGetDigest"]           = 0x00000189
TPM_CC["TestParms"]                 = 0x0000018A
TPM_CC["Commit"]                    = 0x0000018B
TPM_CC["PolicyPassword"]            = 0x0000018C
TPM_CC["ZGen_2Phase"]               = 0x0000018D
TPM_CC["EC_Ephemeral"]              = 0x0000018E
TPM_CC["PolicyNvWritten"]           = 0x0000018F

TPM_CC["PolicyTemplate"]            = 0x00000190
TPM_CC["CreateLoaded"]              = 0x00000191
TPM_CC["PolicyAuthorizeNV"]         = 0x00000192
TPM_CC["EncryptDecrypt2"]           = 0x00000193

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

TPM_CAP = {}
TPM_CAP['FIRST']            = 0x00000000
TPM_CAP['ALGS']             = 0x00000000
TPM_CAP['HANDLES']          = 0x00000001
TPM_CAP['COMMANDS']         = 0x00000002
TPM_CAP['PP_COMMANDS']      = 0x00000003
TPM_CAP['AUDIT_COMMANDS']   = 0x00000004
TPM_CAP['PCRS']             = 0x00000005
TPM_CAP['TPM_PROPERTIES']   = 0x00000006
TPM_CAP['PCR_PROPERTIES']   = 0x00000007
TPM_CAP['ECC_CURVES']       = 0x00000008
TPM_CAP['AUTH_POLICIES']    = 0x00000009
TPM_CAP['LAST']             = 0x00000009
TPM_CAP['VENDOR_PROPERTY']  = 0x00000100
TPM_CAPrev = _reverse_dict('TPM_CAP', TPM_CAP)

TPM_PT = {}
PT_GROUP = 0x00000100
PT_FIXED = PT_GROUP * 1
TPM_PT['FAMILY_INDICATOR']      = PT_FIXED + 0
TPM_PT['LEVEL']                 = PT_FIXED + 1
TPM_PT['REVISION']              = PT_FIXED + 2 
TPM_PT['DAY_OF_YEAR']           = PT_FIXED + 3 
TPM_PT['YEAR']                  = PT_FIXED + 4 
TPM_PT['MANUFACTURER']          = PT_FIXED + 5 
TPM_PT['VENDOR_STRING_1']       = PT_FIXED + 6 
TPM_PT['VENDOR_STRING_2']       = PT_FIXED + 7 
TPM_PT['VENDOR_STRING_3']       = PT_FIXED + 8 
TPM_PT['VENDOR_STRING_4']       = PT_FIXED + 9 
TPM_PT['VENDOR_TPM_TYPE']       = PT_FIXED + 10 
TPM_PT['FIRMWARE_VERSION_1']    = PT_FIXED + 11 
TPM_PT['FIRMWARE_VERSION_2']    = PT_FIXED + 12
TPM_PT['INPUT_BUFFER']          = PT_FIXED + 13 
TPM_PT['HR_TRANSIENT_MIN']      = PT_FIXED + 14
TPM_PT['HR_PERSISTENT_MIN']     = PT_FIXED + 15 
TPM_PT['HR_LOADED_MIN']         = PT_FIXED + 16
TPM_PT['ACTIVE_SESSIONS_MAX']   = PT_FIXED + 17
TPM_PT['PCR_COUNT']             = PT_FIXED + 18
TPM_PT['PCR_SELECT_MIN']        = PT_FIXED + 19
TPM_PT['CONTEXT_GAP_MAX']       = PT_FIXED + 20
# PT_FIXED + 21 is skipped
TPM_PT['NV_COUNTERS_MAX']       = PT_FIXED + 22
TPM_PT['NV_INDEX_MAX']          = PT_FIXED + 23
TPM_PT['MEMORY']                = PT_FIXED + 24 
TPM_PT['CLOCK_UPDATE']          = PT_FIXED + 25
TPM_PT['CONTEXT_HASH']          = PT_FIXED + 26
TPM_PT['CONTEXT_SYM']           = PT_FIXED + 27
TPM_PT['CONTEXT_SYM_SIZE']      = PT_FIXED + 28
TPM_PT['ORDERLY_COUNT']         = PT_FIXED + 29
TPM_PT['MAX_COMMAND_SIZE']      = PT_FIXED + 30
TPM_PT['MAX_RESPONSE_SIZE']     = PT_FIXED + 31
TPM_PT['MAX_DIGEST']            = PT_FIXED + 32
TPM_PT['MAX_OBJECT_CONTEXT']    = PT_FIXED + 33
TPM_PT['MAX_SESSION_CONTEXT']   = PT_FIXED + 34
TPM_PT['PS_FAMILY_INDICATOR']   = PT_FIXED + 35
TPM_PT['PS_LEVEL']              = PT_FIXED + 36
TPM_PT['PS_REVISION']           = PT_FIXED + 37
TPM_PT['PS_DAY_OF_YEAR']        = PT_FIXED + 38
TPM_PT['PS_YEAR']               = PT_FIXED + 39
TPM_PT['SPLIT_MAX']             = PT_FIXED + 40
TPM_PT['TOTAL_COMMANDS']        = PT_FIXED + 41
TPM_PT['LIBRARY_COMMANDS']      = PT_FIXED + 42
TPM_PT['VENDOR_COMMANDS']       = PT_FIXED + 43
TPM_PT['NV_BUFFER_MAX']         = PT_FIXED + 44
TPM_PT['MODES']                 = PT_FIXED + 45
TPM_PT['MAX_CAP_BUFFER']        = PT_FIXED + 46
PT_VAR = PT_GROUP * 2
TPM_PT['PERMANENT']             = PT_VAR + 0
TPM_PT['STARTUP_CLEAR']         = PT_VAR + 1
TPM_PT['HR_NV_INDEX']           = PT_VAR + 2
TPM_PT['HR_LOADED']             = PT_VAR + 3
TPM_PT['HR_LOADED_AVAIL']       = PT_VAR + 4
TPM_PT['HR_ACTIVE']             = PT_VAR + 5
TPM_PT['HR_ACTIVE_AVAIL']       = PT_VAR + 6
TPM_PT['HR_TRANSIENT_AVAIL']    = PT_VAR + 7
TPM_PT['HR_PERSISTENT']         = PT_VAR + 8
TPM_PT['HR_PERSISTENT_AVAIL']   = PT_VAR + 9
TPM_PT['NV_COUNTERS']           = PT_VAR + 10
TPM_PT['NV_COUNTERS_AVAIL']     = PT_VAR + 11
TPM_PT['ALGORITHM_SET']         = PT_VAR + 12
TPM_PT['LOADED_CURVES']         = PT_VAR + 13
TPM_PT['LOCKOUT_COUNTER']       = PT_VAR + 14
TPM_PT['MAX_AUTH_FAIL']         = PT_VAR + 15
TPM_PT['LOCKOUT_INTERVAL']      = PT_VAR + 16
TPM_PT['LOCKOUT_RECOVERY']      = PT_VAR + 17
TPM_PT['NV_WRITE_RECOVERY']     = PT_VAR + 18
TPM_PT['AUDIT_COUNTER_0']       = PT_VAR + 19
TPM_PT['AUDIT_COUNTER_1']       = PT_VAR + 20
TPM_PTrev = _reverse_dict('TPM_PT', TPM_PT)

TPM_PT_PCR = {}
TPM_PT_PCR['FIRST']             = 0x00000000
TPM_PT_PCR['SAVE']              = 0x00000000
TPM_PT_PCR['EXTEND_L0']         = 0x00000001
TPM_PT_PCR['RESET_L0']          = 0x00000002
TPM_PT_PCR['EXTEND_L1']         = 0x00000003
TPM_PT_PCR['RESET_L1']          = 0x00000004
TPM_PT_PCR['EXTEND_L2']         = 0x00000005
TPM_PT_PCR['RESET_L2']          = 0x00000006
TPM_PT_PCR['EXTEND_L3']         = 0x00000007
TPM_PT_PCR['RESET_L3']          = 0x00000008
TPM_PT_PCR['EXTEND_L4']         = 0x00000009
TPM_PT_PCR['RESET_L4']          = 0x0000000A
TPM_PT_PCR['NO_INCREMENT']      = 0x00000011
TPM_PT_PCR['DRTM_RESET']        = 0x00000012
TPM_PT_PCR['POLICY']            = 0x00000013
TPM_PT_PCR['AUTH']              = 0x00000014
TPM_PT_PCR['LAST']              = 0x00000014
TPM_PT_PCRrev = _reverse_dict('TPM_PT_PCR', TPM_PT_PCR)
 
TPM_RC = {}
TPM_RC["SUCCESS"]       = 0x000
TPM_RC["INITIALIZE"]    = 0x100
TPM_RC["FAILURE"]       = 0x101
TPM_RC["NEEDS_TEST"]    = 0x153
TPM_RC["TESTING"]       = 0x90A
TPM_RCrev = _reverse_dict('TPM_RC', TPM_RC)
