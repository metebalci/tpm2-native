import struct
import sys
from tpm2_native.common import *


def is_pcr_selected(pcrNum, pcrSelect):
    pcrSelectNum = int(pcrNum/8)
    pcrBitNum = pcrNum % 8
    return (pcrSelect[pcrSelectNum] & (1 << pcrBitNum)) != 0


def pcr_list(pcrSelect):
    s = []
    for i in range(0, len(pcrSelect) * 8):
        if is_pcr_selected(i, pcrSelect):
            if len(s) > 0:
                s = '%s %d' % (s, i)
            else:
                s = '%d' % i
    return s


def _handle_type_to_dict(propertyId):
    ht = propertyId >> 24
    if ht == TPM_HT['PCR']:
        return ({}, {})
    elif ht == TPM_HT['NV_INDEX']:
        return ({}, {})
    elif ht == TPM_HT['HMAC_SESSION']:
        return ({}, {})
    elif ht == TPM_HT['LOADED_SESSION']:
        return ({}, {})
    elif ht == TPM_HT['POLICY_SESSION']:
        return ({}, {})
    elif ht == TPM_HT['SAVED_SESSION']:
        return ({}, {})
    elif ht == TPM_HT['PERMANENT']:
        return (TPM_RH, TPM_RHrev)
    elif ht == TPM_HT['TRANSIENT']:
        return ({}, {})
    elif ht == TPM_HT['PERSISTENT']:
        return ({}, {})
    else:
        return None


def _get_capability(true_if_sessions, capabilityId, propertyId, propertyCount):
    print('capability:'.rjust(20) + ' %s [0x%x]' % (TPM_CAPrev.get(capabilityId), 
        capabilityId))
    req = struct.pack('!HIIII',
            TPM_ST['SESSIONS'] if true_if_sessions else TPM_ST['NO_SESSIONS'],
            TPM_CC['GetCapability'],
            capabilityId,
            propertyId,
            propertyCount)
    (res, tag, rs, rc) = tpm2_xmit(req)
    if rc == TPM_RC['SUCCESS']:
        (moreData, resCapabilityId) = struct.unpack('!BI', res[0:5])
        moreData = (moreData == 1)
        print('moreData:'.rjust(20) + ' %s' % ('YES' if moreData else 'NO'))
        res = res[5:]
        if resCapabilityId == TPM_CAP['ALGS']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('properties:'.rjust(20))
            for i in range(0, count):
                (algId, attributes) = struct.unpack('!HI', res[0:6])
                res = res[6:]
                alg = TPM_ALGrev.get(algId, "UNKNOWN")
                print(''.rjust(20) + ' %s [0x%x]' % (alg, algId))
                print(''.rjust(23) + 'attributes: 0x%x' % attributes)
                attr_asymmetric = (attributes & 0x1)
                attr_symmetric = (attributes & 0x2)
                attr_hash = (attributes & 0x4)
                attr_object = (attributes & 0x8)
                attr_signing = (attributes & 0x10)
                attr_encrypting = (attributes & 0x20)
                attr_method = (attributes & 0x40)
                if attr_asymmetric:
                    print(''.rjust(23) + 'asymmetric algorithm')
                if attr_symmetric:
                    print(''.rjust(23) + 'symmetric algorithm')
                if attr_hash:
                    print(''.rjust(23) + 'hash algorithm')
                if attr_object:
                    print(''.rjust(23) + 'object')
                if attr_signing:
                    print(''.rjust(23) + 'signing algorithm')
                if attr_encrypting:
                    print(''.rjust(23) + 'encryption/decryption algorithm')
                if attr_method:
                    print(''.rjust(23) + 'method')
                print()
        # CCA and CC is same but ordering can be different
        # TPML_CCA
        elif (resCapabilityId == TPM_CAP['COMMANDS'] or 
                # TPML_CC
                resCapabilityId == TPM_CAP['PP_COMMANDS'] or 
                # TPML_CC
                resCapabilityId == TPM_CAP['AUDIT_COMMANDS']):
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('properties:'.rjust(20))
            for i in range(0, count):
                (attributes, ) = struct.unpack('!I', res[0:4])
                res = res[4:]
                commandIndex = attributes & 0xFFFF
                attributes = (attributes >> 16) & 0xFFFF
                command = TPM_CCrev.get(commandIndex, 'UNKNOWN')
                print(''.rjust(20) + ' %s [0x%x]' % (command, commandIndex))
                print(''.rjust(23) + 'attributes: 0x%x' % attributes)
                if attributes & 0x0040:
                    print(''.rjust(23) + 'nv (may write to NV)')
                if attributes & 0x0080:
                    print(''.rjust(23) + 'extensive (could flush any number of loaded contexts)')
                if attributes & 0x0100:
                    print(''.rjust(23) + 'flushed (any transient handle in the command will be flushed)')
                cHandles = ((attributes >> 9) & 0x7)
                print(''.rjust(23) + '%d handles in the handle area' % cHandles)
                if attributes & 0x1000:
                    print(''.rjust(23) + 'rHandle (handle area in the response)')
                if attributes & 0x2000:
                    print(''.rjust(23) + 'V (command is vendor specific)')
                print()
        elif resCapabilityId == TPM_CAP['TPM_PROPERTIES']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('properties:'.rjust(20))
            for i in range(0, count):
                (propertyId, value) = struct.unpack('!II', res[0:8])
                res = res[8:]
                propertyName = TPM_PTrev.get(propertyId, 'UNKNOWN')
                if (propertyId == TPM_PT['FAMILY_INDICATOR'] or
                        propertyId == TPM_PT['MANUFACTURER'] or
                        propertyId == TPM_PT['VENDOR_STRING_1'] or 
                        propertyId == TPM_PT['VENDOR_STRING_2'] or
                        propertyId == TPM_PT['VENDOR_STRING_3'] or 
                        propertyId == TPM_PT['VENDOR_STRING_4']):
                    print(''.rjust(20) + ' %s [0x%x] = %d [0x%x "%s"]' % (propertyName, 
                        propertyId, 
                        value, 
                        value,
                        struct.pack('!I', value).decode('ascii')))
                else:
                    print(''.rjust(20) + ' %s [0x%x] = %d [0x%x]' % (propertyName, propertyId, value, value))
        elif resCapabilityId == TPM_CAP['PCR_PROPERTIES']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('PCRs:'.rjust(20))
            for i in range(0, count):
                (tag, sizeOfSelect) = struct.unpack('!IB', res[0:5])
                res = res[5:]
                print(''.rjust(20) + ' %s [0x%x]' % (TPM_PT_PCRrev.get(tag, "UNKNOWN"), tag))
                print(''.rjust(23) + ' sizeOfSelect: %d' % (sizeOfSelect,))
                if sizeOfSelect == 0:
                    return
                pcrSelect = []
                for i in range(0, sizeOfSelect):
                    (onePcrSelect,) = struct.unpack('!B', res[0:1])
                    res = res[1:]
                    pcrSelect.append(onePcrSelect)
                print(''.rjust(23) + ' pcrSelect: %s' % (' '.join(['0x%x' % x for x in pcrSelect])).strip())
                print(''.rjust(23) + ' pcrSelect: %s' % pcr_list(pcrSelect))
                print()
        elif resCapabilityId == TPM_CAP['ECC_CURVES']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('supported ECC Curves:'.rjust(20))
            for i in range(0, count):
                (eccCurveId,) = struct.unpack('!H', res[0:2])
                res = res[2:]
                print(''.rjust(20) + ' %s [0x%x]' % (TPM_ECCrev.get(eccCurveId, "UNKNOWN"), eccCurveId))
        elif resCapabilityId == TPM_CAP['HANDLES']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('loaded handles:'.rjust(20))
            for i in range(0, count):
                (handleId,) = struct.unpack('!I', res[0:4])
                res = res[4:]
                print(''.rjust(20) + ' %s [0x%x]' % (TPM_RHrev.get(handleId, "UNKNOWN"), handleId))
        elif resCapabilityId == TPM_CAP['PCRS']:
            (count,) = struct.unpack('!I', res[0:4])
            print('count:'.rjust(20) + ' %d' % count)
            res = res[4:]
            if count == 0:
                return
            print('pcr selections:'.rjust(20))
            for i in range(0, count):
                (hashId, sizeOfSelect) = struct.unpack('!HB', res[0:3])
                res = res[3:]
                print(''.rjust(20) + ' hash: %s [0x%x]' % (TPM_ALGrev.get(hashId, 'UNKNOWN'), hashId))
                print(''.rjust(23) + ' sizeOfSelect: %d' % (sizeOfSelect,))
                if sizeOfSelect == 0:
                    return
                pcrSelect = []
                for i in range(0, sizeOfSelect):
                    (onePcrSelect,) = struct.unpack('!B', res[0:1])
                    res = res[1:]
                    pcrSelect.append(onePcrSelect)
                print(''.rjust(23) + ' pcrSelect: %s' % (' '.join(['0x%x' % x for x in pcrSelect])).strip())
                print(''.rjust(23) + ' pcrSelect: %s' % pcr_list(pcrSelect))
                print()


def _help():
    print('tpm2_GetCapability no_sessions|sessions capability property count')
    print('use tpm2_GetCapability no_sessions ? to see list of capabilities')
    print('use tpm2_GetCapability no_sessions capability ? to see list of properties')
    sys.exit(1)


def _get_property_dict(capabilityId):
    if capabilityId == TPM_CAP['ALGS']:
        return (TPM_ALG, TPM_ALGrev)
    elif capabilityId == TPM_CAP['HANDLES']:
        return (TPM_HT, TPM_HTrev)
    elif capabilityId == TPM_CAP['COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['PP_COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['AUDIT_COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['PCRS']:
        return None # returns None but this is implemented in the command
    elif capabilityId == TPM_CAP['TPM_PROPERTIES']:
        return (TPM_PT, TPM_PTrev)
    elif capabilityId == TPM_CAP['PCR_PROPERTIES']:
        return (TPM_PT_PCR, TPM_PT_PCRrev)
    elif capabilityId == TPM_CAP['ECC_CURVES']:
        return (TPM_ECC, TPM_ECCrev)
    elif capabilityId == TPM_CAP['AUTH_POLICIES']:
        return None
    elif capabilityId == TPM_CAP['VENDOR_PROPERTY']:
        return None
    else:
        return None


def _list_capabilities():
    print('capabilities:'.rjust(20))
    for capabilityId in sorted(TPM_CAP.values()):
        capability = TPM_CAPrev[capabilityId]
        print(''.rjust(20) + ' %s [0x%x]' % (capability, capabilityId))
    sys.exit(0)


def _list_properties(capabilityId):
    (p, r) = _get_property_dict(capabilityId)
    print('properties:'.rjust(20))
    for propertyId in sorted(p.values()):
        propertyName = r[propertyId]
        print(''.rjust(20) + ' %s [0x%x]' % (propertyName, propertyId))
    sys.exit(0)


def main():
    if len(sys.argv) < 3:
        _help()
    sessions = False
    if sys.argv[1] == 'no_sessions':
        sessions = False
    elif sys.argv[1] == 'sessions':
        sessions = True
    else:
        _help()
    if sys.argv[2] == '?':
        _list_capabilities()
    else:
        capability = sys.argv[2]
        capabilityId = TPM_CAP.get(capability, None)
        if capabilityId is None:
            print('capability name: %s is not valid, see the list' % capability)
            sys.exit(1)
        if len(sys.argv) < 4:
            _help()
        elif len(sys.argv) == 4 and sys.argv[3] == '?':
            if capability == 'PCRS':
                print('property for PCRS capability is always fixed and should be 0')
            else:
                _list_properties(capabilityId)
        else:
            propertyName = sys.argv[3]
            if capability != 'PCRS':
                (properties, propertiesRev) = _get_property_dict(capabilityId)
                propertyId = properties.get(propertyName, None)
            else:
                if propertyName != '0':
                    print('property for PCRS capability is always fixed and should be 0')
                else:
                    propertyId = 0
            if propertyId is None:
                print('property name: %s is not valid, see the list' % propertyName)
                sys.exit(1)
            elif len(sys.argv) == 5:
                count = int(sys.argv[4])
                if capability == 'HANDLES':
                    propertyId = propertyId << 24
                _get_capability(sessions, capabilityId, propertyId, count)
            else:
                _help()
