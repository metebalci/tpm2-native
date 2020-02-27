import struct
import sys
from tpm2_native.common import *


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


def _get_property_dict(capabilityId):
    if capabilityId == TPM_CAP['ALGS']:
        return TPM_ALG
    elif capabilityId == TPM_CAP['HANDLES']:
        return None
    elif capabilityId == TPM_CAP['COMMANDS']:
        return TPM_CC
    elif capabilityId == TPM_CAP['PP_COMMANDS']:
        return TPM_CC
    elif capabilityId == TPM_CAP['AUDIT_COMMANDS']:
        return TPM_CC
    elif capabilityId == TPM_CAP['TPM_PROPERTIES']:
        return None
    elif capabilityId == TPM_CAP['PCR_PROPERTIES']:
        return None
    elif capabilityId == TPM_CAP['ECC_CURVE']:
        return None
    elif capabilityId == TPM_CAP['VENDOR_PROPERTY']:
        return None
    else:
        return None


def _help():
    print('tpm2_GetCapability no_sessions|sessions capability property count')
    print('use tpm2_GetCapability no_sessions ? to see list of capabilities')
    print('use tpm2_GetCapability no_sessions capability ? to see list of properties')
    sys.exit(1)


def _get_property_dict(capabilityId):
    if capabilityId == TPM_CAP['ALGS']:
        return (TPM_ALG, TPM_ALGrev)
    elif capabilityId == TPM_CAP['HANDLES']:
        return None
    elif capabilityId == TPM_CAP['COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['PP_COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['AUDIT_COMMANDS']:
        return (TPM_CC, TPM_CCrev)
    elif capabilityId == TPM_CAP['TPM_PROPERTIES']:
        return None
    elif capabilityId == TPM_CAP['PCR_PROPERTIES']:
        return None
    elif capabilityId == TPM_CAP['ECC_CURVE']:
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
            _list_properties(capabilityId)
        else:
            (properties, propertiesRev) = _get_property_dict(capabilityId)
            propertyName = sys.argv[3]
            propertyId = properties.get(propertyName, None)
            if propertyId is None:
                print('property name: %s is not valid, see the list' % propertyName)
                sys.exit(1)
            elif len(sys.argv) == 5:
                count = int(sys.argv[4])
                _get_capability(sessions, capabilityId, propertyId, count)
            else:
                _help()

