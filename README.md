# tpm2-native

This is a collection of tools for playing with TPM v2 modules natively e.g. through SPI. The main purpose is to learn how TPM v2 works by interacting with a TPM. 

I do all my testing on a Raspberry Pi 4 with an [Infineon OPTIGA TPM SLM 9670 Iridium TPM2.0 Evaluation Board](https://www.infineon.com/cms/en/product/evaluation-boards/iridium-slm-9670-tpm2.0/). All the [examples](#Examples) below are also from this platform.

# Install

Simply install with `pip install tpm2-native`. This will install all utilities that can be called natively. All utilities have names starting with `tpm2_`, utilities are simply the command names e.g. tpm2_Startup.

# Supported Commands

The section names are the same as in [Trusted Platform Module Library Part 3: Commands Family 2.0 Level 00 Revision 01.38](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf).

## Start-up

All commands in this section in the spec. are implemented.

- Startup
- Shutdown

## Testing

All commands in this section in the spec. are implemented.

- SelfTest
- IncrementalSelfTest
- GetTestResult

## Random Number Generator

All commands in this section in the spec. are implemented.

- GetRandom
- StirRandom

## Capability Commands

- GetCapability (partially implemented)

# References

- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Infineon Embedded Linux TPM Toolbox 2 (ELTT2) for TPM 2.0](https://github.com/Infineon/eltt2)
- [Infineon Iridium SLM 9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium-slm-9670-tpm2.0/)

# Examples

Startup:

```
$ tpm2_Startup clear
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0xc [12]
        commandCode: 0x144 [TPM_CC_Startup]
req: 80 01 00 00 00 0c 00 00 01 44 00 00
res: 80 01 00 00 00 0a 00 00 00 00
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0xa [10]
       responseCode: 0x0 [TPM_RC_SUCCESS]
```

Shutdown:

```
 $ tpm2_Shutdown clear
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0xc [12]
        commandCode: 0x145 [TPM_CC_Shutdown]
req: 80 01 00 00 00 0c 00 00 01 45 00 00
res: 80 01 00 00 00 0a 00 00 00 00
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0xa [10]
       responseCode: 0x0 [TPM_RC_SUCCESS]
```

IncrementalSelfTest:

```
 $ tpm2_IncrementalSelfTest no_sessions AES
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0x10 [16]
        commandCode: 0x142 [TPM_CC_IncrementalSelfTest]
req: 80 01 00 00 00 10 00 00 01 42 00 00 00 01 00 06
res: 80 01 00 00 00 22 00 00 00 00 00 00 00 0a 00 01 00 14 00 15 00 16 00 18 00 19 00 1a 00 20 00 22 00 23
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0x22 [34]
       responseCode: 0x0 [TPM_RC_SUCCESS]
           toDoList:
                     TPM_ALG_RSA
                     TPM_ALG_RSASSA
                     TPM_ALG_RSAES
                     TPM_ALG_RSAPSS
                     TPM_ALG_ECDSA
                     TPM_ALG_ECDH
                     TPM_ALG_ECDAA
                     TPM_ALG_KDF1_SP800_56A
                     TPM_ALG_KDF1_SP800_108
                     TPM_ALG_ECC
```

Note: toDoList is not the algorithms to be tested. The algorithms sent are to be tested. toDoList is the algorithms that has not been tested yet. For example, if I run above with RSA, then toDoList will not contain RSA.

SelfTest:

```
$ tpm2_SelfTest no_sessions yes
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0xb [11]
        commandCode: 0x143 [TPM_CC_SelfTest]
req: 80 01 00 00 00 0b 00 00 01 43 01
res: 80 01 00 00 00 0a 00 00 00 00
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0xa [10]
       responseCode: 0x0 [TPM_RC_SUCCESS]
```

GetTestResult:

```
$ tpm2_GetTestResult
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0xa [10]
        commandCode: 0x17c [TPM_CC_GetTestResult]
req: 80 01 00 00 00 0a 00 00 01 7c
res: 80 01 00 00 00 1a 00 00 00 00 00 0a 00 06 01 0b 00 00 00 00 0e b8 00 00 01 53
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0x1a [26]
       responseCode: 0x0 [TPM_RC_SUCCESS]
        outDataSize: 0xa [10]
            outData: 00 06 01 0b 00 00 00 00 0e b8
         testResult: 0x0 [TPM_RC_SUCCESS]
```

GetRandom:

```
$ tpm2_GetRandom 16
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0xc [12]
        commandCode: 0x17b [TPM_CC_GetRandom]
req: 80 01 00 00 00 0c 00 00 01 7b 00 10
res: 80 01 00 00 00 1c 00 00 00 00 00 10 7d 17 16 5a e5 16 1a c4 9a 56 f6 5c 9f 4d bd be
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0x1c [28]
       responseCode: 0x0 [TPM_RC_SUCCESS]
    randomBytesSize: 0x10 [16]
        randomBytes: 7d 17 16 5a e5 16 1a c4 9a 56 f6 5c 9f 4d bd be
```

StirRandom: 

```
$ dd if=/dev/random of=indata count=128 bs=1
$ tpm2_StirRandom no_sessions indata
        len(inData): 0x80 [128]
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
        requestSize: 0x8c [140]
        commandCode: 0x146 [TPM_CC_StirRandom]
req: 80 01 00 00 00 8c 00 00 01 46 00 80 3b a9 73 cb c5 ac bc 89 ac 2a 5c b2 c1 b5 cd 32 c7 1e d1 de 12 ea f5 54 ea 43 b4 82 6f 19 ba 99 65 07 c6 20 c4 2e 30 cc d7 d3 0d 02 63 e3 56 77 73 0d b9 f2 c2 5b 9c 0e 46 77 18 d7 c8 d8 4f 27 a4 5e 2b 64 31 b0 b7 62 d2 26 6d db 97 8b 50 27 36 0f 79 8d 4f 95 04 c5 00 65 af 35 ab 40 2d c6 36 c7 04 94 1b fd 92 48 dc d3 9e 19 fa 31 48 ea 21 da 08 73 0d c6 82 77 b9 32 27 2e 35 7a 2a 07
res: 80 01 00 00 00 0a 00 00 00 00
                tag: 0x8001 [TPM_ST_NO_SESSIONS]
       responseSize: 0xa [10]
       responseCode: 0x0 [TPM_RC_SUCCESS]
```

GetCapability:

```
```

TestParms:

``
```
