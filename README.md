# tpm2-native

This is a collection of tools for playing with TPM v2 modules natively e.g. through SPI. The main purpose is to learn how TPM v2 works by interacting with a TPM. 

I do all my testing on a Raspberry Pi 4 with an [Infineon OPTIGA TPM SLM 9670 Iridium TPM2.0 Evaluation Board](https://www.infineon.com/cms/en/product/evaluation-boards/iridium-slm-9670-tpm2.0/).

# Install

Simply install with `pip install tpm2-native`. This will install all utilities that can be called natively. All utilities have names starting with `tpm2_`, utilities are simply the command names e.g. tpm2_Startup.

# Supported Commands

- Startup
- Shutdown
- GetTestResult

# References

- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Infineon Embedded Linux TPM Toolbox 2 (ELTT2) for TPM 2.0](https://github.com/Infineon/eltt2)
- [Infineon Iridium SLM 9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium-slm-9670-tpm2.0/)

# Example

Startup after reset.

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

