#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Filename: getOdexInfo.py

import os
import sys
import struct
from struct import *

DEX_MAGIC           = b'dex\n'
DEX_MAGIC_VERS      = b'035\0'
DEX_OPT_MAGIC       = b'dey\n'
DEX_OPT_MAGIC_VERS  = b'036\0'
DEX_DEP_MAGIC       = b'deps'

class DexOptHeader:
    def __init__(self,buf):
        (
            self.magic,
            self.dexOffset,
            self.dexLength,
            self.depsOffset,
            self.depsLength,
            self.optOffset,
            self.optLength,
            self.flags,
            self.checksum,
        ) = struct.unpack('<8s8I',buf)

class DepsHeader:
    def __init__(self,buf):
        (
            self.nowWhen,
            self.crc,
            self.DALVIK_VM_BUILD,
            self.numDeps,
        ) = struct.unpack('<IIII',buf)

def main():
    fo = open("bouncycastle.odex","rb")
    fo.seek(0,0)
    buf = fo.read(40)
    dexOptHeader = DexOptHeader(buf)
    print("\n ========== DexOptHeader ==========\n")
    print("%s%s"   % ("         magic  =  ",   dexOptHeader.magic))
    print("%s%.8x" % ("     dexOffset  =  0x", dexOptHeader.dexOffset))
    print("%s%.8x" % ("     dexLength  =  0x", dexOptHeader.dexLength))
    print("%s%.8x" % ("    depsOffset  =  0x", dexOptHeader.depsOffset))
    print("%s%.8x" % ("    depsLength  =  0x", dexOptHeader.depsLength))
    print("%s%.8x" % ("     optOffset  =  0x", dexOptHeader.optOffset))
    print("%s%.8x" % ("     optLength  =  0x", dexOptHeader.optLength))
    print("%s%.8x" % ("         flags  =  0x", dexOptHeader.flags))
    print("%s%.8x" % ("      checksum  =  0x", dexOptHeader.checksum))
    print("\n ========== DexOptHeader ==========\n")
    fo.seek(dexOptHeader.depsOffset,0)
    buf = fo.read(16)
    depsHeader = DepsHeader(buf)
    print("\n ========== DepsHeader ========== \n")
    print("%s%.8x" % ("            nowWhen  =  0x", depsHeader.nowWhen))
    print("%s%.8x" % ("                crc  =  0x", depsHeader.crc))
    print("%s%.8x" % ("    DALVIK_VM_BUILD  =  0x", depsHeader.DALVIK_VM_BUILD))
    print("%s%.8x" % ("            numDeps  =  0x", depsHeader.numDeps))
    print("\n ========== DepsHeader ========== \n")
    for i in range(1,depsHeader.numDeps+1,1):
        print("%d" % i)
        len, = struct.unpack('<I',fo.read(4))
        print("%s%.8x" % ("            len  =  0x", len))
        print("%s" % fo.read(len))
        kSHA1DigestLen, = struct.unpack('<20s',fo.read(20))
        print("%s" % kSHA1DigestLen)
        print("需要64位即8字节对齐，depsLength % 8 取余，然后用 8 减去这个余数即是后面需要补 0x00 的位数，每个 deps 是紧凑相邻的，其间不需要补 0x00，只需要在 depsOffset 开始之后的 depsLength 补零就可以了")
    fo.close()

if __name__ == "__main__":
    main()