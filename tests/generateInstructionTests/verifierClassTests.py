from capstone import CS_MODE_MIPS32
from modules.generateInstruction.verifierClass import *
from capstone import *
import pytest

def test_setISA():
    verifier = Verifier()
    verifier.setISA("mips32")
    assert verifier.archType == CS_MODE_MIPS32 and verifier.mode == CS_MODE_MIPS32

def test_initialize():
    verifier = Verifier()
    verifier.setISA("mips32")
    verifier.initialize()
    assert verifier.disassembler != -1

def getVerifier():
    verifier = Verifier()
    verifier.setISA("mips32")
    verifier.initialize()
    return verifier

def test_disassembleNonsense():
    verifier = getVerifier()
    ret = verifier.isValidInstruction(b"\x00\x00\x00\x00")
    assert not ret

def test_disassembleValidAdd():
    verifier = getVerifier()
    # add t0 t0 t0
    ret = verifier.isValidInstruction(b"\x01\x08\x40\x20")
    assert ret

def test_disassembleValidSub():
    verifier = getVerifier()
    # sub t0 t0 t0
    ret = verifier.isValidInstruction(b"\x01\x08\x40\x22")
    assert ret

def test_disassembleValidSll():
    verifier = getVerifier()
    # shift left logical - first register all zeroes, ignored.
    # sll t0 t1 1 
    # 000000 00000 01000 01001 00001 000000
    # 00000000 00001000 01001000 01000000
    ret = verifier.isValidInstruction(b"\x00\x08\x48\x40")
    assert ret
    
def test_disassembleValidOr():
    verifier = getVerifier()
    # ret = verifier.isValidInstruction(b"\x01\x6a\x60\x25")
    instruction = b"\x01\x4b\x48\x25" #or $t1 $t2 $t3
    # verifier.setLittleEndian(False)
    # 0101 0010 1000 0100 1011 0100 0001 0000
    # 0000 0001 0100 1011 0100 1000 0010 0101
    # 0x014b8425
    # 0000 1000 0010 1101 0010 0001 0100 1010
    # 082d214a
    ret = verifier.isValidInstruction(b"\x08\x2d\x21\x4a")
    # ret = verifier.isValidInstruction(b"\x52\x84\xb4\x10")
    assert ret