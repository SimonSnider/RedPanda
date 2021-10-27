from modules.generateInstruction.verifierAdapter import *
import pytest

# def test_setISA():
#     setISA("mips32")
#     assert archType == CS_MODE_MIPS32 and mode == CS_MODE_MIPS32

# def test_initialize():
#     setISA("mips32")
#     initialize()
#     assert disassembler != -1

def init_mips32():
    setISA("mips32")
    initialize()
    setIsLittleEndian(False)
    return


def test_disassembleNonsense():
    init_mips32()
    ret = isValidInstruction(b"\x00\x00\x00\x00")
    assert not ret

def test_disassembleValidAdd():
    init_mips32()
    ret = isValidInstruction(b"\x08\x01\x20\x40")
    # ret = isValidInstruction(b"\x01\x08\x40\x20")
    assert ret

def test_disassembleValidSub():
    init_mips32()
    print("test_disassembleV")
    # sub t0 t0 t0
    instruction = b"\x01\x4b\x48\x22"
    # ret = isValidInstruction(b"\x08\x01\x20\x44", True)
    # ret = isValidInstruction(b"\x01\x08\x40\x22", True)
    ret = isValidInstruction(instruction)
    print(ret)
    assert False

def test_disassembleValidSll():
    init_mips32()
    # shift left logical - first register all zeroes, ignored.
    # sll t0 t1 1 
    # 000000 00000 01000 01001 00001 000000
    # 00000000 00001000 01001000 01000000
    # ret = isValidInstruction(b"\x00\x01\x21\x20")
    ret = isValidInstruction(b"\x00\x08\x48\x40", True)
    assert ret