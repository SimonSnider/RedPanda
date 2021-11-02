from modules.generateInstruction.verifierAdapter import *
import pytest

"""
This file tests the verifierAdapter file. The verifierAdapter file is intended to describe
whether a given instruction is a valid instruction or not given an architecture. For example,
given that it is to use the mips32 archticture and asked whether b'\x00\x00\x00\x00' is a valid
instruction, it should return true because that string represents the no-op instruction.

The following valid instructions are tested in the order given:
no-op
add
sub
sll
srl
or
and

Additionally, test an instruction composed of all 1s (0xffffffff)
to verify that invalid instructions are properly rejected
"""

# verify that the archType and mode variables are being set correctly
def test_setISA():
    setISA("mips32")
    assert getArchType() == CS_ARCH_MIPS and getMode() == CS_MODE_MIPS32

# verify that the disassembler (Capstone object) is being set correctly
def test_initialize():
     setISA("mips32")
     initialize()
     assert getDisassembler() != -1

# initialize the Capstone object
def init_mips32():
    setISA("mips32")
    initialize()
    return

# test the no-op instruction
def testNoOp():
    init_mips32()
    ret = isValidInstruction(b"\x00\x00\x00\x00")
    assert ret

# test an add instruction (add t1 t2 t3)
def testValidAdd():
    init_mips32()
    instruction = b"\x01\x4b\x48\x20"
    ret = isValidInstruction(instruction)
    assert ret

# test a sub instruction (sub t1 t2 t3)
def testValidSub():
    init_mips32()
    instruction = b"\x01\x4b\x48\x22"
    ret = isValidInstruction(instruction)
    assert ret

# test a shift left logical instruction (sll t0 t1 1)
def testValidSll():
    init_mips32()
    instruction = b"\x00\x09\x40\x40"
    ret = isValidInstruction(instruction)
    assert ret

# test a shift right logical instruction (srl t0 t1 1)
def testValidSrl():
    init_mips32()
    instruction = b"\x00\x09\x40\x42"
    ret = isValidInstruction(instruction)
    assert ret

# test a valid or instruction (or t1 t2 t3)
def testValidOr():
    init_mips32()
    instruction = b"\x01\x4b\x48\x25"
    ret = isValidInstruction(instruction)
    assert ret

# test a valid and instruction (and t1 t2 t3)
def testValidAnd():
    init_mips32()
    instruction = b"\x01\x4b\x48\x24" 
    ret = isValidInstruction(instruction)
    assert ret

# test a string that does not represent an instruction (32 bits of only ones)
def testInvalidInstruction():
    init_mips32()
    instruction = b"\xff\xff\xff\xff"
    ret = isValidInstruction(instruction)
    assert not ret