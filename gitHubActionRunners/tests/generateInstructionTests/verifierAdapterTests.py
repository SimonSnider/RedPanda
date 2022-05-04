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
    verifier = initialize("mips32")
    assert verifier.arch == CS_ARCH_MIPS and verifier.mode == CS_MODE_MIPS32

# verify that the disassembler (Capstone object) is being set correctly
def test_initialize():
    verifier = initialize("mips32")
    assert verifier.disassembler != -1

# initialize the Capstone object
def init_mips32():
    return initialize("mips32")

# test the no-op instruction
def testNoOp():
    verifier = init_mips32()
    ret = isValidInstruction(verifier, b"\x00\x00\x00\x00")
    assert ret

# test an add instruction (add t1 t2 t3)
def testValidAdd():
    verifier = init_mips32()
    instruction = b"\x01\x4b\x48\x20"
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a sub instruction (sub t1 t2 t3)
def testValidSub():
    verifier = init_mips32()
    instruction = b"\x01\x4b\x48\x22"
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a shift left logical instruction (sll t0 t1 1)
def testValidSll():
    verifier = init_mips32()
    instruction = b"\x00\x09\x40\x40"
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a shift right logical instruction (srl t0 t1 1)
def testValidSrl():
    verifier = init_mips32()
    instruction = b"\x00\x09\x40\x42"
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a valid or instruction (or t1 t2 t3)
def testValidOr():
    verifier = init_mips32()
    instruction = b"\x01\x4b\x48\x25"
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a valid and instruction (and t1 t2 t3)
def testValidAnd():
    verifier = init_mips32()
    instruction = b"\x01\x4b\x48\x24" 
    ret = isValidInstruction(verifier, instruction)
    assert ret

# test a string that does not represent an instruction (32 bits of only ones)
def testInvalidInstruction():
    verifier = init_mips32()
    instruction = b"\xff\xff\xff\xff"
    ret = isValidInstruction(verifier, instruction)
    assert not ret