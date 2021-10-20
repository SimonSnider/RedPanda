import pytest
from modules.generateInstruction.filterer.filtererBasicMIPS import filterInstruction

def filterValidRTypeInstructions():
    """Test that valid R-Type instructions are not filtered out.
    The following instructions are tested in the order given:
        add
        sub
        sll
        srl
        or
        and
    """
    # Filter the add instruction
    instruction = b"\x00\x21\x00\x20"
    assert filterInstruction(instruction) == True

    # Filter the sub instruction
    instruction = b"\x00\x21\x00\x22"
    assert filterInstruction(instruction) == True

    # Filter the sll instruction
    instruction = b"\x00\x21\x00\x40"
    assert filterInstruction(instruction) == True

    # Filter the srl instruction
    instruction = b"\x00\x21\x00\x42"
    assert filterInstruction(instruction) == True

    # Filter the or instruction
    instruction = b"\x00\x21\x00\x25"
    assert filterInstruction(instruction) == True

    # Filter the and instruction
    instruction = b"\x00\x21\x00\x24"
    assert filterInstruction(instruction) == True

def filterInvalidRTypeInstructions():
    """Test that invalid R-Type instructions are filtered out.
    The following instructions are tested in the order given:
        syscall
        jr
        mfhi
        mflo
        mult
    """
    assert 1;

def filterValidITypeInstructions():
    """Test that valid I-Type instructions are not filtered out.
    The following instructions are tested in the order given:
        addi
        andi
        ori
    """
    assert 1;

def filterInvalidITypeInstructions():
    """Test that invalid I-Type instructions are filtered out.
    The following instructions are tested in the order given:
        lw
        sw
        sb
        sc
    """
    assert 1;


def filterAnyJTypeInstructions():
    """Test all J-Type instructions are filtered out.
    The following instructions are tested in the order given:
        j
        jal
    """
    assert 0;