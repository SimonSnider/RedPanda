import pytest
from modules.generateInstruction.filterer.filtererBasicMIPS import filterInstruction

def test_filterValidRTypeInstructions():
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
    instruction = b"\x01\x4b\x48\x20"
    assert filterInstruction(instruction) == True

    # Filter the sub instruction
    instruction = b"\x01\x4b\x48\x22"
    assert filterInstruction(instruction) == True

    # Filter the sll instruction
    instruction = b"\x00\x0a\x49\x40"
    assert filterInstruction(instruction) == True

    # Filter the srl instruction
    instruction = b"\x00\x0a\x49\x42"
    assert filterInstruction(instruction) == True

    # Filter the or instruction
    instruction = b"\x01\x4b\x48\x25"
    assert filterInstruction(instruction) == True

    # Filter the and instruction
    instruction = b"\x01\x4b\x48\x24"
    assert filterInstruction(instruction) == True

def test_filterInvalidRTypeInstructions():
    """Test that invalid R-Type instructions are filtered out.
    The following instructions are tested in the order given:
        syscall
        jr
    """
    # Filter the syscall instruction
    instruction = b"\x00\x00\x00\x0c"
    assert filterInstruction(instruction) == False

    # Filter the jr instruction
    instruction = b"\x01\x60\x00\x08"
    assert filterInstruction(instruction) == False

def test_filterValidITypeInstructions():
    """Test that valid I-Type instructions are not filtered out.
    The following instructions are tested in the order given:
        addi
        andi
        ori
    """
    # Filter the addi instruction
    instruction = b"\x21\x28\x00\x05"
    assert filterInstruction(instruction) == True

    # Filter the andi instruction
    instruction = b"\x31\x28\x00\x05"
    assert filterInstruction(instruction) == True

    # Filter the ori instruction
    instruction = b"\x35\x28\x00\x05"
    assert filterInstruction(instruction) == True

def test_filterInvalidITypeInstructions():
    """Test that invalid I-Type instructions are filtered out.
    The following instructions are tested in the order given:
        lw
        sw
        sb
    """
    # Filter the lw instruction
    instruction = b"\x8d\x28\x00\x00"
    assert filterInstruction(instruction) == False

    # Filter the sw instruction
    instruction = b"\xad\x28\x00\x00"
    assert filterInstruction(instruction) == False

    # Filter the sb instruction
    instruction = b"\xa1\x28\x00\x00"
    assert filterInstruction(instruction) == False

def test_filterAnyJTypeInstructions():
    """Test all J-Type instructions are filtered out.
    The following instructions are tested in the order given:
        j
        jal
    """
    # Filter the j instruction
    instruction = b"\x08\x00\x00\x00"
    assert filterInstruction(instruction) == False

    # Filter the jal instruction
    instruction = b"\x0c\x00\x00\x12"
    assert filterInstruction(instruction) == False