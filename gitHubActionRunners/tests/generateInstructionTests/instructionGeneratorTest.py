import pytest
from red_panda.generate_instruction import instructionGenerator as instGen
from red_panda.generate_instruction.filterer import filtererBasicMIPS as filterer
from red_panda.generate_instruction import verifierAdapter as veriAdpt

def test_instructionGenerate():
    """Test that the instructions generated from the generateInstruction function are both valid and not filtered out.
    The following instructions are tested in the order given:
        10 randomly generated instructions
    """
    instGen.initialize("mips32")
    veriAdpt.setISA("mips32")
    veriAdpt.initialize()

    for _ in range(10):
        instruction = instGen.generateInstruction()
        
        assert veriAdpt.isValidInstruction(instruction) == 1
        assert filterer.filterInstruction(instruction) == 1