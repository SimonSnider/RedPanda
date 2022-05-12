import pytest
from red_panda.generate_instruction import instructionGenerator as instGen
from red_panda.generate_instruction.filterer import filtererBasicMIPS as filterer
from red_panda.generate_instruction import verifierAdapter as veriAdpt

def test_instructionGenerate():
    """Test that the instructions generated from the generateInstruction function are both valid and not filtered out.
    The following instructions are tested in the order given:
        10 randomly generated instructions
    """
    genEncoding = instGen.initialize("mips32")
    verObject = veriAdpt.initialize("mips32")

    for _ in range(10):
        instruction = instGen.generateInstruction(genEncoding, filterer)
        
        assert veriAdpt.isValidInstruction(verObject, instruction) == 1
        assert filterer.filterInstruction(instruction) == 1
