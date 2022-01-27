from capstone import *
from capstone.mips import *
from dataclasses import dataclass

@dataclass
class Verifier:
     disassembler = -1
     arch = -1
     mode = -1

# instantiate the Capstone object (disassembler)
def initialize(arch, littleEndian=False):
    # Create a new verifier instance
    verifier = Verifier()

    # Clean input
    arch = arch.lower()

    # Set architecture and mode relative to the selected architecture implementation
    if(arch == "mips32"):
        verifier.arch = CS_ARCH_MIPS
        verifier.mode = CS_MODE_MIPS32
    else:
        raise ValueError("Verifier architecture selection invalid. Maybe it is not implemented?", arch)

    # Instantiate Dissassembler in either little endian or big endian mode
    verifier.disassembler = Cs(verifier.arch, 
                               verifier.mode + 
                                    (not not littleEndian) * CS_MODE_LITTLE_ENDIAN + # 1 * CS_MODE_LITTLE_ENDIAN if littleEndian is true - 0 otherwise
                                    (not littleEndian) * CS_MODE_BIG_ENDIAN)         # 1 * CS_MODE_BIG_ENDIAN if littleEndian is false - 0 otherwise
    verifier.disassembler.detail = True

    # return the new verifier object
    return verifier

# given binary code, decide whether it is a valid instruction
def isValidInstruction(verifier, instruction, verbose=False):
    if(verbose):
        print("archType: %i; mode: %i" %(verifier.arch, verifier.mode))

    # attempt to disassemble whether it is a valid instruction
    for insn in verifier.disassembler.disasm(instruction, 0x1000):
        if (verbose): 
            print("%s\t%s\t%x" %(insn.mnemonic, insn.op_str, insn.address))
        return True
    return False