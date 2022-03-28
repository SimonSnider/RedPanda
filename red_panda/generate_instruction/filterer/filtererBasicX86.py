# filterer Module
# Purpose: reject instructions not functional for current model implementation
from red_panda.utilities.printOptions import printStandard
from capstone import *
from capstone.mips import *

def filterInstruction(instruction, verbose=False):
    """

    Arguments:
        instruction -- takes a n bit instruction specified in byte format

        verbose -- turns on printing of generated instruction bytes (default = False)

    Output:
        Returns true if the instruction is not filtered out in the current model
        Returns false otherwise
    """

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    for insn in md.disasm(instruction, 0x1000):
        if(verbose):
            printStandard("%s\t%s" % (insn.mnemonic, insn.op_str))
            printStandard("Groups:", insn.groups)

        mnemonic = insn.mnemonic

        if(mnemonic in []):
            return False

        groups = insn.groups
        if(any(item in []  for item in groups)):
            return False

    return True