# filterer Module
# Purpose: reject instructions not functional for current model implementation
from capstone import *
from capstone.mips import *

def filterInstruction(instruction, verbose=False):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    md.detail = True

    for insn in md.disasm(instruction, 0x1000):
        if(verbose):
            print("%s\t%s" % (insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            for i in insn.operands:
                if i.type == MIPS_OP_REG:
                    if len(insn.operands) == 1:
                        return False;
                    continue;
                if i.type == MIPS_OP_IMM:
                    if len(insn.operands) == 1:
                        return False;
                    continue;
                if i.type == MIPS_OP_MEM:
                    if(verbose):
                        print("Error: Instruction Contains Memory Acess")
                    return False;
        else:
            return False;
    return True