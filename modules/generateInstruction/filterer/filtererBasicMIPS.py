# filterer Module
# Purpose: reject instructions not functional for current model implementation
from capstone import *
from capstone.mips import *

def filterInstruction(instruction):
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
    md.detail = True

    for insn in md.disasm(instruction, 0x1000):
        print("%s\t%s" % (insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            for i in insn.operands:
                if i.type == MIPS_OP_REG:
                    continue;
                if i.type == MIPS_OP_IMM:
                    continue;
                if i.type == MIPS_OP_MEM:
                    print("Error: Instruction Contains Memory Acess")
                    return False;
    return True