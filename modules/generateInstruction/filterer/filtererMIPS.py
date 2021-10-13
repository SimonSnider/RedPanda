# filterer Module
# Purpose: reject instructions not functional for current model implementation
from capstone import *
from capstone.mips import *

def filterInstruction(instruction):
    CODE = b"\x8d\x4c\x32\x08\x01\xd8"

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)
    md.detail = True

    for insn in md.disasm(code, 0x1000):
        print("%s\t%s" % (insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            print("\tNumber of operands: %u" %len(insn.operands))
            c = -1
            for i in insn.operands:
                c += 1
                if i.type == ARM64_OP_REG:
                    continue;
                if i.type == ARM64_OP_IMM:
                    continue;
                if i.type == ARM64_OP_CIMM:
                    continue;
                if i.type == ARM64_OP_FP:
                    print("Error: Instruction Contains Floating Point Operation")
                    return False;
                if i.type == ARM64_OP_MEM:
                    print("Error: Instruction Contains Memory Acess")
                    return False;
    return true