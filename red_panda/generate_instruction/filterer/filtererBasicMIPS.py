# filterer Module
# Purpose: reject instructions not functional for current model implementation
from red_panda.utilities.printOptions import printStandard
from capstone import *
from capstone.mips import *

def filterInstruction(instruction, verbose=False):
    """

    Arguments:
        instruction -- takes a 32 bit instruction specified in byte format

        verbose -- turns on printing of generated instruction bytes (default = False)

    Output:
        Returns true if the instruction is not filtered out in the current model
        Returns false otherwise
    """

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    md.detail = True

    for insn in md.disasm(instruction, 0x1000):
        if(verbose):
            printStandard("%s\t%s" % (insn.mnemonic, insn.op_str))
            printStandard("Groups:%s" % (str(insn.groups)))


        mnemonic = insn.mnemonic

        if(mnemonic in ["beq", "bne", "bgtz", "bltz", "bgez", "blez", "addi"]):
            return False

        groups = insn.groups
        if(any(item in [CS_GRP_INVALID, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET, CS_GRP_PRIVILEGE, MIPS_GRP_FPIDX, MIPS_GRP_FP64BIT, MIPS_GRP_MICROMIPS]  for item in groups)):
            return False

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
                    return False;
        else:
            return False;
    return True
