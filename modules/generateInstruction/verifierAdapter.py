from capstone import *
from capstone.mips import *

# do not access these variables directly from outside this file; use getters instead
disassembler = -1
archType = -1
mode = -1
littleEndian = False # default to big-endian

# setter for littleEndian
def setLittleEndian(isLittleEndian):
	global littleEndian
	littleEndian = not not isLittleEndian

# getter for littleEndian
def getLittleEndian():
	return littleEndian

# define the ISA to use; e.g. mips32
def setISA(architecture):
	isa = architecture.lower()
	global archType
	global mode
	if isa == "mips32":
		archType = CS_ARCH_MIPS
		mode = CS_MODE_MIPS32
		return
	else:
		print("choose mips32, mips64, x86, etc")
		return
	
# getter for archType
def getArchType():
	return archType

# getter for mode
def getMode():
	return mode

# getter for disassembler
def getDisassembler():
	return disassembler

# instantiate the Capstone object (disassembler)
def initialize():
	global disassembler
	if archType == -1 or mode == -1: # then the architecture has not been chosen
		print("call setISA() with an architecture")
		return
	if littleEndian:
		disassembler = Cs(archType, mode+CS_MODE_LITTLE_ENDIAN)
		disassembler.detail = True
		return
	else:
		disassembler = Cs(archType, mode+CS_MODE_BIG_ENDIAN)
		disassembler.detail = True
		return

# given binary code, decide whether it is a valid instruction
def isValidInstruction(instruction, verbose=False):
	if disassembler == -1:
		print("you still need to initialize")
		return False
	if(verbose):
		print("archType: %i; mode: %i" %(archType, mode))
	i = 0
	for insn in disassembler.disasm(instruction, 0x1000):
		i+=1
		if(verbose):
			print("%s\t%s\t%x" %(insn.mnemonic, insn.op_str, insn.address))
	return i>0