from capstone import *
from capstone.mips import *

#CODE = b"000000010000100001000000 00100000" #normal
#CODE = b"01000000010000000000100000000001" #reversed
# CODEB = b"\xa1\x08\x40\x30"
# CODE = b"\x30\x40\x08\x01"
#CODE = b"\x20\x08\x08\x08"
       #xb8\x13\x00\x00"

#b"\x01\x4b\x48\x20"
disassembler = -1
archType = -1
mode = -1
littleEndian = False

def setIsLittleEndian(isLittleEndian):
	global littleEndian
	littleEndian = not not isLittleEndian

def getIsLittleEndian():
	return littleEndian

def setISA(architecture):
	isa = architecture.lower()
	global archType
	global mode
	if isa == "mips32":
		archType = CS_MODE_MIPS32
		mode = CS_MODE_MIPS32
		return
	else:
		print("choose mips32, mips64, x86, etc")
		return
	
def getArchType():
	return archType

def getMode():
	return mode

def getDisassembler():
	return disassembler

def initialize():
	global disassembler
	if archType == -1 or mode == -1:
		print("call setISA() with an architecture")
		return
	if littleEndian:
		disassembler = Cs(archType, mode+CS_MODE_LITTLE_ENDIAN)
		disassembler.detail = True
		return
	else:
		disassembler = Cs(archType, mode+CS_MODE_BIG_ENDIAN)
		print("Made with big endian")
		disassembler.detail = True
		return

def isValidInstruction(instruction, verbose=False):
	print(4)
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
