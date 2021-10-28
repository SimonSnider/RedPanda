from ctypes import sizeof
from capstone import *

#CODE = b"000000010000100001000000 00100000" #normal
#CODE = b"01000000010000000000100000000001" #reversed
# CODEB = b"\xa1\x08\x40\x30"
# CODE = b"\x30\x40\x08\x01"
#CODE = b"\x20\x08\x08\x08"
       #xb8\x13\x00\x00"
disassembler = -1
archType = -1
mode = -1
littleEndian = True

def setIsLittleEndian(isLittleEndian):
	global littleEndian
	if isLittleEndian == True:
		littleEndian = True
		return
	if isLittleEndian == False:
		littleEndian = False
		return

def getIsLittleEndian():
	return littleEndian

def setISA(architecture):
	isa = architecture.lower()
	global archType, mode
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

def initialize():
	global disassembler
	if archType == -1 or mode == -1:
		print("call setISA() with an architecture")
		return
	if littleEndian:
		disassembler = Cs(archType, mode+CS_MODE_LITTLE_ENDIAN)
		return
	else:
		disassembler = Cs(archType, mode+CS_MODE_BIG_ENDIAN)
		return

def isValidInstruction(instruction):
	if disassembler == -1:
		print("initialize")
		return
	i = 0
	for thing in disassembler.disasm(instruction, 0x0000):
		i+=1
	return i>0
