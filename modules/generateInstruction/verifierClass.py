from capstone  import *

class Verifier:
    def __init__(self):
        self.littleEndian = False
        self.archType = -1
        self.mode = -1
        self.disassembler = -1

    def setLittleEndian(self, littleEndian):
        self.littleEndian = not not littleEndian
        if(self.disassembler != -1):
            self.initialize()

    def setISA(self, architecture):
        isa = architecture.lower()
        if(isa=="mips32"):
            self.archType = CS_MODE_MIPS32
            self.mode = CS_MODE_MIPS32
        else:
            print("Currently only supports Mips32")
        # if(isa=="mips64"):
        #     self.archType = CS_MODE_MIPS64
        #     self.mode = CS_MODE_MIPS64
        #     return
        if(self.disassembler != -1):
            self.initialize()

    def getArchType(self):
        return self.archType

    def getMode(self):
        return self.mode

    def initialize(self):
        if(self.littleEndian):
            self.disassembler = Cs(self.archType, self.mode + CS_MODE_LITTLE_ENDIAN)
        else:
            self.disassembler = Cs(self.archType, self.mode + CS_MODE_BIG_ENDIAN)

    def isValidInstruction(self, instruction):
        if self.disassembler == -1:
            print("you still need to initialize")
            return -1
        i = 0
        for thing in self.disassembler.disasm(instruction, 0x0000):
            i+=1
            print("%s" %(thing.op_str))
        return i>0
