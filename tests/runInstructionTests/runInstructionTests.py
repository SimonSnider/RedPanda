import unittest

from capstone import *
from modules.runInstruction import runInstruction
from modules.runInstruction.stateManager import *
from keystone import *
from modules.generateInstruction import instructionGenerator
import math
from modules.models.stateData import *

panda = initializePanda()
instGen = instructionGenerator.initialize()

def Log2(x):
    if (x == 0): return True
    return (math.log10(x)/math.log10(2))
 
# Function to check
# if x is power of 2
def isPowerOfTwo(n):
    return (math.ceil(Log2(n)) == math.floor(Log2(n)))

class TestScript(unittest.TestCase):

    # def testRunMipsInstructionOnce(self):
    #     instruction = "andi $t0, $t1, 0"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')
    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     data: StateData = runInstruction.runInstructions(panda, [encoding], 1, verbose = True)
    #     self.assertEqual(len(data.registerStateLists), 1)
    #     regStateList = data.registerStateLists[0]
    #     self.assertIsInstance(regStateList, RegisterStateList)
    #     self.assertEqual(len(regStateList.beforeStates), 1 * 24 + 1)
    #     self.assertEqual(len(regStateList.afterStates), 1 * 24 + 1)
    #     self.assertNotEqual(regStateList.beforeStates[0].get("T0"), 0)
    #     self.assertEqual(regStateList.afterStates[0].get("T0"), 0)


    # def testRunInstructionsMips(self):
    #     instructions = []
    #     instGen = instructionGenerator.initialize("mips32")
    #     inst = 10
    #     n = 100
    #     md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6+ CS_MODE_BIG_ENDIAN) # misp32
    #     for i in range(inst):
    #         instruction = instructionGenerator.generateInstruction(instGen)
    #         instructions.append(instruction)
    #         for insn in md.disasm(instruction, 0x1000):
    #             print("%s\t%s" %(insn.mnemonic, insn.op_str))

    #     data: StateData = runInstruction.runInstructions(panda, instructions, n)
    #     self.assertEqual(len(data.registerStateLists), inst)
    #     for regStateList in data.registerStateLists:
    #         self.assertEqual(len(regStateList.bitmasks), n*24 + 1)
    #         self.assertEqual(len(regStateList.afterStates), n*24 + 1)
    #         self.assertEqual(len(regStateList.beforeStates), n*24 + 1)
    #         self.assertEqual(regStateList.bitmasks[0], b'\x00\x00\x00\x00')
    #         for i in range(len(regStateList.bitmasks)):
    #             self.assertIsInstance(regStateList.bitmasks[i], bytes)
    #             self.assertIsInstance(regStateList.beforeStates[i], dict)
    #             self.assertIsInstance(regStateList.afterStates[i], dict)
    #             self.assertTrue(isPowerOfTwo(int.from_bytes(regStateList.bitmasks[i], 'big', signed=False)))

    def testRunInstructionsMemoryMips(self):
        instruction = "lw $t2, 0($t4)"
        instruction2 = "sw $t2, 0($t4)"
        CODE = instruction.encode('UTF-8')
        CODE2 = instruction2.encode('UTF-8')
        ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

        ADDRESS = 0x0000
        encoding, count = ks.asm(CODE, ADDRESS)
        encoding2, count = ks.asm(CODE2, ADDRESS)
        instructions = [encoding, encoding2]
        inst = 2
        n = 5


        stateData = runInstruction.runInstructions(panda, instructions, n, True)
        self.assertIsInstance(stateData, StateData)
        self.assertEqual(len(stateData.instructions), inst)
        self.assertEqual(len(stateData.registerStateLists), inst)
        lwStates = stateData.registerStateLists[0]
        swStates = stateData.registerStateLists[1]
        self.assertEqual(len(lwStates.memoryReads), n*24 + 1)
        self.assertEqual(len(swStates.memoryWrites), n*24 + 1)
        for read in lwStates.memoryReads[0]:
            self.assertIsInstance(read, MemoryTransaction)
        for write in lwStates.memoryWrites[0]:
            self.assertIsInstance(write, MemoryTransaction)




if __name__ == '__main__':
    unittest.main()
