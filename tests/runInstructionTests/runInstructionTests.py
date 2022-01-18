import unittest
from modules.runInstruction.runInstruction import runInstruction
from modules.runInstruction.runInstruction import runInstructionSingleRandomReg
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

    # def testRunInstructionOnce(self):
    #     instruction = "andi $t0, $t1, 0"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')
    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     data = runInstruction.runInstructionLoop(panda, encoding, 1, verbose = True)
    #     for regStates in data:
    #         self.assertNotEqual(regStates[1].get("T0"), 0)
    #         self.assertEqual(regStates[2].get("T0"), 0)
    #         self.assertIsInstance(regStates[0], bytes)
    #         self.assertIsInstance(regStates[1], dict)
    #         self.assertIsInstance(regStates[2], dict)

    # def testRunInstructionSingleRandomRegOnce(self):
    #     instruction = "andi $t0, $t1, 0"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')

    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     data = runInstructionSingleRandomReg.runInstructionLoop(panda, encoding, 1, True)
        
    #     self.assertEqual(len(data), 25)
    #     for i in range (len(data)):
    #         regStates = data[i]
    #         self.assertNotEqual(regStates[1].get("T0"), 0)
    #         self.assertEqual(regStates[2].get("T0"), 0)
    #         self.assertIsInstance(regStates[0], bytes)
    #         self.assertIsInstance(regStates[1], dict)
    #         self.assertIsInstance(regStates[2], dict)
    #         if (i == 0): continue
    #         self.assertTrue(isPowerOfTwo(int.from_bytes(regStates[0], 'big')))
    
    # def testRunInstructionLoopSingleRandomReg(self):
    #     instruction = "add $t0, $t1, $t2"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')

    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     n = 100
    #     data = runInstructionSingleRandomReg.runInstructionLoop(panda, encoding, n, False)
    #     self.assertEqual(len(data), n*24 + 1)
    #     for regState in data:
    #         self.assertIsInstance(regState[0], bytes)
    #         self.assertIsInstance(regState[1], dict)
    #         self.assertIsInstance(regState[2], dict)

    # def testRunInstructions(self):
    #     instructions = []
    #     instructionGenerator.initialize()
    #     inst = 10
    #     n = 100
    #     for i in range(inst):
    #         instructions.append(instructionGenerator.generateInstruction())
    #         print(instructions[i])

    #     stateData = runInstruction.runInstructions(panda, instructions, n)
    #     self.assertEqual(len(stateData.keys()), inst)
    #     for key in stateData.keys():
    #         self.assertEqual(len(stateData.get(key)), n)
    #         for regState in stateData.get(key):
    #             self.assertIsInstance(regState[0], bytes)
    #             self.assertIsInstance(regState[1], dict)
    #             self.assertIsInstance(regState[2], dict)

    def testRunInstructionsSingleRandomReg(self):
        instruction = "lw $t2, 4($t4)"
        instruction2 = "sw $t2, 4($t4)"
        CODE = instruction.encode('UTF-8')
        CODE2 = instruction2.encode('UTF-8')
        ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32R6 + KS_MODE_BIG_ENDIAN)

        ADDRESS = 0x0000
        encoding, count = ks.asm(CODE, ADDRESS)
        encoding2, count = ks.asm(CODE2, ADDRESS)
        instructions = [encoding, encoding2]
        inst = 2
        n = 5
        # for i in range(inst):
        #     instructions.append(instructionGenerator.generateInstruction(instGen))

        stateData = runInstructionSingleRandomReg.runInstructions(panda, instructions, n, True)
        self.assertIsInstance(stateData, StateData)
        self.assertEqual(len(stateData.instructions), inst)
        self.assertEqual(len(stateData.registerStates), inst)
        for states in stateData.registerStates:
            self.assertIsInstance(states, RegisterStates)
            self.assertEqual(states.bitmasks[0], b'\x00\x00\x00\x00')
            self.assertEqual(len(states.bitmasks), len(states.beforeStates))
            self.assertEqual(len(states.bitmasks), len(states.afterStates))
            for i in range(len(states.bitmasks)):
                self.assertIsInstance(states.bitmasks[i], bytes)
                self.assertIsInstance(states.beforeStates[i], dict)
                self.assertIsInstance(states.afterStates[i], dict)
                self.assertTrue(isPowerOfTwo(int.from_bytes(states.bitmasks[i], 'big', signed=False)))


if __name__ == '__main__':
    unittest.main()
