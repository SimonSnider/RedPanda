import unittest
from modules.runInstruction.runInstruction import runInstruction
from modules.runInstruction.runInstruction import runInstructionSingleRandomReg
from modules.runInstruction.stateManager import *
from keystone import *
from modules.generateInstruction import instructionGenerator
import math

panda = initializePanda()

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
    #     data = runInstruction.runInstructionLoop(panda, encoding, 1)
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
    #     data = runInstructionSingleRandomReg.runInstructionLoop(panda, encoding, 1)
        
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
    
    # def testRunInstructionLoop(self):
    #     instructionGenerator.initialize()
    #     instruction =  instructionGenerator.generateInstruction()
    #     n = 100
    #     data = runInstruction.runInstructionLoop(panda, instruction, n)
    #     self.assertEqual(len(data), n)
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

    def testRunInstructions(self):
        instructions = []
        instructionGenerator.initialize()
        inst = 10
        n = 5
        for i in range(inst):
            instructions.append(instructionGenerator.generateInstruction())

        stateData = runInstructionSingleRandomReg.runInstructions(panda, instructions, n, True)
        self.assertEqual(len(stateData.keys()), inst)
        for key in stateData.keys():
            self.assertEqual(stateData.get(key)[0][0], b'\x00\x00\x00\x00')
            for regState in stateData.get(key):
                self.assertIsInstance(regState[0], bytes)
                self.assertIsInstance(regState[1], dict)
                self.assertIsInstance(regState[2], dict)
                self.assertTrue(isPowerOfTwo(int.from_bytes(regState[0], 'big', signed=False)))


if __name__ == '__main__':
    unittest.main()