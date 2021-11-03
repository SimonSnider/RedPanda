import unittest
from modules.runInstruction.runInstruction import *
from modules.runInstruction.stateManager import *
from keystone import *
from modules.generateInstruction import instructionGenerator

panda = initializePanda()

class TestScript(unittest.TestCase):
    # def testRunInstructionOnce(self):
    #     print("test1")
    #     instruction = "andi $t0, $t1, 0"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')

    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     data, initialState = runInstructionLoop(panda, encoding, 1)
    #     self.assertIsInstance(initialState, dict)
    #     for regStates in data:
    #         self.assertNotEqual(regStates[1].get("T0"), 0)
    #         self.assertEqual(regStates[2].get("T0"), 0)
    #         self.assertIsInstance(regStates[0], bytes)
    #         self.assertIsInstance(regStates[1], dict)
    #         self.assertIsInstance(regStates[2], dict)
    
    # def testRunInstructionLoop(self):
    #     # panda.reset()
    #     print("test2")
    #     instructionGenerator.initialize()
    #     instruction =  instructionGenerator.generateInstruction()
    #     n = 100
    #     data, initialState = runInstructionLoop(panda, instruction, n)
    #     self.assertEqual(len(data), n)
    #     self.assertIsInstance(initialState, dict)
    #     for regState in data:
    #         self.assertIsInstance(regState[0], bytes)
    #         self.assertIsInstance(regState[1], dict)
    #         self.assertIsInstance(regState[2], dict)

    def testRunInstructions(self):
        # panda.reset()
        print("test3")
        instructions = []
        instructionGenerator.initialize()
        inst = 10
        n = 100
        for i in range(inst):
            instructions.append(instructionGenerator.generateInstruction())
            print(instructions[i])

        stateData, initialState = runInstructions(panda, instructions, n)
        self.assertEqual(len(stateData.keys()), inst)
        self.assertIsInstance(initialState, dict)
        for key in stateData.keys():
            self.assertEqual(len(stateData.get(key)), n)
            for regState in stateData.get(key):
                self.assertIsInstance(regState[0], bytes)
                self.assertIsInstance(regState[1], dict)
                self.assertIsInstance(regState[2], dict)



if __name__ == '__main__':
    unittest.main()