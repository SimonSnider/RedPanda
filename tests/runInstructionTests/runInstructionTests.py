import unittest
from modules.runInstruction.runInstruction import *
from modules.runInstruction.stateManager import *
from keystone import *
from modules.generateInstruction import instructionGenerator

panda = initializePanda()

class TestScript(unittest.TestCase):
    def testRunInstructionOnce(self):
        instruction = "andi $t0, $t1, 0"
        print(instruction)
        CODE = instruction.encode('UTF-8')

        ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

        ADDRESS = 0x0000
        encoding, count = ks.asm(CODE, ADDRESS)
        data = runInstructionLoop(panda, encoding, 1, verbose=True)
        for regStates in data:
            self.assertEqual(regStates[1].get("T0"), 0)
    
    def testRunInstructionLoop(self):
        instructionGenerator.initialize()
        instruction =  instructionGenerator.generateInstruction()
        n = 100
        data = runInstructionLoop(panda, instruction, n)
        self.assertEqual(len(data.keys()), n)

    def testRunInstructions(self):
        instructions = []
        instructionGenerator.initialize()
        inst = 10
        n = 100
        for i in range(inst):
            instructions.append(instructionGenerator.generateInstruction(True))

        stateData: dict = runInstructions(panda, instructions, n, True)
        self.assertEqual(len(stateData.keys()), inst)
        for key in stateData.keys():
            self.assertEqual(len(stateData.get(key)), n)



if __name__ == '__main__':
    unittest.main()