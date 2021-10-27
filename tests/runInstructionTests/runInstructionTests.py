import unittest
from modules.runInstruction.runInstruction import *
from keystone import *

class TestScript(unittest.TestCase):
    def testRunInstructionOnce(self):
        instruction = "andi $t0, $t1, 0"
        print(instruction)
        CODE = instruction.encode('UTF-8')

        ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

        ADDRESS = 0x0000
        encoding, count = ks.asm(CODE, ADDRESS)
        data = runInstructionLoop(encoding, 10)
        for regStates in data:
            self.assertEqual(regStates[1].get("T0"), 0)
    
    # def testRunInstructionLoop(self):
    #     instruction = "" #call generateInstruction Module


    #     data = runInstructionLoop(instruction, 100)
    #     for regStates in data:
    #         self.assertTrue(compareRegStates(regStates[0], regStates[1]))



if __name__ == '__main__':
    unittest.main()