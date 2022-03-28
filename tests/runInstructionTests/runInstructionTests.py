import unittest

from capstone import *
from red_panda.models import stateData
from red_panda.run_instruction import runInstruction
from red_panda.run_instruction.stateManager import *
from keystone import *
from red_panda.generate_instruction import instructionGenerator
import math
from red_panda.models.stateData import *
from red_panda.generate_instruction.filterer import filtererBasicMIPS as mipsFilter
from red_panda.generate_instruction.filterer import filtererBasicX86 as x86Filter
from red_panda.create_output.intermediateJsonOutput import *

instGen = instructionGenerator.initialize()

def Log2(x):
    if (x == 0): return True
    return (math.log10(x)/math.log10(2))
 
# Function to check
# if x is power of 2
def isPowerOfTwo(n):
    return (math.ceil(Log2(n)) == math.floor(Log2(n)))

class TestScript(unittest.TestCase):

#     def testRunMipsInstructionOnce(self):
#         panda = initializePanda("mips")
#         instruction = "andi $t0, $t1, 0"
#         print(instruction)
#         CODE = instruction.encode('UTF-8')
#         ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

#         ADDRESS = 0x0000
#         encoding, count = ks.asm(CODE, ADDRESS)
# #        data: StateData = None
#         data, model = runInstruction.runInstructions(panda, [encoding], 1, verbose = True)
#         self.assertEqual(len(data.registerStateLists), 1)
#         regStateList = data.registerStateLists[0]
#         self.assertIsInstance(regStateList, RegisterStateList)
#         self.assertEqual(len(regStateList.beforeStates), 1 * 24 + 1)
#         self.assertEqual(len(regStateList.afterStates), 1 * 24 + 1)
#         self.assertNotEqual(regStateList.beforeStates[0].get("T0"), 0)
#         self.assertEqual(regStateList.afterStates[0].get("T0"), 0)

    def testRunTwoMipsInstructions(self):
            panda = initializePanda("mips")
            instruction = "andi $t0, $t1, 0"
            instruction2 = "andi $t5, $t6, 0"
            CODE = instruction.encode('UTF-8')
            CODE2 = instruction2.encode('UTF-8')
            ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

            ADDRESS = 0x0000
            encoding, count = ks.asm(CODE, ADDRESS)
            encoding2, count = ks.asm(CODE2, ADDRESS)
    #        data: StateData = None
            data, model = runInstruction.runInstructions(panda, [encoding, encoding2], 1, verbose = True)
            self.assertEqual(len(data.registerStateLists), 2)
            # determine the first regStateList contains data for the first instruction and not the second
            states = data.registerStateLists[0]
            self.assertIsInstance(states, RegisterStateList)
            self.assertEqual(len(states.beforeStates), 1 * 24 + 1)
            self.assertEqual(len(states.afterStates), 1 * 24 + 1)
            for i in range(len(states.beforeStates)):
                self.assertNotEqual(states.beforeStates[i].get("T0"), 0)
                self.assertEqual(states.afterStates[i].get("T5"), states.beforeStates[i].get("T5"))
                self.assertEqual(states.afterStates[i].get("T0"), 0)
            
            # determine the second regStateList contains data for the second instruction and not the first
            states = data.registerStateLists[1]
            self.assertIsInstance(states, RegisterStateList)
            self.assertEqual(len(states.beforeStates), 1 * 24 + 1)
            self.assertEqual(len(states.afterStates), 1 * 24 + 1)
            for i in range(len(states.beforeStates)):
                self.assertNotEqual(states.beforeStates[i].get("T5"), 0)
                self.assertEqual(states.beforeStates[i].get("T0"), states.afterStates[i].get("T0"))
                self.assertEqual(states.afterStates[i].get("T5"), 0)

            self.assertNotEqual(model[0], model[1], "model 0 and model 1 are identical")

    # def testRunX86InstructionOnce(self):
    #     panda = initializePanda("x86_64")
    #     instruction = "AND RAX, 0"
    #     print(instruction)
    #     CODE = instruction.encode('UTF-8')
    #     ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     print(encoding)
    #     data: StateData = None
    #     data, model = runInstruction.runInstructions(panda, [encoding], 1, verbose = True)
    #     self.assertEqual(len(data.registerStateLists), 1)
    #     regStateList = data.registerStateLists[0]
    #     self.assertIsInstance(regStateList, RegisterStateList)
    #     self.assertEqual(len(regStateList.beforeStates), 1 * 14 + 1)
    #     self.assertEqual(len(regStateList.afterStates), 1 * 14 + 1)
    #     print(regStateList.beforeStates[0])
    #     self.assertNotEqual(regStateList.beforeStates[0].get("RAX"), 0)
    #     self.assertEqual(regStateList.afterStates[0].get("RAX"), 0)


    # def testRunInstructionsMips(self):
    #     panda = initializePanda("mips")
    #     print("num_regs: " + str(len(panda.arch.registers)))
    #     instructions = []
    #     instGen = instructionGenerator.initialize("mips32")
    #     inst = 3
    #     n = 1
    #     md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN) # misp32
    #     for i in range(inst):
    #         instruction = instructionGenerator.generateInstruction(instGen, mipsFilter)
    #         instructions.append(instruction)
    #         for insn in md.disasm(instruction, 0x1000):
    #             print("%s\t%s" %(insn.mnemonic, insn.op_str))

    #     data: StateData = None
    #     data, model = runInstruction.runInstructions(panda, instructions, n, verbose=True)
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

    #     saveStateData(data, "intermediate")

    # def testRunInstructionsX86(self):
    #     panda = initializePanda("x86_64")
    #     instructions = []
    #     instGen = instructionGenerator.initialize("x86_64")
    #     inst = 1
    #     n = 100
    #     md = Cs(CS_ARCH_X86, CS_MODE_64)
    #     for i in range(inst):
    #         instruction = instructionGenerator.generateInstruction(instGen, x86Filter)
    #         instructions.append(instruction)
    #         for insn in md.disasm(instruction, 0x1000):
    #             print("%s\t%s" %(insn.mnemonic, insn.op_str))

    #     data: StateData = None
    #     data, model = runInstruction.runInstructions(panda, instructions, n, verbose=True)
    #     self.assertEqual(len(data.registerStateLists), inst)
    #     for regStateList in data.registerStateLists:
    #         self.assertEqual(len(regStateList.bitmasks), n*14 + 1)
    #         self.assertEqual(len(regStateList.afterStates), n*14 + 1)
    #         self.assertEqual(len(regStateList.beforeStates), n*14 + 1)
    #         self.assertEqual(regStateList.bitmasks[0], b'\x00\x00')
    #         for i in range(len(regStateList.bitmasks)):
    #             self.assertIsInstance(regStateList.bitmasks[i], bytes)
    #             self.assertIsInstance(regStateList.beforeStates[i], dict)
    #             self.assertIsInstance(regStateList.afterStates[i], dict)
    #             self.assertTrue(isPowerOfTwo(int.from_bytes(regStateList.bitmasks[i], 'big', signed=False)))

    # def testRunInstructionsMemoryMips(self):
    #     panda = initializePanda("mips")
    #     instruction = "lw $t2, 0($t4)"
    #     instruction2 = "sw $t2, 0($t4)"
    #     CODE = instruction.encode('UTF-8')
    #     CODE2 = instruction2.encode('UTF-8')
    #     ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    #     ADDRESS = 0x0000
    #     encoding, count = ks.asm(CODE, ADDRESS)
    #     encoding2, count = ks.asm(CODE2, ADDRESS)
    #     instructions = [encoding, encoding2]
    #     inst = 2
    #     n = 5


    #     data, model = runInstruction.runInstructions(panda, instructions, n, True)
    #     self.assertIsInstance(data, StateData)
    #     self.assertEqual(len(data.instructions), inst)
    #     self.assertEqual(len(data.registerStateLists), inst)
    #     lwStates = data.registerStateLists[0]
    #     swStates = data.registerStateLists[1]
    #     self.assertEqual(len(lwStates.memoryReads), n*24 + 1)
    #     self.assertEqual(len(swStates.memoryWrites), n*24 + 1)
    #     for read in lwStates.memoryReads[0]:
    #         self.assertIsInstance(read, MemoryTransaction)
    #     for write in lwStates.memoryWrites[0]:
    #         self.assertIsInstance(write, MemoryTransaction)




if __name__ == '__main__':
    unittest.main()
