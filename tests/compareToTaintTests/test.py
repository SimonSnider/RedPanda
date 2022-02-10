from capstone import *
from panda_red.compare_to_taint.correlationProcessor import *
from panda_red.run_instruction.stateManager import *
from keystone import *
from panda_red.generate_instruction import instructionGenerator
import math
from panda_red.models.stateData import *

panda = initializePanda()

def testModelCollection():
    instruction = "add $t1, $t2, $t3"
    # instruction2 = "sw $t2, 0($t4)"
    CODE = instruction.encode('UTF-8')
    # CODE2 = instruction2.encode('UTF-8')
    ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    # encoding2, count = ks.asm(CODE2, ADDRESS)
    # instructions = [encoding, encoding2]
    instructions = [encoding]
    n = 5

    pandaModel = runInstructions(panda, instructions, n, True)
    print(pandaModel)

testModelCollection()