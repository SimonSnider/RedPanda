from panda_red.compare_to_taint.taintComparer import *
from panda_red.compare_to_taint.correlationProcessor import *
from panda_red.models.correlations import *

def function(instruction, architecture, ourCorrelations: Correlations, panda: Panda):
    CODE = instruction.encode('UTF-8')
    arg1 = -1
    arg2 = -1
    if architecture == "mips":
        arg1 = KS_ARCH_MIPS
        arg2 = KS_ARCH_MIPS
    if architecture == "x86_64":
        #TODO: allow for x86 testing
        4

    ks = Ks(arg1, arg2)
    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    instructions = [encoding]
    n = 5
    pandaModel = runInstructions(panda, instructions, n, True)

    print(compare(pandaModel, correlations))
