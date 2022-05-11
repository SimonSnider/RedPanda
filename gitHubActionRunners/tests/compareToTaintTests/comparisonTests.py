from red_panda.models.correlations import *
from red_panda.compare_to_taint.taintComparer import *
from capstone import *
from red_panda.run_instruction.runInstruction import *
from red_panda.run_instruction.stateManager import *
from keystone.keystone import *
from red_panda.generate_instruction import instructionGenerator
import math
from red_panda.models.stateData import *
from red_panda.run_instruction.stateManager import *
from red_panda.get_correlations import correlationCalculatorMemory as calc

def instructionNoMemIdentical():
    """
    This test simulates the comparison of two models which each correctly propagate taints for the instruction:
        r0 = r1 + r2
    """

    pandaModel = [[],[],[]]
    pandaModel[0] = [0, 1, 1]
    pandaModel[1] = [0, 1, 0]
    pandaModel[2] = [0, 0, 1]
    regToWrite = {}
    pandaModel = [pandaModel, regToWrite]

    
    corr = Correlations()
    corr.regToReg = [[0, 1, 1], [0, 1, 0], [0, 0, 1]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    
    assert compare(pandaModel, corr) == [{'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}, {'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}]


def instructionNoMemPandaWrong():
    """
    This test simulates the comparison of two models, one of which correctly propagates taints and one of which,
    PANDA's, incorrectly concludes that r2 is not correlated with r0 in the execution of:
        r0 = r1 + r2
    """

    pandaModel = [[],[],[]]
    pandaModel[0] = [0, 1, 0]
    pandaModel[1] = [0, 1, 0]
    pandaModel[2] = [0, 0, 1]
    regToWrite = {}
    pandaModel = [pandaModel, regToWrite]


    corr = Correlations()
    corr.regToReg = [[0, 1, 1], [0, 1, 0], [0, 0, 1]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    assert(compare(pandaModel, corr) == [{'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}, {'reg to reg': {0:[2]}, 'reads to reg': {}, 'reg to writes': {}}])


def instructionNoMemNewWrong():
    """
    In this test, the PANDA model is correct and the new model is incorrect in tracking the taint flow through:
        r0 = r1 + r2
    """
    pandaModel = [[],[],[]]
    pandaModel[0] = [0, 1, 1]
    pandaModel[1] = [0, 1, 0]
    pandaModel[2] = [0, 0, 1]
    regToWrite = {}
    pandaModel = [pandaModel, regToWrite]


    corr = Correlations()
    corr.regToReg = [[0, 1, 0], [0, 1, 0], [0, 0, 1]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    assert(compare(pandaModel, corr) == [{'reg to reg': {0:[2]}, 'reads to reg': {}, 'reg to writes': {}}, {'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}])



def testModelCollection():
    panda = initializePanda()

    instruction = "add $t1, $t2, $zero"
    CODE = instruction.encode('UTF-8')
    ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

    ADDRESS = 0x0000
    encoding, count = ks.asm(CODE, ADDRESS)
    instruction = [encoding]
    n = 5
    [ourModel, pandaModel, registerNames] = runInstructions(panda, instruction, n, True)
    calc.setArch("mips")

    states = RegisterStateList()
    first = ourModel.registerStateLists[0]
    last = ourModel.registerStateLists[-1]
    states.bitmasks = first.bitmasks
    states.beforeStates = first.beforeStates
    states.afterStates = last.afterStates
    states.memoryReads = last.memoryReads
    states.memoryWrites = last.memoryWrites
    calc.initialize(states, len(panda.arch.registers))
    corr = calc.computeCorrelations()
    output = compare(pandaModel[0], corr)

    assert output == [{'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}, {'reg to reg': {}, 'reads to reg': {}, 'reg to writes': {}}]
    

#testModelCollection()
