from panda_red.models.correlations import *
from panda_red.compare_to_taint.taintComparer import *
from capstone import *
from panda_red.compare_to_taint.correlationProcessor import *
from panda_red.run_instruction.stateManager import *
from keystone import *
from panda_red.generate_instruction import instructionGenerator
import math
from panda_red.models.stateData import *

def test1():
    """
    This test simulates the comparison of two models which each correctly propagate taints for the instruction:
        r0 = r1 + r2
    """
    pandaModel = {}
    pandaModel[("r0", 0)] = [1, 2]
    pandaModel[("r1", 1)] = []
    pandaModel[("r2", 2)] = []

    corr = Correlations()
    corr.regToReg = [[0, 1, 1], [0, 0, 0], [0, 0, 0]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    # assert compare(pandaModel, corr) == [{}, {}]


def test2():
    """
    This test simulates the comparison of two models, one of which correctly propagates taints and one of which,
    PANDA's, incorrectly concludes that r2 is not correlated with r0 in the execution of:
        r0 = r1 + r2
    """
    pandaModel = {}
    pandaModel[("r0", 0)] = [1]
    pandaModel[("r1", 1)] = []
    pandaModel[("r2", 2)] = []

    corr = Correlations()
    corr.regToReg = [[0, 1, 1], [0, 0, 0], [0, 0, 0]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    assert compare(pandaModel, corr) == [{}, {0: [2]}]


def test3():
    """
    In this test, the PANDA model is correct and the new model is incorrect in tracking the taint flow through:
        r0 = r1 + r2
    """
    pandaModel = {}
    pandaModel[("r0", 0)] = [1, 2]
    pandaModel[("r1", 1)] = []
    pandaModel[("r2", 2)] = []

    corr = Correlations()
    corr.regToReg = [[0, 1, 0], [0, 0, 0], [0, 0, 0]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5
    assert compare(pandaModel, corr) == [{("r0", 0): [2]}, {}]



panda = initializePanda()

def testModelCollection():
    instruction = "add $t1, $t2, $zero"
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
