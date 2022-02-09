from panda_red.models.correlations import *
from panda_red.compare_to_taint.taintComparer import *


def test1():
    """
    This test simulates the comparison of two models which each correctly propagate taints for the instruction:
        r1 = r2 + r3
    """
    pandaModel = {}
    pandaModel[("r1", 1)] = [2, 3]
    pandaModel[("r2", 2)] = []
    pandaModel[("r3", 3)] = []

    corr = Correlations()
    corr.regToReg = [[0, 1, 1], [0, 0, 0], [0, 0, 0]]
    corr.regToReadAddress = []
    corr.regToWriteAddress = []
    corr.regToWriteData = []
    corr.readDataToReg = []
    corr.threshold = 0.5

    print(compare(pandaModel, corr))


