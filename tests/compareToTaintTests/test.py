from panda_red.models.correlations import *
from panda_red.compare_to_taint.taintComparer import *


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
