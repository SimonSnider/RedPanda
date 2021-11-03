from modules.getCorrelations.correlationCalculator import *

def test_noCorrelations():
    """
    Test that if the output registers are always the same as the input registers, then the only correlations are between each register and itself. This is tested with 3 registers.
    """
    dataList = [[{
        "r1": 1,
        "r2": 2,
        "r3": 3 
    },{
        "r1": 1,
        "r2": 2,
        "r3": 3 
    }, b'\x00\x00\x00'],[{
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    }, b'\x01\x00\x00'],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    }, b'\x00\x01\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    }, b'\x00\x00\x01']]
    setArch("test", 3)
    dataListUp = [[item[2], item[0], item[1]] for item in dataList]
    initialize(dataListUp, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[1,0,0], [0,1,0], [0,0,1]]

def test_allCorrelated():
    """
    Test that it is possible for every register to be correlated with every other register. This is done by setting all output registers to the minimum of the input registers. This test is done with 3 registers.
    """

    RNaught = {
        "r1": 1,
        "r2": 2,
        "r3": 3 
    }

    RNaughtFinal = {
        "r1": 1,
        "r2": 1,
        "r3": 1
    }

    dataList = [[RNaught, RNaughtFinal,b'\x00\x00\x00'],[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    }, b'\x01\x00\x00'],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    }, b'\x00\x01\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    }, b'\x00\x00\x01']]
    setArch("test", 3)
    dataListUp = [[item[2], item[0], item[1]] for item in dataList]
    initialize(dataListUp, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[1,1,1], [1,1,1], [1,1,1]]

def test_addCorrelated():
    """
    Test for realistic correlations for an add instruction where every register is part of the instruction. The output registers are given by: r1 = r2 + r3. This test is done with 3 registers.
    """
    RNaught = {
        "r1": 1,
        "r2": 2,
        "r3": 3 
    }

    RNaughtFinal = {
        "r1": 5,
        "r2": 2,
        "r3": 3
    }

    dataList = [[RNaught, RNaughtFinal,b'\x00\x00\x00'],[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 5,
        "r2": 2,
        "r3": 3 
    }, b'\x01\x00\x00'],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 3,
        "r2": 0,
        "r3": 3 
    }, b'\x00\x01\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 2,
        "r2": 2,
        "r3": 0 
    }, b'\x00\x00\x01']]
    setArch("test", 3)
    dataListUp = [[item[2], item[0], item[1]] for item in dataList]
    initialize(dataListUp, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[0,0,0], [1,1,0], [1,0,1]]

def test_addCorrelatedWithExtra():
    """
    Test for realistic correlations for an add instruction where not every register is part of the instruction. The output registers are given by: r1 = r2 + r3. This test is done with 5 registers.
    """
    RNaught = {
        "r1": 1,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 5
    }

    RNaughtFinal = {
        "r1": 5,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 5
    }

    dataList = [[RNaught, RNaughtFinal,b'\x00\x00\x00\x00\x00'],[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 5 
    },
    {
        "r1": 5,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 5 
    },b'\x01\x00\x00\x00\x00'],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3,
        "r4": 4,
        "r5": 5 
    },
    {
        "r1": 3,
        "r2": 0,
        "r3": 3,
        "r4": 4,
        "r5": 5 
    }, b'\x00\x01\x00\x00\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0,
        "r4": 4,
        "r5": 5 
    },
    {
        "r1": 2,
        "r2": 2,
        "r3": 0,
        "r4": 4,
        "r5": 5 
    },b'\x00\x00\x01\x00\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 3,
        "r4": 0,
        "r5": 5 
    },
    {
        "r1": 5,
        "r2": 2,
        "r3": 3,
        "r4": 0,
        "r5": 5 
    },b'\x00\x00\x00\x01\x00'],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 0 
    },
    {
        "r1": 5,
        "r2": 2,
        "r3": 3,
        "r4": 4,
        "r5": 0 
    }, b'\x00\x00\x00\x00\x01']]
    setArch("test", 5)
    dataListUp = [[item[2], item[0], item[1]] for item in dataList]
    initialize(dataListUp, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[0,0,0,0,0], [1,1,0,0,0], [1,0,1,0,0],[0,0,0,1,0],[0,0,0,0,1]]
    
#test_noCorrelations()
#test_allCorrelated()
#test_addCorrelated()
#test_addCorrelatedWithExtra()
