from modules.getCorrelations.correlationCalculator import *

def test_noCorrelations():
    RNaught = {
        "r1": 1,
        "r2": 2,
        "r3": 3 
    }

    dataList = [[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 1,
        "r2": 0,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 1,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 1 
    }]]
    setArch("test", 3)
    initialize(dataList, RNaught, RNaught, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[1,0,0], [0,1,0], [0,0,1]]

def test_allCorrelated():
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

    dataList = [[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    },
    {
        "r1": 1,
        "r2": 0,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 1,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 1 
    }]]
    setArch("test", 3)
    initialize(dataList, RNaught, RNaughtFinal, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[1,1,1], [1,1,1], [1,1,1]]

def test_addCorrelated():
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

    dataList = [[
    {
        "r1": 0,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 5,
        "r2": 2,
        "r3": 3 
    },
    {
        "r1": 1,
        "r2": 0,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 3,
        "r2": 0,
        "r3": 3 
    },
    {
        "r1": 0,
        "r2": 1,
        "r3": 0 
    }],[
    {
        "r1": 1,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 2,
        "r2": 2,
        "r3": 0 
    },
    {
        "r1": 0,
        "r2": 0,
        "r3": 1 
    }]]
    setArch("test", 3)
    initialize(dataList, RNaught, RNaughtFinal, 1)
    M = computeCorrelations()

    #print(M)
    assert M == [[0,0,0], [1,1,0], [1,0,1]]
    
#test_noCorrelations()
#test_allCorrelated()
#test_addCorrelated()
