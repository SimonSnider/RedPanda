from modules.models.stateData import *
from modules.models.correlations import *

n = 24 #number of registers about which we care
iterPerRegister = 100
I = n*iterPerRegister
Bs = -1 #B_i

regs = IntermediateData()
memReadVals = IntermediateData()
memReadAddr = IntermediateData()
memWriteVals = IntermediateData()
memWriteAddr = IntermediateData()

regList = ["ZERO", "AT", "V0", "V1", "A0", "A1", "A2", "A3", "T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "T8", "T9", "K0", "K1", "GP", "SP", "FP", "RA"]

def setArch(archType, testV=0):
    """ Intializes an architecture in order to set the number of registers
    
    Arguments:
    archType -- specifies the architecture to use
    testV -- the number of registers to calculate the correlations between (default = 0), only used if archType = test

    Valid Arguments:
    archType -- mips32 , test
    
    """

    global n
    if archType.lower() == "mips32":
        n = 32
    elif archType.lower() == "test":
        n = testV

def initialize(data: RegisterStates, iterPerReg: int = 100):
    """ Initializes the correlation calculator with the data from running an instruction multiple times

    Arguments:
    dataList -- the RegisterStates from the run instruction module. ]
    iterPerReg -- number of times each combination of changed registers is ran (default = 100)

    """
    global iterPerRegister, Bs, n, I, regList, regs, memReadVals, memReadAddr, memWriteVals, memWriteAddr
    
    iterPerRegister = iterPerReg
    I = len(data.bitmasks)-1

    regs.initialInput = data.beforeStates[0]
    regs.initialOutput = data.afterStates[0]
    regs.inputs = data.beforeStates[1:]
    regs.outputs = data.afterStates[1:]
    Bs = data.bitmasks[1:]
    regs.ps = [0]*I
    
    memReadVals.ps = [0]*I
    memReadAddr.ps = [0]*I
    memWriteAddr.ps = [0]*I
    memWriteVals.ps = [0]*I

    regList = list(regs.inputs[0])

    memReadsAddr.initialOutput = data.memoryReads[0]
    memReadVals.initialInput = data.memoryReadVales[0]
    memWritesAddr.initialOutput = data.memoryWrites[0]
    memWriteVals.initialOutput = data.memoryWriteValues[0]
    memReadsAddr.outputs = data.memoryReads[1:]
    memReadVals.inputs = data.memoryReadValues[1:]
    memWritesAddr.outputs = data.memoryWrites[1:]
    memWriteVals.outputs = data.memoryWriteValues[1:]

    maxLengthReads = 0
    # replace with math.max function python equivalent
    for ls in memReadsAddr.outputs:
        if len(ls) > maxLengthReads:
            maxLengthReads = len(ls)
    maxLengthWrites = 0
    for ls in memWritesAddr.outputs:
        if len(ls) > maxLengthWrites:
            maxLengthWrites = len(ls)

    lengthen(memReadsAddr.initialOutput, maxLengthReads)
    lengthen(memReadVals.initialInput, maxLengthReads)
    lengthen(memWritesAddr.initialOutput, maxLengthWrites)
    lengthen(memWriteVals.initialOutput, maxLengthWrites)
    for ls in memReadsAddr.outputs:
        lengthen(ls, maxLengthReads)
    for ls in memWritesAddr.outputs:
        lengthen(ls, maxLengthWrites)
    for ls in memWriteVals.outputs:
        lengthen(ls, maxLengthWrites)
    for ls in memReadVals.inputs:
        lengthen(ls, maxLengthReads)


def lengthen(ls, length):
    remaining = length - len(ls)
    while remaining > 0:
        ls.append(-1)
        remaining -= 1

def calcAreValuesUnequal(v1, v2):
    if(v1 != v2):
        return 1
    return 0
        
def computePs():
    """Calculates the value for each P_i. Must call initialize before this.
    """
    global iterPerRegister, Bs, n, I, regList, regs, memReadVals, memReadAddr, memWriteVals, memWriteAddr

    for iter in range(I):
        newDict = {}
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for reg in Ri0.keys():
            newDict[reg] = calcAreValuesUnequal(RegisterInitialOutput.get(reg),\                                                Rif.get(reg))
        Ps[iter] = newDict

        newList = [0]*len(memReadsInitial)
        for i in range(len(memReadsInitial)):
            newList[i] = calcAreValuesUnequal(memReadsInitial[i], \                                                           memReads[iter][i])
        readPs[iter] = newList

        newList2 = [0]*len(memWritesInitial)
        for i in range(len(memWritesInitial)):
            newList2[i] = calcAreValuesUnequal(memWritesInitial[i]\                                                            memWrites[iter][i])
        writePs[iter] = newList2

        newList3 = [0]*len(memWriteValsInitial)
        for i in range(len(memWritesInitial)):
            newList3[i] = calcAreValuesUnequal(memWriteValsInitial[i],\                                                        memWriteVals[iter][i])
        writeValPs[iter] = newList3
        newList4 = [0]*len(memReadValsInitial)
        for i in range(len(memReadValsInitial)):
            newList4[i] = calcAreValuesUnequal(memReadValsInitial[i],\                                                         memReadVals[iter][i])
        readValPs[iter] = newList4

def getBitVals(bitmask, bitVal):
    if(int.from_bytes(bitmask, 'big') & (1 << bitVal) == 0):
        return 0
    return 1
        
def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.
    Return Value:
    M -- n x m list where M[i][j] is the correlation of register i on register/memory access j
    """
    computePs()
    global iterPerRegister, Bs, n, I, regList, regs, memReadVals, memReadAddr, memWriteVals, memWriteAddr
    M = Correlations()
    
    #M = [[0]*(n + len(memReadsInitial) + 2*len(memWritesInitial)) for _ in range(n)]

    M.regToReg = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 8*(n-i-1))
                denom += bitMaskV
                num += bitMaskV*regs.ps[k].get(regList[j])
            if num == 0 and denom == 0:
                M.regToReg[i][j] = 0
                if i == j:
                    M.regToReg[i][j] = "reflexive"
            else:
                M.regToReg[i][j] = num/denom
                
        for j in range(len(memReadsInitial)):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 8*(n-i-1))
                denom += bitMaskV
                num += bitMaskV*readPs[k][j]
            if num == 0 and denom == 0:
                M[i][j+n] = {"memRAddr": 0}
            else:
                M[i][j+n] = {"memRAddr": num/denom}

        for j in range(len(memWritesInitial)):
            denom = 0
            num = 0
            valueNum = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 8*(n-i-1))
                denom += bitMaskV
                num += bitMaskV*writePs[k][j]
                valueNum += bitMaskV*writeValPs[k][j]
            if num == 0 and denom == 0:
                M[i][j+n+len(memReadsInitial)] = {"memWAddr": 0}
            else:
                M[i][j+n+len(memReadsInitial)] = num/denom
            if valueNum == 0 and denom == 0:
                M[i][j+n+len(memReadsInitial)+len(memWritesInitial)] = {"memWVal": 0}
            else:
                dictionary = {"memWVal": valueNum/denom}
                M[i][j+n+len(memReadsInitial)+len(memWritesInitial)] = dictionary
    for it in range(n):
        M[it] = {regList[it]: M[it]}

    return M
