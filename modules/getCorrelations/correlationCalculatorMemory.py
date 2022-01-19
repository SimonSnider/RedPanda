from modules.models.stateData import *

n = 24 #number of registers about which we care
iterPerRegister = 100
I = n*iterPerRegister
RegisterInitial = -1  #R_0
RegisterInitialOutput = -1 #R_0,f
RegisterInitials = -1 #R_i,0
RegisterFinals = -1   #R_i,f
Bs = -1 #B_i
Ps = -1

memReads = []
memWrites = []
memReadsInitial = []
memWritesInitial = []
readsPs = -1
writePs = -1
writeValPs = -1

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
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs, writeValPs, memWriteVals, memWriteValsInitial
    iterPerRegister = iterPerReg
    I = n*iterPerRegister
    # I = len(data.bitmasks)-1

    RegisterInitial = data.beforeStates[0]
    RegisterInitialOutput = data.afterStates[0]
    RegisterInitials = data.beforeStates[1:]
    RegisterFinals = data.afterStates[1:]
    Bs = data.bitmasks[1:]
    Ps = [0]*I
    readPs = [0]*I
    writePs = [0]*I
    writeValPs = [0]*I

    regList = list(RegisterInitials[0])

#####################################
# TEMP HACK TO FIX DATATYPE CHANGES #
#####################################

    memReads = []
    memWrites = []
    memWriteVals = []

    for currentMemoryIteration in data.memoryReads:
        tempList = []
        for currentMemoryTransaction in currentMemoryIteration:
            tempList.append(currentMemoryTransaction.address)
        memReads.append(tempList)
       
    for currentMemoryIteration in data.memoryWrites:
        tempList = []
        tempValList = []
        for currentMemoryTransaction in currentMemoryIteration:
            tempList.append(currentMemoryTransaction.address)
            tempValList.append(currentMemoryTransaction.value)
        memWrites.append(tempList)
        memWriteVals.append(tempValList)
       
    memReadsInitial = []
    memWritesInitial = []
    memWriteValsInitial = []

    if(len(memReads) > 0): memReadsInitial = memReads[0]
    if(len(memWrites) > 0): memWritesInitial = memWrites[0]
    if(len(memWriteVals) > 0): memWriteValsInitial = memWriteVals[0]
    if(len(memReads) > 1): memReads = memReads[1:]
    if(len(memWrites) > 1): memWrites = memWrites[1:]
    if(len(memWriteVals) > 1): memWriteVals = memWriteVals[1:]

#################
# END TEMP HACK #
#################

    maxLengthReads = 0
    # replace with math.max function python equivalent
    for ls in memReads:
        if len(ls) > maxLengthReads:
            maxLengthReads = len(ls)
    maxLengthWrites = 0
    for ls in memWrites:
        if len(ls) > maxLengthWrites:
            maxLengthWrites = len(ls)

    lengthen(memReadsInitial, maxLengthReads)
    lengthen(memWritesInitial, maxLengthWrites)
    lengthen(memWriteValsInitial, maxLengthWrites)
    for ls in memReads:
        lengthen(ls, maxLengthReads)
    for ls in memWrites:
        lengthen(ls, maxLengthWrites)
    for ls in memWriteVals:
        lengthen(ls, maxLengthWrites)


def lengthen(ls, length):
    remaining = length - len(ls)
    while remaining > 0:
        ls.append(-1)
        remaining -= 1


def computePs():
    """Calculates the value for each P_i. Must call initialize before this.
    """
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs, memWriteValsInitial, memWriteVals, writeValPs
    for iter in range(I):
        newDict = {}
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for reg in Ri0.keys():
            if RegisterInitialOutput.get(reg) != Rif.get(reg):
                newDict[reg] = 1
            else:
                newDict[reg] = 0
        Ps[iter] = newDict

        newList = [0]*len(memReadsInitial)
        for i in range(len(memReadsInitial)):
            if memReadsInitial[i] != memReads[iter][i]:
                newList[i] = 1
            else:
                newList[i] = 0
        
        readPs[iter] = newList

        newList2 = [0]*len(memWritesInitial)
        for i in range(len(memWritesInitial)):
            if memWritesInitial[i] != memWrites[iter][i]:
                newList2[i] = 1
            else:
                newList2[i] = 0
                
        writePs[iter] = newList2

        newList3 = [0]*len(memWriteValsInitial)
        for i in range(len(memWritesInitial)):
            if memWriteValsInitial[i] != memWriteVals[iter][i]:
                newList3[i] = 1
            else:
                newList3[i] = 0
        writeValPs[iter] = newList3

def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.
    Return Value:
    M -- n x m list where M[i][j] is the correlation of register i on register/memory access j
    """
    computePs()
    global iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs, n, writeValPs
    M = [[0]*(n + len(memReadsInitial) + 2*len(memWritesInitial)) for _ in range(n)]
    
    for i in range(n):
        for j in range(n):
            denom = 0
            num = 0
            for k in range(I):
                if int.from_bytes(Bs[k], 'big') & (1 << (8*(n-i-1))) == 0:
                    bitMaskV = 0
                else:
                    bitMaskV = 1
                denom += bitMaskV
                num += bitMaskV*Ps[k].get(regList[j])
            if num == 0 and denom == 0:
                M[i][j] = 0
                if i == j:
                    M[i][j] = {regList[j]: "reflexive"}
            else:
                M[i][j] = {regList[j]: num/denom}
        for j in range(len(memReadsInitial)):
            denom = 0
            num = 0
            for k in range(I):
                if int.from_bytes(Bs[k], 'big') & (1 << (8*(n-i-1))) == 0:
                    bitMaskV = 0
                else:
                    bitMaskV = 1
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
                if int.from_bytes(Bs[k], 'big') & (1 << (8*(n-i-1))) == 0:
                    bitMaskV = 0
                else:
                    bitMaskV = 1
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
