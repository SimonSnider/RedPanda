"""
This file takes in data describing register values, memory values, and memory locations of 
reads and writes before and after each instruction is run. It outputs which values are most
likely to be related given a particular threshold. For more details, see our mathematical model.
"""

from panda_red.models.stateData import *
from panda_red.models.correlations import *

n = 24 #number of registers about which we care
iterPerRegister = 100 # iterations run per set of registers randomized
I = n*iterPerRegister # total number of iterations run
Bs = -1 #B_i
thresh = 0.5 # minimum correlation coefficient required for two elements to be considered correlated
# later, users will have the option to compute the threshold given a p-value

regs = IntermediateData()
memReadVals = IntermediateData()
memReadAddrs = IntermediateData()
memWriteVals = IntermediateData()
memWriteAddrs = IntermediateData()

# regList is overwritten; its value is left in for reference by developers
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
    elif archType.lower() == 'x86':
        n = 16

def initialize(data: RegisterStateList, iterPerReg: int = 100, threshold: float = 0.5):

    """ Initializes the correlation calculator with the data from running an instruction multiple times

    Arguments:
    dataList -- the RegisterStates from the run instruction module.
    iterPerReg -- number of times each combination of changed registers is ran (default = 100)
    threshold -- the minimum computed correlation coefficient for two elements (registers, memory location, memory value) to be considered correlated

    """
    global iterPerRegister, Bs, n, I, regList, regs, memReadVals, memReadAddrs, memWriteVals, memWriteAddrs, thresh

    thresh = threshold
    
    iterPerRegister = iterPerReg
    I = len(data.bitmasks)-1

    regs.initialInput = data.beforeStates[0]
    regs.initialOutput = data.afterStates[0]
    regs.inputs = data.beforeStates[1:]
    regs.outputs = data.afterStates[1:]
    Bs = data.bitmasks[1:]
    regs.ps = [0]*I
    memReadVals.ps = [0]*I
    memReadAddrs.ps = [0]*I
    memWriteAddrs.ps = [0]*I
    memWriteVals.ps = [0]*I

    regList = list(regs.inputs[0])
    n = len(regList)
    memReads0 = []
    memReadVals0 = []
    memWrites0 = []
    memWriteVals0 = []

    for currentMemoryIteration in data.memoryReads:
        tempList = []
        tempValList = []
        for currentMemoryTransaction in currentMemoryIteration:
            tempList.append(currentMemoryTransaction.address)
            tempValList.append(currentMemoryTransaction.value)
        memReads0.append(tempList)
        memReadVals0.append(tempValList)
       
    for currentMemoryIteration in data.memoryWrites:
        tempList = []
        tempValList = []
        for currentMemoryTransaction in currentMemoryIteration:
            tempList.append(currentMemoryTransaction.address)
            tempValList.append(currentMemoryTransaction.value)
        memWrites0.append(tempList)
        memWriteVals0.append(tempValList)

    if(len(memReads0) == 0): memReads0 = [[]]
    if(len(memWrites0) == 0): memWrites0 = [[]]
    if(len(memWriteVals0) == 0): memWriteVals0 = [[]]
    if(len(memReadVals0) == 0): memReadVals0 = [[]]
    
    memReadAddrs.initialOutput = memReads0[0]
    memReadVals.initialInput = memReadVals0[0]
    memWriteAddrs.initialOutput = memWrites0[0]
    memWriteVals.initialOutput = memWriteVals0[0]
    memReadAddrs.outputs = memReads0[1:]
    memReadVals.inputs = memReadVals0[1:]
    memWriteAddrs.outputs = memWrites0[1:]
    memWriteVals.outputs = memWriteVals0[1:]

    maxLengthReads = len(memReadAddrs.initialOutput)
    # replace with math.max function python equivalent
    for ls in memReadAddrs.outputs:
        if len(ls) > maxLengthReads:
            maxLengthReads = len(ls)
    maxLengthWrites = len(memWriteAddrs.initialOutput)
    for ls in memWriteAddrs.outputs:
        if len(ls) > maxLengthWrites:
            maxLengthWrites = len(ls)

    lengthen(memReadAddrs.initialOutput, maxLengthReads)
    lengthen(memReadVals.initialInput, maxLengthReads)
    lengthen(memWriteAddrs.initialOutput, maxLengthWrites)
    lengthen(memWriteVals.initialOutput, maxLengthWrites)
    for ls in memReadAddrs.outputs:
        lengthen(ls, maxLengthReads)
    for ls in memWriteAddrs.outputs:
        lengthen(ls, maxLengthWrites)
    for ls in memWriteVals.outputs:
        lengthen(ls, maxLengthWrites)
    for ls in memReadVals.inputs:
        lengthen(ls, maxLengthReads)

def lengthen(ls, length):
    """
    ls -- a list with at most length elements
    length -- an integer

    The function adds -1's to ls until it has length elements. This lengthening
    allows us to assume that lists describing reads or writes have the same length.
    """
    remaining = length - len(ls)
    while remaining > 0:
        ls.append(-1)
        remaining -= 1

def calcAreValuesUnequal(v1, v2):
    """
    v1, v2 -- integer representations of values in memory

    The function outputs 1 if the values differ and 0 otherwise. 
    """
    if(v1 != v2):
        return 1
    return 0
        
def getBitVals(bitmask, bitVal):
    """
    bitmask -- a string of bits with one bit for each register that describes which
        registers were randomized in a particular iteration of a particular instruction
    bitval -- an index describing the location of the bit describing the register in question

    The function outputs the value of the bit in the bitmask that corresponds to bitVal
    """
    if(int.from_bytes(bitmask, 'big') & (1 << bitVal) == 0):
        return 0
    return 1

def computeMemPs(listLength, initialList, newLists, ps):
    """
    listLength -- the maximal length of any list of read (or write) descriptions
        In MIPS, this value will always be one or zero.
    initialList -- initial values of reads (or writes) of an instruction before a small
        subset of registers is randomized.
    newLists -- lists of values of reads (or writes) of after execution of an instruction
        for which a small subset of registers is randomized
    ps -- A list for output

    This function computes the portion of our p-vector in our math model that deals with memory.
    For more details, see our mathematical model.
    """
    global I
    for iter in range(I):
        newList = [0]*listLength
        for i in range(listLength):
            newList[i] = calcAreValuesUnequal(initialList[i], newLists[iter][i])
        ps[iter] = newList

def computeRegToRegCorrelations():
    """
    This function computes the correlations between the values of registers before
    instructions are executed to their values after execution utilizing a
    predetermined scheme of randomizing in which, currently, one register is 
    randomized per iteration.
    For more details, see our mathematical model.
    """
    global iterPerRegister, Bs, n, regList, I, regs
    for iter in range(I):
        newDict = {}
        Ri0 = regs.inputs[iter]
        Rif = regs.outputs[iter]
        for reg in Ri0.keys():
            newDict[reg] = calcAreValuesUnequal(regs.initialOutput.get(reg), Rif.get(reg))
        regs.ps[iter] = newDict
        
    m = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 1*(i))
                denom += bitMaskV
                num += bitMaskV*regs.ps[k].get(regList[j])
            if num == 0 and denom == 0:
                m[i][j] = 0
                if i == j:
                    m[i][j] = 1
            else:
                m[i][j] = num/denom
    
    return m
    
def computeRegToReadAddrCorrelations():
    """
    This function is another component of our math model. It analyzes how values in registers
    are correlated with the addresses from which values are read.
    """
    global memReadAddrs, n, I, Bs
    computeMemPs(len(memReadAddrs.initialOutput), memReadAddrs.initialOutput, memReadAddrs.outputs, memReadAddrs.ps)
    
    m = [[0]*len(memReadAddrs.initialOutput) for _ in range(n)]
    for i in range(n):
        for j in range(len(memReadAddrs.initialOutput)):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 1*(i))
                denom += bitMaskV
                num += bitMaskV*memReadAddrs.ps[k][j]
            if num == 0 and denom == 0:
                m[i][j] = 0
            else:
                m[i][j] = num/denom
    
    return m
    
def computeRegToWriteAddrCorrelations():
    """
    This function is a component of our math model. It analyzes how values in registers
    are correlated with the addresses into which values are written
    """
    global memWriteAddrs, n, I, Bs
    computeMemPs(len(memWriteAddrs.initialOutput), memWriteAddrs.initialOutput, memWriteAddrs.outputs, memWriteAddrs.ps)
    
    m = [[0]*len(memWriteAddrs.initialOutput) for _ in range(n)]
    for i in range(n):
        for j in range(len(memWriteAddrs.initialOutput)):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 1*(i))
                denom += bitMaskV
                num += bitMaskV*memWriteAddrs.ps[k][j]
            if num == 0 and denom == 0:
                m[i][j] = 0
            else:
                m[i][j] = num/denom
    
    return m
    
def computeRegToReadValCorrelations():
    """
    This function is a component of our math model. It analyzes how values in regsiters
    are correlated with the values read out of memory.
    """
    global memReadVals, n, I, Bs
    computeMemPs(len(memReadVals.initialInput), memReadVals.initialInput, memReadVals.inputs, memReadVals.ps)
    
    m = [[0]*len(memReadVals.initialInput) for _ in range(n)]
    for i in range(n):
        for j in range(len(memReadVals.initialInput)):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 1*(i))
                denom += bitMaskV
                num += bitMaskV*memReadVals.ps[k][j]
            if num == 0 and denom == 0:
                m[i][j] = 0
            else:
                m[i][j] = num/denom
    
    return m
    
def computeRegToWriteValCorrelations():
    """
    This function is a component of our math model. It analyzes how values in registers
    are correlated with the values written into memory.
    """
    global memWriteVals, n, I, Bs
    computeMemPs(len(memWriteVals.initialOutput), memWriteVals.initialOutput, memWriteVals.outputs, memWriteVals.ps)
    
    m = [[0]*len(memWriteVals.initialOutput) for _ in range(n)]
    for i in range(n):
        for j in range(len(memWriteVals.initialOutput)):
            denom = 0
            num = 0
            for k in range(I):
                bitMaskV = getBitVals(Bs[k], 1*(i))
                denom += bitMaskV
                num += bitMaskV*memWriteVals.ps[k][j]
            if num == 0 and denom == 0:
                m[i][j] = 0
            else:
                m[i][j] = num/denom
    
    return m

        
def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.
    Return Value:
    M -- n x m list where M[i][j] represents the correlation of register i on register/memory access j
    """
    global iterPerRegister, Bs, n, I, regList, regs, memReadVals, memReadAddrs, memWriteVals, memWriteAddrs, thresh
    M = Correlations()
    
    M.regToReg = computeRegToRegCorrelations()
    M.regToReadAddress = computeRegToReadAddrCorrelations()
    M.regToWriteAddress = computeRegToWriteAddrCorrelations()
    M.regToWriteData = computeRegToWriteValCorrelations()
    M.readDataToReg = computeRegToReadValCorrelations()
    M.threshold = thresh
    return M
