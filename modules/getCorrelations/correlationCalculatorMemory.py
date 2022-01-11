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
readsPs = -1;
writePs = -1;

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
    if(archType.lower()=="mips32"):
        n = 32
    elif(archType.lower()=="test"):
        n = testV

def initialize(data: RegisterStates, iterPerReg: int = 100):
    """ Initializes the correlation calculator with the data from running an instruction multiple times

    Arguments:
    dataList -- the RegisterStates from the run instruction module. ]
    iterPerReg -- number of times each combination of changed registers is ran (default = 100)

    """
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs
    iterPerRegister = iterPerReg
#    I = n*iterPerRegister
    I = len(data.bitmasks)-1

    RegisterInitial = data.beforeStates[0]
    RegisterInitialOutput = data.afterStates[0]
    RegisterInitials = data.beforeStates[1:]
    RegisterFinals = data.afterStates[1:]
    Bs = data.bitmasks[1:]
    Ps = [0]*I
    readPs = [0]*I
    writePs = [0]*I

    regList = list(RegisterInitials[0])

    memReadsInitial = data.memoryReads[0]
    memWritesInitial = data.memoryWrites[0]
    memReads = data.memoryReads[1:]
    memWrites = data.memoryWrites[1:]

def computePs():
    """Calculates the value for each P_i. Must call initialize before this.
    """
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs
    for iter in range(I):
        newDict = {}
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for reg in Ri0.keys():
            if (RegisterInitialOutput.get(reg) != Rif.get(reg)):
                newDict[reg] = 1
            else:
                newDict[reg] = 0
        Ps[iter] = newDict

        newList = [0]*len(memReadsInitial)
        for i in range(len(memReadsInitial)):
            if(memReadsInitial[i] != memReads[iter][i]):
                newList[i] = 1
            else:
                newList[i] = 0
        
        readPs[iter] = newList

        newList2 = [0]*len(memWritesInitial)
        for i in range(len(memWritesInitial)):
            if(memWriteInitial[i] != memWrites[iter][i]):
                newList2[i] = 1
            else:
                newList2[i] = 0
                
        writePs[iter] = newList2

def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.
    Return Value:
    M -- n x m list where M[i][j] is the correlation of register i on register/memory access j
    """
    computePs()
    global iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, memReads, memWrites, memReadsInitial, memWritesInitial, readPs, writePs
    
    M = [[0]*(n + len(memReadsInitial) + len(memWritesInitial)) for _ in range(n)]
    
    for i in range(n):
        for j in range(n):
            denom = 0
            num = 0
            for k in range(I):
                if(int.from_bytes(Bs[k], 'big')&(1<<(n-i-1)) == 0):
                    bitMaskV = 0
                else:
                    bitMaskV = 1
                denom += bitMaskV
                num += bitMaskV*Ps[k].get(regList[j])
            if(num==0 and denom==0):
                M[i][j] = 0
                if(i==j):
                    M[i][j]=1
            else:
                M[i][j] = num/denom
        for j in range(len(memReadsInitial)):
            denom = 0
            num = 0
            for k in range(I):
                if(int.from_bytes(Bs[k], 'big')&(1<<(n-i-1)) == 0):
                    bitMaskV = 0
                else:
                    bitMaskV = 1
                denom += bitMaskV
                num += bitMaskV*readPs[j]
            if(num==0 and denom==0):
                M[i][j+n] = 0
            else:
                M[i][j+n] = num/denom
        for j in range(len(memWritesInitial)):
            denom = 0
            num = 0
            for k in range(I):
                if(int.from_bytes(Bs[k], 'big')&(1<<(n-i-1)) == 0):
                    bitMaskV = 0
                else:
                    bitMaskV = 1
                denom += bitMaskV
                num += bitMaskV*writePs[j]
            if(num==0 and denom==0):
                M[i][j+n+len(memReadsInitial)] = 0
            else:
                M[i][j+n+len(memReadsInitial)] = num/denom
                

    return M
