import pearson

n = 24 #number of registers about which we care
iterPerRegister = 100 #CHANGE THIS NUMBER. STAT MATH HERE
I = n*iterPerRegister
RegisterInitial = -1  #R_0
RegisterInitialOutput = -1 #R_0,f
RegisterInitials = -1 #R_i,0
RegisterFinals = -1   #R_i,f
Bs = -1 #B_i
Ps = -1

xBar = {}
yBar = {}

regList = ["ZERO", "AT", "V0", "V1", "A0", "A1", "A2", "A3", "T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "T8", "T9", "K0", "K1", "GP", "SP", "FP", "RA"]
# remove bad ones from list above


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

# list has initial register values, 
def initialize(dataList: list, iterPerReg: int = 100):
    """ Initializes the correlation calculator with the data from running an instruction multiple times

    Arguments:
    dataList -- the list of data from the run instruction module. [[0s: byte_literal, InitialRegisterState: dict{registerName, registerValue}, InitialResult: dict{registerName, registerValue}],[bytesChanged: byte_literal, RegisterInitial1: dict{registerName, registerValue}, RegisterFinal1: dict{registerName, registerValue}],...]
    iterPerReg -- number of times each combination of changed registers is ran (default = 100)

    """
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, regList
    iterPerRegister = iterPerReg
    I = n*iterPerRegister
    if(I != len(dataList)-1):
        I = len(dataList)-1
    RegisterInitial = dataList[0][1]
    RegisterInitialOutput = dataList[0][2]
    RegisterInitials = [0]*I
    RegisterFinals = [0]*I
    Bs = [0]*I
    Ps = [0]*I

    i=0
    # guessed indices
    for r in range(len(dataList)-1):
        item = dataList[r+1]
        RegisterInitials[i] = item[1]
        RegisterFinals[i] = item[2]
        Bs[i] = item[0]
        i += 1

    regList = list(RegisterInitials[0])

def getBsDict(bytesB):
    global n, regList
    newDict = {}
    for i in range(n):
        bitMaskV = 1
        if(int.from_bytes(bytesB, 'big')&(1<<(n-i-1)) == 0):
            bitMaskV = 0
        newDict{reglist[i]} = bitMaskV
    
    
def computeAverages():
    global n, iterPerRegister, RegisterInitial, RegisterInitials, RegisterInitialOutput, RegisterFinals, Bs, I, regList, xBar, yBar
    
    xBar = RegisterInitial.copy()
    yBar = RegisterInitial.copy()
    bSum = {}

    regs = regList
    
    for reg in regs:
        yBar{reg} = RegisterInitialOutput.copy()
        bSum{reg} = 0

    for i in range(len(RegisterInitials)):
        ri = RegisterInitials[i]
        rf = RegisterFinals[i]
        b = getBsDict(Bs[i])

        for r1 in regs:
            
            xBar{r1} += ri{r1}*b{r1}
            bSum{r1} += b{r1}

            for r2 in regs:
                yBar{r1}{r2} += rf{r2}*b{r1}


    for r1 in regs:
        xBar{r1} /= bSum{r1}
        for r2 in regs:
            yBar{r1}{r2} /= bSum{r1}
    
    
def pearsonCorrelations(): 
    global n, iterPerRegister, RegisterInitial, RegisterInitials, RegisterInitialOutput, RegisterFinals, Bs, I, regList, xBar, yBar
    
    computeAverages()

    for x in regList:
        for i in range(len(RegisterInitials)):
            
            

def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.

    Return Value:
    M -- n x n list where M[i][j] is the correlation of register i on register j
    """
    global n, iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, xBar, yBar

    correlations = pearsonCorrelations()
    print(correlations)

    M = [[0]*n for _ in range(n)]
    
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

    return M


