import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

n = 24 #number of registers about which we care
iterPerRegister = 100 #CHANGE THIS NUMBER. STAT MATH HERE
I = n*iterPerRegister
RegisterInitial = -1  #R_0
RegisterInitialOutput = -1 #R_0,f
RegisterInitials = -1 #R_i,0
RegisterFinals = -1   #R_i,f
Bs = -1 #B_i
Ps = -1

xBar = []
yBar = [[]]

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

def pearsonCorrelations():
    graph("T2", "T1")
    plt.show()
    computeBars2()
    global n, xBar, yBar, Bs, RegisterInitials, RegisterFinals, I, iterPerRegister
    correlationNums = {}
    xDiffSquaress = {} # sums of (xi-xbar)^2
    yDiffSquaress = {} # sums of (yi-ybar)^2
    regs = RegisterInitials[0].keys()
    for r1 in regs:
        correlationNums[r1] = {}
        xDiffSquaress[r1] = {}
        yDiffSquaress[r1] = {}
        for r2 in regs:
            correlationNums[r1][r2] = 0
            xDiffSquaress[r1][r2] = 0
            yDiffSquaress[r1][r2] = 0
    for iter in range(I):
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for r1 in regs:
            for r2 in regs:
                correlationNums[r1][r2] += (ap(Ri0[r1])-xBar[r1])*(ap(Rif[r2])-yBar[r2])
                xDiffSquaress[r1][r2] += (ap(Ri0[r1])-xBar[r1])*(ap(Ri0[r1])-xBar[r1])
                yDiffSquaress[r1][r2] += (ap(Rif[r2])-yBar[r2])*(ap(Rif[r2])-yBar[r2])

    correlations = {}
    for reg in regs:
        correlations[reg] = {}
        for reg2 in regs:
            denom = ((xDiffSquaress[reg][reg2]*yDiffSquaress[reg][reg2]) ** 0.5)
            if denom == 0:
                if reg == reg2:
                    correlations[reg][reg2] = 1
                else:
                    correlations[reg][reg2] = 0
            else:
                correlations[reg][reg2] = correlationNums[reg][reg2] / denom
            if correlationNums[reg][reg2] == -1/2:
                print(((xDiffSquaress[reg][reg2]*yDiffSquaress[reg][reg2]) ** 0.5))
    return correlations


def apply2sComplement(number):
    if number >= 2 ** 31:
        return number - 2 ** 32
    return number


def ap(n):
    return apply2sComplement(n)


def graph(x, y):
    fig, ax = plt.subplots()
    global n, xBar, yBar, Bs, RegisterInitials, RegisterFinals, I, iterPerRegister
    xData = [0]*I
    yData = [0]*I
    regs = RegisterInitials[0].keys()
    for iter in range(I):
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        xData[iter] = ap(Ri0[x])
        yData[iter] = ap(Rif[y])
    ax.scatter(xData, yData)
    print("correlation between "+x+" and "+y+": "+str(np.corrcoef(xData, yData)))

def computeBars2():
    global n, xBar, yBar, Bs, RegisterInitials, RegisterFinals, I, iterPerRegister
    xBar = {}
    yBar = {}
    regs = RegisterInitials[0].keys()
    for r in regs:
        xBar[r] = 0
        yBar[r] = 0

    for iter in range(I):
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for reg in regs:
            if Ri0[reg]<0:
                print("negative input: " + str(apply2sComplement(Ri0[reg])))
            if Rif[reg]<0:
                print("negative output: " + str(apply2sComplement(Rif[reg])))
            xBar[reg] += apply2sComplement(Ri0[reg])
            yBar[reg] += apply2sComplement(Rif[reg])

    for reg in regs:
        xBar[reg] /= I
        yBar[reg] /= I

    print("input: " + str(Ri0["T2"]))
    print("output: " + str(Rif["T1"]))

def computeBars():
    global n, xBar, yBar, Bs, RegisterInitials, RegisterFinals, I, iterPerRegister
    xBar = {}
    yBar = {}
    regs = RegisterInitials[0].keys()
    for r in regs:
        xBar[r] = 0
        yBar[r] = {}
        for r2 in regs:
            yBar[r][r2] = 0
    
    for iter in range(I):
        Ri0 = RegisterInitials[iter]
        Rif = RegisterFinals[iter]
        for i in range(n):
            reg = list(Ri0.keys())[i]
            if(int.from_bytes(Bs[iter], 'big')&(1<<(4*(n-i-1))) != 0):
                xBar[reg] += Ri0[reg]
                print(reg)
                if reg == "T2":
                    print("input: " + Ri0[reg])
                for reg2 in Rif.keys():
                    yBar[reg][reg2] += Rif[reg2]
                    if reg == "T1":
                        print("output: " + Rif[reg2])
                    
    for r in regs:
        xBar[r] /= I
        for r2 in regs:
            yBar[r][r2] /= I

    print(xBar)
    print(yBar)
            

def computeCorrelations():
    """Calculates the correlation value for each pair of registers. Must call initialize before this.

    Return Value:
    M -- n x n list where M[i][j] is the correlation of register i on register j
    """
    global n, iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I, regList, xBar, yBar
    print("3")
    print(2)
    computeBars2()
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


