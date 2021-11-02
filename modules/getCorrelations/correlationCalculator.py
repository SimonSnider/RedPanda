n = 24 #number of registers about which we care
iterPerRegister = 100 #CHANGE THIS NUMBER. STAT MATH HERE
I = n*iterPerRegister
RegisterInitial = -1  #R_0
RegisterInitialOutput = -1 #R_0,f
RegisterInitials = -1 #R_i,0
RegisterFinals = -1   #R_i,f
Bs = -1 #B_i
Ps = -1

regList = ["ZERO", "AT", "V0", "V1", "A0", "A1", "A2", "A3", "T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "T8", "T9", "K0", "K1", "GP", "SP", "FP", "RA"]
# remove bad ones from list above

"""
Outstanding questions:
    input format

"""



def setArch(archType, testV=0):
    global n
    if(archType.lower()=="mips32"):
        n = 24
    elif(archType.lower()=="test"):
        n = testV

# list has initial register values, 
def initialize(dataList: list, RNaught: dict, RNaughtFinal: dict, iterPerReg: int = 100):
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I, regList
    iterPerRegister = iterPerReg
    I = n*iterPerRegister
    RegisterInitial = RNaught
    RegisterInitialOutput = RNaughtFinal
    RegisterInitials = [0]*I
    RegisterFinals = [0]*I
    Bs = [0]*I
    Ps = [0]*I

    i=0
    # guessed indices
    for item in dataList:
        RegisterInitials[i] = item[0]
        RegisterFinals[i] = item[1]
        Bs[i] = item[2]
        i += 1

    regList = list(RegisterInitials[0])


def computePs():
    global iterPerRegister, RegisterInitial, RegisterInitialOutput, RegisterInitials, RegisterFinals, Bs, Ps, I
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

def computeCorrelations():
    computePs()
    global iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I, regList

    M = [[0]*n for _ in range(n)]
    
    for i in range(n):
        for j in range(n):
            denom = 0
            num = 0
            for k in range(I):
                denom += Bs[k].get(regList[i])
                num += Bs[k].get(regList[i])*Ps[k].get(regList[j])

            M[i][j] = num/denom

    return M

