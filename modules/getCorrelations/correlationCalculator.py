n = 24 #number of registers about which we care
iterPerRegister = 100 #CHANGE THIS NUMBER. STAT MATH HERE
I = n*iterPerRegister
RegisterInitial = -1  #R_0
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



def setArch(archType):
    if(archType.lower()=="mips32"):
        global n
        n = 24

# list has initial register values, 
def initialize(list: list, RNaught: dict, iterPerReg: int = 100):
    global iterPerRegister, RegisterInitial, RegisterInitials, RegisterFinals, Bs, Ps, I
    iterPerRegister = iterPerReg
    I = n*iterPerRegister
    RegisterInitial = RNaught
    RegisterInitials = []
    RegisterFinals = []
    Bs = []
    Ps = []

    i=0
    # guessed indices
    for item in list:
        RegisterInitials[i] = initialR = item[0]
        RegisterFinals[i] = finalR = item[1]
        Bs[i] = item[2]
        Ps[i]=1
        # iterate through initial and final registers to get b, p values
        if(initialR==finalR):
            Ps[i]=0



def computePs():
