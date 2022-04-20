import threading as thread

def ctt():
    numSuccess = 0
    from compareToTaintTests import test
    try:
        test.test1()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test1 failed!")

    try:
        test.test2()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test2 failed!")

    try:
        test.test3()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test3 failed!")

    try:
        test.testModelCollection()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests testModelCollection failed!")

    print(numSuccess, " tests passed in compareToTaintTests.")
    
def stateManagerMipsTests():
    numTests = 0
    numSuccesses = 0
    from runInstructionTests import stateManagerMipsTestsForThreading as smt
    smt.runPanda()
    try:
        numTests += 1
        smt.testRandomizeRegisterState()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testRandomizeRegisterState failed!")
        
    try:
        numTests += 1
        smt.testOffLimitsRegs()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testOffLimitsRegs failed!")
        
    try:
        numTests += 1
        smt.testGetBitTrue()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testGetBitTrue failed!")
        
    try:
        numTests += 1
        smt.testGetBitFalse()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testGetBitFalse failed!")
        
    try:
        numTests += 1
        smt.testRandomizeRegisterWithBitmask()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testRandomizeRegisterWithBitmask failed!")
    try:
        numTests += 1
        smt.testSetRegisters()
        numSuccesses += 1
    except AssertionError:
        print("state manager mips test testSetRegisters failed!")

    print("{} / {} tests passed in stateManagerMipsTests".format(numSuccesses, numTests))
    

        

if __name__ == "__main__":
    t1 = thread.Thread(target=ctt,args=())
    t2 = thread.Thread(target=stateManagerMipsTests, args=())
    t1.start()
    t2.start()

    t1.join()
    t2.join()
    print("All tests compete.")

