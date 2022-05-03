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
    
def stateManagerX86_64Tests():
    numTests2 = 0
    numSuccesses2 = 0
    from runInstructionTests import stateManagerx86_64TestsForThreading as smt2
    smt2.runPanda()
    try:
        numTests2 += 1
        smt2.testRandomizeRegisterState()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testRandomizeRegisterState failed!")
        
    try:
        numTests2 += 1
        smt2.testOffLimitsRegs()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testOffLimitsRegs failed!")
        
    try:
        numTests2 += 1
        smt2.testGetBitTrue()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testGetBitTrue failed!")
        
    try:
        numTests2 += 1
        smt2.testGetBitFalse()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testGetBitFalse failed!")
        
    try:
        numTests2 += 1
        smt2.testRandomizeRegisterWithBitmask()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testRandomizeRegisterWithBitmask failed!")
    try:
        numTests2 += 1
        smt2.testSetRegisters()
        numSuccesses2 += 1
    except AssertionError:
        print("state manager x86_64 test testSetRegisters failed!")

    print("{} / {} tests passed in stateManagerx86_64Tests".format(numSuccesses2, numTests2))
        
def ritTestRunMipsInstructionOnce():
    from runInstructionTests.runInstructionTestsForThreading import testRunMipsInstructionOnce as test
    try:
        test()
    except AssertionError:
        print("run instruction tests testRunMipsInstructionOnce failed!")

if __name__ == "__main__":
    t1 = thread.Thread(target=ctt,args=())
    t2 = thread.Thread(target=stateManagerMipsTests, args=())
    t3 = thread.Thread(target=stateManagerX86_64Tests, args=())
    t4 = thread.Thread(target=ritTestRunMipsInstructionOnce, args=())
    
    # t1.start()
    t2.start()
    # t3.start()
    t4.start()

    # t1.join()
    t2.join()
    # t3.join()
    t4.join()
    print("All tests complete.")

