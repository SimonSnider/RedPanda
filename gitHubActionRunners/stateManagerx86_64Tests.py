from tests.runInstructionTests import stateManagerx86_64TestsForThreading as test

test.runPanda()
test.testRandomizeRegisterState
test.testOffLimitsRegs()
test.testGetBitTrue()
test.testGetBitFalse()
test.testRandomizeRegisterWithBitmask()
test.testSetRegisters()