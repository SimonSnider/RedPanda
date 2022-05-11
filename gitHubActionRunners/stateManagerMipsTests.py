from tests.runInstructionTests import stateManagerMipsTestsForThreading as test

test.runPanda()
test.testRandomizeRegisterState
test.testOffLimitsRegs()
test.testGetBitTrue()
test.testGetBitFalse()
test.testRandomizeRegisterWithBitmask()
test.testSetRegisters()