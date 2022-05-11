from tests.generateInstructionTests import verifierAdapterTests as test

test.test_setISA()
test.test_initialize()
test.testNoOp()
test.testValidAdd()
test.testValidSub()
test.testValidSll()
test.testValidSrl()
test.testValidOr()
test.testValidAnd()
test.testInvalidInstruction()

