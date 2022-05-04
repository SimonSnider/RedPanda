from tests.generateInstructionTests import bitGeneratorTest as test

for bytes in [1,2,4]:
	test.testGenerateRandomBytes(bytes)
	test.testByteBinaryString(bytes)
	
test.testGenerateRandomBytesWithConstraints(1, -50, 50)
test.testGenerateRandomBytesWithConstraints(2, -130, 130)
test.testGenerateRandomBytesWithConstraints(4, -2**16, 2**16)

