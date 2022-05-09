from red_panda.generate_instruction.bitGenerator import *
def testGenerateRandomBytes(bytes):
    """
    call generateRandomBytes 100 times with 1, 2, and 4 bytes and check that
    it is between 0 and 2^(8*x) - 1
    """
    for i in range(100):
        byteData = generateRandomBytes(bytes)
        num = int.from_bytes(byteData, "big", signed=True)
        assert num >= -(2 ** ((bytes * 8) - 1)) and num <= (2 ** ((bytes * 8) - 1)) - 1

testGenerateRandomBytes(1)
testGenerateRandomBytes(2)
testGenerateRandomBytes(4)

def testGenerateRandomBytesWithConstraints(bytes, min, max):
    """
    call generateRandomBytes 100 times with 1, 2, and 4 bytes and check that
    it is between 0 and 2^(8*x) - 1
    """
    for i in range(100):
        byteData = generateRandomBytes(bytes, minValue=min, maxValue=max)
        num = int.from_bytes(byteData, "big", signed=True)
        assert num >= min and num <= max

testGenerateRandomBytesWithConstraints(1, -50, 50)
testGenerateRandomBytesWithConstraints(2, -130, 130)
testGenerateRandomBytesWithConstraints(4, -2**16, 2**16)

def testByteBinaryString(bytes):
    """
    calls generateRandomBytes 100 times with 1, 2, and 4 bytes 
    and converts it to a binary string, then checks that
    the string only contains 1's and 0's
    """
    for i in range(100):
        byteData = generateRandomBytes(bytes)
        string = byteBinaryString(byteData)
        assert all([characters in ["1", "0"] for characters in string])

testByteBinaryString(1)
testByteBinaryString(2)
testByteBinaryString(4)

