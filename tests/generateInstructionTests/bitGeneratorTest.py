from modules.generateInstruction.bitGenerator import *
import pytest

@pytest.mark.parametrize("bytes", [
    1, 2, 4
])

def testGenerateRandomBytes(bytes):
    """
    call generateRandomBytes 100 times with x bytes and check that
    it is in the correct range
    """
    for i in range(100):
        byteData = generateRandomBytes(bytes)
        num = int.from_bytes(byteData, "big")
        assert num > 0 and num <= 2**(bytes*8) - 1

@pytest.mark.parametrize("bytes", [
    1, 2, 4
])

def testByteBinaryString(bytes):
    """
    call generateRandomBytes 100 times with x bytes 
    and convert it to a binary string. check that
    the string only contains 1's and 0's
    """
    for i in range(100):
        byteData = generateRandomBytes(bytes)
        string = byteBinaryString(byteData)
        assert all([characters in ["1", "0"] for characters in string])