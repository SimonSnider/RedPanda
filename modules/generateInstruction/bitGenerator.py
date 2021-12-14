# bitGenerator module
# this module's purpose is to generate random bits to be used as instructions
# random byte outputs need to be of the byte datatype
from random import randint, seed

def setRandomSeed(random_seed):
    """
    Arguments:
        random_seed -- an int to set as the random seed
    Outputs
        sets the seed for randint calls
    """
    seed(random_seed)

def generateRandomBytes(numBytes, byteorder='big', minValue = None, maxValue = None):
    """
    Arguments:
        numBytes -- the length of the number to be returned in bytes
        byteorder -- the endian style of the bytes to be returned ['big', 'little']
        minValue -- the minimum value for the random bytes. Default -(2 ** ((numBytes - 1) * 8))
        maxValue -- the maximum value for the random bytes. Default (2 ** ((numBytes - 1) * 8)) - 1
    Outputs:
        returns a random number between minValue and maxValue converted to bytes
    """
    if (minValue is None):
        minValue = -(2 ** ((numBytes * 8) - 1))
    if (maxValue is None):
        maxValue = (2 ** ((numBytes * 8) - 1)) - 1
    
    return randint(minValue, maxValue).to_bytes(numBytes, byteorder=byteorder, signed=True)

def generateRandomBits(numBits, byteorder='big', minValue = None, maxValue = None):
    """
    Arguments:
        numBits -- the length of the number to be returned in bits
        byteOrder -- the endian style of the bytes to be returned ['big', 'little']
        minValue -- the minimum value for the random bytes. Default -(2 ** (numBits - 1))
        maxValue -- the maximum value for the random bytes. Default (2 ** (numBits - 1)) - 1
    Outputs:
        returns a random number converted to bytes
    """
    if (minValue is None):
        minValue = -(2 ** (numBits - 1))
    if (maxValue is None):
        maxValue = (2 ** (numBits - 1)) - 1
    return randint(minValue, maxValue).to_bytes((numBits + 7) // 8, byteorder=byteorder, signed=True)

def byteBinaryString(byteData):
    """
    Arguments:
        byteData -- a byte literal
    Outputs:
        returns the string representation of the binary byte data, retaining leading zeroes
    """
    num = int.from_bytes(byteData, 'big', signed=False)
    return format(num, '0{}b'.format(len(byteData)*8))
