# bitGenerator module
# this module's purpose is to generate random bits to be used as instructions
# random byte outputs need to be of the byte datatype
from random import randint

def generateRandomBytes(numBytes, byteorder='big'):
    maxInt = (2 ** (numBytes * 8)) - 1
    return randint(0, maxInt).to_bytes(numBytes, byteorder=byteorder, signed=False)

def generateRandomBits(numBits, byteorder='big'):
    maxInt = (2 ** (numBits)) - 1
    return randint(0, maxInt).to_bytes((numBits + 7) // 8, byteorder=byteorder, signed=False)

def byteBinaryString(byteData):
    num = int.from_bytes(byteData, 'big', signed=False)
    return format(num, '0{}b'.format(len(byteData)*8))
