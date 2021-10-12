from modules.generateInstruction.bitGenerator import *

print("Begin random byte generation test")

print("call generateRandomBytes with 4 bytes.")
for i in range(5):
    byteData = generateRandomBytes(4)
    print("result",i,byteBinaryString(byteData))