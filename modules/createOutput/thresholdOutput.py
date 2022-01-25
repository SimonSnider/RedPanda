from modules.models.correlations import *

def generateOutput(data, filename):
    filename = filename + ".txt"
    with open(filename, 'w') as f:
        for datai in data:
            f.write("\nCorrelations with >= " + str(datai.threshold) + "\n")

            for i in range(len(datai.regToReg)):
                for j in range(len(datai.regToReg)):
                    if (i == j and datai.regToReg[i][j] <= 1-datai.threshold):
                        f.write(f"Register {i} is not correlated with itself: {datai.regToReg[i][j]}\n")
                    if (i != j and datai.regToReg[i][j] >= datai.threshold):
                        f.write(f"Register {i} is correlated with register {j}: {datai.regToReg[i][j]}\n")

            for i in range(len(datai.regToReadAddress)):
                for j in range(len(datai.regToReadAddress[0])):
                    if (datai.regToReadAddress[i][j] >= datai.threshold):
                        f.write(f"Register {i} is correlated with the address of read {j}: {datai.regToReadAddress[i][j]}\n")

            for i in range(len(datai.readDataToReg)):
                for j in range(len(datai.readDataToReg[0])):
                    if (datai.readDataToReg[i][j] >= datai.threshold):
                        f.write(f"Value of read {i} is correlated with register {j}: {datai.readDataToReg[i][j]}\n")

            for i in range(len(datai.regToWriteAddress)):
                for j in range(len(datai.regToWriteAddress[0])):
                    if (datai.regToWriteAddress[i][j] >= datai.threshold):
                        f.write(f"Register {i} is correlated with the address of write {j}: {datai.regToWriteAddress[i][j]}\n")

            for i in range(len(datai.regToWriteData)):
                for j in range(len(datai.regToWriteData[0])):
                    if (datai.regToWriteData[i][j] >= datai.threshold):
                        f.write(f"Register {i} is correlated with the value being written on write {j}: {datai.regToWriteData[i][j]}\n")
