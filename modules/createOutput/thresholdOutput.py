from modules.models.correlations import *

def generateOutput(data, filename):
    with open(filename, 'w') as f:
        f.write("Correlations with >= " + str(data.threshold) + "\n")

        for i in range(len(data.regToReg)):
            for j in range(len(data.regToReg)):
                if (i == j and data.regToReg[i][j] <= 1-data.threshold):
                    f.write(f"Register {i} is not correlated with itself: {data.regToReg[i][j]}\n")
                if (i != j and data.regToReg[i][j] >= data.threshold):
                    f.write(f"Register {i} is correlated with register {j}: {data.regToReg[i][j]}\n")

        for i in range(len(data.regToReadAddress)):
            for j in range(len(data.regToReadAddress[0])):
                if (data.regToReadAddress[i][j] >= data.threshold):
                    f.write(f"Register {i} is correlated with the address of read {j}: {data.regToReadAddress[i][j]}\n")

        for i in range(len(data.readDataToReg)):
            for j in range(len(data.readDataToReg[0])):
                if (data.readDataToReg[i][j] >= data.threshold):
                    f.write(f"Value of read {i} is correlated with register {j}: {data.readDataToReg[i][j]}\n")

        for i in range(len(data.regToWriteAddress)):
            for j in range(len(data.regToWriteAddress[0])):
                if (data.regToWriteAddress[i][j] >= data.threshold):
                    f.write(f"Register {i} is correlated with the address of write {j}: {data.regToWriteAddress[i][j]}\n")

        for i in range(len(data.regToWriteData)):
            for j in range(len(data.regToWriteData[0])):
                if (data.regToWriteData[i][j] >= data.threshold):
                    f.write(f"Register {i} is correlated with the value being written on write {j}: {data.regToWriteData[i][j]}\n")
