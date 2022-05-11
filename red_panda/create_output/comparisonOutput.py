from red_panda.models.correlations import *
from red_panda.compare_to_taint.taintComparer import *

def printAllCorrelations(corrDict, writeFile, registerNames):
    print("length of register names", len(registerNames))
    for reg in corrDict.keys():
        tainted = corrDict[reg]
        if(reg>=len(registerNames)):
            # memory transaction
            for reg2 in tainted:
                writeFile.write(f"Memory read labeled {reg} affects register {registerNames[reg2]}.\n")
        else:
            if(len(tainted) == 0):
                writeFile.write(f"Register {registerNames[reg]} does not affect anything.\n")
            else:
                for reg2 in tainted:
                    print(reg, reg2)
                    writeFile.write(f"Register {registerNames[reg]} affects register {registerNames[reg2]}.\n")

def generateOutput(instructionNames, data, filename, registerNames):
    filename = filename + "Comparison.txt"
    with open(filename, 'a') as f:
        ourModel = extractNewModel(data[0])
        pandaModel = convertMatrixToDict(data[1][0], 0.5)

        f.write("\nInstruction: " + instructionNames + "\n")

        f.write("Taint based on random testing:\n\n")
        printAllCorrelations(ourModel, f, registerNames)
        f.write("\nTaint based on PANDA's taint system:\n\n")
        printAllCorrelations(pandaModel, f, registerNames)

        [pandaTainted, randomTainted] = compare(data[1], data[0])
        
        f.write("\nDifferences in taint models:\n")

        if(len(pandaTainted.keys()) == 0 and len(randomTainted.keys()) == 0):
            f.write("None\n")
        else:
            for corr in pandaTainted.keys():
                for reg in pandaTainted[corr]:
                    f.write(f"PANDA found that register {corr} affects register {reg}, while the random testing did not.\n")
            for corr in randomTainted.keys():
                for reg in randomTainted[corr]:
                    f.write(f"Random testing found that register {corr} affects register {reg}, while PANDA did not.\n")

        f.write("---------------------------------------------\n")

        
        
        
        
