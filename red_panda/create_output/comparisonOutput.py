from panda_red.models.correlations import *
from panda_red.compare_to_taint.taintComparer import *

def printAllCorrelations(corrDict, writeFile):
    for reg in corrDict.keys():
        tainted = corrDict[reg]
        if(len(tainted) == 0):
            writeFile.write(f"Register {reg} does not affect anything.\n")
        else:
            for reg2 in tainted:
                writeFile.write(f"Register {reg} affects register {reg2}.\n")

def generateOutput(instructionNames, data, filename):
    filename = filename + "Comparison.txt"
    with open(filename, 'w') as f:
        ourModel = extractNewModel(data[0])
        pandaModel = convertMatrixToDict(data[1], 0.5)

        f.write("Taint based on random testing:\n")
        printAllCorrelations(ourModel, f)
        f.write("\nTaint based on PANDA's taint system:\n")
        printAllCorrelations(pandaModel, f)

        [pandaTainted, randomTainted] = compare(data[1], data[0])
        
        f.write("\nDifferences in taint models:\n")

        if(len(pandaTainted) == 0 and len(randomTainted) == 0):
            f.write("None\n")
        else:
            for corr in pandaTainted.keys():
                for reg in pandaTainted[corr]:
                    f.write(f"PANDA found that register {corr} affects register {reg}, while the random testing did not.\n")
            for corr in randomTainted.keys():
                for reg in randomTainted[corr]:
                    f.write(f"Random testing found that register {corr} affects register {reg}, while PANDA did not.\n")

        
        
        
        
