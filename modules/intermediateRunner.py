"""Intermediary Component which may be used as a standalone executable or as a callable module from other scripts

Execution
Arguments:
        arg1 -- output file

        arg2 -- arch -- specifies the architecture for which the system is run (default = MIPS32)
        Valid Arguments:
            mips32 -- Use the MIPS architecture

        arg3 -- instructionTotal -- specifies the total number of random instructions to generate data for (default = 1)

        arg4 -- instructionIterations -- specifies the number times an instruction is run and data is generated (default = 10)

        arg5 -- analysis model -- specifies the type of analysis to be run on the data
        Valid Arguments:
            reg-coorelational -- calculate coorelation between register values before and after an instruction is run
"""

from modules.runInstruction.instructionRunner import generateInstructionData
from modules.getCorrelations import correlationCalculator as CC
import sys
import csv

def runProgram():
    print("Specify an output file name (default = data)")
    outputFileName = input() or "data"
    outputFileName = outputFileName + ".csv"

    print("Specify an architecture (default = 0)")
    print("Supported Architectures")
    print("    0 - mips32")
    arch = int(input() or 0)

    print("Specify the number of instructions to generate data for (default = 1)")
    numInstructions = int(input() or 1)

    print("Specify the number of times an instruction is run (default = 10)")
    instructionIterations = int(input() or 10)

    print("Specify the analysis model (default = 0)")
    print("Supported Models")
    print("    0 - reg-coorelational")
    model = int(input() or 0)

    print("Verbose? (default = 0)")
    verbose = int(input() or 0)

    instructionData = generateInstructionData(arch, numInstructions, instructionIterations, verbose)

    CC.setArch("mips32")
    analyzedData = []
    
    instructionKeys = instructionData.keys()
    for i in range(1):
        dat = instructionData[instructionKeys[i]]
        CC.initialize(dat, 1)
        analyzedData.append(CC.computeCorrelations())

    # fields = ['InstructionName', 'Coorelation'] 
        
    with open(outputFileName, 'w') as csvfile: 
        writer = csv.writer(csvfile) 
        # writer.writerow(fields)
        writer.writerows(analyzedData)

runProgram()