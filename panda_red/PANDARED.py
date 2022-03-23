"""Intermediary Component which may be used as a standalone executable or as a callable module from other scripts

Execution
Arguments:
        arg1 -- output file

        arg2 -- arch -- specifies the architecture for which the system is run (default = MIPS32)
        Valid Arguments:
            mips32 -- Use the MIPS architecture
            x86_64 -- Use the x86_64 architecture

        arg3 -- instructionTotal -- specifies the total number of random instructions to generate data for (default = 1)

        arg4 -- instructionIterations -- specifies the number times an instruction is run and data is generated (default = 10)

        arg5 -- analysis model -- specifies the type of analysis to be run on the data
        Valid Arguments:
            reg-coorelational -- calculate coorelation between register values before and after an instruction is run
"""

import math
import random
import os
from panda_red.run_instruction.instructionRunner import generateInstructionData
from panda_red.get_correlations import correlationCalculatorMemory as MC
from panda_red.generate_instruction import instructionGenerator as instructionGen
from panda_red.compare_to_taint import taintComparer as TC
from panda_red.utilities.printOptions import *
from keystone.keystone import *
import argparse

module_location = os.path.abspath(__file__)
module_dir = os.path.dirname(module_location)

def runModel(arch, mode, instructionIterations, outputFileName, outputModel=0, instructionsFile = "", numInstructions = 1, verbose = 0, threshold = 0.5, seed = random.randint(-214322, 1421535)):
    printMainFunction("System initialized in the following mode:")
    printMainFunctionBody("Architecture: " + arch)
    printMainFunctionBody("Iterations:   " + str(instructionIterations))
    printMainFunctionBody("Output Model: " + str(outputModel))
    printMainFunctionBody("Name:         " + str(outputFileName))
    printMainFunction("System initialized using seed: " + str(seed))
   
    #
    # Generate instructions or load them from a file
    #
    if outputModel == 0:
        from panda_red.create_output import matrixOutput as output
    elif outputModel == 1:
        from panda_red.create_output import thresholdOutput as output
    #else:
        #from modules.createOutput import matrixOutput as output

    if mode == 0:
        # Instructions are generated randomly using the generateInstruction module
        instructionList = []
        instructionGenerator = instructionGen.initialize(arch)
        if arch == "mips32":
            from panda_red.generate_instruction.filterer import filtererBasicMIPS as filter
        elif arch == "x86_64":
            from panda_red.generate_instruction.filterer import filtererBasicX86 as filter
        else:
            printError("Specified architecture: " + arch + " not valid")
            return
        for _ in range(numInstructions):
            instructionList.append(instructionGen.generateInstruction(instructionGenerator, filter, verbose))
    elif mode == 1:
        # Instructions are given in byte format in a text file
        instructionList = []
        numInstructions = 0

        # Read file
        with open(instructionsFile) as f:
            lines = f.readlines()

        # Parse file
        for line in lines:
            # Ignore comments and blank lines
            if (line[0] == '#') or (len(line) < 2):
                continue;

            instructionList.append(bytes(line, encoding="raw_unicode_escape"))
            numInstructions = numInstructions + 1
    elif mode == 2:
        # Instructions are given in an unassembled format in a text file
        instructionList = []
        numInstructions = 0
        
        # Instantiate the Keystone assembler to assemble instructions
        if (arch == "mips32"):
            KS = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
        elif (arch == "x86_64"):
            KS = Ks(KS_ARCH_X86,KS_MODE_64)
        else:
            printError("Specified architecture: " + arch + " not valid")
            return
        ADDRESS = 0x0000

        # Read file
        with open(instructionsFile) as f:
            lines = f.readlines()

        # Parse file
        for line in lines:
            #Ignore comments and blank lines
            if (line[0] == '#') or (len(line) < 2):
                continue;

            code = line.encode('UTF-8')
            encoding, count = KS.asm(code, ADDRESS)

            instructionList.append(encoding)
            numInstructions += 1
    else:
        printError("Specified mode: " + mode + " not valid")
        return

    #
    # Run the instructions through the Panda.re engine
    #
    printMainFunction("Instruction retrieval complete, beginning to run instructions")
    instructionData, pandaModels = generateInstructionData(arch, instructionList, instructionIterations, verbose)
    #
    # Generate coorelation data from the instruction results
    #
    # MC.setArch(arch)
    printMainFunction("Running instructions complete, beginning to analyze correlations")
    analyzedData = []

    for i in range(numInstructions):
        if(verbose): printStandard("Generating correlations for: " + str(instructionList[i]))
        dat = instructionData.registerStateLists[i]
        pandaModel = pandaModels[i]

        MC.initialize(dat, instructionIterations, threshold)
        calcdCorrelations = MC.computeCorrelations(verbose)
        analyzedData.append(calcdCorrelations)

        comparison = TC.compare(pandaModel, calcdCorrelations)
        printComment(comparison)

        from panda_red.create_output import comparisonOutput as compOutput
        compOutput.generateOutput(instructionData.instructionNames[i], [calcdCorrelations, pandaModel], outputFileName)

    printMainFunction("Analysis complete, generating output file")
    output.generateOutput(instructionData.instructionNames, analyzedData, outputFileName)
    printMainFunction("Output complete, ending red panda execution")

parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
parser.add_argument("-architecture", type=str, help="the instruction set architecture to generate and run instructions in", choices=["mips32", "x86_64"])
group = parser.add_mutually_exclusive_group()
group.add_argument("-random_instructions", type=int, help="a number of random instructions to generate")
group.add_argument("-bytes_file", type=str, help="path to a file with a list of byte-assembled instructions")
group.add_argument("-instructions_file", type=str, help="path to a file with a list of unassembled instructions")
parser.add_argument("-iterations", type=int, help="the number of times an instruction is randomly run for each register in the specified ISA")
parser.add_argument("-analysis_model", type=int, help="the mathematical model used for analysis: 0 - reg-correlations, 1 - mem-reg-correlations", choices=[0, 1])
parser.add_argument("-output_model", type=int, help="choose the model for output: 0 - matrix, 1 - threshold", choices=[0,1])
parser.add_argument("-name", type=str, help="the name for the current run of the system, will become the name of the output file")
parser.add_argument("-v", "--verbose", help="enable verbose mode for each system step", action="store_true")
parser.add_argument("-i", "--intermediate", help="print a file containing the register contents of each run", action="store_true")
parser.add_argument("-threshold", type=float, help="the correlation threshold for instructions to register as tainted")
parser.add_argument("-seed", type=int, help="the seed to generate instructions with")

args = parser.parse_args()

printComment(str(args))
if(args.random_instructions):
    mode = 0
elif(args.bytes_file):
    mode = 1
elif(args.instructions_file):
    mode = 2
else:
    printError("Must specify an instruction source")
    quit()

if(args.seed):
    runModel(args.architecture, mode, args.iterations, args.name, args.output_model, args.instructions_file, args.random_instructions, args.verbose, args.threshold, args.seed)
else:
    runModel(args.architecture, mode, args.iterations, args.name, args.output_model, args.instructions_file, args.random_instructions, args.verbose, args.threshold)
