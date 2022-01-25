from modules.models.correlations import *
import csv

def generateOutput(instructionNames, data, filename):
    """
    Generates output for a Correlation Data Object in the form of a matrix printed in csv format.

    Arguments:
        data -- A list of Correlation objects which should be printed

    Output:
        A single csv file containing the correlation matrix of the specified input.
    """
    with open(filename + ".csv", 'w') as csvfile: 
        writer = csv.writer(csvfile) 

        # writer.writerow(fields)
        for index, singleInstructionData in enumerate(data):
            writer.writerow(["Instruction:", instructionNames[index]])

            writer.writerow(["Reg to Reg Correlations"])
            writer.writerows(singleInstructionData.regToReg)
            
            writer.writerow(["Reg to Read Address Correlations"])
            writer.writerows(singleInstructionData.regToReadAddress)

            writer.writerow(["Reg to Write Address Correlations"])
            writer.writerows(singleInstructionData.regToWriteAddress)

            writer.writerow(["Reg to Write Data Correlations"])
            writer.writerows(singleInstructionData.regToWriteData)
            
            writer.writerow(["Read Data to Reg Correlations"])
            writer.writerows(singleInstructionData.readDataToReg)
