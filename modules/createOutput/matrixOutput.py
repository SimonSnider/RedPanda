import csv

def generateOutput(data, filename):
    """
    Generates output for a Correlation Data Object in the form of a matrix printed in csv format.

    Arguments:
        data -- A list of Correlation objects which should be printed

    Output:
        A single csv file containing the correlation matrix of the specified input.
    """
    with open(outputFileName + ".csv", 'w') as csvfile: 
        writer = csv.writer(csvfile) 

        # writer.writerow(fields)
        for singleInstructionData in data:
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