COMMENT = '\033[90m'
ERROR = '\033[91m'
FUNCTION = '\033[92m'
WARNING = '\033[93m'
STANDARD = '\033[94m'
ENDCOLOR = '\033[0m'
ISDEBUG = False

def printComment(comment):
    if(ISDEBUG): print(COMMENT + str(comment) + ENDCOLOR)

def printError(error):
    print(ERROR + "[ERROR] " + ENDCOLOR + str(error))

def printMainFunction(function):
    print(FUNCTION + "[RED PANDA] " + ENDCOLOR + str(function))
    
def printMainFunctionBody(function):
    print(FUNCTION + "            " + ENDCOLOR + str(function))

def printSubsystemFunction(function):
    print(FUNCTION + "[subsystem] " + ENDCOLOR + str(function))

def printWarning(warning):
    print(WARNING + "[WARNING] " + ENDCOLOR + str(warning))

def printStandard(standard):
    print(STANDARD + str(standard) + ENDCOLOR)