import json
from red_panda.models.stateData import *
from red_panda.run_instruction import instructionRunner as IR
from keystone.keystone import *

instruction = "add $t1, $t2, $t3"
print(instruction)
CODE = instruction.encode('UTF-8')

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return ("0x" + obj.hex())
        return json.JSONEncoder.default(self, obj)

ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)

ADDRESS = 0x1000
encoding, count = ks.asm(CODE, ADDRESS)

data: StateData = IR.generateInstructionData("mips", [encoding], 1)



jsonstr = stateDataToJson(data)
print("\njson data:")
# print(jsonstr)


# with open('stateData.json', 'w') as outfile:
#     outfile.write(jsonstr)