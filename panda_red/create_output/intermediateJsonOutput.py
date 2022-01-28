from panda_red.models.stateData import *
from dataclasses import asdict
import json

def saveStateData(data: StateData, filename):
    """
    Arguments:
        data -- a StateData object
        filename -- the name of the file to write to
    Outputs:
        Converts the StateDate to json and writes it to the file
    """
    class MyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return ("0x" + obj.hex())
            return json.JSONEncoder.default(self, obj)
    stateDataJson = json.dumps(asdict(data))
    with open(filename + ".json", 'w') as jsonFile:
        jsonFile.write(stateDataJson)