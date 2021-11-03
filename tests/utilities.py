def generateConsoleInputGenerator(inputs):
    for in in inputs:
        yield in_

def setConsoleInputs(monkeypatch, inputs):
    inputGenerator = generateConsoleInputGenerator(inputs)
    monkeypatch.setattr('builtins.input', lambda : next(inputGenerator))