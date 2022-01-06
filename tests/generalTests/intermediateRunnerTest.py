from os import error
import pytest
from modules import intermediateRunner as intRun
from tests.utilities import setConsoleInputs

def test_enterValidSettings(monkeypatch):
    """
    """
    setConsoleInputs(monkeypatch, ['data', '0', '0', '1', '10', '0', '0'])

    try:
        intRun.runProgram();
        assert True
    except:
        assert False