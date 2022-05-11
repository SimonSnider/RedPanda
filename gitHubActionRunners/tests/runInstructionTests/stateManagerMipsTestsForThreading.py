from red_panda.run_instruction.stateManager import *
from pandare import Panda
from capstone import *
from capstone.mips import *
from keystone import *
from enum import Enum
from random import choice, randint
import os
import unittest

ADDRESS = 0
panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic"],
        raw_monitor=False)

regState1 = {}
regState2 = {}
regState3 = {}
regState4 = {}


# @pytest.mark.skip(reason="do not run this, let panda do it")
@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)
    global regState1, regState2, regState3, regState4
    regState1 = getRegisterState(panda, cpu)
    # print("randomizing register state")
    randomizeRegisters(panda, cpu)
    # panda.arch.dump_regs(cpu)
    regState2 = getRegisterState(panda, cpu)
    # print(regState2)
    bitmask = b'\x00\x00\x05\x00'
    randomizeRegisters(panda, cpu, bitmask)
    regState3 = getRegisterState(panda, cpu)
    setRegisters(panda, cpu, regState2)
    regState4 = getRegisterState(panda, cpu)
    # print(regState3)
    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS
    panda.end_analysis()
    
def runPanda():
    panda.run()

def testRandomizeRegisterState():
    """
    Check that the randomized register state is different from the original register state.
    """
    global regState1, regState2
    assert compareRegStates(regState1, regState2), "register state not randomized properly"

def testOffLimitsRegs():
    """
    check that the skipped registers in mips are still 0 after randomization
    """
    global regState2
    for key in skippedMipsRegs:
        assert regState2.get(key) == 0, 'key: {0} not skipped properly during randomization'.format(key)

def testGetBitTrue():
    n = b'\x01'
    assert getBit(n, 0)
    n = b'\x03'
    assert getBit(n, 0)
    n = b'\x02'
    assert getBit(n, 1)
    n = b'\x80'
    assert getBit(n, 7)
    n = b'\x80\x00\x00'
    assert getBit(n, 23)
    n = b'\x00\x40\x00'
    assert getBit(n, 14)

def testGetBitFalse():
    n = b'\x01'
    assert not getBit(n, 1)
    n = b'\x03'
    assert not getBit(n, 3)
    n = b'\x02'
    assert not getBit(n, 0)
    n = b'\x80'
    assert not getBit(n, 2)
    n = b'\x80\x00\x00'
    assert not getBit(n, 22)
    n = b'\x00\x40\x00'
    assert not getBit(n, 15)

def testRandomizeRegisterWithBitmask():
    """
    during the execution randomizeRegisterState was called with a bitmask indicating the 9th and 11th register,
    T0 and T2, should be randomized. Check that T0 and T2 changed but T1 and T3 remained the same
    """
    assert compareRegStates(regState2, regState3)
    assert regState2['T0'] != regState3['T0']
    assert regState2['T1'] == regState3['T1']
    assert regState2['T2'] != regState3['T2']
    assert regState2['T3'] == regState3['T3']

def testSetRegisters():
    """
    after testing randomize registers with bitmask, set the registers back to regState2 and check if regState4 and regState2 are the same
    """
    assert not compareRegStates(regState2, regState4)
    


