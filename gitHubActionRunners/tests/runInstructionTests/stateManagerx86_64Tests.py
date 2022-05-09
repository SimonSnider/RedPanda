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
panda = Panda("x86_64",
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
    print("randomizing register state")
    randomizeRegisters(panda, cpu)
    panda.arch.dump_regs(cpu)
    regState2 = getRegisterState(panda, cpu)
    print(regState2)
    bitmask = b'\x00\x00\x05'
    randomizeRegisters(panda, cpu, bitmask)
    regState3 = getRegisterState(panda, cpu)
    setRegisters(panda, cpu, regState2)
    regState4 = getRegisterState(panda, cpu)
    print(regState3)
    # Set starting_pc
    panda.arch.set_pc(cpu, ADDRESS)
    panda.end_analysis()

class TestScript(unittest.TestCase):
    def testRandomizeRegisterState(self):
        """
        Check that the randomized register state is different from the original register state.
        """
        global regState1, regState2
        self.assertTrue(compareRegStates(regState1, regState2))

    def testOffLimitsRegs(self):
        """
        check that the skipped registers in mips are still 0 after randomization
        """
        global regState2
        for key in skippedX86Regs:
            self.assertEqual(regState2.get(key), 0, msg='key: {0}'.format(key))

    def testGetBitTrue(self):
        n = b'\x01'
        self.assertTrue(getBit(n, 0))
        n = b'\x03'
        self.assertTrue(getBit(n, 0))
        n = b'\x02'
        self.assertTrue(getBit(n, 1))
        n = b'\x80'
        self.assertTrue(getBit(n, 7))
        n = b'\x80\x00\x00'
        self.assertTrue(getBit(n, 23))
        n = b'\x00\x40\x00'
        self.assertTrue(getBit(n, 14))

    def testGetBitFalse(self):
        n = b'\x01'
        self.assertFalse(getBit(n, 1))
        n = b'\x03'
        self.assertFalse(getBit(n, 3))
        n = b'\x02'
        self.assertFalse(getBit(n, 0))
        n = b'\x80'
        self.assertFalse(getBit(n, 2))
        n = b'\x80\x00\x00'
        self.assertFalse(getBit(n, 22))
        n = b'\x00\x40\x00'
        self.assertFalse(getBit(n, 15))

    def testRandomizeRegisterWithBitmask(self):
        """
        during the execution randomizeRegisterState was called with a bitmask indicating the 9th and 11th register,
        T0 and T2, should be randomized. Check that T0 and T2 changed but T1 and T3 remained the same
        """
        self.assertTrue(compareRegStates(regState2, regState3))
        self.assertEqual(regState2['RCX'], regState3['RCX'])
        self.assertNotEqual(regState2['RAX'], regState3['RAX'])
        self.assertEqual(regState2['RBX'], regState3['RBX'])
        self.assertNotEqual(regState2['RDX'], regState3['RDX'])

    def testSetRegisters(self):
        """
        after testing randomize registers with bitmask, set the registers back to regState2 and check if regState4 and regState2 are the same
        """
        self.assertFalse(compareRegStates(regState2, regState4))
        



if __name__ == '__main__':
    panda.run()
    unittest.main()
