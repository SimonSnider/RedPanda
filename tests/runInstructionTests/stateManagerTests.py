from modules.runInstruction.stateManager import *
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

# @pytest.mark.skip(reason="do not run this, let panda do it")
@panda.cb_after_machine_init
def setup(cpu):
    '''
    After our CPU has been created, allocate memory and set starting state
    '''
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)
    global regState1
    regState1 = getRegisterState(panda, cpu)
    print("randomizing register state")
    randomizeRegisters(panda, cpu)
    panda.arch.dump_regs(cpu)
    global regState2
    regState2 = getRegisterState(panda, cpu)
    print(regState2)
    # print(regState2)
    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS
    panda.end_analysis()

#@panda.queue_blocking
#def runner():
#    panda.end_analysis()
    

panda.run()

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
        for key in skippedMipsRegs:
            self.assertEqual(regState2.get(key), 0, msg='key: {0}'.format(key))


if __name__ == '__main__':
    unittest.main()
