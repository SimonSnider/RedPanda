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
    # Set starting_pc
    cpu.env_ptr.active_tc.PC = ADDRESS
    panda.end_analysis()

#@panda.queue_blocking
#def runner():
#    panda.end_analysis()
    


class TestScript(unittest.TestCase):
    def test(self):
        print("before test run")
        panda.run()
        print("after test run")
        # assert False
        global regState1, regState2
        assert compareRegStates(regState1, regState2)

if __name__ == '__main__':
    unittest.main()
