#!/usr/bin/env python3
from pandare import Panda

panda = Panda("mips",
        extra_args=["-M", "configurable", "-nographic", '-d', 'in_asm'],
        raw_monitor=True) # Allows for a user to ctrl-a + c then type quit if things go wrong

print(panda.libpanda_path)