#!/usr/bin/env python

with open("/dev/shm/SHM.1.0x14000", "r+b") as f:
    f.seek(0xd6c)
    f.write(bytes([1,0,0,0]))
