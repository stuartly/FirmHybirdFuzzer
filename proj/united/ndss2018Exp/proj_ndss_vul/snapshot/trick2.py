#!/usr/bin/env python

with open("/dev/shm/SHM.1.0x14000", "r+b") as f:
    f.seek(0x150)
    f.write(bytes([0,0,0,0]))
    f.seek(0x14c)
    f.write(bytes([0,0,0,0]))
    f.seek(0x154)
    f.write(bytes([0,0,0,0]))
