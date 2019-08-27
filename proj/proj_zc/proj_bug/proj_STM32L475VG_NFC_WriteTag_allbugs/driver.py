#!env python

from avatar2 import *
from avatar2.peripherals import *

from os.path import abspath
from time import sleep

from capstone import *
from capstone.arm import *

import angr as a
import claripy
import archinfo

import threading
import subprocess
import os

import logging
# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr').setLevel('INFO')
import traceback

import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral

import random

# proj specific settings
RAM_START = 0x20000000
RAM_SIZE = 0x18000

RAM_FILE1 = {'start': RAM_START, 'size': RAM_SIZE,
             'file': "/dev/shm/SHM.2." + format(RAM_SIZE, '#04x')
            }

RAM_FILE2 = {'start': 0x10000000, 'size': 0x8000,
              'file': "/dev/shm/SHM.2." + format(0x8000, '#04x')
            }

RAM_FILES = [
    RAM_FILE1,
    RAM_FILE2,
]

sample = './project.bin'
OUT_DIR = "./myavatar"
QEMU_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build/arm-softmmu/qemu-system-arm"
ROM_START = 0x8000000
ROM_SIZE = 0x100000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}

QCOW2_Path = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_nxp_bug/proj_nxp_bug.qcow2"
# binary starts at LOAD_OFFSET
LOAD_OFFSET = 0x0
RAW_BIBARY = True

ASSERT_FUNC = {}


# DEBUG_PORT
DEBUG_PORT = 0x40013804


Chip_Specific_Info = {}
# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
# memcpy_addr = 0x56bd
# memset_addr = 0x56c1
# strlen_addr = 0x58f3
# stopHooks = {memcpy_addr, memset_addr, strlen_addr}
stopHooks = {}

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)



if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

       # Add first target
    print("[+] Creating the QEMUTarget")
    qemu = avatar.add_target(QemuTarget, #name = 'qemu',
                             gdb_executable="arm-none-eabi-gdb",
                             firmware=sample, cpu_model="cortex-m4",
                             executable=QEMU_PATH,
                             # drive_qcow2 =QCOW2_Path,Can't convert 'numpy.int64' object to str implicitly
                             entry_address=0x0,
                             raw=RAW_BIBARY,
                             interval=0.2)

    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILES, #name= 'angr',
                             load_options={'main_opts': {'backend': 'blob', 'custom_arch': 'ARM', \
                                                         'custom_base_addr': LOAD_OFFSET,
                                                         'custom_entry_point': 0x1001}})

    with open(sample, "rb") as binary_file:
        # Read the whole file at once
        ROM = binary_file.read()

    # add memory
    for ramfile in RAM_FILES:
        avatar.add_memory_range(ramfile['start'], ramfile['size'], name="ram" + ramfile['file'],
                                permissions='rw-')
    # ram = avatar.add_memory_range(RAM_FILE1['start'], RAM_FILE1['size'], name='ram',
    #                               permissions='rw-')

    rom = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'], name='rom',
                                  file=sample,
                                  permissions='r-x', alias=ROM_FILE['alias'])

    bootloader = avatar.add_memory_range(0x0, 0x100000,
                                         name='bootloader',
                                         file=sample,
                                         permissions='r-x', alias=ROM_FILE['alias'])

    IgnorePeripheralList = {
        "all-device": (0x40000000, 0x50000000),
    }
    # Fast works fine.
    # Explore_Single fine.
    # Explore_All?
    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START, stopHooks=stopHooks,
                                qemu_target=qemu, angr_target=angr, chip_specific={},
                                alg=utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts=ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=3,
                                depth=1,
                                his=40,
                                permissions='rw-')

    # start

    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in QEMU until a peripherial is accessed")

    qemu.cont()
    qemu.wait()



