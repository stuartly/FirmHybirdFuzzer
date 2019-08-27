#!/usr/bin/env python

from avatar2 import *

import logging

import concolic.utils as utils
import concolic.peripheral as peripheral

import random

# proj specific settings
RAM_START = 0x20000000
RAM_SIZE = 0x14000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.1." + format(RAM_SIZE, '#04x')
            }

sample = './expat_panda.bin'
OUT_DIR = "./myavatar"
QEMU_PATH = "qemu-system-arm"
ROM_START=0x0
ROM_SIZE=0x80000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': 0x08000000}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

DEBUG_PORT = 0x40004c04

# this data is delivered to Angr for correct execution
# Qemu is able to implement system control registers
# Chip_Specific_Info = {0xe000ed00: ("cpuid", 0x410FC241),
#                       0xe000e01c: ("SysTick Calibration Value Register", 0x00),
#                       0xe000e400: ("cpuid", 0xF0),
#                       }
Chip_Specific_Info = {}
# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.

stopHooks = {}

ASSERT_FUNC = {}


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)


ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    qemu = avatar.add_target(QemuTarget,
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m3",
                              executable=QEMU_PATH,
                              raw = RAW_BIBARY,
                             interval = 0.2)

    logger.info("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, \
            load_options={'main_opts': {'backend':'blob', 'custom_arch':'ARM', \
                                        'custom_base_addr': LOAD_OFFSET, 'custom_entry_point': 0x1001}})

    with open(sample, "rb") as binary_file:
            # Read the whole file at once
            ROM = binary_file.read()


    # add memory
    ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'], name='rom',
                                   file=sample,
                                   permissions='r-x', alias = ROM_FILE['alias'])

    #IgnorePeripheralList = {
    #        "all-device": (0x40000000, 0x30000),
    #        }
    IgnorePeripheralList = {
            "all-device": (0x40000000, 0x4c00),
            "all-device1": (0x40004d00, 0x20000-0x4d00),
            "all-device2": (0x40020000, 0x10000),
            }
    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=0x08000000, stopHooks = stopHooks,
                                qemu_target=qemu, angr_target=angr, chip_specific = {}, alg = utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts = ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=6,
                                depth=5,
                                his = 30,
                                permissions='rw-')


    
    qemu.additional_args = ["-serial", "tcp::%s,server,nowait" % 9998]
    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in QEMU until a peripherial is accessed")
#    qemu.set_breakpoint(0x3746)



    qemu.cont()
    qemu.wait()


    while True:
        pass


