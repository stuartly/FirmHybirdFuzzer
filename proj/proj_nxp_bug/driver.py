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
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.2." + format(RAM_SIZE, '#04x')
            }
RAM_FILES = [
    RAM_FILE,
    {'start': RAM_START + 0x80000000, 'size': RAM_SIZE,
     'file': "/dev/shm/SHM.3." + format(RAM_SIZE, '#04x')
     },
]

sample = './frdmk66f_rtos_hello_bug.axf.raw'
OUT_DIR = "./myavatar"
QEMU_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build/arm-softmmu/qemu-system-arm"
ROM_START = 0x0
ROM_SIZE = 0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}

QCOW2_Path="/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_nxp_bug/proj_nxp_bug.qcow2"


# binary starts at LOAD_OFFSET
LOAD_OFFSET = 0x0
RAW_BIBARY = True

ASSERT_FUNC = {0x3e5d, }

# DEBUG_PORT
DEBUG_PORT = 0x4006a007

# this data is delivered to Angr for correct execution
# Qemu is able to implement system control registers
# Chip_Specific_Info = {0xe000ed00: ("cpuid", 0x410FC241),
#                       0xe000e01c: ("SysTick Calibration Value Register", 0x00),
#                       0xe000e400: ("cpuid", 0xF0),
#                       }
Chip_Specific_Info = {}
# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
memcpy_addr = 0x56bd
memset_addr = 0x56c1
strlen_addr = 0x58f3
# stopHooks = {memcpy_addr, memset_addr, strlen_addr}
stopHooks = {}

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

scanf_addr = 0x4291
printf_addr = 0x4e1

ROM = bytearray()

QEMU_PLUGINS = ["Segment_Tracker", "Call_Stack"]

def before_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print('save vm snaphost before finishing the setup of shared memory 0x%x' % 0xe52)
    qemu.saveVMSnapshot("HHH0")

def after_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print('save vm snaphost after finishing the setup of shared memory 0x%x' % 0xe52)
    qemu.saveVMSnapshot("HHH1")


if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)
    avatar.watchmen.add_watchman('BreakpointHit', 'before', before_hit_breakpoint, is_async=False)
    avatar.watchmen.add_watchman('BreakpointHit', 'after', after_hit_breakpoint, is_async=False)

    # Add first target
    print("[+] Creating the QEMUTarget")
    qemu = avatar.add_target(QemuTarget,
                             gdb_executable="arm-none-eabi-gdb",
                             firmware=sample, cpu_model="cortex-m4",
                             # gdb_port = random.randint(300, 100000),
                             # qmp_port = random.randint(300, 100000),
                             executable=QEMU_PATH,
                             drive_qcow2 =QCOW2_Path,
                             #plugins = QEMU_PLUGINS,
                             raw=RAW_BIBARY,
                             interval=0.2)
    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILES, \
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

    # ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
    #                                permissions='rw-')

    # ram1 = avatar.add_memory_range(RAM_FILE['start']+0x70000000, RAM_FILE['size'], name='ram1',
    #                               permissions='rw-')

    rom = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'] - ROM_FILE['start'], name='rom',
                                  file=sample,
                                  permissions='r-x', alias=ROM_FILE['alias'])

    bootloader = avatar.add_memory_range(ROM_FILE['start'] + 0x60000000, ROM_FILE['size'] - ROM_FILE['start'],
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
    peripheral.start_exec_time = time.time()

    qemu.infoVMSnapshot()
    qemu.loadVMSnapshot("HHH0")

    logger.info("[+] Running in QEMU until a peripherial is accessed")
    # qemu.set_breakpoint(0xe3c)
    qemu.set_breakpoint(0x4e6e)

    # while True:
    qemu.cont()
    qemu.wait()


