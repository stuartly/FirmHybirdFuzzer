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
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

PROJ_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_hjx/frdmk66f_lwip_httpsrv_bm"
FIRMWARE_NAME = "frdmk66f_lwip_httpsrv_bm" # firmware name
ELF_SUFFIX = "axf" # elf file suffix
sample = os.path.join(PROJ_PATH, '.'.join([FIRMWARE_NAME, ELF_SUFFIX, 'raw']))
OUT_DIR = "./myavatar"
QEMU_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
ROM_START = 0x0
ROM_SIZE = 0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}

QCOW2_Path = os.path.join(PROJ_PATH, "snapshot.qcow2")
# binary starts at LOAD_OFFSET
LOAD_OFFSET = 0x0
RAW_BIBARY = True

ASSERT_FUNC = {0x0000C27C, }

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

stopHooks = {}

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    print("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget,name="panda",
                             gdb_executable="arm-none-eabi-gdb",
                             firmware=sample, cpu_model="cortex-m4",
                             # gdb_port = random.randint(300, 100000),
                             # qmp_port = random.randint(300, 100000),
                             executable=QEMU_PATH,
                             #drive_qcow2 =QCOW2_Path,
                             raw=RAW_BIBARY,
                             interval=1)
    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, \
                             load_options={'main_opts': {'backend': 'blob', 'custom_arch': 'ARM', \
                                                         'custom_base_addr': LOAD_OFFSET,
                                                         'custom_entry_point': 0x1001}})

    with open(sample, "rb") as binary_file:
        # Read the whole file at once
        ROM = binary_file.read()

    # add memory
    ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'], name='rom',
                                   file=sample,
                                   permissions='r-x', alias = ROM_FILE['alias'])


    IgnorePeripheralList = {
        "all-device": (0x40000000, 0x50000000),
    }
    # Fast works fine.
    # Explore_Single fine.
    # Explore_All?
    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START, stopHooks=stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific={},
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
    peripheral.start_exec_time=time.time()


    #Note: when using panda, add the panda plugin firstly, the stackobject and heapobject has some problem
    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]
    plugins += ['inst=true']
    plugins += ['callstack=true']
    plugins += ['callframe=true']
    plugins += ['segment=true']
    plugins += ['div=true']

    funcs = utils.get_symbols(os.path.join(PROJ_PATH, '.'.join([FIRMWARE_NAME, ELF_SUFFIX])))

    plugins += ['stackobjects=true']
    plugins += ['debugfile=%s' % os.path.join(PROJ_PATH, "funcs.json")]

    plugins += ['hooknetwork=true']
    # plugins += ['net_fun=%d' % 0]
    # plugins += ['net_buf_file=%s' % '/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/united/ndss2018Exp/proj_ndss_vul/fuzzing/sample_trigger']
    # plugins += ['crash_path=%s' % '/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/united/ndss2018Exp/proj_ndss_vul/fuzzing']
    # plugins += ['buf_reg_index=%d' % 0]
    # plugins += ['len_reg_index=%d' % 1]
    
    # the format of skip_funcs parameter is %d-%d-%d-...., if just skip one funcs, then %d
    plugins += ['skip_funcs=%d-%d' % (funcs.get('DbgConsole_Printf', 0), funcs.get('hjx_bug111', 0))]

    heap_funcs = ['malloc', 'free', 'pvPortMalloc', 'vPortFree']
    plugins += ['heapobjects=true']
    plugins += ['%s=%d' % (f, funcs.get(f, 0)) for f in heap_funcs]

    # plugins += ['fstring=true']
    # plugins += ['printf=%d' % funcs.get('DbgConsole_Printf', 0)]

    wycinwyc_args = ','.join(plugins)
    logger.info("[+] wycinwyc_args: " + wycinwyc_args)
    panda.load_plugin('wycinwyc', wycinwyc_args)



    logger.info("[+] Running in Panda until a peripherial is accessed")


    panda.cont()
    panda.wait()



