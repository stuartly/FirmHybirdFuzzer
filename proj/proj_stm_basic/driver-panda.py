#!/home/ubuntu/.virtualenvs/angr/bin/python

from avatar2 import *
from avatar2.peripherals import *

from os.path import abspath
from time import sleep

from capstone import *
from capstone.arm  import *

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



# proj specific settings
RAM_START = 0x20000000
RAM_SIZE = 0x20000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.1." + format(RAM_SIZE, '#04x')
            }
# RAM_FILE = "/dev/shm/SHM.0.0x20000"
# sample = '/home/ubuntu/CORTEX-M4-QEMU/freertos_uart.axf.raw'
sample = './STM32F407.bin'
OUT_DIR = "./myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
ROM_START=0x0
ROM_SIZE=0x100000
# ROM_FILE = (ROM_START, ROM_SIZE, sample, False)
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': 0x8000000}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

# this data is delivered to Angr for correct execution
# Qemu is able to implement system control registers
Chip_Specific_Info = {
                      }
# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
memcpy_addr = 0x80002dd
memset_addr = 0x8012e6d
stopHooks = {memcpy_addr, memset_addr, 0x800020f, 0x800021d, 0x800022d, 0x8000241, 0x8000257, 0x8000263,0x800026a,
             0x8000277}
# stopHooks = {}

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    print("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget,
                              gdb_executable="arm-none-eabi-gdb",name = 'panda',
                              firmware=sample, cpu_model="cortex-m4",
                              executable=PANDA_PATH,
                              raw = RAW_BIBARY,
                             interval = 0.2)
    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, \
            load_options={'main_opts': {'backend':'blob', 'custom_arch':'ARM', \
                                        'custom_base_addr': LOAD_OFFSET, 'custom_entry_point': 0x1001}})

    catch = open("%s/%s_io.txt" % (avatar.output_directory, panda.name), "w")

    with open(sample, "rb") as binary_file:
            # Read the whole file at once
            ROM = binary_file.read()


    # add memory
    ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'] - ROM_FILE['start'], name='rom',
                                   file=sample,
                                   permissions='r-x', alias = ROM_FILE['alias'])

    IgnorePeripheralList = {
            "all-device": (0x40000000, 0xA0001000),
            }

    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START + ROM_FILE['alias'], stopHooks = stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific = {},
                                alg=utils.Alg_Enum.Explore_Single,
                                forward_depth=10,
                                depth=4,
                                his=50,
                                permissions='rw-')


    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    peripheral.start_exec_time = time.time()

    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]
    # plugins += ['callstack=true']
    # plugins += ['callframe=true']
    # plugins += ['segment=true']
    # plugins += ['div=true']
    # plugins += ['stackobjects=true']
    # plugins += ['debugfile=%s/%s' % ( PROJ_PATH + "/snapshot/",'funcs.json')]
    # funcs = get_symbols('./expat_panda.elf')
    #
    # heap_funcs = ['malloc', 'free', 'realloc']
    # heap_funcs_r = ['_malloc_r', '_realloc_r', '_free_r']
    #
    # plugins += ['heapobjects=true']
    # plugins += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]
    # plugins += ['%s=%d' % (f[1:], funcs[f]) for f in heap_funcs_r]
    # plugins += ['fstring=true']
    # plugins += ['printf=%d' % funcs['printf']]
    # plugins += ['fprintf=%d' % funcs['vfprintf']]
    # plugins += ['sprintf=%d' % funcs['sprintf']]
    wycinwyc_args = ','.join(plugins)
    logger.info("[+] wycinwyc_args: " + wycinwyc_args)
    panda.load_plugin('wycinwyc', wycinwyc_args)

    # io.log_io("[+] Set breakpoint at very beginning")
    # uart handler
    # qemu.set_breakpoint(0x190c)
    # ResetISR
    # qemu.set_breakpoint(0x23E)
    # random
    # qemu.set_breakpoint(0x2944)
    # xPortStartScheduler
    # qemu.set_breakpoint(0x20a8)
    # uart_task
    # qemu.set_breakpoint(0xbd6)


    logger.info("[+] Running in QEMU until a peripherial is accessed")

    # sleep(1000)

    panda.cont()
    panda.wait()

