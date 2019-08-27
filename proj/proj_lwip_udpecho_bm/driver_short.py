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

import concolic.utils as utils
import concolic.peripheral as peripheral

import random

# proj specific settings
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }
# RAM_FILE = "/dev/shm/SHM.0.0x40000"
# sample = '/home/ubuntu/CORTEX-M4-QEMU/freertos_uart.axf.raw'
sample = './frdmk66f_lwip_udpecho_bm_short.axf.raw'
OUT_DIR = "./myavatar"
QEMU_PATH = "qemu-system-arm"
ROM_START=0x0
ROM_SIZE=0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

#DEBUG_PORT
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
memcpy_addr = 0x00017bfb
memset_addr = 0x00017c11
stopHooks = {memcpy_addr, memset_addr, 0x6df1, 0x1709f} #memp_init_pool
# stopHooks = {memset_addr}

ASSERT_FUNC = {0x411,}

ROM = bytearray()

# QEMU_PATH = os.path.abspath(QEMU_PATH)

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    print("[+] Creating the QEMUTarget")
    qemu = avatar.add_target(QemuTarget,
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                             # gdb_port=random.randint(300, 100000),
                             # qmp_port=random.randint(300, 100000),
                              executable=QEMU_PATH,
                              raw = RAW_BIBARY,
                             interval = 0.2)
    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, \
            load_options={'main_opts': {'backend':'blob', 'custom_arch':'ARM', \
                                        'custom_base_addr': LOAD_OFFSET, 'custom_entry_point': 0x1001}})

    catch = open("%s/%s_io.txt" % (avatar.output_directory, qemu.name), "w")
    io = utils.IO(avatar.output_directory, qemu.name)

    with open(sample, "rb") as binary_file:
            # Read the whole file at once
            ROM = binary_file.read()


    # add memory
    ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'] - ROM_FILE['start'], name='rom',
                                   file=sample,
                                   permissions='r-x', alise = ROM_FILE['alias'])

    IgnorePeripheralList = {
            "all-device": (0x40000000, 0x50000000),
            }

    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                io=io, rom=ROM, rom_offset=ROM_START, stopHooks = stopHooks,
                                qemu_target=qemu, angr_target=angr, chip_specific = {},
                                alg = utils.Alg_Enum.Explore_Single,
                                asserts=ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=10,
                                depth=4,
                                his=50,
                                permissions='rw-')


    # start
    io.log_io("[+] Initializing the targets")
    avatar.init_targets()

    # io.log_io("[+] Set breakpoint at very beginning")
    # ethernetif_input
    # qemu.set_breakpoint(0x1890)
    # CLOCK_GetOutClkFreq
    # qemu.set_breakpoint(0xf3bd)
    # qemu.set_breakpoint(0xe8d0)
    # qemu.set_breakpoint(0x17254)


    io.log_io("[+] Running in QEMU until a peripherial is accessed")

    # sleep(1000)

    qemu.cont()
    qemu.wait()

    # test gdb
    t = qemu.rr('pc')
    print("read pc from gdb: " + format(t, '#04x'))

    # test qmp
    qmp_regs = qemu.protocols.monitor.get_registers()
    print(qmp_regs)
    active_irqs = qemu.protocols.monitor.get_active_irqs()
    # qemu.protocols.monitor.inject_interruption(0)

    qemu.protocols.gdb.remote_disconnect()

    while True:
        pass
    qemu.cont()
    qemu.wait()
    t = qemu.rr('pc')
    print("read pc from gdb: " + format(t, '#04x'))



    catch.close()
    avatar.shutdown()
