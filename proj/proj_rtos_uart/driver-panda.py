#!env python

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

import random

# proj specific settings
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

sample = './freertos_uart.axf.raw'
OUT_DIR = "./myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
ROM_START=0x0
ROM_SIZE=0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

ASSERT_FUNC = {0x4A8+1,}

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
memcpy_addr = 0x692b
memset_addr = 0x6941
strlen_addr = 0x6951
# since we can detect long loop, we do not need stopHooks here
stopHooks = {}
# stopHooks = {memcpy_addr, memset_addr, strlen_addr}
# stopHooks = {memset_addr}


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    panda = avatar.add_target(QemuTarget,
                              gdb_executable="arm-none-eabi-gdb",name = 'panda',
                              firmware=sample, cpu_model="cortex-m4",
                             # gdb_port = random.randint(300, 100000),
                             # qmp_port = random.randint(300, 100000),
                              executable=PANDA_PATH,
                              raw = RAW_BIBARY,
                             interval = 60)
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
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'] - ROM_FILE['start'], name='rom',
                                   file=sample,
                                   permissions='r-x', alias = ROM_FILE['alias'])



    IgnorePeripheralList = {
            "all-device": (0x40000000, 0x50000000),
            }
    # Fast ?
    # Explore_Single ?
    # Explore_Single_Explore_All OK with forward_depth=2
    # Explore_Single_Ignore_Speed makes wrong decision
    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START, stopHooks = stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific = {}, alg = utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts = ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=2,
                                depth=1,
                                his = 40,
                                permissions='rw-')

    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    peripheral.start_exec_time = time.time()


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
    # qemu.set_breakpoint(0x6BC)
    # after UART_RTOS_Send
    # qemu.set_breakpoint(0x6E2)

    # UART_TransferHandleIRQ
    # qemu.set_breakpoint(0x22A8)

    logger.info("[+] Running in QEMU until a peripherial is accessed")

    # sleep(1000)

    panda.cont()
    panda.wait()

    # test gdb
    # t = qemu.rr('pc')
    # logger.info("read pc from gdb: " + format(t, '#04x'))

    # test qmp
    # qmp_regs = qemu.protocols.monitor.get_registers()
    # logger.info(qmp_regs)
    # active_irqs = qemu.protocols.monitor.get_active_irqs()
    # qemu.protocols.monitor.inject_interruption(0)

    panda.protocols.gdb.remote_disconnect()

    while True:
        pass
    qemu.cont()
    qemu.wait()
    t = qemu.rr('pc')
    logger.info("read pc from gdb: " + format(t, '#04x'))



    catch.close()
    avatar.shutdown()
