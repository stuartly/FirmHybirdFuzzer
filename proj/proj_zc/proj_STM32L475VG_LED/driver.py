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
RAM_SIZE = 0x40000000 - 0x20000000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.1." + format(RAM_SIZE, '#04x')
            }
RAM_FILES = [
    RAM_FILE,
    {'start': 0x10000000, 'size': 0x8000,
     'file': "/dev/shm/SHM.2." + format(RAM_SIZE, '#04x')
     },
]

sample = './Hello_STM.hex.raw'
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


def before_remote_memory_access(avatar, remote_memory_msg, **kwargs):
    print('State in watchman before read remote memory access: %s' % qemu.state)
    qemu.saveVMSnapshot("test_qemu_snapshot")

def after_remote_memory_access(avatar, remote_memory_msg, **kwargs):
    print('State in watchman after read remote memory access: %s' % qemu.state)
    # qemu.infoVMSnapshot()

def before_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print('State in watchman before hitting breakpoint: %s' % qemu.state)
    qemu.infoVMSnapshot()

def after_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print('State in watchman after hitting breakpoint: %s' % qemu.state)
    qemu.infoVMSnapshot()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Watchmen
    avatar.watchmen.add_watchman('RemoteMemoryRead', 'before', before_remote_memory_access, is_async=False)
    avatar.watchmen.add_watchman('RemoteMemoryRead', 'after', after_remote_memory_access, is_async=False)
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
    # buggy
    # qemu.set_breakpoint(0xd8c)
    # subprocess.run("dd if=/snapshot/ramFile of=/dev/shm/SHM.1.0x14000", shell=True)

    logger.info("[+] Running in QEMU until a peripherial is accessed")

    peripheral.qemu_instance = qemu

    # sleep(1000)
    # qemu.saveVMSnapshot("test_qemu_snapshot")
    # qemu.infoVMSnapshot()
    # qemu.loadVMSnapshot("test_qemu_snapshot")

    qemu.cont()
    qemu.wait()





    logger.info("[+] Finding bugs")

    regs = utils.get_registers(qemu.rr)

    scanf = a.SIM_PROCEDURES['libc']['scanf']
    printf = a.SIM_PROCEDURES['libc']['printf']
    strlen = a.SIM_PROCEDURES['libc']['strlen']
    memcpy = a.SIM_PROCEDURES['libc']['memcpy']
    memset = a.SIM_PROCEDURES['libc']['memset']
    angr.angr.hook(scanf_addr, scanf())
    angr.angr.hook(printf_addr, printf())
    angr.angr.hook(strlen_addr, strlen())
    angr.angr.hook(memcpy_addr, memcpy())
    angr.angr.hook(memset_addr, memset())

    try:
        exp = utils.explore(angr, regs, rom=ROM, rom_offset=ROM_START)
        exp.run()
    except:
        traceback.print_exc()
        import IPython;

        IPython.embed()

    qemu.protocols.gdb.remote_disconnect()

    while True:
        pass
    qemu.cont()
    qemu.wait()
    t = qemu.rr('pc')
    print("read pc from gdb: " + format(t, '#04x'))

    catch.close()
    avatar.shutdown()
