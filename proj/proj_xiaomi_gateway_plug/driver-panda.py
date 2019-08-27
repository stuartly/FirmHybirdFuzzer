#!/usr/bin/env python
from avatar2 import *

import logging

import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)

# proj specific settings
RAM_START = 0x20000000
RAM_SIZE = 0x20000
RAM_FILE1 = {'start': RAM_START, 'size': RAM_SIZE,
             'file': "/dev/shm/SHM.1." + format(RAM_SIZE, '#04x')
             }
RAM_FILE2 = {'start': 0x100000, 'size': 0x60000,
             'file': "/dev/shm/SHM.3." + format(0x60000, '#04x')
             }

RAM_FILES = [
    RAM_FILE1,
    RAM_FILE2,
]
sample = './plug.bin'
OUT_DIR = "./logfiles/myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
ROM_START = 0x1f000000
ROM_SIZE = 0x1000000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}

ROM_EFFECTIVE_START = 0x100000

ROM_LOAD_TO_EFFECTIVE_OFFSET = ROM_EFFECTIVE_START - ROM_START
ROM_EFFECTIVE_TO_LOAD_OFFSET = ROM_START - ROM_EFFECTIVE_START

# binary starts at LOAD_OFFSET
LOAD_OFFSET = 0x00
# if RAW_BIBARY is false, must provide entry_address
RAW_BIBARY = True

DEBUG_PORT = 0x46040000


ASSERT_FUNC = {}
MANUAL_PATH = {0x100467,}

# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
stopHooks = {}
MANUAL_PATH = {0x00104ED1,}


if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    print("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget, name='panda',
                             gdb_executable="arm-none-eabi-gdb",
                             firmware=sample, cpu_model="cortex-m4",
                             executable=PANDA_PATH,
                             entry_address=0x100000,
                             raw=RAW_BIBARY)
    print("[+] Creating the AngrTarget")
    # be careful, to support multiple rams, add "S" to "ram_file"
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILES, name='angr',
                             load_options={'main_opts': {'backend': 'blob', 'custom_arch': 'ARM',
                                                         'custom_base_addr': LOAD_OFFSET,
                                                         'custom_entry_point': 0x1001}})

    with open(sample, "rb") as binary_file:
        # Read the whole file at once
        ROM = binary_file.read()

    # add memory
    for ramfile in RAM_FILES:
        avatar.add_memory_range(ramfile['start'], ramfile['size'], name="ram" + ramfile['file'],
                                permissions='rwx')

    # ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
    #                                permissions='rw-')

    rom = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'], name='rom',
                                  file=sample,
                                  permissions='r-x', alias=ROM_FILE['alias'])

    bootloader = avatar.add_memory_range(0, 0x10000, name='bootloader',
                                         file="./bootloader.bin",
                                         permissions='r-x', alias=None)

    IgnorePeripheralList = {
        "all-device": (0x40000000, 0x10000000),
    }

    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=0x100000 - 0xc8,
                                load_to_effective_offset=ROM_LOAD_TO_EFFECTIVE_OFFSET,
                                effective_to_load_offset=ROM_EFFECTIVE_TO_LOAD_OFFSET,
                                stopHooks=stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific={},
                                asserts=ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                manual_path=MANUAL_PATH,
                                alg=utils.Alg_Enum.Explore_Single_Explore_All,
                                forward_depth=2,
                                depth=2,
                                his=40,
                                permissions='rw-')

    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    peripheral.start_exec_time=time.time()

    logger.info("[+] Running in QEMU until a peripherial is accessed")
    # qemu.set_breakpoint(0x70a)
    # Note: when using panda, add the panda plugin firstly, the stackobject and heapobject has some problem
    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]
    plugins += ['inst=true']
    # plugins += ['callstack=true']
    # plugins += ['callframe=true']
    # plugins += ['segment=true']
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

    while True:
        panda.cont()
        panda.wait()

