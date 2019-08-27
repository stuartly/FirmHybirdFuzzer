#!/usr/bin/env python

from avatar2 import *
import logging
import concolic.utils as utils
import concolic.peripheral as peripheral
import subprocess


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s - %(message)s')
logger_fh = logging.FileHandler(filename="./logfiles/app.txt", mode='w')
logger.addHandler(logger_fh)
logger_fh.setFormatter(formatter)

PANDA_PATH = "/build/arm-softmmu/qemu-system-arm"
OUT_DIR = "./logfiles/myavatar"
PROJ_PATH = ""


# proj specific settings
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

sample = './net.bin'
ROM_START=0x0
ROM_SIZE=0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

# DEBUG_PORT = None
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

__assertion_failed = 0x9469
ASSERT_FUNC = {__assertion_failed}

FIXPV = {0x4006a004:0x80}


if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget, name='panda',
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                              executable=PANDA_PATH,
                              raw = RAW_BIBARY,
                             interval = 1)

    logger.info("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, name='angr', \
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

    IgnorePeripheralList = {
            "all-device": (0x40000000, 0x1000000),
            }
    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START, stopHooks = stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific = {}, alg = utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts = ASSERT_FUNC,
                                fixedPeriV = FIXPV,
                                debug_port=DEBUG_PORT,
                                forward_depth=3,
                                depth=2,
                                his = 30,
                                permissions='rw-')


    
    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in PANDA until a peripherial is accessed")
    # panda.set_breakpoint(0xf32)


    # logger.info("[+] Use previous states")
    # with open(PROJ_PATH + "/snapshot/regs.json", 'r') as f:
    #     regs = json.loads(f.read())
    #     for r, v in regs.items():
    #         panda.write_register(r, v)
    # logger.info("[+] Registers ==> Done")
    # subprocess.run("dd if=" + PROJ_PATH + "/snapshot/ramFile of=/dev/shm/SHM.0.0x40000", shell=True)
    # logger.info("[+] Memory ==> Done")
    # logger.info("[+] Manipulate Qemu memory and registers ------------> Done!")


    # logger.info("[+] Load panda plugins")
    # plugins += ['callstack=true']
    # funcs = get_symbols('./expat_panda.elf')

    # heap_funcs = ['malloc', 'free', 'realloc']

    # plugins += ['heapobjects=true']
    # plugins += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]
    # plugins += ['fstring=true']
    # plugins += ['printf=%d' % funcs['printf']]
    # hooknet_args = ','.join(plugins)

    # hooknet_args = ''
    # logger.info("[+] hooknet2: " + hooknet_args)
    # panda.load_plugin('hooknet2', hooknet_args)


    panda.cont()
    panda.wait()


    while True:
        pass


