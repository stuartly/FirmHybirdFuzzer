#!env python

import logging
from avatar2 import *
import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

chop_lsb = lambda x: x - x % 2

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
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
PROJ_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_zc/proj_bug/proj_STM32L475VG_NFC_WriteTag_allbugs"
ROM_START = 0x8000000
ROM_SIZE = 0x100000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}


# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

ASSERT_FUNC = {}

def get_symbols(filename):
    funcs = {}
    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        sym_sec = elf.get_section_by_name('.symtab')
        for symbol in sym_sec.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC' or \
               symbol.name =='rtc_inited':
                funcs[str(symbol.name)] = chop_lsb(symbol['st_value'])
    return funcs

#DEBUG_PORT
DEBUG_PORT = 0x40013804

# this data is delivered to Angr for correct execution
# Qemu is able to implement system control registers
# Chip_Specific_Info = {0xe000ed00: ("cpuid", 0x410FC241),
#                       0xe000e01c: ("SysTick Calibration Value Register", 0x00),
#                       0xe000e400: ("cpuid", 0xF0),
#                       }
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

# scanf_addr = 0x4291
# printf_addr = 0x4e1


ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    print("[+] Creating the PandaTarget")
    panda = avatar.add_target(PandaTarget, name="panda",
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                              #gdb_port = 3333,
                              #qmp_port = 3334,
                              executable=PANDA_PATH,
                              raw = RAW_BIBARY,
                             interval = 60)
    print("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILES, \
            load_options={'main_opts': {'backend':'blob', 'custom_arch':'ARM', \
                                        'custom_base_addr': LOAD_OFFSET, 'custom_entry_point': 0x1001}})


    with open(sample, "rb") as binary_file:
            # Read the whole file at once
            ROM = binary_file.read()


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
                                qemu_target=panda, angr_target=angr, chip_specific={},
                                alg=utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts=ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=2,
                                depth=1,
                                his=40,
                                permissions='rw-')

    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    peripheral.start_exec_time = time.time()

    #Note: when using panda, add the panda plugin firstly, the stackobject and heapobject has some problem
    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]
    plugins += ['callstack=true']
    plugins += ['callframe=true']
    plugins += ['segment=true']
    plugins += ['div=true']

    # get funcs.json
    funcs = get_symbols('./expat_panda.elf')
    f = open("funcs2.json", "a")
    f.write(str(funcs))
    f.close()

    plugins += ['stackobjects=true']
    plugins += ['debugfile=%s/%s' % (PROJ_PATH, 'funcs2.json')]
    #
    #heap_funcs = ['malloc', 'free', 'realloc']
    #heap_funcs_r = ['_malloc_r', '_realloc_r', '_free_r']
    #
    #plugins += ['heapobjects=true']
    # plugins += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]
    # plugins += ['%s=%d' % (f[1:], funcs[f]) for f in heap_funcs_r]
    # plugins += ['fstring=true']
    # plugins += ['printf=%d' % funcs['printf']]
    # plugins += ['fprintf=%d' % funcs['vfprintf']]
    # plugins += ['sprintf=%d' % funcs['sprintf']]
    wycinwyc_args = ','.join(plugins)
    logger.info("[+] wycinwyc_args: " + wycinwyc_args)
    panda.load_plugin('wycinwyc', wycinwyc_args)


    panda.cont()
    panda.wait()

    logger.info("[+] Finding bugs")

    regs = utils.get_registers(panda.rr)

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
        import IPython; IPython.embed()


    avatar.shutdown()
