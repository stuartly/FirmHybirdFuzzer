#!/usr/bin/env python

import logging
from avatar2 import *
import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral
import subprocess

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

chop_lsb = lambda x: x - x % 2


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s - %(message)s')
logger_fh = logging.FileHandler(filename="./app.txt", mode='w')
logger.addHandler(logger_fh)
logger_fh.setFormatter(formatter)

# Global setting
OUT_DIR = "./myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
PROJ_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/united/ndss2018Exp/proj_ndss_vul"

# proj specific settings
sample = './expat_panda.bin'

DEBUG_PORT = 0x40004c04
TCP_USART_PORT = 9998

RAM_START = 0x20000000
RAM_SIZE = 0x14000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.1." + format(RAM_SIZE, '#04x')
            }

ROM_START=0x0
ROM_SIZE=0x80000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': 0x08000000}

# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BINARY=True


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

#set the start time.
peripheral.start_exec_time = time.time()


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


def start_panda_angr(avatar):
    """
    start panda & angr
    """
    # Add first target
    logger.info("[+] Creating the PANDATarget")
    panda = avatar.add_target(PandaTarget, name='panda',
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m3",
                              executable=PANDA_PATH,
                              raw = RAW_BINARY,
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

    # serial = avatar.add_memory_range(0x40004c00, 0x400, 'usart',
    #                                  persmissions='rw-')
    # serial2 = avatar.add_memory_range(0x40004400, 0x400, 'usart2',
    #                                  permissions='rw-')


    IgnorePeripheralList = {
            "PeripheralRange1": (0x40000000, 0x400),
            "PeripheralRange2": (0x40004800, 0x400),
            "PeripheralRange3": (0x40005000, 0x1000000-0x5000),
            }

    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=0x08000000, stopHooks = stopHooks,
                                qemu_target=panda, angr_target=angr, chip_specific = {}, 
                                alg = utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts = ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=6,
                                depth=5,
                                his = 30,
                                permissions='rw-')

    # Properties
    # serial.qemu_name = 'stm32l1xx-usart'
    # serial.qemu_properties = {'type' : 'serial', 'value': 0, 'name':'chardev'}
    # panda.additional_args = ["-serial", "tcp::%s,server,nowait" % TCP_USART_PORT]
    # serial2.qemu_name = 'stm32l1xx-usart'
    # serial2.qemu_properties = {'type' : 'serial', 'value': 1, 'name':'chardev'}

    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in PANDA until a peripherial is accessed")
    # panda.set_breakpoint(0x800b12c)

    # logger.info("[+] Use previous states")
    # with open(PROJ_PATH + "/snapshot/regs.json", 'r') as f:
    #     regs = json.loads(f.read())
    #     for r, v in regs.items():
    #         panda.write_register(r, v)
    # logger.info("[+] Registers ==> Done")
    # subprocess.run("dd if=" + PROJ_PATH + "/snapshot/ramFile of=/dev/shm/SHM.1.0x14000", shell=True)
    # logger.info("[+] Memory ==> Done")
    # logger.info("[+] Manipulate Qemu memory and registers ------------> Done!")


    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory,'conf.json')]
    # plugins += ['callstack=true']
    plugins += ['callframe=true']
    plugins += ['segment=true']

    plugins += ['hooknetwork=true']
    plugins += ['net_fun=%d' % 0x800b688]
    plugins += ['net_buf_file=%s' % "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/united/ndss2018Exp/proj_ndss_vul/fuzzing/sample_trigger"]
    plugins += ['crash_path=%s' % "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/united/ndss2018Exp/proj_ndss_vul/fuzzing"]
    plugins += ['buf_reg_index=%d' % 0]
    plugins += ['len_reg_index=%d' % 1]

    #get funcs.json
    funcs = get_symbols('./expat_panda.elf')
    f = open("funcs2.json", "a")
    f.write(str(funcs))
    f.close()

    plugins += ['stackobjects=true']
    plugins += ['debugfile=%s/%s' % ( PROJ_PATH,'funcs2.json')]

    heap_funcs = ['malloc', 'free', 'realloc']
    heap_funcs_r = ['_malloc_r', '_realloc_r', '_free_r']
    #
    plugins += ['heapobjects=true']
    plugins += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]
    plugins += ['%s=%d' % (f[1:], funcs[f]) for f in heap_funcs_r]
    # plugins += ['fstring=true']
    # plugins += ['printf=%d' % funcs['printf']]
    # plugins += ['fprintf=%d' % funcs['vfprintf']]
    # plugins += ['sprintf=%d' % funcs['sprintf']]
    wycinwyc_args = ','.join(plugins)
    logger.info("[+] wycinwyc_args: " + wycinwyc_args)
    panda.load_plugin('wycinwyc', wycinwyc_args)

    panda.cont()

    logger.info("[+] After panda.cont()")

    panda.wait()





if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)
    start_panda_angr(avatar)



    while True:
        pass


