#!/usr/bin/env python

from avatar2 import *
import logging
import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral

# proj specific settings
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

sample = './frdmk66f_freertos_uart.axf.raw'
OUT_DIR = "./logfiles/myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
QCOW2_Path="/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/pro_situ_bugs/NXP_K66_Board/proj_nxp_frdmk66f_freertos_uart/snapshot.qcow2"
PROJ_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/pro_situ_bugs/NXP_K66_Board/proj_nxp_frdmk66f_freertos_uart"

ROM_START=0x0
ROM_SIZE=0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}

# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True
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
# funcs = utils.get_symbols('./frdmk66f_freertos_uart.axf')
# __assertion_failed = format(funcs["__assertion_failed"], "#04x")
# ASSERT_FUNC = {__assertion_failed}
ASSERT_FUNC = {}
FIXPERIPHERALV = {0x4006a004:0x80}

logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)


ROM = bytearray()

def before_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print("save vm snaphost before finishing the setup of shared memory")
    panda.saveVMSnapshot("Snapshot_before")


def after_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    print("save vm snaphost after finishing the setup of shared memory")
    panda.saveVMSnapshot("Snapshot_after")


if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)
    avatar.watchmen.add_watchman('BreakpointHit', 'before', before_hit_breakpoint, is_async=False)
    avatar.watchmen.add_watchman('BreakpointHit', 'after', after_hit_breakpoint, is_async=False)

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget, name='panda',
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                              executable=PANDA_PATH,
                              drive_qcow2=QCOW2_Path,
                              raw = RAW_BIBARY,
                              interval = 10)

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
                                fixedPeriV = FIXPERIPHERALV,
                                debug_port=DEBUG_PORT,
                                forward_depth=5,             #The forward_depth and depth should be adjusted via experiment.
                                depth=2,
                                his = 30,
                                permissions='rw-')

    
    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in QEMU until a peripherial is accessed")
    peripheral.start_exec_time = time.time()

    # Note: when using panda, add the panda plugin firstly, the stackobject and heapobject has some problem
    logger.info("[+] Load panda plugins")

    funcs = utils.get_symbols('./frdmk66f_Bug_freertos_uart.axf')
    f = open("funcs.json", "a")
    f.write(str(funcs))
    f.close()

    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]

    plugins += ['callstack=true']
    plugins += ['callframe=true']
    plugins += ['segment=true']
    plugins += ['div=true']
    plugins += ['stackobjects=true']
    plugins += ['debugfile=%s/%s' % (PROJ_PATH, 'funcs.json')]

    plugins += ['heapobjects=true']
    heap_funcs = ['pvPortMalloc', 'free', 'vPortFree']
    plugins += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]

    plugins += ['fstring=true']
    plugins += ['printf=%d' % funcs['DbgConsole_Printf']]
    # plugins += ['fprintf=%d' % funcs['vfprintf']]
    # plugins += ['sprintf=%d' % funcs['sprintf']]

    wycinwyc_args = ','.join(plugins)
    logger.info("[+] wycinwyc_args: " + wycinwyc_args)
    panda.load_plugin('wycinwyc', wycinwyc_args)

    #panda.set_breakpoint(0x836)
    panda.cont()
    panda.wait()


    while True:
        pass


