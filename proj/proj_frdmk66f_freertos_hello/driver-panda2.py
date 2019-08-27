#!/usr/bin/env python

from avatar2 import *
from time import sleep
from multiprocessing import Process, Queue

import logging
import os

import hybridFuzz.fuzz as fuzz
import hybridFuzz.utils as utils
import hybridFuzz.peripheral as peripheral

from elftools.elf.elffile import ELFFile

chop_lsb = lambda x: x - x % 2

import random

# time/secs
RUN_TIME = 300
ONE_RUN_TIME = 120

# save snapshot before breakpoint or not
Snapshot_Name = "snapshot_befo_"
breakpoint = 0x7f6
is_before = True

# proj specific settings
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

sample = './frdmk66f_freertos_hello.axf.raw'
OUT_DIR = "./logfiles/myavatar"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
PROJ_PATH="/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_frdmk66f_freertos_hello"
QCOW2_Path="/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_frdmk66f_freertos_hello/snapshot.qcow2"
ROM_START=0x0
ROM_SIZE=0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

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


__assertion_failed = 0x1c51
ASSERT_FUNC = {__assertion_failed}

FIXPERIPHERALV = {0x4006a004:0x80}


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)


ROM = bytearray()

def before_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    while (avatar.targets['panda'].state != TargetStates.STOPPED):
        continue
    print("save vm snapshot before finishing the setup of shared memory")
    avatar.targets['panda'].saveVMSnapshot(Snapshot_Name)
    print("successfully saved")

def after_hit_breakpoint(avatar, remote_memory_msg, **kwargs):
    while(avatar.targets['panda'].state != TargetStates.STOPPED):
        continue
    print("save vm snapshot after finishing the setup of shared memory")
    avatar.targets['panda'].saveVMSnapshot(Snapshot_Name)
    print("successfully saved")

def updateState_after_cb(avatar, *args, **kwargs):
    if(args[0].state==TargetStates.EXITED):
        fuzz.gvfw.close()
        fuzz.total_time = fuzz.total_time + time.time() - peripheral.start_exec_time
        fuzz.save_gpq()
        print('Child process', os.getpid(), 'end')
        avatar.q.put(os.getpid())
        avatar.q.put(fuzz.total_time)
        sleep(10)
    return

def run(q):
    fuzz.gvfw.write("---------------New loop---------------\n")
    print('Parent process:', os.getppid(), 'Child process:', os.getpid())
    print("[+] Initializing the global_peripheral_queue")
    fuzz.init_gpq(ONE_RUN_TIME, q)
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)
    avatar.watchmen.add_watchman('UpdateState', 'after', updateState_after_cb)
    avatar.q = q

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    panda = avatar.add_target(PandaTarget, name='panda',
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                              executable=PANDA_PATH,
                              drive_qcow2=QCOW2_Path,
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
                                fixedPeriV = FIXPERIPHERALV,
                                debug_port=DEBUG_PORT,
                                forward_depth=4,
                                # depth=3,
                                his = 30,
                                permissions='rw-')


    
    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    peripheral.start_exec_time = time.time()

    ret = panda.infoVMSnapshot()
    if(Snapshot_Name not in ret):
        panda.set_breakpoint(breakpoint)
        print("set breakpoint",breakpoint)
    else:
        panda.loadVMSnapshot(Snapshot_Name)
        print("load snapshot",Snapshot_Name)

    if (is_before):
        avatar.watchmen.add_watchman('BreakpointHit', 'before', before_hit_breakpoint, is_async=False)
    else:
        avatar.watchmen.add_watchman('BreakpointHit', 'after', after_hit_breakpoint, is_async=False)

    logger.info("[+] Running in QEMU until a peripherial is accessed")
    # qemu.set_breakpoint(0x70a)
    # Note: when using panda, add the panda plugin firstly, the stackobject and heapobject has some problem
    logger.info("[+] Load panda plugins")
    plugins = ['mapfile=%s/%s' % (avatar.output_directory, 'conf.json')]
    # plugins += ['callstack=true']
    # plugins += ['callframe=true']
    # plugins += ['segment=true']
    # plugins += ['stackobjects=true']
    plugins += ['inst=true']
    # plugins += []
    funcs = get_symbols('./frdmk66f_freertos_hello.axf')
    f = open("funcs2.json", "a")
    f.write(str(funcs))
    f.close()
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

if __name__ == "__main__":
    print('rm myavatar',os.system('rm -rf %s'%OUT_DIR))
    print('Parent process:', os.getpid())
    rt = 0
    while (1):
        if (rt >= RUN_TIME):
            break
        q = Queue()
        child = Process(target=run, args=(q,))
        child.start()
        spid = q.get()
        rt = q.get()
        q.close()
        # sp = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
        # out, err = sp.communicate()
        # for line in out.splitlines():
        #     if 'qemu' in line:
        #         pid = int(line.split(None, 1)[0])
        #         print('kill qemu', os.kill(pid, signal.SIGKILL))
        print('kill qemu', os.system("ps -C qemu-system-arm -o pid=|xargs kill -9"))
        print('kill', spid, os.system('kill %d' % spid))
        # sleep(1)

    fuzz.clear_gpq()
    print("Timeout")


