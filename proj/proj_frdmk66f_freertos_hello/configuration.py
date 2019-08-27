# if you discover any variable need to modify in run_control.py, please move it here
# -----System Settings----- #
# check xxx only when EN_xxx is True
# time/secs
EN_RUN_TIME = True # set this False to run only once
RUN_TIME = 300
EN_ONE_RUN_TIME = True
ONE_RUN_TIME = 120

# bb2bb
EN_BB2BB = True
BB2BB = 20

# save snapshot before START_PC or if exist already, load snapshot and run from START_PC
# need *.qcow2 file exists
# SNAPSHOT_NAME must be completely defferent, if one is contained by another, the one may not be created
SNAPSHOT_NAME = "snapshot_before_f_"
EN_START_PC = True
START_PC = 0x7f6
# end running after END_PC
EN_END_PC = True
END_PC = 0x30ce


# -----Proj Settings----- #

# ----Avatar---- #
PROJ_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_frdmk66f_freertos_hello"
OUT_DIR = PROJ_PATH +"/logfiles/myavatar"
GV_FILE = OUT_DIR+"/gvfile.txt"

# ----Symbols---- #
SYMBOL_FILE = PROJ_PATH+'/frdmk66f_freertos_hello.axf'
SYMBOL_OUTPUT = PROJ_PATH+'/funcs2.json'

# ----Panda Target---- #
SAMPLE = PROJ_PATH +'/frdmk66f_freertos_hello.axf.raw'
CPU_MODEL="cortex-m4"
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
QCOW2_Path = PROJ_PATH+"/snapshot.qcow2"
RAW_BIBARY = True
INTERVAL=1

# ----Angr Target---- #
# binary starts at LOAD_OFFSET
LOAD_OFFSET = 0x0
ENTRY_POINT = 0x1001

# ----Memory---- #
RAM_START = 0x1fff0000
RAM_SIZE = 0x40000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }
ROM_START = 0x0
ROM_SIZE = 0x200000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': SAMPLE, 'alias': None}

# ---Ignore Peripheral--- #
IGNORE_PERIPHERAL_MEM = 0x40000000
IGNORE_PERIPHERAL_SIZE = 0x1000000
STOP_HOOKS = {}
ASSERT_FUNC = {}
# this data is delivered to Angr for correct execution
# Qemu is able to implement system control registers
# Chip_Specific_Info = {0xe000ed00: ("cpuid", 0x410FC241),
#                       0xe000e01c: ("SysTick Calibration Value Register", 0x00),
#                       0xe000e400: ("cpuid", 0xF0),
#                       }
# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
CHIP_SPECIFIC_INFO = {}
# Fast = 1
# Explore_Mgr = 2
# Explore_Single = 3
# Explore_Single_Ignore_Speed = 4
# Explore_Single_Explore_All = 5
ALG=5
ASSERT_FUNC = {}
FIX_PERIPHERAL_V = {0x4006a004: 0x80}
DEBUG_PORT = 0x4006a007
FORWARD_DEPTH = 4
DEPTH = 3
HIS = 30

# ----Plugins---- #
EN_INST = False
EN_CALL_STACK = False
EN_CALL_FRAME = False
EN_SEGMENT = False
EN_HEAP_OBJ = False
EN_STACK_OBJ = False
EN_FORMAT = False
EN_DIV = False
