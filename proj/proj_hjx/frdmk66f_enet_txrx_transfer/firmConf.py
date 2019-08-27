import hybridFuzz.utils as utils
# if you discover any variable need to modify in run_control.py, please move it here

# --------------------Firmware Setting------------------- #

# Firmware Dir
PROJ_PATH     = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_hjx/frdmk66f_enet_txrx_transfer"
FIRMWARE_NAME = "frdmk66f_enet_txrx_transfer"

SAMPLE      = PROJ_PATH + '/' + FIRMWARE_NAME + '.axf.raw'
SYMBOL_FILE = PROJ_PATH + '/' + FIRMWARE_NAME + '.axf'
QCOW2_Path  = PROJ_PATH + "/snapshot.qcow2"

# RAM
RAM_START = 0x1fff0000
RAM_SIZE  = 0x40000
RAM_FILE1  = {'start': RAM_START, 'size': RAM_SIZE, 'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')}
RAM_FILE = [ RAM_FILE1 ]

# ROM
ROM_START = 0x0
ROM_SIZE  = 0x200000
ROM_FILE  = {'start': ROM_START, 'size': ROM_SIZE, 'file': SAMPLE, 'alias': None}

# BOOT LOADER
EN_BOOT_LOADER = False
BOOT_LOADER_START = 0x0
BOOT_LOADER_SIZE = 0x100000

# LOAD_OFFSET
LOAD_OFFSET = 0x0
ENTRY_POINT = 0x1001
RAW_BIBARY  = True

INTERVAL = 1

# Unknown Peripheral Memory Range
UNKNOWN_PERIPHERAL_MEM_START = 0x40000000
UNKNOWN_PERIPHERAL_MEM_SIZE  = 0x50000000

# Debug Port
DEBUG_PORT = 0x4006a007



# --------------------Fuzzing Setting-------------------- #

# Fuzzing Boundary
EN_START_PC = False
START_PC    = 0xA86              # save snaphost at START_PC when first reach here, and start execution from here in later run
EN_END_PC   = False
END_PC      = 0xCB6              # stop execution at END_PC

# Execution Control
EN_MULTIPLE_RUN_TIME = False     # set this False to run only once
RUN_TIME             = 7200      # Total time of multiple run (time/sec)
EN_ONE_RUN_TIME      = True      # set time limit for single run
ONE_RUN_TIME         = 3200      # Total time of single run  (time/sec)

# Coverage Feedback Setting
EN_BB2BB = False                  # Enable counting the ratio of unique BB2BB coverage
BB2BB    = 100                   # Setting the total unique BB2BB number which is obtained by static analysis in advance

# Emulator
PANDA_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-panda/arm-softmmu/qemu-system-arm"
QEMU_PATH = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/build-qemu/arm-softmmu/qemu-system-arm"


# Fuzzing Output Dir
GRAPH_DIR     = PROJ_PATH + "/out-graph"
LOG_DIR       = PROJ_PATH + "/logfiles"
OUT_DIR       = PROJ_PATH + "/myavatar"
SYMBOL_OUTPUT = PROJ_PATH + '/funcs.json'
GV_FILE       = OUT_DIR + "/gvfile.txt"


# Sanpshot Name
SNAPSHOT_NAME = "snapshot_before_f_"


# --------------Symbolic Execution Setting--------------- #
CHIP_INFO          = {}
STOP_HOOKS         = {}
ASSERT_FUNC        = {}
FIXED_PERIPHERAL   = {}
MANUAL_PATH        = {}
PRIVATE_PERIPHERAL = {}
FORWAED_DEPTH      = 5
CONTEX_DEPTH       = 3
HIS                = 40
# class Alg_Enum(Enum):
#     Fast = 1
#     Explore_Mgr = 2
#     Explore_Single = 3
#     Explore_Single_Ignore_Speed = 4
#     Explore_Single_Explore_All = 5
PATH_SELECTION_MODE = utils.Alg_Enum.Explore_Single_Explore_All    # Path selection strategy

CREATE_SAMPLE = True
CREATE_QCOW2 = True

# -----------Fault Detection Plugin Setting-------------- #
EN_INST         = False
EN_CALL_STACK   = False
EN_CALL_FRAME   = False
EN_SEGMENT      = False
EN_HEAP_OBJ     = False
EN_STACK_OBJ    = False
EN_FORMAT       = False
EN_DIV          = False
EN_NET_HOOK     = True
EN_BYPASS_VERIFY= False
# --------Heap object tracking Plugin Setting------------ #
HEAP_FUNCS   = ['malloc', 'free', 'realloc']
HEAP_FUNCS_R = ['_malloc_r', '_realloc_r', '_free_r']
# --------Heap object tracking Plugin Setting------------ #
NET_FUNC      = "ENET_ReadFrame"
BUF_REG_INDEX = 2
LEN_REG_INDEX = 3