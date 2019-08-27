import numpy as np
import time
import pickle
import os
from ctypes import *

total_path = 0


# Class of Seed
class Seed:
    def __init__(self, value, peripheral):
        self.value = value
        self.belongPerpherial = peripheral
        self.start_exec_time = 0
        self.end_exec_time = 0
        self.exec_time = 0
        self.exec_cnt = 0
        self.exec_path = []
        self.start_pc = 0
        self.end_pc = 0
        self.trigger_new_BB_To_BB = 0
        self.trigger_new_Peripheral_To_Peripheral = 0
        self.hitInstNum = 0
        self.hitBlockNum = 0
        self.score = 0

    def ComsumMe(self):
        self.start_exec_time = time.time()
        self.exec_cnt += 1

    def GetExecTime(self):
        return time.time() - self.start_exec_time

    def MutateMe(self):
        energy = 3
        mutationsList = Mutate(self.value, energy)
        for ele in mutationsList:
            ele_seed_instance = Seed(ele, self.belongPerpherial)
            global_peripheral_queue.setdefault(self.belongPerpherial, []).append(ele_seed_instance)

    @staticmethod
    def get_BB2BB_bitmap_size():
        # return 0

        Path_To_Interface = '/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/QemuInterface.so'

        # python call C to check if has new coverage
        interface = CDLL(Path_To_Interface)

        # call interface api

        ret = interface.get_bitmap_size()

        return ret

    @staticmethod
    def get_Peri2Peri_bitmap_size():
        return len(peripheral_to_periphearl_bitmap)

    def UpdateMe(self, truple):
        self.exec_time = self.GetExecTime()
        if Trigger_New_B2B():
            self.trigger_new_BB_To_BB = 1
        else:
            self.trigger_new_BB_To_BB = 0
        if Trigger_New_P2P(self, truple):
            self.trigger_new_Peripheral_To_Peripheral = 1
        else:
            self.trigger_new_Peripheral_To_Peripheral = 0

    def FilterMe(self):
        if global_peripheral_queue.__contains__(self.belongPerpherial):
            queue = global_peripheral_queue.get(self.belongPerpherial)

            if self.trigger_new_BB_To_BB == 0 and self.trigger_new_Peripheral_To_Peripheral == 0:
                queue.remove(self)
            elif self.exec_cnt >2 and (self.trigger_new_BB_To_BB == 1 or self.trigger_new_BB_To_BB == 1):
                queue.remove(self)
            else:
                queue.remove(self)
                queue.append(self)

# initialize global_peripheral_queue
def init_gpq(ONE_RUN_TIME, BB2BB, GVFILE,GRAPH_DIR, LOG_DIR, sst, queue):
    global global_peripheral_queue
    global peripheral_to_periphearl_bitmap
    global total_path
    global total_execution
    global total_start_time
    global single_start_time
    global one_run_time
    global bb2bb
    global q
    global gvfw
    global log_dir
    global graph_dir
    one_run_time = ONE_RUN_TIME
    q = queue
    gvfw = open(GVFILE, mode='a', buffering=1)
    log_dir = LOG_DIR
    graph_dir = GRAPH_DIR
    single_start_time = sst
    try:
        fr = open('/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/gpqFile.txt', 'rb')
        global_peripheral_queue = pickle.load(fr)
        peripheral_to_periphearl_bitmap = pickle.load(fr)
        total_path = pickle.load(fr)
        total_execution = pickle.load(fr)
        single_start_time = pickle.load(fr)
        total_start_time = pickle.load(fr)
        bb2bb = pickle.load(fr)
        fr.close()
    except IOError:
        global_peripheral_queue={}
        peripheral_to_periphearl_bitmap = []
        total_path = 0
        total_execution = 0
        total_start_time = sst
        bb2bb = 0
    finally:
        single_start_time = sst
        bb2bb = BB2BB
        save_gpq()

def load_gpq():
    global global_peripheral_queue
    global peripheral_to_periphearl_bitmap
    global total_path
    global total_execution
    global single_start_time
    global total_start_time
    global bb2bb
    try:
        fr = open('/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/gpqFile.txt', 'rb')
        global_peripheral_queue = pickle.load(fr)
        peripheral_to_periphearl_bitmap = pickle.load(fr)
        total_path = pickle.load(fr)
        total_execution = pickle.load(fr)
        single_start_time = pickle.load(fr)
        total_start_time = pickle.load(fr)
        bb2bb = pickle.load(fr)
        fr.close()
    except IOError:
        pass

def update_gpq(gv_file):
    '''call from c'''
    load_gpq()

    global single_start_time
    global total_start_time
    global total_execution
    global bb2bb
    tet = time.time() - single_start_time
    tt = time.time() - total_start_time
    total_execution += 1

    bbcov = 0
    if bb2bb > 0:
        bbcov = total_path / bb2bb

    if Trigger_New_B2B():
        trigger_new_BB_To_BB = 1
    else:
        trigger_new_BB_To_BB = 0

    # todo: update peripheral_to_periphearl_bitmap
    # gv_file = "/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/proj/proj_hjx/frdmk66f_lwip_httpsrv_bm/myavatar/gvfile.txt"
    with open(gv_file, mode='a', buffering=1) as gvfw:
        gvfw.write("trigger_new_BB_To_BB: %d\n"
                    "unique PP_To_PP: %d\n"
                    "unique BB_To_BB: %d\n"
                    "Total_Path: %d\n"
                    "Total_Events: %d\n"
                    "Total_Single_Exec_Time: %.3f\n"
                    "Total_Exec_Time: %.3f\n"
                    "Coverage of BB_To_BB: %.3f\n"
                    "---------------------------------\n"
                    % (trigger_new_BB_To_BB,
                       Seed.get_Peri2Peri_bitmap_size(),
                       Seed.get_BB2BB_bitmap_size(),
                       total_path,
                       total_execution,
                       tet,
                       tt,
                       bbcov))
        gvfw.flush()
        os.fsync(gvfw.fileno())

    save_gpq()

# save global_peripheral_queue
def save_gpq():
    global global_peripheral_queue
    global peripheral_to_periphearl_bitmap
    global total_path
    global total_execution
    global single_start_time
    global total_start_time
    global bb2bb
    with open('/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/gpqFile.txt', mode='wb', buffering=0) as fw:
        pickle.dump(global_peripheral_queue, fw)
        pickle.dump(peripheral_to_periphearl_bitmap, fw)
        pickle.dump(total_path, fw)
        pickle.dump(total_execution, fw)
        pickle.dump(single_start_time, fw)
        pickle.dump(total_start_time, fw)
        pickle.dump(bb2bb, fw)
        fw.flush()
        os.fsync(fw.fileno())

def clear_gpq():
    try:
        fr = open('/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt', 'r')
        shmid = fr.read()
        fr.close()
        print("rm shm", os.system('ipcrm shm %s' % shmid))
        print("rm shm_id.txt", os.system('rm -rf /home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt'))
    except IOError:
        print("rm shm")
    print("rm gpqFile",os.system('rm -rf /home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/gpqFile.txt'))

# global variable
global_peripheral_queue = {}
global_peripheral_pathMap = {}

exec_seed = Seed(0, 0)
peripheral_access_point = None
peripheral_to_periphearl_bitmap = []
visited_peripheral_access_point = []

schedule_mode = 1  # probability mode 1; time mode: 0;
schedule_cnt = 1  # schedule counter

total_path = 0
total_execution = 0
single_start_time = 0
total_start_time = 0

one_run_time = 0
bb2bb = 0
q = object
gvfw = None
log_dir = None
graph_dir = None

hook_network_receive_fun = {}


# Mutate Operator - Bitflip
def BitFlip(int_type, offset):
    mask = 1 << offset
    return (int_type ^ mask)


# generate new mutations based on seed input
def Mutate(seed, energy):
    mutationsList = []
    for i in range(energy):
        index = np.random.random_integers(5)
        # TODO: add more mutate operators, and the (low, high) could be reconfigred

        # add random number
        if index == 0:
            seed = seed + np.random.randint(0, 10)
            mutationsList.append(int(seed))
            continue

        # add random number
        if index == 1:
            seed = seed - np.random.randint(0, 10)
            mutationsList.append(int(seed))
            continue

        # Single Bitflip
        if index == 2:
            offset = np.random.randint(0, 10)
            seed = BitFlip(seed, offset)
            mutationsList.append(int(seed))
            continue

        # Four Bitflip
        if index == 3:
            offset = np.random.randint(0, 10)
            for i in range(offset, offset + 4):
                seed = BitFlip(seed, i)
            mutationsList.append(int(seed))
            continue

        # Eight Bitflip
        if index == 4:
            offset = np.random.randint(0, 10)
            for i in range(offset, offset + 8):
                seed = BitFlip(seed, i)
            mutationsList.append(int(seed))
            continue

    return mutationsList


def Trigger_New_B2B():
    # return 0

    Path_To_Interface = '/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/QemuInterface.so'

    # python call C to check if has new coverage
    interface = CDLL(Path_To_Interface)

    # call interface api
    ret = interface.hit_new_bits()

    return ret


def Trigger_New_P2P(seed, truple):
    # maintain a peripheral_to_peripheral bitmap, and update trigger_new_Peripheral_To_Peripheral
    if truple not in peripheral_to_periphearl_bitmap:
        peripheral_to_periphearl_bitmap.append(truple)
        return True
    else:
        return False
