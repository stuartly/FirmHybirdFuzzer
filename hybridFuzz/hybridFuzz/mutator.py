#!/usr/bin python3.5

import os
import re
import random
from functools import cmp_to_key
from collections import OrderedDict
import json

#########################################
# by default, type(seed) is bytearray.  #
# and we don't check this in functions. #
#########################################

##############################################################################
# operations of seed files                                                   #
# todo: file num may repeated use (loop, mode operation);                    #
#       in this case, end < front.                                           #
#       if do this, we'd better to ensure file num is increasing one by one. #
##############################################################################
PRFFIX_SEED_FILENAME = "seed_id-"
PATTERN_SEED_FILENAME = re.compile(r"{0}\d+".format(PRFFIX_SEED_FILENAME))
STATUS_FILE = "seed_status.json"
'''
{
    "pre_seed_file": "filename", // no pre is empty str: ""
    "front_id": num,
    "end_id": num,
    "seed_files": {
        "file1": cycle,
        "file2": cycle,
        ...
        "filen": cycle
    }
}
'''


def string_cmp(a, b):
    '''
    see functools.cmp_to_key(func), notice the return value of func:(no True or False)
        - a negative number for less-than,
        - zero for equality
        - a positive number for greater-than
    '''
    if a == b:
        return 0
    elif len(a) == len(b):
        return 1 if a > b else -1
    else:
        return 1 if len(a) > len(b) else -1


def write_buf_2_file(buf, filename):
    with open(filename, mode="wb") as fwb:
        fwb.write(buf)


def read_buf_from_file(filename):
    if os.path.exists(filename):
        with open(filename, mode="rb") as frb:
            ret = frb.read()
        return bytearray(ret)
    else:
        print("[-] err in reading seed file!")
        return bytearray()



################
# mutate seeds #
################
INTERESTING_8 = [
   -128, # 0x80, Overflow signed 8-bit when decremented
   -1,   # 0xff
    0, 1,
    16,  # One-off with common buffer size
    32,  # One-off with common buffer size
    64,  # One-off with common buffer size
    100, # One-off with common buffer size
    127  # Overflow signed 8-bit when incremented
]

INTERESTING_16 = [
   -32768, # 0x8000, Overflow signed 16-bit when decremented
   -129,   # 0xff7f, Overflow signed 8-bit
    128,   # Overflow signed 8-bit
    255,   # Overflow unsig 8-bit when incremented #
    256,   # Overflow unsig 8-bit
    512,   # One-off with common buffer size
    1000,  # One-off with common buffer size
    1024,  # One-off with common buffer size
    4096,  # One-off with common buffer size
    32767  # Overflow signed 16-bit when incremented
]

INTERESTING_32 = [
   -2147483648, # 0x80000000, Overflow signed 32-bit when decremented
   -100663046,  # 0xfa0000fa, Large negative number (endian-agnostic)
   -32769,      # 0xffff7fff, Overflow signed 16-bit
    32768,      # Overflow signed 16-bit
    65535,      # Overflow unsig 16-bit when incremented
    65536,      # Overflow unsig 16 bit
    100663045,  # Large positive number (endian-agnostic)
    2147483647  # Overflow signed 32-bit when incremented
]

interesting_8  = INTERESTING_8
interesting_16 = INTERESTING_8 + INTERESTING_16
interesting_32 = INTERESTING_8 + INTERESTING_16 + INTERESTING_32

DATA_UNIT = {
    "byte": {
        "byte_num": 1,
        "interesting": interesting_8
    },
    "word": {
        "byte_num": 2,
        "interesting": interesting_16
    },
    "dword": {
        "byte_num": 4,
        "interesting": interesting_32
    }
}

ARITH_MAX = 35 # Maximum offset for integer addition / subtraction stages

# Caps on block sizes for cloning and deletion operations. Each of these
# ranges has a 33% probability of getting picked, except for the first
# two cycles where smaller blocks are favored:
HAVOC_BLK_SMALL  = 32
HAVOC_BLK_MEDIUM = 128
HAVOC_BLK_LARGE  = 1500
HAVOC_BLK_XL     = 32768 # Extra-large blocks, selected very rarely (<5% of the time):

MAX_FILE = 1 * 1024 * 1024 # Maximum size of input file, in bytes (keep under 100MB)

# Maximum stacking for havoc-stage tweaks. The actual value is calculated
# like this: 
# n = random between 1 and HAVOC_STACK_POW2
# stacking = 2^n
# In other words, the default (n = 7) produces 2, 4, 8, 16, 32, 64, or
# 128 stacked tweaks:
HAVOC_STACK_POW2 = 7

ENDIAN = ["big", "little"]

##########################
# sth. about lwip packet #
##########################
# refer to: lwip/src/include/lwip/def.h
# refer to: lwip/src/include/lwip/prot/ethernet.h, enum eth_type
ETH_TYPE = [
    bytearray(b"\x08\x00"), # ETHTYPE_IP, Internet protocol v4 */
    bytearray(b"\x08\x06"), # ETHTYPE_ARP, Address resolution protocol */
    bytearray(b"\x08\x42"), # ETHTYPE_WOL, Wake on lan */
    bytearray(b"\x80\x35"), # ETHTYPE_RARP, RARP */
    bytearray(b"\x81\x00"), # ETHTYPE_VLAN, Virtual local area network */
    bytearray(b"\x86\xDD"), # ETHTYPE_IPV6, Internet protocol v6 */
    bytearray(b"\x88\x63"), # ETHTYPE_PPPOEDISC, PPP Over Ethernet Discovery Stage */
    bytearray(b"\x88\x64"), # ETHTYPE_PPPOE, PPP Over Ethernet Session Stage */
    bytearray(b"\x88\x70"), # ETHTYPE_JUMBO, Jumbo Frames */
    bytearray(b"\x88\x92"), # ETHTYPE_PROFINET, Process field network */
    bytearray(b"\x88\xA4"), # ETHTYPE_ETHERCAT, Ethernet for control automation technology */
    bytearray(b"\x88\xCC"), # ETHTYPE_LLDP, Link layer discovery protocol */
    bytearray(b"\x88\xCD"), # ETHTYPE_SERCOS, Serial real-time communication system */
    bytearray(b"\x88\xE3"), # ETHTYPE_MRP, Media redundancy protocol */
    bytearray(b"\x88\xF7"), # ETHTYPE_PTP, Precision time protocol */
    bytearray(b"\x91\x00") # ETHTYPE_QINQ, Q-in-Q, 802.1ad */
]

def set_eth_type(seed, idx=12):
    if random.randint(0, 1) and len(seed) > idx+1:
        etht = random.choice(ETH_TYPE)
        seed[idx], seed[idx+1] = etht[0], etht[1]

# CVE-2018-16601 - IP DoS\Memory corruption
CVE_PACKET1 = (b"\x00\x00\x5e\x00\x01\x24\xac\xd1\xb8\xd1\x9b\x63\x08\x00\x4f\x00"    # \x4f
               b"\x00\x34\x09\xf6\x00\x00\x40\x06\x14\xf5\x42\x47\x29\x95\xc0\xa8"
               b"\x00\x66\x9a\xa0\x01\xbb\x33\x0f\x32\xbb\xa6\xcd\x4e\xc0\x80\x10"
               b"\x05\xce\x78\x7a\x00\x00\x01\x01\x08\x0a\xb7\x75\x25\x74\x00\x00"
               b"\x07\xf5")

# CVE-2018-16603 - TCP information leak
CVE_PACKET2 = (b"\x00\x00\x5e\x00\x01\x24\xac\xd1\xb8\xd1\x9b\x63\x08\x00\x45\x00"
               b"\x00\x34\x09\xf6\x00\x00\x40\x06\x14\xf5\x42\x47\x29\x95\xc0\xa8"
               b"\x00\x66") # with tcp mark and no tcp header

# CVE-2018-16523 - TCP Options information leak\DoS
CVE_PACKET3 = (b"\x00\x00\x5e\x00\x01\x24\xac\xd1\xb8\xd1\x9b\x63\x08\x00\x45\x00"
               b"\x00\x34\x09\xf6\x00\x00\x40\x06\x14\xf5\x42\x47\x29\x95\xc0\xa8"
               b"\x00\x66\x9a\xa0\x00\x50\x33\x0f\x32\xbb\xa6\xcd\x4e\xc0\xf0\x02" # \xf0
               b"\x05\xce\x78\x7a\x00\x00\x01\x01\x08\x0a\xb7\x75\x25\x74\x00\x00"
               b"\x07\xf5")

# CVE-2018-16524 - TCP Options information leak\DoS
CVE_PACKET4 = (b"\x00\x00\x5e\x00\x01\x24\xac\xd1\xb8\xd1\x9b\x63\x08\x00\x45\x00"
               b"\x00\x34\x09\xf6\x00\x00\x40\x06\x14\xf5\x42\x47\x29\x95\xc0\xa8"
               b"\x00\x66\x9a\xa0\x00\x50\x33\x0f\x32\xbb\xa6\xcd\x4e\xc0\x80\x02"
               b"\x05\xce\x78\x7a\x00\x00\x02\x04\x00\x00\x00\x00\x25\x74\x00\x00" # \x02\x04\x00\x00\x00\x00
               b"\x07\xf5")

REAL_PACKET5 = bytes([
    # ethe payload
    255, 255, 255, 255, 255, 255, # dest
    72, 77, 126, 169, 87, 31, # src
    8, 0, # u16, type
    # ip payload
    69, # _v_hl, if type is ETHTYPE_IP, this valus must 0x4?, and ? is ip_head_len(ip layer will *5)
    0, # _tos
    1, 72, # u16, _len
    127, 46, # u16, id
    0, 0, # u16, offset
    128, # _ttl
    17, # _proto
    241, 137, # u16, cksum
    114, 212, 86, 25, # dest
    255, 255, 255, 255, # src
    0, 68, 0, 67, 1, 52, 185, 189, 1, 1, 6, 0, 152, 98, 96, 188, 3, 0, 0, 0, 114, 212, 86, 25, 0, 0
])

EXAMPLE_PACKETS = [CVE_PACKET1, CVE_PACKET2, CVE_PACKET3, CVE_PACKET4, REAL_PACKET5]


def choose_block_len(limit):
    rlim = min(limit, 3)
    case = random.randint(0, rlim-1)
    if case == 0:
        min_value = 1
        max_value = HAVOC_BLK_SMALL
    elif case == 1:
        min_value = HAVOC_BLK_SMALL
        max_value = HAVOC_BLK_MEDIUM
    else:
        if random.randint(0, 10-1):
            min_value = HAVOC_BLK_MEDIUM
            max_value = HAVOC_BLK_LARGE
        else:
            min_value = HAVOC_BLK_LARGE
            max_value = HAVOC_BLK_XL

    if min_value >= limit:
        min_value = 1

    return min_value + random.randint(0, min(max_value, limit)-min_value)


def locate_diffs(seed1, seed2):
    f_loc = -1
    l_loc = -1
    minlen = min(len(seed1), len(seed2))
    for pos in range(minlen):
        if seed1[pos] != seed2[pos]:
            if f_loc == -1:
                f_loc = pos
            l_loc = pos
    return f_loc, l_loc


def flip_bit(seed):
    mut_pos = random.randint(0, len(seed)-1)
    mut_pos = mut_pos << 3
    seed[mut_pos >> 3] ^= (128 >> (mut_pos & 7))


def set_interesting_val(seed, data_unit=None):
    if data_unit is None or data_unit not in DATA_UNIT.keys():
        data_unit = random.choice(list(DATA_UNIT.keys()))
    else:
        if len(seed) >= DATA_UNIT[data_unit]["byte_num"]:
            mut_pos = random.randint(0, len(seed)-DATA_UNIT[data_unit]["byte_num"])
            interesting_val = random.choice(DATA_UNIT[data_unit]["interesting"])
            set_val_bytearray = bytearray(
                interesting_val.to_bytes(DATA_UNIT[data_unit]["byte_num"], byteorder=random.choice(ENDIAN),
                                         signed=True))
            for i in range(DATA_UNIT[data_unit]["byte_num"]):
                seed[mut_pos+i] = set_val_bytearray[i]
        else:
            return


def add_byte(b1, b2):
    return (b1 + b2) % 256


def sub_byte(b1, b2):
    return (b1 - b2) % 256


def sub_or_add_data(seed, data_unit=None, operation=None):
    if data_unit is None or data_unit not in DATA_UNIT.keys():
        data_unit = random.choice(list(DATA_UNIT.keys()))
    if operation not in [add_byte, sub_byte]:
        operation = random.choice([add_byte, sub_byte])

    if len(seed) >= DATA_UNIT[data_unit]["byte_num"]:
        mut_pos = random.randint(0, len(seed)-DATA_UNIT[data_unit]["byte_num"])
        op_num = 1 + random.randint(0, ARITH_MAX-1)
        op_num_bytearray = bytearray(
            op_num.to_bytes(DATA_UNIT[data_unit]["byte_num"], byteorder=random.choice(ENDIAN), signed=True))
        for i in range(DATA_UNIT[data_unit]["byte_num"]):
            seed[mut_pos+i] = operation(seed[mut_pos+i], op_num_bytearray[i])
    else:
        return


def set_random_byte(seed):
    mut_pos = random.randint(0, len(seed)-1)
    mut_val = random.randint(0, 255)
    seed[mut_pos] ^= mut_val


def delete_bytes(seed):
    if len(seed) >= 2:
        del_len = choose_block_len(len(seed)-1)
        del_from = random.randint(0, len(seed)-del_len)
        for i in range(del_len):
            seed.pop(del_from) # don't pop(del_from+i), because seed will change every pop operation
    else:
        return


def clone75_or_insert25_bytes(seed, maxlen):
    if maxlen < len(seed):
        for i in range(len(seed)-maxlen):
            seed.pop(random.randint(0, len(seed)-1))

    if len(seed) + HAVOC_BLK_XL < MAX_FILE:
        clone_to = random.randint(0, len(seed)-1)
        if random.randint(0, 4-1): # 1, 2, 3, 75% clone
            clone_len = choose_block_len(len(seed))
            clone_len = min(clone_len, abs(maxlen-len(seed)))
            clone_from = random.randint(0, len(seed)-clone_len)
            clone_bytes = seed[clone_from:clone_from+clone_len]
            for i in range(clone_len):
                seed.insert(clone_to + i, clone_bytes[i])
        else: # 0, 25% insert
            clone_len = choose_block_len(HAVOC_BLK_XL-1)
            clone_len = min(clone_len, abs(maxlen-len(seed)))
            insert_byte = random.randint(0, 255) if random.randint(0, 1) else random.choice(seed)
            for i in range(clone_len):
                seed.insert(clone_to + i, insert_byte) # here as same as seed.insert(clone_to, insert_byte)
    else:
        return


def overwrite_bytes_chunk75_or_fix25(seed):
    if len(seed) >= 2:
        copy_len = choose_block_len(len(seed)-1)
        copy_from = random.randint(0, len(seed)-copy_len)
        copy_to = random.randint(0, len(seed)-copy_len)
        if not random.randint(0, 4-1): # 25% select fixed bytes
            fix_byte = random.randint(0, 255) if random.randint(0, 1) else random.choice(seed)
            for i in range(copy_len):
                seed[copy_to+i] = fix_byte
        elif copy_from != copy_to: # %75 select chunk bytes
            copy_bytes = seed[copy_from:copy_from+copy_len]
            for i in range(copy_len):
                seed[copy_to+i] = copy_bytes[i]
    else:
        return


def havoc(seed, maxlen):
    use_stacking = 1 << random.randint(1, HAVOC_STACK_POW2)
    for i in range(use_stacking):
        mut_op = random.randint(0, 13)
        if mut_op == 0:
            flip_bit(seed)
            # print(seed.hex())
        elif mut_op == 1:
            set_interesting_val(seed, "byte")
            # print(seed.hex())
        elif mut_op == 2:
            set_interesting_val(seed, "word")
            # print(seed.hex())
        elif mut_op == 3:
            set_interesting_val(seed, "dword")
            # print(seed.hex())
        elif mut_op == 4:
            sub_or_add_data(seed, "byte", sub_byte)
            # print(seed.hex())
        elif mut_op == 5:
            sub_or_add_data(seed, "byte", add_byte)
            # print(seed.hex())
        elif mut_op == 6:
            sub_or_add_data(seed, "word", sub_byte)
            # print(seed.hex())
        elif mut_op == 7:
            sub_or_add_data(seed, "word", add_byte)
            # print(seed.hex())
        elif mut_op == 8:
            sub_or_add_data(seed, "dword", sub_byte)
            # print(seed.hex())
        elif mut_op == 9:
            sub_or_add_data(seed, "dword", add_byte)
            # print(seed.hex())
        elif mut_op == 10:
            set_random_byte(seed)
            # print(seed.hex())
        elif mut_op == 11:
            delete_bytes(seed)
            # print(seed.hex())
        elif mut_op == 12:
            clone75_or_insert25_bytes(seed, maxlen)
            # print(seed.hex())
        elif mut_op == 13:
            overwrite_bytes_chunk75_or_fix25(seed)
            # print(seed.hex())


def splice_buffers(seed, maxlen, seedpath):
    if os.path.exists(seedpath):
        filelist = os.listdir(seedpath)
        seed_file_list = [f for f in filelist if re.fullmatch(PATTERN_SEED_FILENAME, f)]
        f_diff, l_diff = -1, -1
        attempts = 0
        target_filename = random.choice(seed_file_list)
        target_seed = read_buf_from_file(os.path.join(seedpath, target_filename))
        while (target_seed == b'' or (
                (f_diff < 0 or l_diff < 2 or f_diff == l_diff) and (attempts < 2 * len(seed_file_list)))):
            attempts += 1
            target_filename = random.choice(seed_file_list)
            target_seed = read_buf_from_file(os.path.join(seedpath, target_filename))
            f_diff, l_diff = locate_diffs(seed, target_seed)

        if f_diff < 0 or l_diff < 2 or f_diff == l_diff:
            return

        split_at = f_diff + random.randint(0, abs(l_diff - f_diff - 1))
        for i, v in enumerate(target_seed):
            seed.insert(split_at + i, v)

    havoc(seed, maxlen)


def genone(seedlen):
    # todo: if seedlen > some num, maybe error?
    return bytearray(random.sample(range(0, 256), k=seedlen))


# The space-time overhead of this function is not negligible,
# so call it as little as possible.
def check_status_file(seedpath):
    if not os.path.exists(seedpath):
        os.mkdir(seedpath)
    status_file = os.path.join(seedpath, STATUS_FILE)
    is_valid = True
    if os.path.exists(status_file):
        with open(status_file, mode='r', encoding="utf-8") as fr:
            seed_status = OrderedDict(json.load(fr))
            pre_seed_file = seed_status.get("pre_seed_file", "")
            # front_seed_file = "{0}{1}".format(PRFFIX_SEED_FILENAME, seed_status.get("front_id", -1))
            end_seed_file = "{0}{1}".format(PRFFIX_SEED_FILENAME, seed_status.get("end_id", 0))
            seed_files = list(seed_status.get("seed_files", {}).keys())
            if len(seed_files) == 0:
                is_valid = False
            elif len(seed_files) == 1 and seed_files[-1] != end_seed_file:
                is_valid = False
            else:
                seed_files.sort(key=cmp_to_key(string_cmp))
                if seed_files[-1] != end_seed_file:
                    is_valid = False
            for f in seed_files + [pre_seed_file, end_seed_file]: #, front_seed_file
                fn = os.path.join(seedpath, f)
                if not os.path.exists(fn):
                    is_valid = False
                    break
    else:
        is_valid = False

    if not is_valid:
        filelist = os.listdir(seedpath)
        seed_file_list = [f for f in filelist if re.fullmatch(PATTERN_SEED_FILENAME, f)]
        seed_file_list.sort(key=cmp_to_key(string_cmp))
        if len(seed_file_list) > 0:
            front = re.findall(re.compile(r"\d+"), seed_file_list[0])[0]
            end = re.findall(re.compile(r"\d+"), seed_file_list[-1])[0]
        else:
            front, end = 0, -1

        seed_status = OrderedDict({
            "pre_seed_file": "",
            "front_id": int(front),
            "end_id": int(end),
            "seed_files": OrderedDict({

            })
        })
        for f in seed_file_list:
            seed_status["seed_files"][f] = 0

        with open(status_file, mode='w', encoding="utf-8") as fw:
            json.dump(seed_status, fw)
            fw.flush()


def init_seed_status(seedpath):
    check_status_file(seedpath)
    status_file = os.path.join(seedpath, STATUS_FILE)
    with open(status_file, mode='r', encoding="utf-8") as fr:
        seed_status = OrderedDict(json.load(fr))
        seed_status["seed_files"] = OrderedDict(seed_status["seed_files"])
    if len(seed_status["seed_files"]) == 0:
        end = seed_status["end_id"]
        end += 1
        fn = PRFFIX_SEED_FILENAME + str(end)
        seed_status["seed_files"][fn] = 0
        write_buf_2_file(genone(60), os.path.join(seedpath, fn)) # can't 500, don't know why. just 60
        for pack in EXAMPLE_PACKETS:
            end += 1
            fn = PRFFIX_SEED_FILENAME + str(end)
            seed_status["seed_files"][fn] = 0
            write_buf_2_file(pack, os.path.join(seedpath, fn))
        seed_status["end_id"] = end
        with open(status_file, mode='w', encoding="utf-8") as fw:
            json.dump(seed_status, fw)
            fw.flush()


# Before calling this function, you must call check_status_file()/init_seed_status() function at least once.
# By default, this function considers that the status_file is correct.
# That means: the seedpath is existed, the status_file is existed, and the context in status_file is credible.
"""
1. read a buf as a ret_seed
2. if front > end, means a loop done ==> set front and mutate(havoc or splice_buffers) all seed(all cycle+1)
3. if num of seed file < 2 ==> genone
4. if hit new bb2bb and pre_seed is exist ==> mutate: havoc and splice_buffers
5. if pre_seed cycle > 2 ==> remove
"""
def pass_buf_to_Cpp(seedpath, maxlen, is_hit):
    status_file = os.path.join(seedpath, STATUS_FILE)
    with open(status_file, mode='r', encoding="utf-8") as fr:
        seed_status = OrderedDict(json.load(fr))
        seed_status["seed_files"] = OrderedDict(seed_status["seed_files"])
    if seed_status["pre_seed_file"] != "":
        pre_seed_file = seed_status["pre_seed_file"]
    else:
        pre_seed_file = "nopreseed"  # os.path.join(seedpath, "nopreseed") will must be existed

    # check filequeue, if empty ==> genone and write, else read file, as return
    front, end = seed_status["front_id"], seed_status["end_id"]
    seed_file_list = list(seed_status.get("seed_files", {}).keys())
    seed_file_list.sort(key=cmp_to_key(string_cmp))
    if end < front and len(seed_file_list) > 0:
        front = int(re.findall(re.compile(r"\d+"), seed_file_list[0])[0])
        front -= 1 # whatever situation, front will +1 before this func return. so do not repect +1
        # mutate all!
        for sf in seed_file_list:
            s = read_buf_from_file(os.path.join(seedpath, sf))
            if random.randint(0, 1):
                havoc(s, maxlen)
            else:
                splice_buffers(s, maxlen, seedpath)
            end += 1
            fn = PRFFIX_SEED_FILENAME + str(end)
            seed_status["seed_files"][fn] = 0
            seed_status["seed_files"][sf] += 1
            set_eth_type(s, 12)
            write_buf_2_file(s, os.path.join(seedpath, fn))
    elif len(seed_file_list) < 2:
        ran_seed = genone(maxlen)
        end += 1
        fn = PRFFIX_SEED_FILENAME + str(end)
        seed_status["seed_files"][fn] = 0
        set_eth_type(ran_seed, 12)
        write_buf_2_file(ran_seed, os.path.join(seedpath, fn))

    # if need mutate? yes ==> mutate and write, else pass
    if is_hit and os.path.exists(os.path.join(seedpath, pre_seed_file)):
        pre_seed = read_buf_from_file(os.path.join(seedpath, pre_seed_file))

        mut_seed = pre_seed.copy()
        # print("before mutate...")
        # print(mut_seed.hex())
        havoc(mut_seed, maxlen)
        # print("after mutate1...")
        # print(mut_seed.hex())
        end += 1
        fn = PRFFIX_SEED_FILENAME + str(end)
        seed_status["seed_files"][fn] = 0
        set_eth_type(mut_seed, 12)
        write_buf_2_file(mut_seed, os.path.join(seedpath, fn))

        mut_seed = pre_seed.copy()
        splice_buffers(mut_seed, maxlen, seedpath)
        # print("after mutate2...")
        # print(mut_seed.hex())
        end += 1
        fn = PRFFIX_SEED_FILENAME + str(end)
        seed_status["seed_files"][fn] = 0
        set_eth_type(mut_seed, 12)
        write_buf_2_file(mut_seed, os.path.join(seedpath, fn))
        print("[+] mutate done(havoc and splice_buffers)!")

        seed_status["seed_files"][pre_seed_file] += 1

    # rm seed which mutate time > 5
    is_front_rm, is_front_done = False, True
    seed_file_list = list(seed_status.get("seed_files", {}).keys())
    seed_file_list.sort(key=cmp_to_key(string_cmp))
    for sf in seed_file_list:
        fid = int(re.findall(re.compile(r"\d+"), sf)[0])
        if seed_status["seed_files"][sf] > 2:
            if fid == front:
                is_front_rm, is_front_done = True, False
            os.remove(os.path.join(seedpath, sf))
            seed_status["seed_files"].pop(sf)
        elif is_front_rm and not is_front_done:
            front = fid
            is_front_rm = False
            is_front_done = True
    # update pre seed
    ret_seed_file = os.path.join(seedpath, PRFFIX_SEED_FILENAME + str(front))
    seed_status["pre_seed_file"] = PRFFIX_SEED_FILENAME + str(front)
    # print("[in mutator] ret_seed_file is " + ret_seed_file)
    ret_seed = read_buf_from_file(ret_seed_file)
    # print(ret_seed.hex())
    front += 1
    while not os.path.join(seedpath, PRFFIX_SEED_FILENAME + str(front)):
        if front > end:
            if is_hit:
                seed_file_list = list(seed_status.get("seed_files", {}).keys())
                seed_file_list.sort(key=cmp_to_key(string_cmp))
                front = int(re.findall(re.compile(r"\d+"), seed_file_list[0])[0])
            break
        front += 1

    seed_status["front_id"] = front
    seed_status["end_id"] = end
    with open(status_file, mode='w', encoding="utf-8") as fw:
        json.dump(seed_status, fw)
        fw.flush()
        os.fsync(fw.fileno())

    if random.randint(0, 1):
        pad_idx = len(ret_seed)
        for i in range(maxlen - pad_idx):
            ret_seed.insert(pad_idx+i, random.randint(0, 255)) # todo: I don't know why call genone will not work!!!
    return ret_seed