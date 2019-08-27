#!/home/ubuntu/.virtualenvs/angr/bin/python
# encoding: utf-8
import struct

import angr, claripy
import archinfo
# import monkeyhex
#from archinfo import *

from capstone import *
from capstone.arm  import *

import logging
logging.getLogger('angr').setLevel('INFO')

load = 0
entry = 0x001e01


def disas(code, addr, count):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    for insn in md.disasm(code, addr, count):
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        if len(insn.operands) > 0:
            print("\tNumber of operands: %u" %len(insn.operands))
            c = -1
            for i in insn.operands:
                c += 1
                if i.type == ARM_OP_REG:
                    print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                if i.type == ARM_OP_IMM:
                    print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
                if i.type == ARM_OP_CIMM:
                    print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
                if i.type == ARM_OP_FP:
                    print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
                if i.type == ARM_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.value.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.base)))
                    if i.value.mem.index != 0:
                        print("\t\t\toperands[%u].mem.index: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.index)))
                    if i.value.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: 0x%x" \
                            %(c, i.value.mem.disp))

                if i.shift.type != ARM_SFT_INVALID and i.shift.value:
                    print("\t\t\tShift: type = %u, value = %u" \
                        %(i.shift.type, i.shift.value))

                #if i.ext != ARM_EXT_INVALID:
                #    print("\t\t\tExt: %u" %i.ext)

        if insn.writeback:
            print("\tWrite-back: True")
        if not insn.cc in [ARM_CC_AL, ARM_CC_INVALID]:
            print("\tCode condition: %u" %insn.cc)
        if insn.update_flags:
            print("\tUpdate-flags: True")

def arm_brach(insn):
    #normal branch
    if insn.id in (ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ, ARM_INS_B):
        return True
    #pop pc
    if insn.id in (ARM_INS_POP,):
        for i in insn.operands:
            if 'pc' == insn.reg_name(i.value.reg):
                return True
    #mov/add/sub pc
    if insn.id in (ARM_INS_MOV, ARM_INS_ADD, ARM_INS_SUB):
        if 'pc' == insn.reg_name(insn.operands[0].value.reg):
            return True
    return False

def skipable(insn):
    # no operands -> can be skipped?
    if len(insn.operands) == 0:
        return True
    if insn.id in (ARM_INS_MSR, ARM_INS_MRS):
        return True
    return False

def combine_adjacent_ins(r):
    ret = []
    for ent in r:
        if len(ret) == 0:
            ret.append(ent)
            continue

        if ret[-1][0] + ret[-1][1] == ent[0]:
            ret[-1][1] += ent[1]
        else:
            ret.append(ent)
    return ret


def disas_gethooks(code, addr):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    l = 0
    r = []
    for insn in md.disasm(code, addr, 100):
        # print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if skipable(insn):
            # print "can skip" + format(l) + " " + format(insn.size)
            r.append([addr + l + 1, insn.size])
        l += insn.size
        if arm_brach(insn):
            break

    ret = combine_adjacent_ins(r)
    return ret

input0 = claripy.BVS('input0', 32)
input1 = claripy.BVS('input1', 32)


def print_state(s):
    print s
    print s.solver.satisfiable()

def init_env(state):
    state.regs.r0 = 0x400ff000
    state.regs.r1 = 0x400ff040
    state.regs.r2 = 0xff0000
    state.regs.r3 = 0x1038
    state.regs.r4 = 0x20012f60
    state.regs.r5 = 0x40047000
    state.regs.r6 = 0x1000000
    state.regs.r7 = 0x400ff080
    state.regs.r8 = 0
    state.regs.r9 = 0
    state.regs.r10 = 0
    state.regs.r11 = 0
    state.regs.r12 = 0x1083e5
    state.regs.r13 = 0x20022018
    state.regs.r14 = 0x10843d


ROM = bytearray()


sample = '/home/ubuntu/IoT-ConcolicExecution/STM32F107.bin'

with open(sample, "rb") as binary_file:
        # Read the whole file at once
        ROM = binary_file.read()

def ins_hook_before(state):
    if state.inspect.instruction != None:
        print 'instruction (before) hook at', format(state.inspect.instruction, '#04x')

def ins_hook_after(state):
    if state.inspect.instruction != None:
        print 'instruction (after) hook at', format(state.inspect.instruction, '#04x')


def statement_hook(state):
    print 'statement hook at', format(state.inspect.statement, '#04x')


def state_advance(state):
    print_state(state)
    succ = state.step()
    if len(succ.successors) > 1:
        for s in succ.successors:
            state_advance(s)
    elif len(succ.successors) == 1:
        state_advance(succ.successors[0])

def simgr_advance(sigmr):
    while len(simgr.active) == 1:
        print("single exit, next: " + repr(simgr.active[0]))
        simgr.step()

def debug_funcRead(state):
    print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address

def debug_funcWrite(state):
    print 'Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address


proj = angr.Project(sample, auto_load_libs=False, main_opts={'backend': 'blob', 'custom_arch': 'ARM', \
        'custom_base_addr': load, 'custom_entry_point': entry})


state = proj.factory.blank_state(addr=entry, remove_options= angr.options.simplification | {angr.options.OPTIMIZE_IR})
init_env(state)

simgr = proj.factory.simgr(state)

def nothing(state):
    print "[+] skipped instruction"
    pass

while len(simgr.active) == 1:
    s = simgr.active[0]

    # for skipable_ins in disas_gethooks(ROM[s.addr - 1 - ROM_START:], s.addr - 1):
    #     if not proj.is_hooked(skipable_ins[0]):
    #         proj.hook(skipable_ins[0], nothing, length=skipable_ins[1])

    block = proj.factory.block(s.addr, traceflags = 0xff, num_inst = 7)
    block.pp()
    irsb = block.vex
    irsb.pp()
    simgr.step()
    if simgr.errored:
        import IPython; IPython.embed()
