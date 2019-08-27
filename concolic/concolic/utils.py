from capstone import *
from capstone.arm  import *
from avatar2 import *

import logging
import traceback
import itertools
from enum import Enum

logger = logging.getLogger(__name__)

def nothing(state):
    logger.debug("[+] skipped instruction")
    logger.debug("[+] state.addr: " + format(state.addr, "#04x"))
    pass


def sameBasicBlock(state1, state2):
    """
    Determine wheter two states are in a same basic block
    """
    if state1.addr == state2.addr:
        return True

    if state1.addr in state2.block().instruction_addrs or \
       state2.addr in state1.block().instruction_addrs:
        return True

    return False


def state_end_with_return(s, code_full, rom_offset):
    code = code_full[s.addr - 1 - rom_offset:]
    addr = s.addr - 1
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True

    for insn in md.disasm(code, addr, 100):
        if arm_return(insn):
            return True
        if arm_branch(insn):
            return False
    return False

def path_default(s0, s1, code, rom_offset):
    # if Sx ends with return ins, we choose Sx
    if state_end_with_return(s0, code, rom_offset):
        return 0
    if state_end_with_return(s1, code, rom_offset):
        return 1

    # code far away is favorable
    if s0.addr > s1.addr:
        return 0
    else:
        return 1

    # any other heuristic? default
    return 1


def compare_state_regs(s0, s1):
    """
    Compare two states' concrete registers.
    Return True, if each concrete register value is equal.
    """
    regs0 = s0.regs
    regs1 = s1.regs

    if regs0.r0.concrete and regs1.r0.concrete and (s0.solver.eval(regs0.r0) != s1.solver.eval(regs1.r0)):
        logger.debug("s0r0 :" + format(s0.solver.eval(regs0.r0)) + "  s1r0: " + format(s1.solver.eval(regs1.r0)))
        return False
    if regs0.r1.concrete and regs1.r1.concrete and (s0.solver.eval(regs0.r1) != s1.solver.eval(regs1.r1)):
        logger.debug("s0r1 :" + format(s0.solver.eval(regs0.r1)) + "  s1r1: " + format(s1.solver.eval(regs1.r1)))
        return False
    if regs0.r2.concrete and regs1.r2.concrete and (s0.solver.eval(regs0.r2) != s1.solver.eval(regs1.r2)):
        logger.debug("s0r2 :" + format(s0.solver.eval(regs0.r2)) + "  s1r2: " + format(s1.solver.eval(regs1.r2)))
        return False
    if regs0.r3.concrete and regs1.r3.concrete and (s0.solver.eval(regs0.r3) != s1.solver.eval(regs1.r3)):
        logger.debug("s0r3 :" + format(s0.solver.eval(regs0.r3)) + "  s1r3: " + format(s1.solver.eval(regs1.r3)))
        return False
    if regs0.r4.concrete and regs1.r4.concrete and (s0.solver.eval(regs0.r4) != s1.solver.eval(regs1.r4)):
        logger.debug("s0r4 :" + format(s0.solver.eval(regs0.r4)) + "  s1r4: " + format(s1.solver.eval(regs1.r4)))
        return False
    if regs0.r5.concrete and regs1.r5.concrete and (s0.solver.eval(regs0.r5) != s1.solver.eval(regs1.r5)):
        logger.debug("s0r5 :" + format(s0.solver.eval(regs0.r5)) + "  s1r5: " + format(s1.solver.eval(regs1.r5)))
        return False
    if regs0.r6.concrete and regs1.r6.concrete and (s0.solver.eval(regs0.r6) != s1.solver.eval(regs1.r6)):
        logger.debug("s0r6 :" + format(s0.solver.eval(regs0.r6)) + "  s1r6: " + format(s1.solver.eval(regs1.r6)))
        return False
    if regs0.r7.concrete and regs1.r7.concrete and (s0.solver.eval(regs0.r7) != s1.solver.eval(regs1.r7)):
        logger.debug("s0r7 :" + format(s0.solver.eval(regs0.r7)) + "  s1r7: " + format(s1.solver.eval(regs1.r7)))
        return False
    if regs0.r8.concrete and regs1.r8.concrete and (s0.solver.eval(regs0.r8) != s1.solver.eval(regs1.r8)):
        logger.debug("s0r8 :" + format(s0.solver.eval(regs0.r8)) + "  s1r8: " + format(s1.solver.eval(regs1.r8)))
        return False
    if regs0.r9.concrete and regs1.r9.concrete and (s0.solver.eval(regs0.r9) != s1.solver.eval(regs1.r9)):
        logger.debug("s0r9 :" + format(s0.solver.eval(regs0.r9)) + "  s1r9: " + format(s1.solver.eval(regs1.r9)))
        return False
    if regs0.r10.concrete and regs1.r10.concrete and (s0.solver.eval(regs0.r10) != s1.solver.eval(regs1.r10)):
        logger.debug("s0r10 :" + format(s0.solver.eval(regs0.r10)) + "  s1r10: " + format(s1.solver.eval(regs1.r10)))
        return False
    if regs0.r11.concrete and regs1.r11.concrete and (s0.solver.eval(regs0.r11) != s1.solver.eval(regs1.r11)):
        logger.debug("s0r11 :" + format(s0.solver.eval(regs0.r11)) + "  s1r11: " + format(s1.solver.eval(regs1.r11)))
        return False
    if regs0.r12.concrete and regs1.r12.concrete and (s0.solver.eval(regs0.r12) != s1.solver.eval(regs1.r12)):
        logger.debug("s0r12 :" + format(s0.solver.eval(regs0.r12)) + "  s1r12: " + format(s1.solver.eval(regs1.r12)))
        return False
    if regs0.r13.concrete and regs1.r13.concrete and (s0.solver.eval(regs0.r13) != s1.solver.eval(regs1.r13)):
        logger.debug("s0r13 :" + format(s0.solver.eval(regs0.r13)) + "  s1r13: " + format(s1.solver.eval(regs1.r13)))
        return False
    if regs0.r14.concrete and regs1.r14.concrete and (s0.solver.eval(regs0.r14) != s1.solver.eval(regs1.r14)):
        logger.debug("s0r14 :" + format(s0.solver.eval(regs0.r14)) + "  s1r14: " + format(s1.solver.eval(regs1.r14)))
        return False
    if regs0.r15.concrete and regs1.r15.concrete and (s0.solver.eval(regs0.r15) != s1.solver.eval(regs1.r15)):
        logger.debug("s0r15 :" + format(s0.solver.eval(regs0.r15)) + "  s1r15: " + format(s1.solver.eval(regs1.r15)))
        return False
    return True


def same_state(s0, s1):
    """
    Determine whether two states are equal.
    """
    # TODO -- Potential bugs
    # Angr bug. state may have symbolic ip when do state stepping
    if s0.regs.ip.symbolic or s1.regs.ip.symbolic:
        return False
    if s0.addr != s1.addr:
        return False
    return compare_state_regs(s0, s1)

def fix_states(stateList):
    s00 = stateList[0][0]
    s10 = stateList[1][0]
    s01 = stateList[0][1]
    s11 = stateList[1][1]
    return same_state(s00, s10) and same_state(s01, s11)


def hookSkippedCode(state):
    """
    Hook the code, which angr cannot handle, to be skipped
    """
    for skipable_ins in disas_gethooks(Step_Hook.code[state.addr - 1 - Step_Hook.rom_offset:], state.addr - 1,
                                       state.block(state.addr).instructions
                                       ):
        if not state.project.is_hooked(skipable_ins[0]):
            state.project.hook(skipable_ins[0], nothing, length=skipable_ins[1])



class PMRSettings():
    """
    - Peripheral Memory Range Settings
    Global peripheral memory range settings
    """
    his_vec = []
    his_vec_full = False
    pmr = []
    global_v = []
    explore = False

    # global configurations -- TODO - temporary place
    pri_periph = False
    his = 50
    depth = 1
    forward_depth = 3
    asserts = {}
    manual_path = {}
    stopHooks = {}
    fixedPeriV = {}

    # uart debug
    debug_port = None
    firmware_debug = open("./logfiles/debug.txt", "a")


def in_asserts(state):
    """
    Reduce the effort to know the first instruction of a state.
    """
    return stateInList(state, PMRSettings.asserts)


def in_fixedPV(addr):
    if addr in PMRSettings.fixedPeriV:
        return PMRSettings.fixedPeriV[addr]
    return None


def record_hisPath(addr):
    """
    Record path to be compared in the future.
    """
    logger.debug("-cc-> record_hisPath: addr: " + format(addr, "#04x"))
    if len(PMRSettings.his_vec) != PMRSettings.his:
        PMRSettings.his_vec.append(addr)
    else:
        PMRSettings.his_vec.pop(0)
        PMRSettings.his_vec.append(addr)
        PMRSettings.his_vec_full = True


def log_realPath(angrPath):
    """
    Log the addr of each state in the path.
    """
    real_path = open("./logfiles/real_path.txt", "a")
    for path in angrPath:
        real_path.write(path + '\n')
    real_path.flush()
    real_path.close()


def repeatedSubstringCount(source):
    """Look for the shortest substring which when repeated equals
       the source string, without any left over characters.
       Return the maximum repeat count, 1 if none found.
    """
    length = len(source)
    maxLoop = 1

    for x in range(1, length // 2 + 1):
        substr = source[0-x:]

        for y in range(length//len(substr), 1, -1):
            if source[:length - y * len(substr)] + substr * y == source:
                maxLoop = maxLoop if maxLoop > y else y

    return maxLoop


def long_loop():
    """Test last 20 his if they contain more than 5 repeated cycles
    """
    if not PMRSettings.his_vec_full:
        return False

    # logger.debug("utils.PMRSettings.his_vec[-20:]: " + repr(utils.PMRSettings.his_vec[-20:]))
    if repeatedSubstringCount(PMRSettings.his_vec[-20:]) >= 5:
        return True
    return False


def hasMRS(state):
    """
    Determine whether this state contains a MRS instruction
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    insns = md.disasm(Step_Hook.code[state.addr - 1 - Step_Hook.rom_offset:], state.addr - 1,
                      state.block(state.addr).instructions)
    # logger.debug("-cc-> insns length: " + format(state.block(state.addr).instructions, "#04x"))
    for insn in insns:
        # logger.debug("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if insn.id in [ARM_INS_MRS]:
            return True

    return False


def isForQemu(state):
    """
    Determine whether it should transfer to Qemu
    TODO -- This function has a potential problem:
            If a peripheral value needs a long path to be generated, transferring to Qemu early leads
            to a wrong value.
    """
    if PMRSettings.pri_periph:
        logger.debug('[+] transfering to qemu due to private_peripheral')
        PMRSettings.pri_periph = False
        return True

    if state.addr in PMRSettings.stopHooks:
        logger.debug('[+] transfering to qemu due to designated long loop')
        return True

    # long loop such as memcpy?
    if len(PMRSettings.global_v) != 0 and long_loop():
        logger.debug('[+] transfering to qemu due to detected long loop')
        return True

    if state.addr >= 0xffff0000:
        logger.debug('[+] transfering to qemu due to interrupt ret')
        return True

    if hasMRS(state):
        logger.debug('[+] transfering to qemu due to MRS instruction')
        return True

    return False


def normal_step(simgr):
    """
    """
    if len(simgr.active) > 1:
        # Sometimes simgr.step() sets pri_periph *and* gets diverge.
        if PMRSettings.pri_periph:
            PMRSettings.pri_periph = False
        return simgr
    elif len(simgr.active) == 0:
        logger.debug("-cc-> dead state?")
        return simgr

    state = simgr.active[0]
    hookSkippedCode(state)

    if isForQemu(state):
        simgr.stopToQemu = True

    return simgr











class Step_Hook():
    code = bytearray()
    rom_offset = 0

    @staticmethod
    def concolic_step_func(sm):
        for state in sm.active:
            hookSkippedCode(state)
        return sm

class Alg_Enum(Enum):
    Fast = 1
    Explore_Mgr = 2
    Explore_Single = 3
    Explore_Single_Ignore_Speed = 4
    Explore_Single_Explore_All = 5


class Alg():
    def __init__(self, root_state, simgr, alg, proj, cpsr):
        self.root_state = root_state
        self.sm = simgr
        self.alg = alg
        self.proj = proj
        self.cpsr = cpsr

        # for Alg_Enum.Fast
        self.stateList = []
        self.stateListMaxLen = 2


    # Alg_Enum.Fast
    # ++++++++++++++++++++++++++++++
    def select_path_fast(self, sm):
        """
        Just see one following state.
        Heuristic ways, refer to path_default()
        """
        if len(simgr.active) > 2:
            logger.debug('more than 2 branches ... ignoring others')

        if len(self.stateList) == self.stateListMaxLen:
            self.stateList.pop(0)
        self.stateList.append([sm.active[0], sm.active[1]])

        path = path_default(sm.active[0], sm.active[1], Step_Hook.code, Step_Hook.rom_offset)

        # if the previous states are equal, take the opposite
        # A dead loop detection
        if len(self.stateList) == self.stateListMaxLen and fix_states(self.stateList):
            assert(path <= 1)
            return 1-path
        return path

    # ------------------------------
    # Alg_Enum.Fast


    # Alg_Enum.Explore_Mgr
    # ++++++++++++++++++++++++++++++

    def select_path_explore_mgr(self, sm):
        """
        Walk 5 steps and find the longest and highest one as the path.
        """
        # deep copy cannot deal with rom and rom_offset
        temp_sm = sm.copy(True)
        temp_temp_sm_list = []
        j = 0
        for s in temp_sm.active:
            temp_temp_sm = self.proj.factory.simgr(s)
            for i in range(5):
                try:
                    temp_temp_sm.step(step_func = Step_Hook.concolic_step_func, opt_level=0)
                    logger.debug("select_path_explore. current len: " +
                                              format(len(temp_temp_sm.active)))
                except:
                    logger.debug("select_path_explore error. current len: " +
                                              format(len(temp_temp_sm.active)))
                    traceback.print_exc()
                    break
            temp_temp_sm_list.append((j, temp_temp_sm))
            j+=1

        index = 0
        current_len = 0
        result = []

        for i, temp_temp_sm in temp_temp_sm_list:
            len_temp = len(temp_temp_sm.active)
            logger.debug("select_path_explore: len: " + format(len_temp))
            if len_temp > current_len:
                result = []
                current_len = len_temp
                result.append(i)
            elif len_temp == current_len:
                result.append(i)

        # favor more diversity

        # default: the higher address
        addr = 0
        for i in result:
            if temp_sm.active[i].addr > addr:
                addr = temp_sm.active[i].addr
                index = i

        return index

    # ------------------------------
    # Alg_Enum.Explore_Mgr



    # Alg_Enum.Explore_Single
    # ++++++++++++++++++++++++++++++
    def concolic_step_func_run1(self, sm):
        for state in sm.active:
            hookSkippedCode(state)

        if len(sm.active) == 1:
            s = sm.active[0]
            if loop_incremental(sm.ret, s) or in_asserts(s):
                logger.debug(repr(sm.ret))
                logger.debug('loop or assert detected ..')
                sm.dead = True
            if s.addr >= 0xffff0000:
                logger.debug('interrupt ret. assume high priority, thus regard as diverge')
                sm.div = True
            sm.ret.append(s)
        elif len(sm.active) == 0:
            sm.dead = True
        else:
            sm.div = True
        return sm

    def until_function1(self, sm):
        if len(sm.ret) > PMRSettings.forward_depth:
            return True
        if sm.dead or sm.div:
            return True

    def state_advance1(self, state):
        """
        stop at first diverge, abandon loops
        """
        # only hook skipable_ins for the init state. Others will be hooked by step_function
        hookSkippedCode(state)

        sm = self.proj.factory.simgr(state)

        sm.ret = [state]
        sm.dead = False
        sm.div = False

        sm.run(step_func=self.concolic_step_func_run1, until=self.until_function1, opt_level=0)
        logger.debug("advance result:")
        logger.debug(str(sm.ret))

        if sm.dead:
            return [[]]

        return [sm.ret]

    def all_history_states(self, state):
        ret = []
        his = state.history.parent
        while his.depth != 0:
            ret.insert(0, his.state)
            his = his.parent
        ret.insert(0, his.state)
        return ret


    # Alg_Enum.Explore_Single_Explore_All
    # ++++++++++++++++++++++++++++++
    def _filter_loop(self, state):
        bucket = self.all_history_states(state)
        if loop_incremental(bucket, state) or in_asserts(state):
            logger.debug('loop or assert detected .. move to loop')
            return True
        return False

    def _filter_intret(self, state):
        if state.addr >= 0xffff0000:
            logger.debug('interrupt ret. assume high priority, thus regard as diverge, mov to intret')
            return True
        return False


    def concolic_step_func_run2(self, sm):
        for state in sm.active:
            hookSkippedCode(state)

        assert(len(sm.active) != 0), "empty sm?"
        sm.move(from_stash='active', to_stash='loop', filter_func=self._filter_loop)
        sm.move(from_stash='active', to_stash='intret', filter_func=self._filter_intret)

        if len(sm.active) != 0 and sm.active[0].history.depth > PMRSettings.forward_depth:
            sm.move(from_stash='active', to_stash='max')

        return sm


    def advance_result2(self, sm):
        for s in sm.stashes['loop']:
            # bucket = self.all_history_states(s)
            # bucket.append(s)
            # logger.debug('loop: ' + repr(bucket))
            sm.ret.append([])
        for s in sm.stashes['intret']:
            bucket = self.all_history_states(s)
            bucket.append(s)
            logger.debug('int ret: ' + repr(bucket))
            sm.ret.append(bucket)
        for s in sm.stashes['max']:
            bucket = self.all_history_states(s)
            bucket.append(s)
            logger.debug('max length: ' + repr(bucket))
            sm.ret.append(bucket)


    def state_advance2(self, state):
        # only hook skipable_ins for the init state. Others will be hooked by step_function
        hookSkippedCode(state)

        state.history.depth = 0

        sm = self.proj.factory.simgr(state)

        sm.ret = []

        sm.run(step_func=self.concolic_step_func_run2, opt_level=0)
        self.advance_result2(sm)

        return sm.ret


    def select_path_explore_single(self, sm):

        ret = []
        addrs = []
        statePath = {}
        for s in sm.active:
            addrs.append(s.addr)
            statePath[s.addr] = []

            if detect_deadLoop(s, self.root_state):
                logger.debug("-cc-> dead loop???")
                statePath[s.addr].append([])
                ret.extend(statePath[s.addr])
                logger.debug(str(s) + " direct loop detected")
                continue
            if in_asserts(s):
                statePath[s.addr].append([])
                ret.extend(statePath[s.addr])
                logger.debug(str(s) + " assert detected")
                continue

            # ======================================
            logger.debug("exploring " + str(s))

            if self.alg == Alg_Enum.Explore_Single or self.alg == Alg_Enum.Explore_Single_Ignore_Speed:
                r = self.state_advance1(s)
            elif self.alg == Alg_Enum.Explore_Single_Explore_All:
                r = self.state_advance2(s)

            if len(r):
                logger.debug(str(s) + " has " + format(len(r)) + " possible paths.")
            else:
                logger.debug(str(s) + " fails to advance or loop detected or assert detected")
            statePath[s.addr].extend(r)
            ret.extend(statePath[s.addr])

        # # ret is extended according to the order of addrs[0...1]
        # logger.debug("-cc-> ret: " + str(ret))
        # # dict in lower version of Python does not keep the order of input data
        # logger.debug("-cc-> statePath: " + str(statePath))

        # ======================================
        # check similarity with PMRSettings.his_vec
        min_scores = self.similarity_with_his(PMRSettings.his_vec, ret)

        # min scores
        if len(min_scores) == 1:
            logger.debug("select " + format(min_scores[0]) + " due to similarity check")
            return self.branchSelection(min_scores[0], statePath, addrs)

        index = min_scores
        if self.alg == Alg_Enum.Explore_Single:
            # same score, the quicker diverge, the more favorable
            lens = [len(ss) if len(ss) != 0 else 100 for ss in ret]
            min_len = min([lens[x] for x in min_scores])
            index = [i for i, j in enumerate(lens) if j == min_len]

            if len(index) == 1:
                logger.debug("select " + format(index[0]) + " due to a shortest path to a diverge")
                return self.branchSelection(index[0], statePath, addrs)

        # ======================================
        # default: the higher address
        # for interrupts, we choose lower address because we want to handle all cases
        selection = {}
        for i in index:
            assert(len(ret[i]) != 0), "possibly dead code ... (assert or while 1)"
            x = self.branchSelection(i, statePath, addrs)
            selection[addrs[x]] = x

        # last 9 bits for interrupt number. 16 is for the first peripheral
        # if 0x000022A8 <= addrs[index[0]] <= 0x000027B2:
        if self.cpsr & 0x01FF >= 16: # interrupt is true
            index_r = selection[sorted(selection)[0]]
            logger.debug("select " + format(index_r) + " due to lower addr (in interrupt)")
        else:
            index_r = selection[sorted(selection)[-1]]
            logger.debug("select " + format(index_r) + " due to higher addr")

        return index_r


    def similarity_with_his(self, his, states):
        # return highest indexes
        scores = []
        for s in states:
            if len(s) == 0:
                # lease likely to be choosen. max similarity
                scores.append(100)
                continue
            scores.append(self.similarity([entry.addr for entry in s], his))
        logger.debug('scores:' + repr(scores))
        return [i for i, j in enumerate(scores) if j == min(scores)]

    def similarity(self, vec, his):
        """
        0-100, 0 is the lest similar; 100 is the most similar;
        100 is exclusive for definite loop/assert etc.
        this function returns 0-90 for others
        """
        repeated_n = 0
        joint_set = set(vec) & set(his)
        for x in vec + his:
            if x in joint_set:
                repeated_n += 1
        score = repeated_n / float(len(vec + his))
        score *= 90
        return round(score)


    def branchSelection(self, x, sp, addrs):
        """
        Select one branch according to the length.
        TODO -- Assumption: in Python, list is ordered.
        Actually, in Python 3.7, dict has the generated order.
        """
        ll = 0
        i =0
        for addr in addrs:
            assert(addr == addrs[i]), "addr: " + format(addr, "#04x") + " addrs[i]: " + format(addrs[i], "#04x") + " i: " + str(i)
            ll += len(sp[addr])
            if x < ll:
                return i
            i += 1

    def process(self):
        if stateInList(self.root_state, PMRSettings.manual_path):
            # manual selection for a path
            class Dummy:
                branch_index = 0
            dummy = Dummy()
            logger.info('manually choose a path: (take a while to load terminal, ctrl+d after input)')
            logger.info('Hint: dummy.branch_index=')
            import IPython; IPython.embed()
            return dummy.branch_index

        PMRSettings.explore = True
        if self.alg == Alg_Enum.Fast:
            ret = self.select_path_fast(self.sm)
        if self.alg == Alg_Enum.Explore_Mgr:
            ret = self.select_path_explore_mgr(self.sm)
        if self.alg == Alg_Enum.Explore_Single or self.alg == Alg_Enum.Explore_Single_Ignore_Speed\
                or self.alg == Alg_Enum.Explore_Single_Explore_All:
            ret = self.select_path_explore_single(self.sm)

        PMRSettings.explore = False
        return ret


def stateInList(state, l):
    """
    Determine whether the instruction addresses of a state are in a list
    provided by ...
    """
    if not l:
        # empty list
        return False
    for addr in state.block().instruction_addrs:
        if addr in l:
            return True
    return False




def advance(s, addr):
    # todo: may have skipaale inst?
    # why not simgr?
    succ = s.step(size=addr - s.addr, opt_level=0)
    tmp = succ.successors[0]
    assert tmp.addr == addr
    return tmp


def detect_deadLoop(state1, state2):
    """
    Detect whether two states are in a (dead) loop.
    """
    _deadloop = False
    if sameBasicBlock(state1, state2):
        # logger.debug("-cc-> sameBasicBlock: state1.addr: " + format(state1.addr, "#04x") + "  state2.addr: " + format(state2.addr, "#04x"))
        if state1.addr == state2.addr:
            if isDeadLoop([state1, state2]):
                _deadloop = True
        elif state1.addr > state2.addr:
            tmp = advance(state2, state1.addr)
            if isDeadLoop([state1, tmp]):
                _deadloop = True
        else:
            tmp = advance(state1, state2.addr)
            if isDeadLoop([tmp, state2]):
                _deadloop = True

    return _deadloop


def isDeadLoop(states):
    # TODO -- need more thinking.
    if len(states) == 0 or len(states) == 1:
        return False
    for pair in itertools.combinations(range(len(states)), r=2):
        if same_state(states[pair[0]], states[pair[1]]):
            return True
    return False

def loop_incremental(states, state):
    # states is a list of states different from each other
    # state is compared with states
    if state is not None:
        for s in states:
            if same_state(s, state):
                return True
    return False


def arm_return(insn):
    #bx lr, or other regs?
    if insn.id in (ARM_INS_BX, ) and 'lr' == insn.reg_name(insn.operands[0].value.reg):
        logger.info('detect bx lr')
        return True
    #pop pc
    if insn.id in (ARM_INS_POP,):
        for i in insn.operands:
            if 'pc' == insn.reg_name(i.value.reg):
                logger.info('detect pop pc')
                return True
    #mov/add/sub pc
    if insn.id in (ARM_INS_MOV, ARM_INS_ADD, ARM_INS_SUB):
        if 'pc' == insn.reg_name(insn.operands[0].value.reg):
            logger.info('detect mov pc')
            return True
    return False


def arm_branch(insn):
    #normal branch
    if insn.id in (ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ, ARM_INS_B, ARM_INS_CBZ, ARM_INS_CBNZ):
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
    if insn.id in [ARM_INS_IT]:
        return False
    if insn.id in [ARM_INS_MRS] and PMRSettings.explore:
        # TODO -- Potential bugs
        logger.debug("skipped ins: 0x%x:\t%s\t%s -- Exploring" % (insn.address, insn.mnemonic, insn.op_str))
        return True
    if len(insn.operands) == 0 and insn.id != ARM_INS_NOP:
        logger.debug("skipped ins: 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        return True
    if insn.id in (ARM_INS_MSR, ARM_INS_BKPT):
        logger.debug("skipped ins: 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
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

def disas_gethooks(code, addr, length):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    l = 0
    r = []
    for insn in md.disasm(code, addr, length):
        # logger.debug("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if skipable(insn):
            # logger.debug("can skip at " + format(addr + l, '#04x') + " size: " + format(insn.size))
            r.append([addr + l + 1, insn.size])
        l += insn.size
        if arm_branch(insn):
            break

    ret = combine_adjacent_ins(r)
    return ret

def arrary_to_dict(regs, pc):
    d = {'r0': regs[0], 'r1': regs[1], 'r2': regs[2], 'r3': regs[3], 'r4': regs[4],
         'r5': regs[5], 'r6': regs[6], 'r7': regs[7], 'r8': regs[8], 'r9': regs[9],
         'r10': regs[10], 'r11': regs[11], 'r12': regs[12], 'r13': regs[13], 'r14': regs[14],
         'r15': pc | 1 , 'sp': regs[13], 'lr': regs[14], 'pc': pc | 1, 'cpsr': regs[16]}
    return d


def tb_info(regs_dic):
    s = "CPU env:\n"
    # todo
    s += repr(regs_dic)
    s += '\n cpsr: ' + format(regs_dic['cpsr'], '#05x')
    s += '\n pc: ' + format(regs_dic['pc'], '#05x')
    logger.debug(s)


all_regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
        'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc', 'cpsr']

def get_registers(rr):
    d = {}
    for r in all_regs:
        d[r] = rr(r)
        if r == 'pc':
            d[r] = d[r] | 1

    return d

class explore():
    def __init__(self, angr = None, regs = None, rom = None, rom_offset= None):
        self.angr = angr
        self.regs = regs
        self.ram_file = angr.ram_file
        self.rom = rom
        self.rom_offset = rom_offset

    def run(self):
        state = self.angr.angr.factory.avatar_state(self.angr, load_register_from=self.regs,
                                                    ram_file=self.ram_file)
        state.rom = self.rom
        state.rom_offset = self.rom_offset
        sm = self.angr.angr.factory.simgr(state, save_unconstrained=True)
        while len(sm.unconstrained) == 0:
            sm.step(step_func=Step_Hook.concolic_step_func, opt_level=0)

        unconstrained_state = sm.unconstrained[0]
        crashing_input = unconstrained_state.posix.dumps(0)

        with open('./crash_input.bin', 'wb') as fp:
            fp.write(crashing_input)
        logger.debug("buffer overflow found!")
        logger.debug(repr(crashing_input))
