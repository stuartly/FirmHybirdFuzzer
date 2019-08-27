from capstone import *
from capstone.arm import *
from avatar2 import *
from avatar2.peripherals import *

import angr as a
import claripy
import archinfo

import traceback
import uuid

import hybridFuzz.utils as utils
import hybridFuzz.fuzz as fuzz
import hybridFuzz.graph as graph
import subprocess

import time
import os
import sys
import numpy as np
from random import choice


seedqueue_max_len = 20 # default 20
symbolic_probability = 3  # default 3, probability to use symbolic execution (0-9)

logger = logging.getLogger(__name__)

# user configure file, load from the drive.py
peripheral_constraint_map = {}

start_exec_time = 0

class IgnorePeripheral(AvatarPeripheral):

    def inMemoryRange(self, addr):
        """
        Determine whether an address is in the peripheral memory ranges
        """
        for mr in utils.PMRSettings.pmr:
            if mr[0] <= addr <= mr[1]:
                return True
        return False

    def debug_funcRead(self, state):
        """
        Handle memory read operation:
        1. Put a symbol for the value from a peripheral.
        2. Return chip specific value
        3. Back to Qemu for private peripheral
        4. Read RAM
        """
        addr = state.solver.eval(state.inspect.mem_read_address)

        # if already meet core peripheral, we do not need to solve it and replay.
        if self.inMemoryRange(addr) and not utils.PMRSettings.pri_periph:
            ##### todo: need to extract real width
            sym_input = claripy.BVS('input' + uuid.uuid4().hex.upper(), state.inspect.mem_read_length * 8)
            if state.inspect.mem_read_length == 4:
                state.mem[addr].uint32_t = sym_input
            elif state.inspect.mem_read_length == 2:
                state.mem[addr].uint16_t = sym_input
            elif state.inspect.mem_read_length == 1:
                state.mem[addr].uint8_t = sym_input
            else:
                logger.debug("cannot handle length")
                assert False

            if not utils.PMRSettings.explore:
                tup = [addr, state.scratch.ins_addr, sym_input]
                utils.PMRSettings.global_v.append(tup)
                # only print out sym insertion for real path
                logger.debug("[+] insert one sym at pc " + format(state.scratch.ins_addr, '#05x')
                             + " for addr " + format(addr, '#05x') + ". " + format(len(utils.PMRSettings.global_v)))
            return

        if addr in self.chip_specific.keys():
            state.mem[addr].uint32_t = self.chip_specific[addr][1]
            return

        if not utils.PMRSettings.explore and 0xe0000000 <= addr <= 0xefffffff:
            logger.debug('unknown system control register in Anger')
            # should transter to QEMU
            utils.PMRSettings.pri_periph = True

    def debug_funcRead_a(self, state):
        logger.debug("Read, explore? " + str(utils.PMRSettings.explore))
        addr = state.solver.eval(state.inspect.mem_read_address)
        if not state.inspect.mem_read_expr.symbolic:
            expr = state.solver.eval(state.inspect.mem_read_expr)
            logger.debug('Read (after) value: ' + format(expr, '#04x') + ' from ' + format(addr, '#04x') + " pc: "
                         + format(state.scratch.ins_addr, '#04x'))
        else:
            logger.debug('Read (after) value: ' + " sym " + ' from ' + format(addr, '#04x') + " pc: "
                         + format(state.scratch.ins_addr, '#04x'))

    def debug_funcWrite(self, state):
        logger.debug("Write, explore? " + str(utils.PMRSettings.explore))

        addr = state.solver.eval(state.inspect.mem_write_address)
        if not state.inspect.mem_write_expr.symbolic:
            expr = state.solver.eval(state.inspect.mem_write_expr)
            logger.debug('Write (before) ' + format(expr, '#04x') + ' to ' + format(addr, '#04x') + " pc: "
                         + format(state.scratch.ins_addr, '#04x'))
        else:
            logger.debug('Write (before) ' + " sym " + ' to ' + format(addr, '#04x') + " pc: "
                         + format(state.scratch.ins_addr, '#04x'))

    def explore_path(self, depth, simgr, regs_dic, angrPath):
        """
        Explore paths in angr
        """
        angrPath.append("----------------")
        angrPath.append("Start: " + self.name)
        while depth != 0:
            simgr.stopToQemu = False
            logger.debug("-cc-> depth =================> " + format(depth))
            while len(simgr.active) == 1 and not simgr.stopToQemu:
                # step until the first symbolic branch
                # Not likely to transfer to Qemu for the first state.
                state = simgr.active[0]

                utils.record_hisPath(state.addr)
                angrPath.append(format(state.addr, "#04x"))

                simgr.step(step_func=utils.normal_step, opt_level=0)

            assert (not utils.PMRSettings.pri_periph)
            if simgr.stopToQemu:
                break
            assert (len(simgr.active) != 1)

            if len(simgr.active) >= 2:
                logger.debug(format(len(simgr.active)) + ' branch BB in depth: ' + format(depth))
                for s_debug in simgr.active:
                    logger.debug("-cc-> s_debug.addr: " + format(s_debug.addr, "#04x"))

                alg = utils.Alg(state.copy(), simgr, self.alg, self.angr.angr, regs_dic['cpsr'])
                branch_index = alg.process()

                logger.debug('taking branch ' + format(branch_index))
                keep_addr = simgr.active[branch_index].addr
                simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda state: state.addr != keep_addr)
                assert (len(simgr.active) == 1)
            depth -= 1

        # last choosen path is not recorded
        utils.record_hisPath(simgr.active[0].addr)
        angrPath.append(format(simgr.active[0].addr, "#04x"))

    def solve_path(self, simgr, pc, angrPath):
        """
        Generete the peripheral values according to paths
        """
        logger.debug("[+] active state #: " + format(len(simgr.active)))
        logger.debug("[+] global_v #: " + format(len(utils.PMRSettings.global_v)))
        logger.debug("[+] solving ...")

        assert (len(simgr.active) == 1)
        state = simgr.active[0]
        logger.debug("solving for state: " + str(state))
        # global_v: [[addr, ins_addr, sym_input], ...]
        for list_entry in utils.PMRSettings.global_v:
            # If we want to feed a fixed value, here is also a place.
            sym = list_entry[2]

            r = state.solver.eval_upto(sym, 3)
            assert len(r) != 0

            import numpy as np
            r = np.array(r, dtype=np.int)
            r = r[np.nonzero(r)]
            if len(r) == 0:
                solved_v = 0
            else:
                solved_v = np.min(r)

            list_entry.append(solved_v)
            logger.debug("solved, addr: " + format(list_entry[0], '#04x') +
                         " value: " + format(solved_v, '#04x') +
                         " size: " + format(sym.length // 8) +
                         " pc: " + format(list_entry[1], '#04x'))

        assert (len(simgr.active) == 1)

        ret = utils.PMRSettings.global_v[0][3]
        fetch_v = utils.PMRSettings.global_v.pop(0)
        logger.debug("[+] consume one sym at addr: " + format(fetch_v[0], '#04x') + ", pc: " + format(fetch_v[1],'#04x') + ".#" + format(len(utils.PMRSettings.global_v)))
        logger.debug("feed data: " + format(ret, '#04x'))
        logger.debug("Done...")
        assert (fetch_v[1] & ~1 == pc & ~1), "fetch_v[1]: " + format(fetch_v[1], "#04x") + ", pc: " + format(pc, "#04x")

        angrPath.append("\n")
        utils.log_realPath(angrPath)

        return ret

    # qemuTarget read data from angrTarget when reach a peripheral
    def hw_read(self, offset, size, pc, regs):
        fuzz.load_gpq()
        if(fuzz.peripheral_access_point is not None):
            fuzz.exec_seed = fuzz.global_peripheral_queue[fuzz.peripheral_access_point][-1]
        try:
            self.busy = True
            fixed = utils.in_fixedPV(self.address + offset, pc)
            if fixed:
                return fixed

            logger.debug("+++++++++++++++++++++++++++++++++")
            logger.debug("[+] QEMU reached peripheral: read")
            logger.debug("IGN: " + self.name + " read at: " + format(self.address + offset, '#04x') +
                         "(self.address: " + format(self.address, '#04x') +
                         " offset: " + format(offset, '#04x') + "), size: " + format(size, '#04x') +
                         ", pc: " + format(pc, '#04x'))

            regs_dic = utils.arrary_to_dict(regs, pc)
            utils.tb_info(regs_dic)

            # get fuzz.peripheral_access_point
            fuzz.peripheral_access_point = pc & ~1

            # TODO: return a network packet if it is a network peripheral access

            if fuzz.peripheral_access_point not in fuzz.visited_peripheral_access_point:
                fuzz.visited_peripheral_access_point.append(fuzz.peripheral_access_point)

            # online generating a peripheral-dependence-graph
            graph.current_peripheral_node = format(fuzz.peripheral_access_point, "#04x")
            read_from_peripheral_addr = format(self.address + offset, "#04x") + ":" + str(fuzz.exec_seed.value)
            graph.peripheral_access_dependencce_dot.edge(graph.last_peripheral_node, graph.current_peripheral_node,
                                                         label=read_from_peripheral_addr)

            # record peripheral_to_peripheral truple
            truple = [graph.last_peripheral_node, graph.current_peripheral_node]
            graph.last_peripheral_node = graph.current_peripheral_node
            # graph.peripheral_access_dependencce_dot.render("%s/%s"%(fuzz.graph_dir, 'pdg.gv'), view=False)

            fuzz.total_execution += 1

            # update the information of executed seed, and optimize seed queue
            if fuzz.exec_seed.start_exec_time != 0:
                fuzz.exec_seed.UpdateMe(truple)  # update seed execution info
                fuzz.exec_seed.FilterMe()  # filter seed from seed_queue

                if fuzz.exec_seed.trigger_new_BB_To_BB == 1:
                    fuzz.total_path += 1

                # DEBUG: output details of executed_seed
                tet = time.time() - start_exec_time
                tt = time.time() - fuzz.total_start_time
                bbcov=0
                if fuzz.bb2bb > 0:
                    bbcov = fuzz.total_path/fuzz.bb2bb
                fuzz.gvfw.write("exec_seed: %d\n"
                                "acess_peripheral: %d\n"
                                "exec_time: %.3f\n"
                                "exec_cnt: %d\n"
                                "trigger_new_BB_To_BB: %d\n"
                                "trigger_new_Peripheral_To_Peripheral: %d\n"
                                "unique PP_To_PP: %d\n"
                                "unique BB_To_BB: %d\n"
                                "Total_Path: %d\n"
                                "Total_Events: %d\n"
                                "Total_Single_Exec_Time: %.3f\n"
                                "Total_Exec_Time: %.3f\n"
                                "Coverage of BB_To_BB: %.3f\n"
                                "---------------------------------\n"
                                %(fuzz.exec_seed.value,
                                  fuzz.exec_seed.belongPerpherial,
                                  fuzz.exec_seed.exec_time,
                                  fuzz.exec_seed.exec_cnt,
                                  fuzz.exec_seed.trigger_new_BB_To_BB,
                                  fuzz.exec_seed.trigger_new_Peripheral_To_Peripheral,
                                  fuzz.exec_seed.get_Peri2Peri_bitmap_size(),
                                  fuzz.exec_seed.get_BB2BB_bitmap_size(),
                                  fuzz.total_path,
                                  fuzz.total_execution,
                                  tet,
                                  tt,
                                  bbcov))
                fuzz.gvfw.flush()
                os.fsync(fuzz.gvfw.fileno())
                                  
                if (fuzz.bb2bb > 0 and fuzz.total_path >= fuzz.bb2bb):
                    fuzz.gvfw.close()
                    fuzz.save_gpq()
                    print('Child process', os.getpid(), 'end BB2BB covered')
                    fuzz.q.put(os.getpid())
                    fuzz.q.put(tt)
                    fuzz.q.put(fuzz.total_path)
                    sleep(10)
                elif (fuzz.one_run_time > 0 and tet >= fuzz.one_run_time):
                    fuzz.gvfw.close()
                    fuzz.save_gpq()
                    print('Child process', os.getpid(), 'end timeout')
                    fuzz.q.put(os.getpid())
                    fuzz.q.put(tt)
                    fuzz.q.put(fuzz.total_path)
                    sleep(10)

                fuzz.exec_seed.MutateMe()  # generate mutations from the seed

                # if fuzz.exec_seed.trigger_new_BB_To_BB:
                #     fuzz.exec_seed.MutateMe()  # generate mutations from the seed

                # if fuzz.exec_seed.trigger_new_Peripheral_To_Peripheral:
                #     fuzz.exec_seed.MutateMe()

                # if fuzz.exec_seed.trigger_new_BB_To_BB or fuzz.exec_seed.trigger_new_Peripheral_To_Peripheral:
                #     fuzz.exec_seed.MutateMe()

            # situation 1: value for the peripheral has been generated by angrTarget and stored in global_v.
            # addr, pc, sym, branch1 input, branch2 input, etc...

            while len(utils.PMRSettings.global_v) != 0:
                logger.debug("[+] reuse previous solver result")
                logger.debug("[+] current solver result count: #" + format(len(utils.PMRSettings.global_v)))
                # In some cases, angr generate a value for a peripheral, but Qemu does not walk that path.
                # e.g., itt eq
                #       ldreq r1, [r0, #80]
                # Anyway, regenerate a value for the peripheral does not matter and affects consumed time only.
                fetch_v = utils.PMRSettings.global_v.pop(0)
                if fetch_v[1] & ~1 == fuzz.peripheral_access_point:
                    logger.debug(
                        "[+] consume one sym at addr: " + format(fetch_v[0], '#04x') + ", pc: " + format(fetch_v[1],
                                                                                                         '#04x'))
                    ret_v = fetch_v[3]

                    # create a seed based on PeripherlID and return value
                    consum_seed = fuzz.Seed(ret_v, fuzz.peripheral_access_point)

                    # record exec seed instance
                    fuzz.global_peripheral_queue.setdefault(consum_seed.belongPerpherial, []).append(consum_seed)
                    fuzz.exec_seed = consum_seed
                    fuzz.exec_seed.ComsumMe()
                    logger.debug("feed data 1: " + format(consum_seed.value, '#04x'))

                    # TODO: an grammar constraint check for generated peripheral input
                    # if peripheral_constraint_map.__contains__(fuzz.peripheral_access_point):
                    #     pconstraint = peripheral_constraint_map[fuzz.peripheral_access_point]
                    #     # simple check way "> pconstraint"
                    #     if consum_seed.value > pconstraint:
                    #         return consum_seed.value

                    return consum_seed.value

            # Schedule of symbolic execution and fuzzing
            if len(fuzz.global_peripheral_queue) == 0 or fuzz.global_peripheral_queue.__contains__(
                    fuzz.peripheral_access_point) == False:
                consum_seed = self.generate_symbolic_execution(regs_dic, pc)

            if fuzz.global_peripheral_queue.__contains__(fuzz.peripheral_access_point):
                queue = fuzz.global_peripheral_queue[fuzz.peripheral_access_point]
                if (len(queue) <= seedqueue_max_len):
                    consum_seed = self.generate_symbolic_execution(regs_dic, pc)
                else:
                    if (fuzz.schedule_mode == 1):  # schedule mode: Probability
                        import random
                        if (random.randint(0, 9) < symbolic_probability):  # 30% to use symbolic execution
                            consum_seed = self.generate_from_seedQueue(queue)
                        else:
                            consum_seed = self.generate_symbolic_execution(regs_dic, pc)

                    elif (fuzz.schedule_mode == 0):  # schedule mode: schedule count
                        if (fuzz.schedule_cnt <= 5):
                            consum_seed = self.generate_symbolic_execution(regs_dic, pc)
                            fuzz.schedule_cnt += 1
                        elif (fuzz.schedule_cnt > 5 and fuzz.schedule_cnt <= 10): # default (5, 15]
                            consum_seed = self.generate_from_seedQueue(queue)
                            fuzz.schedule_cnt += 1
                        else:
                            fuzz.schedule_cnt = 2
                            consum_seed = self.generate_symbolic_execution(regs_dic, pc)

            # record exec seed instance
            fuzz.global_peripheral_queue.setdefault(consum_seed.belongPerpherial, []).append(consum_seed)
            fuzz.exec_seed = consum_seed
            fuzz.exec_seed.ComsumMe()
            logger.debug("feed data 2: " + format(consum_seed.value, '#04x'))

            self.busy = False

            # TODO: an grammar constraint check for generated peripheral input
            # constraint = peripheral_constraint_map[fuzz.peripheral_access_point]
            # if satisfy(consum_seed.value, constraint):
            #   return consum_seed.value

            return consum_seed.value
        except:
            traceback.print_exc()
        finally:
            # print("global_peripheral_queue: ", os.getpid(), sys.getsizeof(fuzz.global_peripheral_queue),fuzz.global_peripheral_queue)
            fuzz.save_gpq()
            logger.debug("---------------------------------")
            self.busy = False

    # get the first seed from the queue
    def generate_from_seedQueue(self, queue):
        consum_seed = queue[0]
        return consum_seed

    # generate a seed based on the value solved by symbolic execution
    def generate_symbolic_execution(self, regs_dic, pc):
        logger.debug("[+] Switching the execution to angr")
        state = self.angr.angr.factory.avatar_state(self.angr, load_register_from=regs_dic,
                                                    ram_file=self.angr.ram_file)
        # only hook skipable_ins for the init state. Others will be hooked by step_function
        utils.hookSkippedCode(state)

        # hooks
        state.inspect.b('mem_read', when=a.BP_BEFORE, action=self.debug_funcRead)
        # state.inspect.b('mem_read', when=a.BP_AFTER, action=self.debug_funcRead_a)
        # state.inspect.b('mem_write', when=a.BP_BEFORE, action=self.debug_funcWrite)

        logger.debug("[+] ANGR stepping")

        # note synchronous exceptions are NOT handled yet. RTOS may be stuck ...
        # need to transfer to QEMU if a synchronous exception is taken
        # send PV is writing 0x10000000 to 0xE0000ED04
        simgr = self.angr.angr.factory.simgr(state)

        # possibly use unicore to skip unsupported instructions?
        # how Oppologist works under the hook is unknown. avoid using it.
        # simgr.use_technique(angr.exploration_techniques.Oppologist())

        self.angr.angr.engines.vex.default_strict_block_end = True

        # angrPath log the path walked in angr.
        angrPath = []
        # generate value by symbolic execution of angr
        self.explore_path(utils.PMRSettings.depth, simgr, regs_dic, angrPath)
        ret = self.solve_path(simgr, pc, angrPath)
        # create seed based on perihpheralID and reture value
        PeripheralID = pc & ~1
        consum_seed = fuzz.Seed(ret, PeripheralID)
        return consum_seed

    def nop_write(self, offset, size, value, pc, regs):
        self.busy = True
        logger.debug("[+] QEMU reached peripheral: write")
        logger.debug("IGN: " + self.name + " write at: " + format(self.address + offset, '#04x') +
                    "(self.address: " + format(self.address, '#04x') +
                    " offset: " + format(offset, '#04x') + "), size: " + format(size, '#04x') +
                    ", value: " + format(value,'#04x') +
                    ", pc: " + format(pc, '#04x'))

        # regs_dic = utils.arrary_to_dict(regs, pc)
        # utils.tb_info(regs_dic)

        if utils.PMRSettings.debug_port and self.address + offset <= utils.PMRSettings.debug_port < self.address + offset + size:
            logger.debug("[+] writing to debug port")
            utils.PMRSettings.firmware_debug.write(str(chr(value)))
            utils.PMRSettings.firmware_debug.flush()
        elif not utils.PMRSettings.debug_port and (0x20 <= value <= 0x7f or value == 0xa or value == 0xd):
            # determine which address is debug_port.
            utils.PMRSettings.firmware_debug.write(
                format(self.address + offset, "#04x") + "\t" + format(value, "#04x") + "\t" + str(chr(value)) + "\n")
            utils.PMRSettings.firmware_debug.flush()
        self.busy = False
        return True

    def get_global_v(self):
        return utils.PMRSettings.global_v

    def __init__(self, name, address, size, rom, rom_offset,
                 angr_target, qemu_target, chip_specific={}, stopHooks={},
                 alg=utils.Alg_Enum.Fast, depth=1, his=20, forward_depth=5, asserts={},
                 manual_path={},
                 manual_selection={},
                 fixedPeriV={},
                 debug_port=None,
                 **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.nop_write

        self.angr = angr_target
        self.qemu = qemu_target
        self.alg = alg

        self.chip_specific = chip_specific

        utils.PMRSettings.his = his
        utils.PMRSettings.asserts = asserts
        utils.PMRSettings.manual_path = manual_path
        utils.PMRSettings.manual_selection = manual_selection
        utils.PMRSettings.stopHooks = stopHooks
        utils.PMRSettings.fixedPeriV = fixedPeriV
        utils.PMRSettings.depth = depth
        utils.PMRSettings.forward_depth = forward_depth
        utils.Step_Hook.code = rom
        utils.Step_Hook.rom_offset = rom_offset

        utils.PMRSettings.pmr.append([address, address + size])

        if self.alg == utils.Alg_Enum.Fast:
            utils.PMRSettings.depth = 1
            utils.PMRSettings.his = 20

        assert utils.PMRSettings.his >= 20

        utils.PMRSettings.debug_port = debug_port

        self.busy = False
