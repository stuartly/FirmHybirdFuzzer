#!/usr/bin/env python

import logging

from argparse import ArgumentParser, RawTextHelpFormatter
from os import system, listdir, getcwd
from signal import SIGALRM, signal, alarm
from sys import argv, exit
from sys import stdout
from select import select
from threading import Event
from time import sleep, time
from types import MethodType

from boofuzz import *
from boofuzz.instrumentation import External

from numpy.random import choice
from tabulate import tabulate


# global variables keeping track of input and crashes
inputs = []
input_names = []
input_distr = [0] * 6
crash_distr = [0] * 6
lcheck_distr = [0] * 6
hcheck_distr = [0] * 6


# Logger
logger = logging.getLogger('fuzzing')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s - %(message)s')
logger_fh = logging.FileHandler(filename="./fuzzer.txt", mode='w')
logger.addHandler(logger_fh)
logger_fh.setFormatter(formatter)
logger.propagate = False


HEURISTIC_BLACKLIST = set(['0x080069ac!'])


class Panda_wycinwyc_procmon(External, object):

    def __init__(self, pandalogpath):
        super(self.__class__, self).__init__()

        self.pandalogpath = pandalogpath

        self.panda_log = None
        self.crashed = False
        self.num_fuzzed = 0
        self.num_crashed = 0

    def verify_log(self):
        """
        Check whether one of the wycinwyc-heuristics detected a corruption
        :return:
        """
        if self.panda_log:
            new_log_data = select([self.panda_log], [], [])
            if new_log_data:
                for line in self.panda_log.readlines():
                    if line.startswith('[!]'):
                        if set(line.split()) & HEURISTIC_BLACKLIST:
                            return 0
                        self.crashed = True
                        return -1
        return 0

    def pre_send(self, total_mutant_index):
        pass

    # Update our countners
    def post_send(self):
        self.num_fuzzed += 1

        if self.crashed:
            self.crashed = False
            self.num_crashed += 1
            return False
        return True

    def stop_target(self):
        return True

    def start_target(self):
        self.panda_log = open(self.pandalogpath, 'r')
        return True

    def restart_target(self):
        self.stop_target()
        return False if not self.start_target() else True


def target_recv_until_oend(target, max_bytes):
    """
    a special marker to signal end-of-output. This function fetches all
    the output from the target, and returns when the marker is seen or the target
    crashed.
    :param target:
    :param max_bytes:
    :return:
    """
    if target._fuzz_data_logger is not None:
        target._fuzz_data_logger.log_info("Receiving...")

    logger.debug("Receiving...")

    data = ''

    start_time = 0
    while data[-5:] != 'OEND\n' and len(data) <= max_bytes:
        if target.procmon.verify_log():
            return "CRASHED"
        byte = target._target_connection.recv(1)
        if byte == '':
            if not start_time:
                start_time = time()
        else:
            start_time = 0

        if start_time and time() - start_time >= target._target_connection.timeout:
            break
        data += byte

    if target._fuzz_data_logger is not None:
        target._fuzz_data_logger.log_recv(data)

    logger.debug(data)

    return data


# This is our liveness check!
def session_post_send(target, fuzz_data_logger, session, sock,
                      *args, **kwargs):
    global inputs, crash_distr, lcheck_distr, hckeck_distr, input_idx

    logger.debug("liveness check!")

    liveness = '<test>AAAAA</test>\n\n'
    expected_response = ('test\r\nOEND\r\n')

    input_idx = inputs.index(session.last_send)
    input_distr[input_idx] += 1

    # this happens only if one of our heuristics got triggered
    if target.procmon.crashed:
        hcheck_distr[input_idx] += 1
    else:
        sock.open()
        sock.send(liveness)
        resp = target.recv(10000)

        # return if liveness check succeeded
        if resp.split() == expected_response.split():
            # everything's fine, let's getta out a here
            return
        else:
            lcheck_distr[input_idx] += 1

    # Timeout or failed liveness check
    target.procmon.crashed = True
    crash_distr[input_idx] += 1


def main(port=9998, timeout=5, duration=3600, corruption_probability=0.1, verbose=True):

    def end_fuzzing(signum, frame):
        """
        print at the end of a session
        :param signum:
        :param frame:
        :return:
        """
        logger.info("##### Session finished! #####")
        logger.info("Arguments: %s" % ' '.join(argv))
        logger.info("Num_crashes: %d" % target.procmon.num_crashed)
        logger.info("Num_fuzzs: %d" % target.procmon.num_fuzzed)
        logger.info(tabulate(zip(input_names, input_distr, crash_distr,
                           lcheck_distr, hcheck_distr),
                    headers=['name', '#input', '#detected_crashes',
                                '#liveness_checks', '#heuristic']))
        logger.info("#############################")
        logger.info("")
        stdout.flush()
        exit(0)

    def select_file_cb(target, log, session, node, edge):
        global input_distr
        s_get("request_1").reset()

        # strong assumptions: the first input is always the dummy-input
        # n = choice([i for i in range(0, 2)], p=probs)
        # return inputs[n]
        return inputs[0]

    # generate our list of inputs for fuzzing
    global inputs, input_names
    for f in sorted(listdir('./sample_trigger')):
        with open('./sample_trigger/'+f, 'r') as input:
            input_names.append(f)
            inputs.append(input.read())
    assert len(inputs) == 1

    # define probabilities for the different inputs
    # prob = corruption_probability
    # probs = [1-prob] + [prob/ (len(inputs)-1)] * (len(inputs)-1)

    # create a dummy block to have boofuzz complains
    s_initialize("request_1")
    if s_block_start("block_1"):
        s_string('dummy', fuzzable=True)
        s_block_end()

    logger.debug("[+] Create the target using TCP to connect panda")

    # create the target, choose tcp-connection
    target = sessions.Target(SocketConnection(host='127.0.0.1', port=port, send_timeout=timeout, recv_timeout=timeout))

    # use custom recv function
    target.recv = MethodType(target_recv_until_oend, target)

    # create out procmon
    target.procmon = Panda_wycinwyc_procmon('/doit/firmware/test/proj_ndss_vul/myavatar/panda_out.txt')

    # do a first reset to have a blank state
    target.procmon.restart_target()

    # set-up the timeout
    signal(SIGALRM, end_fuzzing)
    alarm(duration)

    fuzzing_session = sessions.Session(target=target, crash_threshold_request=300, receive_data_after_fuzz=True,
                                       sleep_time=3.0)

    fuzzing_session.post_send = session_post_send

    logger.debug("Finish config! Begin fuzzing! Enjoy!")

    # infinite fuzz_loop, will be interrupted by SIGALRM
    while True:
        logger.debug("Connect...")
        fuzzing_session.connect(s_get("request_1"), callback=select_file_cb)
        logger.debug("Fuzzing...")
        fuzzing_session.fuzz()
        logger.debug("Finish one time fuzzing...")


if __name__ == '__main__':
    main()



