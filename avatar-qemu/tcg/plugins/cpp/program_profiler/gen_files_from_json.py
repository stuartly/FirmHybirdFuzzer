#!/usr/bin/env python3

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys

from jinja2 import Environment, FileSystemLoader
from graphviz import Digraph

symbol_file_prefix = 'symbol_'


def current_file_path():
    return os.path.realpath(__file__)


def template_dir():
    return os.path.join(os.path.dirname(current_file_path()), 'templates')


def ext_dir():
    return os.path.join(os.path.dirname(current_file_path()), 'ext')


def flamegraph_script():
    return os.path.join(
        os.path.dirname(current_file_path()), 'tools/flamegraph.pl')


def get_jinja_env(template_dir):
    return Environment(loader=FileSystemLoader(template_dir), autoescape=True)


class TimeoutException(Exception):
    pass


def deadline(timeout, *args):
    """is a the decotator name with the timeout parameter in second"""

    def decorate(f):
        """ the decorator creation """

        def handler(signum, frame):
            """ the handler for the timeout """
            raise TimeoutException(
            )  #when the signal have been handle raise the exception

        def new_f(*args):
            """ the initiation of the handler,
            the lauch of the function and the end of it"""
            signal.signal(signal.SIGALRM,
                          handler)  #link the SIGALRM signal to the handler
            signal.alarm(timeout)  #create an alarm of timeout second
            res = f(*args)  #lauch the decorate function with this parameter
            signal.alarm(0)  #reinitiate the alarm
            return res  #return the return value of the fonction

        new_f.__name__ = f.__name__
        return new_f

    return decorate


@deadline(10)
def render_dot_in_limited_time(dot, out_dot_file, out_img_file):
    try:
        dot.render(out_dot_file)
    except TimeoutException:
        logging.warning('DOT_FILE: generate file was too long, skipping it...')
        try:
            os.remove(out_img_file)
        except OSError:
            pass


def log():
    global _logger
    return _logger


def setup_logger():
    global _logger
    _logger = logging.getLogger()
    _logger.setLevel(logging.DEBUG)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("GEN_FILES: %(message)s")
    stream_handler.setFormatter(formatter)
    _logger.addHandler(stream_handler)


def create_output_dir(output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)


def load_json(input_json):
    with open(input_json) as f:
        data = json.load(f)

    return data


def get_basic_block_src_start(block):
    block_instrs = block['instructions']
    if not block_instrs:
        return ''
    first_instr = block_instrs[0]
    src = ''
    src_node = first_instr['src']
    if src_node:
        src = src_node['file'] + ':' + str(src_node['line'])
    return src


def get_symbol_src_start(s):
    # first block has the lowest id, which matches the first time block
    # was created, thus the entry block of function
    first_block = s['basic_blocks'][0]
    return get_basic_block_src_start(first_block)


def get_symbol_name(s):
    name = s['name']
    if not name:
        name = hex(s['pc'])
    return name


def stats_to_dict(s, stats):
    num_times_entered = s['num_times_entered']
    num_times_repeated = s['num_times_repeated']
    instructions_executed = s['instructions_executed']
    instructions_executed_percentage = 0
    if instructions_executed:
        instructions_executed_percentage = 100.0 * instructions_executed / stats[
            'instructions_executed']
    instructions_executed_memory = s['instructions_executed_memory']
    instructions_executed_memory_percentage = 0
    if instructions_executed_memory:
        instructions_executed_memory_percentage = 100.0 * instructions_executed_memory / s[
            'instructions_executed']
    instructions_executed_arithmetic_and_logic = s[
        'instructions_executed_arithmetic_and_logic']
    instructions_executed_arithmetic_and_logic_percentage = 0
    if instructions_executed_arithmetic_and_logic:
        instructions_executed_arithmetic_and_logic_percentage = 100.0 * instructions_executed_arithmetic_and_logic / s[
            'instructions_executed']
    instructions_executed_control = s['instructions_executed_control']
    instructions_executed_control_percentage = 0
    if instructions_executed_control:
        instructions_executed_control_percentage = 100.0 * instructions_executed_control / s[
            'instructions_executed']
    bytes_read = s['bytes_read']
    bytes_read_percentage = 0
    if bytes_read:
        bytes_read_percentage = 100.0 * bytes_read / stats['bytes_read']
    bytes_written = s['bytes_written']
    bytes_written_percentage = 0
    if bytes_written:
        bytes_written_percentage = 100.0 * bytes_written / stats[
            'bytes_written']
    return dict(
        num_times_entered=num_times_entered,
        num_times_repeated=num_times_repeated,
        instructions_executed=instructions_executed,
        instructions_executed_percentage=instructions_executed_percentage,
        instructions_executed_arithmetic_and_logic=
        instructions_executed_arithmetic_and_logic,
        instructions_executed_arithmetic_and_logic_percentage=
        instructions_executed_arithmetic_and_logic_percentage,
        instructions_executed_memory=instructions_executed_memory,
        instructions_executed_memory_percentage=
        instructions_executed_memory_percentage,
        instructions_executed_control=instructions_executed_control,
        instructions_executed_control_percentage=
        instructions_executed_control_percentage,
        bytes_read=bytes_read,
        bytes_read_percentage=bytes_read_percentage,
        bytes_written=bytes_written,
        bytes_written_percentage=bytes_written_percentage)


def get_symbol_url(s):
    return symbol_file_prefix + str(s['id']) + '.html'


def generate_loops_index(loops_list, stats, cpu_loop_stacks,
                         mem_read_loop_stacks, mem_write_loop_stacks,
                         output_dir, output_file, output_index, j2env,
                         template_file):
    cpu_flamegraph_file_name = output_file + '.cpu_flamegraph.txt'
    cpu_flamegraph_image_file_name = cpu_flamegraph_file_name + '.svg'
    cpu_flamegraph_file = os.path.join(output_dir, cpu_flamegraph_file_name)
    cpu_flamegraph_image_file = os.path.join(output_dir,
                                             cpu_flamegraph_image_file_name)
    mem_read_flamegraph_file_name = output_file + '.mem_read_flamegraph.txt'
    mem_read_flamegraph_image_file_name = mem_read_flamegraph_file_name + '.svg'
    mem_read_flamegraph_file = os.path.join(output_dir,
                                            mem_read_flamegraph_file_name)
    mem_read_flamegraph_image_file = os.path.join(
        output_dir, mem_read_flamegraph_image_file_name)
    mem_write_flamegraph_file_name = output_file + '.mem_write_flamegraph.txt'
    mem_write_flamegraph_image_file_name = mem_write_flamegraph_file_name + '.svg'
    mem_write_flamegraph_file = os.path.join(output_dir,
                                             mem_write_flamegraph_file_name)
    mem_write_flamegraph_image_file = os.path.join(
        output_dir, mem_write_flamegraph_image_file_name)
    output_file = os.path.join(output_dir, output_file)

    # create list of loops
    loops = []
    for l in sorted(loops_list, key=lambda x: x['loop_header']['pc']):
        lh = l['loop_header']
        pc = hex(lh['pc'])
        src = get_basic_block_src_start(lh)

        syms = []
        for s in lh['symbols']:
            sym = dict(name=get_symbol_name(s), url=get_symbol_url(s))
            syms.append(sym)
        loop = dict(
            pc=pc,
            src=src,
            symbols=syms,
            stats=stats_to_dict(l['stats'], stats),
            stats_cumulated=stats_to_dict(l['stats_cumulated'], stats))
        loops.append(loop)

    log().info('generate loops index file %s', output_file)
    out = j2env.get_template(template_file).render(
        title='Loops Index',
        cpu_flamegraph_file=cpu_flamegraph_image_file_name,
        mem_read_flamegraph_file=mem_read_flamegraph_image_file_name,
        mem_write_flamegraph_file=mem_write_flamegraph_image_file_name,
        index_file=output_index,
        loops=loops)
    with open(output_file, 'w') as f:
        f.write(out)

    generate_flamegraph_from_loop_stacks(cpu_loop_stacks, cpu_flamegraph_file,
                                         cpu_flamegraph_image_file, 'hot',
                                         'instructions', 'Instructions')
    generate_flamegraph_from_loop_stacks(
        mem_read_loop_stacks, mem_read_flamegraph_file,
        mem_read_flamegraph_image_file, 'green', 'bytes read', 'Memory read')
    generate_flamegraph_from_loop_stacks(
        mem_write_loop_stacks, mem_write_flamegraph_file,
        mem_write_flamegraph_image_file, 'blue', 'bytes written',
        'Memory write')


def generate_flamegraph(stacks, flamegraph_file, flamegraph_image_file, color,
                        countname, entryname, title):
    log().info('generate flamegraph file %s', flamegraph_file)
    with open(flamegraph_file, 'w') as f:
        for s in stacks:
            stack = ';'.join(s['entries'])
            f.write(stack + ' ' + str(s['count']) + '\n')
    with open(flamegraph_file, 'r') as infile:
        with open(flamegraph_image_file, 'w') as outfile:
            subprocess.check_call(
                [
                    flamegraph_script(), "--colors", color, '--countname',
                    countname, '--nametype', entryname, '--hash', '--title',
                    title, '--width', '900'
                ],
                stdin=infile,
                stdout=outfile)


def generate_flamegraph_from_call_stacks(call_stacks, flamegraph_file,
                                         flamegraph_image_file, color,
                                         countname, title):
    stacks = []
    for cs in call_stacks:
        stacks.append(
            dict(
                entries=[x['name'] for x in cs['symbols']], count=cs['count']))
    generate_flamegraph(stacks, flamegraph_file, flamegraph_image_file, color,
                        countname, "function:", title)


def generate_flamegraph_from_loop_stacks(loop_stacks, flamegraph_file,
                                         flamegraph_image_file, color,
                                         countname, title):
    stacks = []
    for ls in loop_stacks:
        stacks.append(
            dict(
                entries=[hex(x['pc']) for x in ls['basic_blocks']],
                count=ls['count']))
    generate_flamegraph(stacks, flamegraph_file, flamegraph_image_file, color,
                        countname, "loop:", title)


def generate_index(symbols, stats, cpu_call_stacks, mem_read_call_stacks,
                   mem_write_call_stacks, original_json_input, output_dir,
                   output_file, loops_index, j2env, template_file):
    cpu_flamegraph_file_name = output_file + '.cpu_flamegraph.txt'
    cpu_flamegraph_image_file_name = cpu_flamegraph_file_name + '.svg'
    cpu_flamegraph_file = os.path.join(output_dir, cpu_flamegraph_file_name)
    cpu_flamegraph_image_file = os.path.join(output_dir,
                                             cpu_flamegraph_image_file_name)
    mem_read_flamegraph_file_name = output_file + '.mem_read_flamegraph.txt'
    mem_read_flamegraph_image_file_name = mem_read_flamegraph_file_name + '.svg'
    mem_read_flamegraph_file = os.path.join(output_dir,
                                            mem_read_flamegraph_file_name)
    mem_read_flamegraph_image_file = os.path.join(
        output_dir, mem_read_flamegraph_image_file_name)
    mem_write_flamegraph_file_name = output_file + '.mem_write_flamegraph.txt'
    mem_write_flamegraph_image_file_name = mem_write_flamegraph_file_name + '.svg'
    mem_write_flamegraph_file = os.path.join(output_dir,
                                             mem_write_flamegraph_file_name)
    mem_write_flamegraph_image_file = os.path.join(
        output_dir, mem_write_flamegraph_image_file_name)
    output_dot_file_name = output_file + '.call_graph.dot.txt'
    output_dot_file = os.path.join(output_dir, output_dot_file_name)
    output_file = os.path.join(output_dir, output_file)

    syms = []
    dot = Digraph(format='svg')

    # create list of symbols and dot graph
    for s in sorted(symbols, key=lambda x: x['pc']):
        id = s['id']
        sym_url = get_symbol_url(s)
        name = get_symbol_name(s)
        pc = hex(s['pc'])
        size = s['size']

        src = get_symbol_src_start(s)

        binary = s['file']
        if not binary:
            binary = ''

        sym = dict(
            name=name,
            pc=pc,
            size=size,
            src=src,
            binary=binary,
            url=sym_url,
            stats=stats_to_dict(s['stats'], stats),
            stats_cumulated=stats_to_dict(s['stats_cumulated'], stats))
        syms.append(sym)

        dot_name = name
        if not dot_name:
            dot_name = pc
        dot.node(str(id), label=dot_name, URL=sym_url)
        for called in s['calls']:
            dot.edge(str(id), str(called['id']))

    log().info('generate index file %s', output_file)
    out = j2env.get_template(template_file).render(
        title='Index',
        call_graph_dot_file=output_dot_file_name,
        call_graph_file=output_dot_file_name + '.svg',
        cpu_flamegraph_file=cpu_flamegraph_image_file_name,
        mem_read_flamegraph_file=mem_read_flamegraph_image_file_name,
        mem_write_flamegraph_file=mem_write_flamegraph_image_file_name,
        json_file=original_json_input,
        loops_index=loops_index,
        symbols=syms)
    with open(output_file, 'w') as f:
        f.write(out)

    generate_flamegraph_from_call_stacks(cpu_call_stacks, cpu_flamegraph_file,
                                         cpu_flamegraph_image_file, 'hot',
                                         'instructions', 'Instructions')
    generate_flamegraph_from_call_stacks(
        mem_read_call_stacks, mem_read_flamegraph_file,
        mem_read_flamegraph_image_file, 'green', 'bytes read', 'Memory read')
    generate_flamegraph_from_call_stacks(
        mem_write_call_stacks, mem_write_flamegraph_file,
        mem_write_flamegraph_image_file, 'blue', 'bytes written',
        'Memory write')

    svg_out = output_dot_file + '.svg'
    log().info('generate dot file %s', output_dot_file)
    log().info('generate svg file %s', svg_out)
    render_dot_in_limited_time(dot, output_dot_file, svg_out)


@deadline(10)
def generate_symbol_file(sym, stats, output_dir, output_file, index_file,
                         j2env, template_file, sym_number, sym_total_number):
    output_dot_file_name = output_file + '.cfg.dot.txt'
    output_dot_file = os.path.join(output_dir, output_dot_file_name)
    output_file = os.path.join(output_dir, output_file)

    dot = Digraph(format='svg')
    dot.attr('node', shape='box')

    sources = []
    assembly = []

    for s in sym['src']:
        src = dict(
            file=s['file'],
            line=s['line'],
            src=s['str'],
            executed=s['executed'])
        sources.append(src)

    for i in sym['instructions']:
        inst = dict(pc=hex(i['pc']), asm=i['str'], executed=i['executed'])
        assembly.append(inst)

    for b in sym['basic_blocks']:
        id = b['id']
        pc = b['pc']
        b_label = hex(pc)
        b_label += '\n_______________________'
        for src in b['src']:
            b_label += '\n'
            b_label += src['str']
        b_label += '\n_______________________'
        for i in b['instructions']:
            b_label += '\n'
            b_label += i['str']

        loop_header = b['loop_header']
        if loop_header:
            b_label += '\n_______________________'
            b_label += '\n'
            b_label += 'LOOP ' + hex(loop_header['pc'])

        called_symbols = dict()

        for succ in b['successors']:
            is_in_same_symbol = False
            for b in sym['basic_blocks']:
                if b['id'] == succ['id']:
                    is_in_same_symbol = True

            if is_in_same_symbol:
                dot.edge(str(id), str(succ['id']))
            else:
                for s in succ['symbols']:
                    called_symbols[s['id']] = s

        if len(called_symbols.values()) > 0:
            b_label += '\n_______________________'

        for s in called_symbols.values():
            called_symbol_name = s['name']
            if not called_symbol_name:
                called_symbol_name = hex(pc)
            b_label += '\nCALL ' + called_symbol_name

        if len(b['symbols']) > 1:
            b_label += '\n_______________________'
            for s in b['symbols']:
                name = get_symbol_name(s)
                b_label += '\nSHARED BLOCK ' + name

        dot.node(str(id), label=b_label)

    name = get_symbol_name(sym)
    pc = hex(sym['pc'])
    orig_file = sym['file']
    src = get_symbol_src_start(sym)
    size = sym['size']

    def list_builder(syms):
        res = []
        for s in syms:
            data = dict()
            data['name'] = get_symbol_name(s)
            data['url'] = get_symbol_url(s)
            res.append(data)
        return res

    calls = list_builder(sym['calls'])
    callers = list_builder(sym['callers'])

    progress_str = '[' + str(sym_number) + '/' + str(sym_total_number) + ']'
    log().info('%s generate symbol file %s', progress_str, output_file)
    out = j2env.get_template(template_file).render(
        title='Symbol',
        cfg_dot_file=output_dot_file_name,
        cfg_file=output_dot_file_name + '.svg',
        index_file=index_file,
        sym_name=name,
        sym_pc=pc,
        sym_size=size,
        sym_file=orig_file,
        sym_src=src,
        sym_callers=callers,
        sym_calls=calls,
        sources=sources,
        assembly=assembly,
        sym_stats=stats_to_dict(sym['stats'], stats),
        sym_stats_cumulated=stats_to_dict(sym['stats_cumulated'], stats))
    with open(output_file, 'w') as f:
        f.write(out)

    svg_out = output_dot_file + '.svg'
    log().info('%s generate dot file %s', progress_str, output_dot_file)
    log().info('%s generate svg file %s', progress_str, svg_out)
    try:
        dot.render(output_dot_file)
    except:
        logging.warning('DOT_FILE: error while generating it...')
        try:
            os.remove(svg_out)
        except OSError:
            pass


def generate_files(input_json, output_dir):
    log().info('generate files in %s', output_dir)
    create_output_dir(output_dir)
    j = load_json(input_json)

    log().info('read templates from %s', template_dir())
    j2env = get_jinja_env(template_dir())

    out_ext_dir = os.path.join(output_dir, 'ext')
    if os.path.exists(out_ext_dir):
        shutil.rmtree(out_ext_dir)
    shutil.copytree(ext_dir(), out_ext_dir)
    shutil.copyfile(input_json, os.path.join(output_dir, 'data.json'))
    output_index = 'index.html'
    output_loops_index = 'loops.html'

    # replace symbols/blocks id by objects
    # create dict for symbols/blocks
    symbols_dict = dict()
    for s in j['symbols']:
        symbols_dict[s['id']] = s
    blocks_dict = dict()
    for b in j['basic_blocks']:
        blocks_dict[b['id']] = b
    # map id to objects
    for s in j['symbols']:
        if not s['name']:
            s['name'] = hex(s['pc'])
        s['calls'] = [symbols_dict[called_id] for called_id in s['calls']]
        s['basic_blocks'] = [
            blocks_dict[block_id] for block_id in s['basic_blocks']
        ]
    for b in j['basic_blocks']:
        b['successors'] = [blocks_dict[succ_id] for succ_id in b['successors']]
        if b['loop_header']:
            b['loop_header'] = blocks_dict[b['loop_header']]
        b['symbols'] = [symbols_dict[sym_id] for sym_id in b['symbols']]
    for cs in j['cpu_call_stacks']:
        cs['symbols'] = [symbols_dict[sym_id] for sym_id in cs['symbols']]
    for cs in j['mem_read_call_stacks']:
        cs['symbols'] = [symbols_dict[sym_id] for sym_id in cs['symbols']]
    for cs in j['mem_write_call_stacks']:
        cs['symbols'] = [symbols_dict[sym_id] for sym_id in cs['symbols']]
    for l in j['loops']:
        l['loop_header'] = blocks_dict[l['loop_header']]
    for ls in j['cpu_loop_stacks']:
        ls['basic_blocks'] = [
            blocks_dict[block_id] for block_id in ls['basic_blocks']
        ]
    for ls in j['mem_read_loop_stacks']:
        ls['basic_blocks'] = [
            blocks_dict[block_id] for block_id in ls['basic_blocks']
        ]
    for ls in j['mem_write_loop_stacks']:
        ls['basic_blocks'] = [
            blocks_dict[block_id] for block_id in ls['basic_blocks']
        ]

    # compute callers
    for s in j['symbols']:
        s.update({'callers': []})

    for s in j['symbols']:
        for called in s['calls']:
            called['callers'].append(s)

    generate_index(j['symbols'], j['statistics'], j['cpu_call_stacks'],
                   j['mem_read_call_stacks'], j['mem_write_call_stacks'],
                   'data.json', output_dir, output_index, output_loops_index,
                   j2env, 'index.html')
    generate_loops_index(j['loops'], j['statistics'], j['cpu_loop_stacks'],
                         j['mem_read_loop_stacks'], j['mem_write_loop_stacks'],
                         output_dir, output_loops_index, output_index, j2env,
                         'loops.html')

    total_syms = len(j['symbols'])
    sym_number = 1
    for s in j['symbols']:
        output_file = symbol_file_prefix + str(s['id']) + '.html'
        try:
            generate_symbol_file(s, j['statistics'], output_dir, output_file,
                                 output_index, j2env, 'symbol.html',
                                 sym_number, total_syms)
        except TimeoutException:
            logging.warning(
                'SYMBOL_FILE: generate file was too long, skipping it...')
            try:
                os.remove(os.path.join(output_dir, output_file))
            except OSError:
                pass

        sym_number += 1


def main(argv):
    setup_logger()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-o', '--output-dir', help='output directory', required=True)
    parser.add_argument('-i', '--input-file', help='input file', required=True)
    args = parser.parse_args(argv)
    generate_files(args.input_file, args.output_dir)


if __name__ == '__main__':
    main(sys.argv[1:])
