
import idaapi
import idautils
import idc
from sets import Set

def block_split(startEA, endEA):
    num = 0
    first=startEA
    h = idautils.Heads(startEA, endEA)
    for i in h:
        mnem = idc.GetMnem(i)
        if mnem == "BL" or mnem == "BLX":
            num = num + 1
    return num

# end of block_split
#------------------------------------------------------------------------------------------------------------------------

def function_extract(func, callees):
    func_name = GetFunctionName(func)
    callees[func_name] = callees.get(func_name, Set())
    for ref_ea in CodeRefsTo(func, 0):
        caller_name = GetFunctionName(ref_ea)
        callees[caller_name] = callees.get(caller_name, Set())
        callees[caller_name].add(func_name)


# end of function_extract
#------------------------------------------------------------------------------------------------------------------------

def traverse(func, callees, couFunc):
    couFunc.append(func)
    if func in callees.keys():
        funcs = callees[func]
        if len(funcs):
            for f in funcs:
                if f not in couFunc:
                    traverse(f, callees, couFunc)

# end of traverse
#------------------------------------------------------------------------------------------------------------------------

def BB_extract(output_file, func):
    cnt = 0
    num = 0
    f = idaapi.FlowChart(idaapi.get_func(func))
    cfg_adjmat = []

    global BB2BB_num

    for block in f:
        cfg_row =[0]*f.size
        print >> output_file, ""
        print >> output_file, "	Basic Block:"
        print >> output_file, "		BB_ID: [%d]" % (block.id)

        bb_asm_start_address = "{0:x}".format(block.startEA)
        bb_asm_end_address = "{0:x}".format(block.endEA)

        print >> output_file, "		Binary File Starting Address: %#x" % (block.startEA)
        print >> output_file, "		Binary File Ending Address: %#x" % (block.endEA)

        print >> output_file, "		Basic Block Successors:"

        for i in range(block_split(block.startEA, block.endEA)):
            num = num + 2
        for succ_block in block.succs():
            num = num + 1
            cfg_row[succ_block.id] = 1
            print >> output_file, "			Starting Address: %x - Ending Address: %x - BB_ID: [%d]" % (succ_block.startEA, succ_block.endEA, succ_block.id)
        cfg_adjmat.append(cfg_row)

    print >> output_file, "\n"
    print >> output_file, "CFG Adjacency Matrix for Function: %s\n" % (GetFunctionName(func))
    for cfg_row in cfg_adjmat:
        print >> output_file, "BB_ID [%d]: " %(cnt), cfg_row
        cnt += 1

    BB2BB_num = BB2BB_num + num
    print >> output_file, "\n"
    print >> output_file, "The num of %s BB2BB is %d." % (GetFunctionName(func), num)
    print >> output_file, "---------------------------------------------------------"
    print >> output_file, "\n"

# end of BB_extract
#------------------------------------------------------------------------------------------------------------------------

def controller():
    info_filename = idc.AskFile(1, "*.*", "Extract Binary File Info")

    basename = idc.GetInputFile()
    info_filename = basename + ".info"

    output_file = open(info_filename,'w')

    funcs = idautils.Functions()
    callees = dict()
    func2add = dict()
    startFunc = []
    countedFunc = []
    global BB2BB_num

    for f in funcs:
        func_name = GetFunctionName(f)
        func2add[func_name] = f
        function_extract(f, callees)

    if len(startFunc) == 0:
        for key in func2add.keys():
            startFunc.append(key)

    for func in startFunc:
        traverse(func, callees, countedFunc)

    countedFunc = list(set(countedFunc))

    for f in countedFunc:
        print >> output_file, "The function is %s: " % (f)
        BB_extract(output_file, func2add[f])                              

    print >> output_file, "The num of BB2BB is %d." % (BB2BB_num)

        
# end of controller
#------------------------------------------------------------------------------------------------------------------------      

BB2BB_num = 0
q = None
f = None
idc.Wait()
controller()

