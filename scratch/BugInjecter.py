
import idaapi
import idautils
import idc
from sets import Set
import os
import re
import shutil

def function_extract(func, callees):
    func_name = GetFunctionName(func)
    callees[func_name] = callees.get(func_name, Set())
    for ref_ea in CodeRefsTo(func, 0):
        caller_name = GetFunctionName(ref_ea)
        callees[caller_name] = callees.get(caller_name, Set()) #add the functions from "CodesRefsTo" to a dictionary for extracting CG and CG adjacency Matrix
        callees[caller_name].add(func_name)  


# end of function_extract
#------------------------------------------------------------------------------------------------------------------------

def cg_extract(output_file, callees, injectedF, fInWhile):
    functions = callees.keys()

    for key in functions:
        print >> output_file, "key: %s " % (key)
        if callees.has_key(key):
            for calling in callees[key]:
                print >> output_file, "     %s " % (calling)
    for key in functions:
        if key in fInWhile:
            traverse(key, callees, injectedF)

# end of cg_extract
#------------------------------------------------------------------------------------------------------------------------

def traverse(func, callees, injectedF):
    injectedF.append(func)
    if func in callees.keys():
        funcs = callees[func]
        if len(funcs):
            for f in funcs:
                if f not in injectedF:
                    traverse(f, callees, injectedF)
                
# end of traverse
#------------------------------------------------------------------------------------------------------------------------

def readFilename(file_dir):   
    for root, dirs, files in os.walk(file_dir):         
        return files,dirs,root 
        
def findstring(pathfile, func, output_file, bug):    
    global bugnum
    if '.c' not in pathfile:
        return False
    fp = open(pathfile, "r")
    strr = fp.read()
    loc = process_method(strr, func)
    if loc:
        bugnum = bugnum + 1
        print >> output_file, "%s : %s" % (pathfile,func)
        print >> output_file, "bug :\n %s" % bug
        index = loc[1]
        while 1:
            if strr[index] != "\n":
                index += 1
            else:
                index += 1
                break
        with open(pathfile, mode="w") as f:
            f.write(strr[:index] + bug + strr[index:])

def startfind(files,dirs,root,injectedFunc, output_file, bug):
    for ii in files:
        try:
            for f in injectedFunc:
                findstring(root+"\\"+ii, f, output_file, bug)
        except Exception as err:
            continue
    for jj in dirs:
        fi,di,ro = readFilename(root+"\\"+jj)
        startfind(fi,di,ro,injectedFunc, output_file, bug)

def process_method(text, func):
    pattern = re.compile(r"\w\s(" + func + ")(\s)?\(\w+.*\w*\)(\n)?{")
    c = re.search(pattern, text)
    if c:
        return c.span()
    return False

def copy_dir(olddir_path,newdir_path):
    if os.path.exists(newdir_path):
        shutil.rmtree(newdir_path, ignore_errors=True)
    shutil.copytree(olddir_path, newdir_path)

def buildProject(workspace, newdir_path, project_name):
    if os.path.exists(workspace):
        shutil.rmtree(workspace, ignore_errors=True)
    os.mkdir(workspace)

    IDE_PATH=r"E:\MCUXpresso\MCUXpressoIDE_10.3.1_2233"
    TOOLCHAIN_PATH=IDE_PATH + r"\ide\tools\bin"
    IDE=IDE_PATH + r"\ide\mcuxpressoidec.exe"
    command = IDE + u""" -nosplash --launcher.suppressErrors -application org.eclipse.cdt.managedbuilder.core.headlessbuild -data """ + workspace +""" -import """ + newdir_path +""" -build """ + project_name
    os.system(command)

# end of find file
#------------------------------------------------------------------------------------------------------------------------
def controller():
    bugs = { 'stack_overflow' :
"""
    /* Bug: stack overflow */
    char sof_src[4] = {0};
    strcpy(sof_src, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

""",
        'heap_overflow' :
"""
    /* Bug: heap overflow */
    char *hbof_data = (char *)malloc(sizeof(char) * 10);
    char *hbof_str = (char *)malloc(sizeof(char) * 10);
    strcpy(hbof_str, "BBBBBBBBBB");
    strcpy(hbof_data, "AAAAAAAAAAAAAAAAAAAAAAAAA");
    char hbofch = hbof_str[2];
    free(hbof_data);
    free(hbof_str);

""",
        'null_pointer_deference' :
"""
    /* Bug: Null Pointer Deference */
    int *null_p;
    *null_p = 3;

""",
        'out_of_bound_access' :
"""
    /* Bug: Out-Of-Bound Write*/
    int oobw_safe[4] = {0};
    int oobw_src[4] = {0};
    oobw_src[5] = 0x1234;

    /* Bug: Out-Of-Bound Read*/
    int oobr_src[4] = {0};
    int oobr_a = oobr_src[5];

""",
        'double_free' :
"""
    /* Bug: double free */
    int *df_p1 = (int *)malloc(sizeof(int));
    free(df_p1);
    free(df_p1);

""",
        'use_after_free' :
"""
    /* Bug: use after free */
    char *uaf_data = (char *)malloc(100 * sizeof(char));
    free(uaf_data);
    memset(uaf_data, 'A', 100 - 1);

""",
        'div_zero' :
"""
    /* Bug: div zero */
    int div0_a = 5;
    int div0_b = 0;
    int div0_c = div0_a / div0_b;

""",
        'integer_overflow' :
"""
    /* Bug: integer overflow */
    int iof_a = 0xfffff0f0;
    int iof_b = 0x0fff;
    int iof_c = iof_a + iof_b;

""",
        'format_string_overflow' :
"""
    /* Bug: Format String Overflow*/
    printf("There are %d bugs. This is a testcase %d. \\n", 10);
    int safe[5] = {0};

""",
        'original' :
""" """
    }
    callees = dict()
    func_num = 0
    injectedF = []
    info_filename = idc.AskFile(1, "*.*", "Extract Binary File Info")

    # name of project
    basename = idc.GetInputFile()
    info_filename = basename + ".info"

    output_file = open(info_filename,'w')

    funcs = idautils.Functions()

    global bugnum

    for f in funcs:
        func_num += 1
        func_name = GetFunctionName(f)
        function_extract(f, callees)

    fInWhile = ['ENET_GetRxFrameSize', 'ENET_ReadFrame', 'ENET_GetRxErrBeforeReadFrame', 'PHY_GetLinkStatus', 'ENET_SendFrame']
    numLimit = 0
    cg_extract(output_file, callees, injectedF, fInWhile) # extract CG and CG adjacency matrix

    injectedF = list(set(injectedF))
    if numLimit != 0 and numLimit < len(injectedF):
        injectedFNum = len(injectedF)
        for f in injectedF:
            if random.randint(0, injectedFNum - 1) >= numLimit:
                injectedF.remove(f)
    for f in injectedF:
        print >> output_file, "injected func: %s " % (f)

    project_name = basename[:-4]
    base_path = os.getcwd()
    olddir_path = u"E:\\MCUXpresso\\workspace\\frdmk66f_enet__enet_txrx_transfer"
    newdir_path = base_path + u"\\newer\\" + project_name
    bugfiles = base_path + u'\\bugfiles\\'
    workspace = base_path + u'\\workspace\\'

    if not os.path.exists(bugfiles):
        os.mkdir(bugfiles)

    for bug in bugs.keys():
        copy_dir(olddir_path,newdir_path)
        file_path = newdir_path
        files,dirs,root = readFilename(file_path)
        bugnum = 0
        startfind(files, dirs, root, injectedF, output_file, bugs[bug])
        buildProject(workspace, newdir_path, project_name)
        print >> output_file, "bugnum : %d" % (bugnum)

        try:
            shutil.copyfile(newdir_path + u'\\Release\\' + basename, bugfiles + project_name + '_' + bug + '.axf')
        except Exception as err:
            continue

    if os.path.exists(workspace):
        shutil.rmtree(workspace, ignore_errors=True)
    if os.path.exists(newdir_path):
        shutil.rmtree(newdir_path, ignore_errors=True)

# end of controller
#------------------------------------------------------------------------------------------------------------------------

q = None
f = None
bugnum = 0
idc.Wait()
controller()

