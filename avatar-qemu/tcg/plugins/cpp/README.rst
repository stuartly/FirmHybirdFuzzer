Plugin CPP
==========

How to build
------------

Plugin CPP is written using c++14, (GCC >= 6). Plugins written with it use c++14
as well.

To build, install dependencies:

- apt build-dep qemu
- apt install libcapstone-dev
- apt install libelfin-dev (contains libdwarf++ and libelf++)

Then configure:

::
    ./configure --enable-tcg-plugin-cpp --target-list=x86_64-linux-user,arm-linux-user,aarch64-linux-user,i386-linux-user

Then build:

::

    make -j4

How to use
----------

Plugin CPP is usable as a normal qemu plugin (named cpp). It can be considered
as a metaplugin. To control which ones you want to activate, PLUGIN_CPP env var
must be set to a list of plugins.

To list plugins available:

::
    ./x86_64-linux-user/qemu-x86_64 -tcg-plugin cpp /bin/true

To activate some plugins:

::

    PLUGIN_CPP=count_instructions,coverage ./x86_64-linux-user/qemu-x86_64 -tcg-plugin cpp /bin/true

Like others QEMU plugins, you can use TPI_OUTPUT to specify a file for plugin
output.

Internals
---------

Plugin CPP can be considered as an Instrumentation Framework, since it has no
dependences on QEMU (a port to DynamoRIO has been done). It aims to offer a
nicer and simpler interface to write instrumentation plugins. On the opposite of
classic instrumentation framework, it does not allow to modify generated code.
It works entirely with callbacks (via inheritance - virtual functions) and
offers structures to represent symbols, translation blocks, instructions, and
much more.

Interface to connect Plugin CPP to an existing instrumenter (QEMU, DR) is
declared in plugin_instrumentation_api.h. (See ../cpp.c for QEMU example).
Instrumenter to just need to declare when a block is translated, when it
executes, and what is memory accessed. In particular, it does not have to
declare calls, symbols, or other things. Those are computed by Plugin CPP
itself.

Interface to write plugins is declared in plugin_api.h.

A minimal plugin is null:

::

    #include "plugin_api.h"

    class plugin_null : public plugin
    {
    public:
        plugin_null()
            : plugin("null", "does nothing")
        {
        }

        // you can connect to some events by overriding some methods from plugin
        // class
    };

    // register plugin in framework to make it available
    REGISTER_PLUGIN(plugin_null);

Information available are:

- Symbols (listed from ELF sections, or found dynamically via calls)
- Source code (found from DWARF information)
- Current call stack
- Transition type between blocks
- Instructions (already disassembled with capstone)
- Memory accesses done dynamically (with address and size) for each block
  execution.

Note: Multithreaded programs are handled and works correctly. This is
implemented using a lock for each block execution. Thus, overhead in
multithreaded mode is very important.

PP: Program profiler
--------------------

Between all the plugins, program_profiler is the most complex one. It aims to
profile exhaustively a running program, and reports as much information as it
can. Its output is a json file. This file can then be converted to a set of HTML
files using a python script
(tcg/plugins/cpp/program_profiler/gen_files_from_json.py). All this boring stuff
is simplified by using driver pp located at root of qemu.

Supported architectures are: i386, x86_64, arm, aarch64, and they match name of
directory where QEMU builds its binaries ('$arch'-linux-user).

You can stop profiling when you want by hitting CTRL-C, and information found so
far will still be available.

::

    ./pp x86_64  ~/out /bin/true

For an arm binary, you must give sysroot given to QEMU (-L option).

::

    ./pp arm:/usr/arm-linux-gnueabi ~/out ../try/bin_arm

Output consists of:

- Index file summarizing program (per symbols). It has a flamegraph for
  instructions, memory read and memory write. For each symbol, you can know how
  much time was spent in it (relatively to whole program), for itself, and when
  it is included on call stack (a.k.a. cumulated). In more, you can know what
  types of instructions were executed and their percentage (memory, ALU,
  control).
- One file per symbol (showing its stats, assembly, source code and CFG).
- Loop index file shows loops detected during execution (with associated
  flamegraph).

Internally, the plugin computes following information:

- tranform translation blocks in basic blocks (single entry point/exit), since
  translation block can overlap between them.
- create control flow graph for each symbol
- from this CFG, detect loops (by running WCS algorithm when a new transition is
  found between two blocks).
- handles multithreaded programs correctly (one loop/call stack per thread)
- maintain a call and loop stack and statistics associated to every context

All those information are computed on the fly, when block is executed. It allows
to profile a program in a single run.

It was written to scale on very big programs. For instance, we can instrument
big binaries like ffmpeg or servo (written in rust). Memory usage is big with
debug information (> 10GB on Servo) but is not linear with time of execution (we
don't keep any kind of trace while program is running).

Performance
-----------

Performance was not analyzed very deeply, thus, numbers given here are just
found on some specific examples that could not be representative.

From a vanilla QEMU execution, overhead for running null plugin is between x30
and x100. Parsing of DWARF info can be long but is a constant time whether
program runs 1 second or 1 hour.

Running pp overhead is between x100 and x300 (> x1000 on multithreaded
programs).
