
## NDSS 2018 paper experiment
1. driver.py -- Qemu target to main to display `Hello World`.
2. panda.py -- Panda target to detect memory corruptions with plugins.
3. target_source -- ELF source files
4. fuzzing -- fuzzing tool based on boofuzz (python2).
5. avatar_panda -- based on avatar-panda commit 28f718b3bc17e4e476fcc1eec29f85f004433d36.
6. snapshot -- snapshot of registers and memory dump, which accelerate the execution.


## Snapshot
Files in `snapshot`:
- ramFile is the ram file which is `dd` to `/dev/shm/SHM.1.0x14000`.
- backramFile is the backup.
- regs.json is registers file.
- trick1.py and trick2.py modify `/dev/shm/SHM.1.0x14000` to stop using peripheral when receiving.
- getMemoryDump.sh is for get memory dump.
- funcs.json is for panda plugins and it contains symbols in the ELF file.
- good directory contains the snapshot starting from main function.
- uartSnapshot contains the snapshot starting from uart loop.


#### Trick in the expriment
- Run the original path-exploration to `address(main)+0xc`.
- Get the registers and memory dump with gdb and dd.
- This is the snapshots.


#### Reason
If we set the snapshot just before the uart receiving point, Qemu cannot record the return addresses.
This will lead plugins in panda to report errors.


## Experiment Steps
1. In order to use panda plugins, capstone (4.0-alpha5) shoubld be installed in the path($LD_LIBRARY_PATH). When running panda.py, it also needs capstone library path.
2. Comment the code which uses previous state in panda.py.
3. Set proper panda path in panda.py.
4. Run ./panda.py to get the snapshot.(Regsiters and memory dump)
5. Un-Comment the code.
6. Run ./panda.py
7. Run ./snapshot/trick2.py and ./snapshot/trick1. py
8. Run ./fuzzing/run_fuzzer.py


### Experiment results
There are five malicious XML file.
They can trigger the related vulnerabilities with some false positives, i.e., non-mapped address.
All in all, these experiments succeed in proving the effectiveness of panda plugins.


