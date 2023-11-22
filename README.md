## Installation
We suggest installing all the components in a single [python virtual environment](https://virtualenvwrapper.readthedocs.io/en/latest/). 
Due to various errors installing keystone, we also suggest installing Angr first, which properly installs keystone.
Because of the dependency on Angr, make sure you work on Python 3.

1. download [ARM GCC toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads) and put it in PATH
2. install Angr, 
    + method #1: `pip install angr; pip uninstall angr` to install angr dependencies. Download angr's source code from PyPI Website and install angr through `pip install -e ./`. In this way, angr can be patched freely.
    + method #2: install [angr-dev](https://github.com/angr/angr-dev). In this way, you can always keep updated by executing ```./git_all.sh pull```.
3. patch Angr: we make every effort to avoid interfering with the official Angr release. However, you do need to apply the follow patch. 
    ```
    --- a/angr/state_plugins/plugin.py
    +++ b/angr/state_plugins/plugin.py
    @@ -20,7 +20,11 @@ class SimStatePlugin(object):
             """
             Sets a new state (for example, if the state has been branched)
             """
    -        self.state = state._get_weakref()
    +        from angr.state_plugins import SimStateHistory
    +        if isinstance(self, SimStateHistory):
    +            self.state = state._get_strongref()
    +        else:
    +            self.state = state._get_weakref()
    
         def set_strongref_state(self, state):
             pass
    ```
4. build avatar-qemu and put qemu-system-arm in PATH (refer to README in AVATAR-QEMU DIR)
5. install Avatar2: `cd avatar2 && pip install -e ./` (refer to README in AVATAR2 DIR)
6. install hybridfuzz: 'cd hybridfuzz && pip install -e ./' (refer to README in hybridfuzz DIR)

## Running
We offer a demo you can fuzz it directly by running FirmwareFuzzer-Qemu.py, or you can fuzz other firmware according to the follower steps:
1. copy script/firmConf.py to path/to/firmware/;
2. edit settings(more details in Configuration) in path/to/firmware/firmConf.py;
3. edit line "import path/to/firmware.firmConf" in script/FirmwareFuzzer-Qemu.py;
4. run script/FirmwareFuzzer-Qemu.py.


## Configuration
To control the fuzz process, we modify the values of variables in firmConf.py for each firmware. Here we show some common settings:

First is the path/name settings which always need to change for defferent firmware.

    PROJ_PATH     = "path/to/demo"
    FIRMWARE_NAME = "demo name"
    
Second is the start/end settings and time setting deciding which part of the firmware need to fuzz and how long it fuzzed. 

    EN_START_PC = True
    START_PC    = 0x258e8           # save snaphost at START_PC when first reach here, and start execution from here in later run
    EN_END_PC   = True
    END_PC      = 0x258fc 
    
    SNAPSHOT_NAME = "snapshot_from_ControllerTask"
    
    EN_MULTIPLE_RUN_TIME = False    # set this False to run only once
    RUN_TIME             = 3600*3   # Total time of multiple run (time/sec)
    EN_ONE_RUN_TIME      = False    # set time limit for single run
    ONE_RUN_TIME         = 3600      
 
Third is the plugin settings to do some extra things when fuzzing firmware.
 
    PLUGIN = "tcg-plugin-hook_network.so"
    # PLUGIN = "tcg-plugin-stackobject_tracking.so"
    # PLUGIN = "tcg-plugin-heapobject_tracking.so"
    # PLUGIN = "tcg-plugin-instruction_tracking.so"
    # PLUGIN = None
    
Above is only some setting we may change frequently. For more settings' information, please refer to comments in script/firmConf.py or search reference in source code.

**Note：** please refer to [Firmware-Benchmark](https://github.com/stuartly/Firmware-Benchmark) if you want you fuzz more IoT fimware samples.


## Reference
```
@ARTICLE{10214030,
  author={Situ, Lingyun and Zhang, Chi and Guan, Le and Zuo, Zhiqiang and Wang, Linzhang and Li, Xuandong and Liu, Peng and Shi, Jin},
  journal={IEEE Internet of Things Journal}, 
  title={Physical Devices-Agnostic Hybrid Fuzzing of IoT Firmware}, 
  year={2023},
  volume={10},
  number={23},
  pages={20718-20734},
  doi={10.1109/JIOT.2023.3303780}}
```
