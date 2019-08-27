#!/bin/bash

touch RESTART

while true
do
#    echo "------> again "
    if [ -e 'RESTART' ]
    then
        rm RESTART
        killall qemu-system-arm
        killall arm-none-eabi-gdb
        killall -s SIGKILL qemu-system-arm
        pkill -f "python ./panda.py"
        pkill -f "qemu-system-arm"
        pkill -f "arm-none-eabi-gdb"

        rm -rf myavatar

        python ./panda.py &
        echo "done"
    fi
    sleep 0.001
done
