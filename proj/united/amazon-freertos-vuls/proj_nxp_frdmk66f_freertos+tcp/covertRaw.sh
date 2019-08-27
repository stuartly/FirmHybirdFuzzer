#!/bin/bash

arm-none-eabi-objcopy -O binary $1".elf" $1".bin"

arm-none-eabi-objdump -d $1".elf" > xx

readelf -s $1".elf" | grep __assertion_failed
