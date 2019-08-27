#!/bin/bash

arm-none-eabi-objcopy --input-target=elf32-little --output-target=binary $1 $1".raw"
