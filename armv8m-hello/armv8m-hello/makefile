IMAGE := kernel.elf

CROSS_COMPILE = arm-none-eabi-

CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
GDB = $(CROSS_COMPILE)gdb
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

CFLAGS = -mcpu=cortex-m4 -O0 -g -nostdlib -nostartfiles -ffreestanding

all: $(IMAGE)

OBJS = main.o

boot.o: boot.s
	$(CC) -mcpu=cortex-m4 -g -c boot.s -o boot.o

$(IMAGE): kernel.ld boot.o $(OBJS)
	$(LD) boot.o $(OBJS) -T kernel.ld -o $(IMAGE)
	$(OBJDUMP) -d $(IMAGE) > kernel.list
	$(OBJDUMP) -t $(IMAGE) | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > kernel.sym
	$(READELF) -A $(IMAGE)

dumpvmstate:
	qemu-system-arm -machine mps2-an505 -cpu cortex-m33 \
	                    -m 1024 \
			    -nographic -serial mon:stdio \
	                    -kernel $(IMAGE) \
			    -dump-vmstate vmstate.json 

qemu:
	@qemu-system-arm -M ? | grep mps2-an511 >/dev/null || exit
	qemu-system-arm -machine mps2-an511 -cpu cortex-m3 \
	                    -m 4096 \
			    -nographic -serial mon:stdio \
	                    -kernel $(IMAGE) 
			   
gdbserver:
	qemu-system-arm -machine mps2-an511 -cpu cortex-m3 \
				-nographic -qmp tcp:127.0.0.1:3334,server,nowait \
				-nographic -serial mon:stdio \
				-d unimp \
	                    -kernel $(IMAGE) \
			    -S -s 
gdb: $(IMAGE)
	$(GDB) $^ -ex "target remote:1234"


gdbqemu:
	gdb --args qemu-system-arm -machine mps2-an511 -cpu cortex-m3 -nographic -serial mon:stdio -kernel kernel.elf


debugqemu:
	gdb -ex "b qmp_active_irqs" --args /home/ubuntu/CORTEX-M4-QEMU/build/arm-softmmu//qemu-system-arm -machine mps2-an511 -cpu cortex-m3 \
		-kernel kernel.elf \
		-nographic -qmp tcp:127.0.0.1:3336,server,nowait \
		-nographic -serial mon:stdio \
		-S -s
inkdgb:
	$(GDB) $^ -ex "target remote:1234"
			    
debugqemu1:
	gdb -ex "b avatar_rmemory_write" --args \
		/home/ubuntu/CORTEX-M4-QEMU/build/arm-softmmu/qemu-system-arm -machine flex -d unimp -kernel /home/ubuntu/CORTEX-M4-QEMU/proj/proj_rtos_uart/myavatar/conf.json -gdb tcp::3333 -S -nographic -qmp tcp:127.0.0.1:3334,server,nowait


inkdgb1:
	$(GDB) $^ -ex "target remote:3333"

clean:
	rm -f $(IMAGE) *.o *.list *.sym

.PHONY: all qemu clean
