/* Linker script to configure memory regions. */
MEMORY
{
   NS_CODE (rx)     : ORIGIN = 0x00000000, LENGTH = 512K
   RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 16k
}

/* Entry Point */
ENTRY(Reset_Handler)



SECTIONS
{

    .text : 
    {
        KEEP(*(.isr_vector))
        *(.text)
        *(.data)
    	*(.bss) 
    } > NS_CODE
    /* Set stack top to end of RAM. */
    __StackTop = ORIGIN(RAM) + LENGTH(RAM);
    

}


