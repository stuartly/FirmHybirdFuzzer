

.section .isr_vector 	
    .long    __StackTop         /* Initial Top of Stack */
    .long    Reset_Handler + 1      /* Reset Handler */
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Reset_Handler + 1
    .long    Int0_Handler + 1
   

.text
.global Reset_Handler
Reset_Handler:  
    CPSIE   I
    ldr     R0, =0x20000000
    mov     R1, #0
    str     R1, [r0]
    ldr     R0, = main
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    bx      R0

.text
.global Int0_Handler
Int0_Handler:
    push {r7, lr}
    ldr     R0, =0x20000000
    ldr r1, [r0]
    add  r1, r1, #1
    str  r1, [r0]
    pop {r7, pc}
