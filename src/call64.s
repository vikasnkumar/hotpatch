BITS 64
; the function pointer is placed in RBX/EBX followed by a triggered breakpoint
; the arguments are expected in RDI and RSI respectively. The return value will
; be extracted from RAX
nop
nop
nop
nop
call [rbx]
int 3
