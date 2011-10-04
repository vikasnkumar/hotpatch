BITS 32
; in 32-bit mode the arguments are passed on the stack. Since we need only two
; arguments at max, we will only push 2 registers. The return value will be
; taken from EAX;
; the function pointer is placed in EBX followed by a triggered breakpoint.
push esi
push edi
call [ebx]
int 3
