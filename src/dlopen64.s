BITS 64
;The aim of this code is to call dlopen() and it is very restrictive in what it
;can and cannot do. The function that this code will perform will very much
;depend on what exists in the registers at that point of time.
; calling brk()
xor rax, rax ; zero out the RAX for the return value
xor rdi, rdi ; zero out the RDI for the first argument
mov al, 0xc ; __NR_brk is 12. Using DL to reduce NULLs in output bytes
syscall
mov rdi, rax ; moving the result into rdi
; lets allocate 0x0100 bytes
xor rcx, rcx
mov cl, 0xFF
inc rcx
add rdi, rcx ; add the 0xFF to RDI without NULLs in output bytes
xor rax, rax
mov al, 0xc
syscall     ; with this you have allocated memory of count bytes

; calling exit()
xor rax, rax
xor rdi, rdi
mov al, 0x3c
syscall
