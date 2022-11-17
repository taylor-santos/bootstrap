; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .text
_start:

    ; exit(0)
    xor rdi, rdi
    jmp exit

; Terminates the process and returns the value supplied in $rdi
exit:
    mov rax, 0x3c               ; SYS_exit
    syscall                     ; exit()