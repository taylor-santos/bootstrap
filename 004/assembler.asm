; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

brkinc: equ 4096

section .rodata
    im_call:    db      'call'
    il_call     equ $-im_call
    im_cmp:     db      'cmp'
    il_cmp      equ $-im_cmp
    im_inc:     db      'inc'
    il_inc      equ $-im_inc
    im_je:      db      'je'
    il_je       equ $-im_je
    im_jmp:     db      'jmp'
    il_jmp      equ $-im_jmp
    im_jne:     db      'jne'
    il_jne      equ $-im_jne
    im_lea:     db      'lea'
    il_lea      equ $-im_lea
    im_mov:     db      'mov'
    il_mov      equ $-im_mov
    im_ret:     db      'ret'
    il_ret      equ $-im_ret
    im_sub:     db      'sub'
    il_sub      equ $-im_sub
    im_syscall: db      'syscall'
    il_syscall  equ $-im_syscall
    im_test:    db      'test'
    il_test     equ $-im_test
    im_xor:     db      'xor'
    il_xor      equ $-im_xor

op_table:
    dq im_call
    op_im_sz: equ $-op_table
    db il_call
    op_row_sz: equ $-op_table
    dq im_cmp
    db il_cmp
    dq im_inc
    db il_inc
    dq im_je
    db il_je
    dq im_jmp
    db il_jmp
    dq im_jne
    db il_jne
    dq im_lea
    db il_lea
    dq im_mov
    db il_mov
    dq im_ret
    db il_ret
    dq im_sub
    db il_sub
    dq im_syscall
    db il_syscall
    dq im_test
    db il_test
    dq im_xor
    db il_xor

    op_table_end: equ $
    op_row_ct: equ (op_table_end-op_table)/op_row_sz

newline: db `\n`, 0

section .bss

section .text
_start:
    ; call brk(0) to get start of break
    xor edi, edi
    call brk
    ; save start of break to $RBX
    mov rbx, rax
    ; read in
    call stdin_to_heap
    ; tokenize input
    mov rdi, rbx                ; arg1 - buf
    mov rsi, rax                ; arg2 - count
    call tokenize
    ; exit(0)
    xor edi, edi
    jmp exit


; EDI - char
is_ident_start:
    cmp dil, '.'
    je is_ident2
    sub edi, 'A'
    cmp dil, '9'
    jna is_ident3
    xor eax, eax
    ret

; EDI - char
is_ident:
    cmp dil, '9'
    jbe is_ident1
    sub edi, 'A'
    cmp dil, '9'
    jna is_ident3
    xor eax, eax
    ret
is_ident1:
    xor eax, eax
    cmp dil, 47
    seta al
    ret

is_ident2:
    mov eax, 1
    ret

is_ident3:
    mov rax, 0x3FFFFFF43FFFFFF
    bt rax, rdi
    setc al
    movzx eax, al
    ret

; RDI - input string
; RSI - input length
tokenize:
    mov r11, rdi                ; store input ptr in r11
    lea r12, [rdi + rsi]        ; store input end ptr in r12
    mov rbp, r12                ; store next available heap loc in rbp
    ; get current program break and store it in r15
    xor edi, edi
    call brk
    mov r15, rax
tokenize_loop:
    ; check if at end of input
    cmp r11, r12
    ; end loop if at end
    jge tokenize_end
    mov r13b, BYTE [r11]        ; get current char in r13b
    ; call is_ident_start() on current char
    mov edi, r13d
    call is_ident_start
    test rax, rax
    jne tokenize_ident

    cmp r13d, '#'
    je tokenize_comment

    inc r11
    jmp tokenize_loop

tokenize_ident:
    ; char is ident
    ; TODO
    mov r14, r11                ; store start of ident in r14
tokenize_ident2:
    inc r11
    ; check for end of input
    cmp r11, r12
    ; end loop if at end
    jge tokenize_keyword
    mov r13b, BYTE [r11]        ; store current char in r13b
    ; check if char is alphanumeric
    mov edi, r13d
    call is_ident
    test rax, rax
    jne tokenize_ident2

tokenize_keyword:
    ; finished lexing ident, check if it's a known keyword
    mov rdi, r14
    mov rsi, r11
    sub rsi, r14
    call match_keyword
    cmp rax, -1
    je tokenize_found_ident
    ; found keyword
    mov rdi, r14
    mov rsi, r11
    sub rsi, r14
    call puts

    mov rdi, newline
    mov rsi, 1
    call puts

    jmp tokenize_loop

tokenize_comment:
    ; comment
    inc r11
    cmp r11, r12
    ; end loop if at end
    jge tokenize_end
    ; loop until newline is encountered
    mov r13b, BYTE [r11]        ; store current char in r13b
    cmp r13b, `\n`
    jne tokenize_comment

    inc r11
    jmp tokenize_loop

tokenize_found_ident:
    xor edi, edi                ; token type 0 = ident
    mov rsi, r11                ;
    sub rsi, r14                ; ident length
    mov rdx, r14                ; ident ptr
    mov rcx, rbp                ; heap ptr
    mov r8, r15                 ; brk
    call write_token
    add rbp, 3 * 8              ; increment heap ptr
    jmp tokenize_loop

tokenize_end:
    ret

; RDI - token type
; RSI - token data1
; RDX - token data2
; RCX - heap pointer
; R8  - current program break
write_token:
    push r13
    mov rax, r8
    mov r13, rsi
    push r12
    mov r12, rdi
    push rbp
    mov rbp, rdx
    lea rdx, [rcx + 3 * 8]
    push rbx
    mov rbx, rcx
    sub rsp, 8
    cmp rdx, r8
    jnb write_token2
write_token1:
     mov QWORD [rbx + 0 * 8], r12   ; token type
     mov QWORD [rbx + 1 * 8], r13   ; data1
     mov QWORD [rbx + 2 * 8], rbp   ; data2
     add rsp, 8
     pop rbx
     pop rbp
     pop r12
     pop r13
     ret
write_token2:
     lea rdi, [r8 + brkinc]
     call brk
     jmp write_token1

; RDI - char
is_alpha:
    and edi, -33                ; unset the 6th bit to make uppercase
    xor eax, eax
    sub edi, 'A'                ; shift values so 'A'=0 and 'Z'=25
    cmp dil, 25
    setbe al                    ; set RAX to 1 if the value is between 0 and 25 inclusive, 0 otherwise
    ret

; RDI - char
is_num:
    sub edi, '0'                ; shift so '0'=0 and '9'=9
    xor eax, eax
    cmp dil, 9                  ; check if input is between 0 and 9 inclusive
    setbe al
    ret

; RDI - name string
; RSI - name length
; returns RAX - index of matched keyword, or -1 if no match
; clobbers RDX, RCX (via strncmp), R8, R9, R10
match_keyword:
    mov rdx, rsi           ; store str length in rdx, arg3 for strncmp
    mov r10, op_table      ; store table ptr in R10
    xor r9d, r9d           ; store index in r9
match_keyword1:
    mov r8b, BYTE [r10 + op_im_sz]
    ; check if table entry is same length as argument
    cmp r8, rdx
    ; loop if different lengths
    jne match_keyword2
    ; if same lengths, call strncmp
    mov rsi, QWORD [r10]
    call strncmp
    ; if strings differ, increment and loop
    test eax, eax
    jne match_keyword2
    ; if strings match, return index
    mov rax, r9
    ret
match_keyword2:
    ; increment table pointer
    add r10, op_row_sz
    inc r9
    ; check if table ptr is at end and loop if not
    cmp r10, op_table_end
    jl match_keyword1
    ; if no matches found, return -1
    mov rax, -1
    ret


stdin_to_heap:
    push r12
    push rbp
    push rbx
    ; initialize total count to 0
    xor ebp, ebp
    ; brk(0) to get intial break
    xor edi, edi
    call brk
    ; store initial break in $RCX
    mov rbx, rax
stdin_to_heap1:
    ; increment break by brkinc
    mov r12, rbx
    add rbx, brkinc
    mov rdi, rbx
    call brk
    ; read brkinc bytes from stdin
    mov rdi, r12
    mov rsi, brkinc
    call read_stdin
    ; increment total count by amount read
    add rbp, rax
    ; continue reading if full amount was consumed
    cmp rax, brkinc
    je NEAR stdin_to_heap1
    ; set return value to total count
    mov rax, rbp
    pop rbx
    pop rbp
    pop r12
    ret

; RDI - address of buffer
; RSI - number of bytes to read
; return RAX - number of bytes read
read_stdin:
    push r11
    push rcx
    xor eax, eax                ; SYS_read
    mov rdx, rsi                ; count
    mov rsi, rdi                ; buf
    xor edi, edi                ; STDIN
    syscall
    pop rcx
    pop r11
    ret

; RDI - address of buffer to read from
; RSI - number of bytes to write
puts:
    push r11
    push rcx
    mov rax, 0x1                ; SYS_write
    mov rdx, rsi                ; count
    mov rsi, rdi                ; buf
    mov rdi, 0x1                ; STDOUT
    syscall
    pop rcx
    pop r11
    ret


; Sets the program break to the address supplied in $RDI
; Returns the new break in $RAX
brk:
    push r11
    push rcx
    mov rax, 0x0c               ; SYS_brk
    syscall
    pop rcx
    pop r11
    ret

; RDI - str1
; RSI - str2
; RDX - n
; return RAX: returns 0 if equal, otherwise relative difference of first different char
; clobbers RCX, R8
strncmp:
    xor eax, eax
    test rdx, rdx
    jne NEAR strncmp2
    jmp QWORD strncmp5
strncmp1:
    cmp cl, r8b
    jne NEAR strncmp3
    inc rax
    cmp rdx, rax
    je NEAR strncmp4
strncmp2:
    movzx ecx, BYTE [rdi + rax]
    movzx r8d, BYTE [rsi + rax]
    test cl, cl
    jne NEAR strncmp1
strncmp3:
    movzx eax, cl
    sub eax, r8d
    ret
strncmp4:
    xor eax, eax
strncmp5:
    ret

; Terminates the process and returns the value supplied in $rdi
exit:
    mov eax, 0x3c               ; SYS_exit
    syscall                     ; exit()
