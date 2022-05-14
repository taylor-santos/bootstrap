; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .rodata
	im_call: db 'call'
	il_call: equ $-im_call
	im_je: db 'je'
	il_je: equ $-im_je
	im_jg: db 'jg'
	il_jg: equ $-im_jg
	im_jge: db 'jge'
	il_jge: equ $-im_jge
	im_jl: db 'jl'
	il_jl: equ $-im_jl
	im_jle: db 'jle'
	il_jle: equ $-im_jle
	im_jmp: db 'jmp'
	il_jmp: equ $-im_jmp
	im_jne: db 'jne'
	il_jne: equ $-im_jne
	im_ret: db 'ret'
	il_ret: equ $-im_ret
	im_syscall: db 'syscall'
	il_syscall: equ $-im_syscall

table:
	dq im_call
	db il_call, 1, 0xE8, 0
	row_w: equ $-table            ; calculate the width in bytes of one table row
	dq im_je
	db il_je, 2, 0x0F, 0x84
	dq im_jg
	db il_jg, 2, 0x0F, 0x8F
	dq im_jge
	db il_jge, 2, 0x0F, 0x8D
	dq im_jl
	db il_jl, 2, 0x0F, 0x8C
	dq im_jle
	db il_jle, 2, 0x0F, 0x8E
	dq im_jmp
	db il_jmp, 1, 0xE9, 0
	dq im_jne
	db il_jne, 2, 0x0F, 0x85
	dq im_ret
	db il_ret, 1, 0xC3, 0
	dq im_syscall
	db il_syscall, 2, 0x0F, 0x05
	row_c: equ ($-table)/row_w    ; calculate the total number of rows in the table
	table_end: equ $

section .bss
	brkinc:         equ 64

; r12 - Current source code pointer
; r13 - Start of current token
; r14 - End of output buffer
; r15 - Current output buffer address
; rbx - Source code end pointer

; stack:
; [ end of input buffer / start of output ]
; [ end of output buffer ]

section .text
_start:
	push rbp
	mov rbp, rsp
	call stdin_to_heap
	push rbx             ; store output buffer address on stack
	mov r10, 0xDEADBEEFDEADBEEF  ;
	push r10             ; reserve space for buffer size (to be filled after parsing)
	mov r15, rbx
scan_loop:
	call scan
	cmp rax, -1
	je NEAR ident_pass

	cmp rax, 0x0
	jne NEAR scan_loop1
	; scanner returned hex literal
print_hex:
	add r13, 2                 ; increment current token pointer by 2 bytes
	cmp r13, r12               ; check that there are at least 2 characters in the buffer
	jg NEAR scan_loop
	movzx rdx, BYTE [r13-2]
	call hex_to_byte
	mov r10b, dl
	movzx rdx, BYTE [r13-1]
	call hex_to_byte
	shl r10b, 4
	add dl, r10b
	call putc
	jmp QWORD print_hex

scan_loop1: ; label?
	cmp rax, 0x1
	jne NEAR scan_loop2
	; scanner returned label
	; TODO
	mov r10, r12 ;
	sub r10, r13 ; calculate label width
	shl r10, 1
	push r10     ; store label width
	push r13     ; store label text address
	push r15     ; store current instruction address
	jmp QWORD scan_loop

scan_loop2: ; identifier?
	cmp rax, 0x2
	jne NEAR scan_loop3
	; scanner returned identifier
	mov r10, r12     ;
	sub r10, r13     ; calculate label width
	shl r10, 1       ; unset ident flag
	inc r10          ; set ident flag
	push r10         ; store label width + flag
	push r13         ; store label text address
	push r15         ; store current instruction address

	mov rdx, 0x7F    ;
	call putc        ;
	call putc        ;
	call putc        ;
	call putc        ; save a dummy address to output
	
	; TODO
	jmp QWORD scan_loop

scan_loop3: ; instruction
	; scanner returned instruction
	sub rax, 0x3    ; adjust id so it works as instruction index
	imul rax, row_w ; adjust for table row width
	add rax, table  ; adjust for table start offset

	push r12
	push r13
	lea r13, [rax + 10]       ; start of instruction bytes in table
	movzx r12, BYTE [rax + 9] ; get instruction byte count from table
put_bytes:
	movzx rdx, BYTE [r13]
	call putc
	inc r13
	dec r12
	test r12, r12
	jne NEAR put_bytes

	pop r13
	pop r12
	jmp QWORD scan_loop

scan_restart:
	inc r12
scan:
	cmp r12, rbx
	jl NEAR scan0
	mov rax, -1
	ret
scan0:
	mov r13, r12             ; set start address of current token
	movzx rax, BYTE [r12]
	cmp al, '#'
	je NEAR scan_comment
	cmp al, '.'
	je NEAR scan_ident
	cmp al, '0'
	jl NEAR scan_restart
	cmp al, '9'
	jle NEAR scan_hex
	cmp al, 'A'
	jl NEAR scan_restart
	cmp al, 'F'
	jle NEAR scan_mhex
	cmp al, 'Z'
	jle NEAR scan_ident
	cmp al, '_'
	je NEAR scan_ident
	cmp al, 'a'
	jl NEAR scan_restart
	cmp al, 'f'
	jle NEAR scan_mhex
	cmp al, 'z'
	jle NEAR scan_ident
	jmp QWORD scan_restart

scan_mhex: ; scan maybe hex - could be hex or identifier/label
	inc r12
	cmp r12, rbx
	jge NEAR scan_hex_end
	movzx rax, BYTE [r12]
	cmp al, '0'
	jl NEAR scan_hex_end
	cmp al, '9'
	jle NEAR scan_mhex
	cmp al, ':'
	jle NEAR scan_label_end ; ends in ':', must be label
	cmp al, 'A'
	jl NEAR scan_hex_end
	cmp al, 'F'
	jle NEAR scan_mhex
	cmp al, 'Z'
	jle NEAR scan_ident
	cmp al, '_'
	je NEAR scan_ident
	cmp al, 'a'
	jl NEAR scan_hex_end
	cmp al, 'f'
	jle NEAR scan_mhex
	cmp al, 'z'
	jle NEAR scan_ident
	jmp QWORD scan_hex_end

scan_hex:
	inc r12
	cmp r12, rbx
	jge NEAR scan_hex_end
	movzx rax, BYTE [r12]
	cmp al, '0'
	jl NEAR scan_hex_end
	cmp al, '9'
	jle NEAR scan_hex
	cmp al, 'A'
	jl NEAR scan_hex_end
	cmp al, 'F'
	jle NEAR scan_hex
	cmp al, 'a'
	jl NEAR scan_hex_end
	cmp al, 'f'
	jle NEAR scan_hex
scan_hex_end:
	mov rax, 0x0
	ret

scan_ident:
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	movzx rax, BYTE [r12]
	cmp al, '0'
	jl NEAR scan_ident_end
	cmp al, '9'
	jle NEAR scan_ident
	cmp al, ':'
	je NEAR scan_label_end
	cmp al, 'A'
	jl NEAR scan_ident_end
	cmp al, 'Z'
	jle NEAR scan_ident
	cmp al, '_'
	je NEAR scan_ident
	cmp al, 'a'
	jl NEAR scan_ident_end
	cmp al, 'z'
	jle NEAR scan_ident
scan_ident_end:
	push r14
	xor r14, r14   ; initialize table index
	push r15
	mov r15, table ; initialize table pointer

	mov rdx, r12 ;
	sub rdx, r13 ; strncmp n arg: len of current token
	mov rsi, r13 ; strncmp str2 arg: token string

table_loop:
	cmp dl, [r15 + 8]            ; get length from table and compare to strlen
	jne NEAR table_loop_continue ; continue if lengths are different
	mov rdi, [r15]               ; strncmp str1 arg: table instruction string
	call strncmp
	test rax, rax                ;
	jne NEAR table_loop_continue ; continue if token doesn't match table entry
	mov rax, r14 ; 
	add rax, 0x3 ; return instruction table index offset by other token types
	pop r15
	pop r14
	ret
table_loop_continue:
	add r15, row_w      ; increment table pointer
	inc r14             ;
	cmp r14, row_c      ;
	jl NEAR table_loop  ; increment and compare table index
; end of table_loop
	mov rax, 0x2
	pop r15
	pop r14
	ret

scan_label_end:
	mov rax, 0x1
	ret

scan_comment:
	inc r12
	cmp r12, rbx
	jl NEAR scan_comment0
	mov rax, -1
	ret
scan_comment0:
	movzx rax, BYTE [r12]
	cmp al, `\n`
	je NEAR scan
	cmp al, `\r`
	je NEAR scan
	jmp QWORD scan_comment


ident_pass:
	mov [rbp - 16], r15
	lea r12, [rbp - 24]     ; ident symbol table pointer
ident_loop:
	cmp r12, rsp
	jle NEAR ident_loop_end

	mov rdx, [r12]          ; get flag/ident length
	test rdx, 1             ; check ident flag
	je NEAR ident_loop_continue
	shr rdx, 1              ; remove flag bit
	mov rdi, [r12 - 8]      ; ident text pointer

	lea r13, [rbp - 24]     ; label symbol table pointer
label_loop:
	cmp r13, rsp
	jle NEAR label_loop_end

	mov r10, [r13]          ; get flag/ident length
	test r10, 1             ; check ident flag
	jne NEAR label_loop_continue ; continue if not a label
	shr r10, 1              ; remove flag bit
	cmp r10, rdx            ; compare label length with ident length
	jne NEAR label_loop_continue ; continue if lengths differ
	mov rsi, [r13 - 8]      ; label text into strncmp str2 arg
	call strncmp
	test rax, rax                ;
	jne NEAR label_loop_continue ; continue if token doesn't match table entry
	mov r10, [r13 - 16]     ;
	sub r10, [r12 - 16]     ; calculate offset between ident and label
	sub r10, 4              ; account for width of jump address
	mov r11, [r12 - 16]
	mov DWORD [r11], r10d          ; overwrite output at correct location with offset value

	jmp QWORD ident_loop_continue ; matching label found, continue to next ident

label_loop_continue:
	sub r13, 3*8            ; increment label symbol table pointer
	jmp QWORD label_loop

label_loop_end:
	jmp QWORD exit_failure        ; no labels matching ident found

ident_loop_continue:
	sub r12, 3*8            ; increment ident symbol table pointer
	jmp QWORD ident_loop

ident_loop_end:
	jmp QWORD exit


; Read the whole contents of stdin onto the heap.
; Returns:
;   r12 - pointer to start of block
;   rbx - pointer to end of block
;   r14 - pointer to top of brk
stdin_to_heap:
	mov rax, 0x0c            ; SYS_brk
	xor rdi, rdi             ; arg: brk
	syscall                  ; brk(0)
	mov rsi, rax             ; SYS_read buf argument
	mov r12, rax             ; output
	mov rdx, brkinc          ; SYS_read count argument
stdin_to_heap0:
	lea rdi, [rsi + brkinc]  ; set brk arg
	mov rax, 0x0c            ; SYS_brk
	syscall                  ; brk()
	xor rax, rax             ; SYS_read
	xor rdi, rdi             ; STDIN
	syscall                  ; read()
	cmp rax, brkinc          ;
	jl NEAR stdin_to_heap1   ; exit loop when EOF is encountered
	add rsi, brkinc          ; increment brk pointer
	jmp QWORD stdin_to_heap0 ; loop until EOF is encountered
stdin_to_heap1:
	lea rbx, [rsi + rax]     ; output end of input
	lea r14, [rsi + brkinc]  ; output top of brk
	ret


; rdi - str1
; rsi - str2
; rdx - n
; rax: returns 0 if equal, otherwise relative difference of first different char
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

; rdx - input and output
; assumes input is a valid hex digit in ASCII, undefined behavior if not
hex_to_byte:
	cmp dl, '9'
	jg NEAR hex_to_byte1
	sub dl, '0'
	jmp QWORD hex_to_byte3
hex_to_byte1:
	cmp dl, 'F'
	jg NEAR hex_to_byte2
	sub dl, 'A'-0xA
	jmp QWORD hex_to_byte3
hex_to_byte2:
	sub dl, 'a'-0xA
hex_to_byte3:
	ret

; rdx - write lowest byte to output buffer on heap
putc:
	cmp r15, r14              ; check if buffer is full
	jl NEAR putc0
	lea rdi, [r14 + brkinc]   ; arg: brk
	mov rax, 0x0c             ; SYS_brk
	syscall
	mov r14, rdi
putc0:
	mov [r15], dl
	inc r15
	ret

; rsi - pointer to start
; rdx - total size
flush:
	mov rax, 0x1       ; SYS_write
	mov rdi, 0x1       ; STDOUT
	syscall
	ret

exit:
	mov rsi, [rbp - 8]
	mov rdx, [rbp - 16]       ;
	sub rdx, rsi              ; subtract start from end to get length of output
	call flush
	mov rax, 0x3c   ; SYS_exit
	mov rdi, 0x0    ; return code
	syscall

exit_failure:
	mov rax, 0x3c   ; SYS_exit
	mov rdi, 0x1    ; return code
	syscall