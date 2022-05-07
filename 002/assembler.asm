; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .rodata
	s_endl: db `\n`
	s_tab:  db `\t`
	s_lbl: db 'label:', `\t`
	z_lbl: equ $-s_lbl
	s_id:  db 'ident:', `\t`
	z_id:  equ $-s_id
	s_hex: db 'hex:  ', `\t`
	z_hex: equ $-s_hex
	s_ins: db 'instr:', `\t`
	z_ins: equ $-s_ins

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
	db il_je, 2, 0x0F, 0xCD
	dq im_jg
	db il_jg, 2, 0x0F, 0x8F
	dq im_jge
	db il_jge, 2, 0x0F, 0x8D
	dq im_jl
	db il_jl, 2, 0x0F, 0x8C
	dq im_jle
	db il_jle, 2, 0x8F, 0x8E
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
	int_to_str_buf: resb 32
	out_sz:         equ 64
	out_buf:        resb out_sz


; r12 - Current source code pointer
; r13 - Start of current token
; r14 - Current instruction pointer in brk
; r15 - Output buffer index
; rbx - Source code end pointer

; stack:
; [ bottom of brk   ]
; ; [ end of code brk ]

section .text
_start:
	xor r15, r15             ; initialize output buffer index
	xor rdi, rdi             ; arg <- 0
	mov rax, 0x0c            ; SYS_brk
	syscall                  ; call brk(0)
	push rax                 ; save bottom of brk to stack
	mov r12, rax             ; set source code ptr to bottom of brk
	mov rbx, rax             ; set rbx to brk pointer
	mov rdx, brkinc          ; SYS_read count argument
gets:
	lea rdi, [rbx + brkinc]  ; increment brk pointer and store in brk() arg
	mov rax, 0x0c            ; SYS_brk
	syscall                  ; brk()
	mov rsi, rbx             ; arg: buf
	mov rbx, rax             ; set brk pointer to new increment
	mov rax, 0x0             ; arg: SYS_read
	xor rdi, rdi             ; arg: STDIN
	syscall                  ; read()
	cmp rax, brkinc          ;
	je NEAR gets             ; keep reading as long as EOF is not encountered
	lea r14, [rsi + rax]     ; initialize instruction pointer to end of code
	mov rbx, r14
scan_loop:
	call scan
	cmp rax, -1
	je NEAR exit

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
	jmp QWORD scan_loop

scan_loop2: ; identifier?
	cmp rax, 0x2
	jne NEAR scan_loop3
	; scanner returned identifier
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

exit:
	call flush
	mov rax, 0x3c   ; exit()
	mov rdi, 0x0    ; return code
	syscall

; calculates edi % 10 and returns rax
; clobbers rcx
mod10:
	mov     eax, edi
	mov     ecx, 10
	cdq
	idiv    ecx
	mov     eax, edx
	ret

; calculates edi / 10 and returns rax
; clobbers rcx
div10:
	mov     eax, edi
	mov     ecx, 10
	cdq
	idiv    ecx
	ret

; writes rdi as a string to int_to_str_buf
; rdi - input int, gets overwritten
; returns rax - length of written string
; clobbers r10, rcx
int_to_str:
	mov r10, int_to_str_buf
	call int_to_str_recurse
	mov rax, r10
	sub rax, int_to_str_buf
	ret
int_to_str_recurse:
	call mod10
	add rax, '0'
	cmp rdi, 10
	jl NEAR int_to_str_end
	push rax
	call div10
	mov rdi, rax
	call int_to_str_recurse
	pop rax
int_to_str_end:
	mov [r10], al
	inc r10
	ret
	mov [r10], BYTE '0'
	inc r10
	ret

; print rdi to stdout
; clobbers r10, rcx
print_int:
	call int_to_str
	mov rdx, rax    ; len
	mov rax, 0x1    ; write()
	mov rdi, 0x1    ; STDOUT
	mov rsi, int_to_str_buf
	syscall
	ret

println:
	mov rax, 0x1    ; SYS_write
	mov rdi, 0x1    ; STDOUT
	mov rsi, s_endl ; buf
	mov rdx, 0x1    ; count
	syscall
	ret

print_tab:
	mov rax, 0x1
	mov rsi, s_tab
	mov rdx, 0x1
	syscall
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

; rdx - write lowest byte to output buffer
putc:
	cmp r15, out_sz
	jl NEAR putc0
	push rdx
	call flush
	pop rdx
putc0:
	mov [out_buf + r15], dl
	inc r15
	ret

flush:
	mov rax, 0x1     ; SYS_write
	mov rdi, 0x1     ; STDOUT
	mov rsi, out_buf ; buf
	mov rdx, r15     ; count
	syscall
	xor r15, r15     ; reset index
	ret