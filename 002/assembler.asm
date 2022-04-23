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
	dq il_call
	row_w: equ $-table            ; calculate the width in bytes of one table row
	dq im_je
	dq il_je
	dq im_jg
	dq il_jg
	dq im_jge
	dq il_jge
	dq im_jl
	dq il_jl
	dq im_jle
	dq il_jle
	dq im_jmp
	dq il_jmp
	dq im_jne
	dq il_jne
	dq im_ret
	dq il_ret
	dq im_syscall
	dq il_syscall
	row_c: equ ($-table)/row_w    ; calculate the total number of rows in the table
	table_end: equ $

section .bss
	brkinc:  equ 64
	int_to_str_buf: resb 32


; r12 - Current source code pointer
; r13 - Start of current token
; rbx - Source code end pointer

; stack:
; [ bottom of brk ]
; [ top of brk    ]

section .text
_start:
	xor rdi, rdi             ; arg <- 0
	mov rax, 0x0c            ; brk()
	syscall                  ; call brk(0)
	push rax                 ; save bottom of brk to stack
	mov rbx, rax             ; set rbx to brk pointer
	mov rdx, brkinc          ; SYS_read count argument
gets:
	lea rdi, [rbx + brkinc]  ; increment brk pointer and store in brk() arg
	mov rax, 0x0c            ; SYS_brk
	syscall                  ; brk()
	mov rsi, rbx             ; move prev brk pointer to buf argument
	mov rbx, rax             ; set brk pointer to new increment
	mov rax, 0x0             ; SYS_read
	xor rdi, rdi             ; STDIN
	syscall                  ; read()
	cmp rax, brkinc          ;
	je gets                  ; keep reading as long as EOF is not encountered
	sub rbx, brkinc          ;
	add rbx, rax             ; 

	mov r12, [rsp]           ; set source code ptr to bottom of brk
	push rbx                 ; push top of brk to stack
scan_loop:
	call scan
	cmp rax, -1
	je exit

	cmp rax, 0x0
	jne scan_loop1
	mov rsi, s_hex
	mov rdx, z_hex
	jmp print_token

scan_loop1:
	cmp rax, 0x1
	jne scan_loop2
	mov rsi, s_lbl
	mov rdx, z_lbl
	jmp print_token

scan_loop2:
	cmp rax, 0x2
	jne scan_loop3
	mov rsi, s_id
	mov rdx, z_id
	jmp print_token

scan_loop3:
	mov rsi, s_ins
	mov rdx, z_ins
	jmp print_token
	
print_token:
	mov rdi, 0x1    ; STDOUT
	mov rax, 0x1    ; write()
	syscall

	mov rax, 0x1    ; write()
	mov rdi, 0x1    ; STDOUT
	mov rsi, r13
	mov rdx, r12
	sub rdx, r13
	syscall
	call println

	jmp scan_loop

scan_restart:
	inc r12
scan:
	cmp r12, rbx
	jl scan0
	mov rax, -1
	ret
scan0:
	mov r13, r12             ; set start address of current token
	mov al, [r12]
	cmp al, '#'
	je scan_comment
	cmp al, '.'
	je scan_ident
	cmp al, '0'
	jl scan_restart
	cmp al, '9'
	jle scan_hex
	cmp al, 'A'
	jl scan_restart
	cmp al, 'F'
	jle scan_mhex
	cmp al, 'Z'
	jle scan_ident
	cmp al, '_'
	je scan_ident
	cmp al, 'a'
	jl scan_restart
	cmp al, 'f'
	jle scan_mhex
	cmp al, 'z'
	jle scan_ident
	jmp scan_restart

scan_mhex: ; scan maybe hex - could be hex or identifier
	inc r12
	cmp r12, rbx
	jge scan_hex_end
	mov al, [r12]
	cmp al, '0'
	jl scan_hex_end
	cmp al, '9'
	jle scan_mhex
	cmp al, ':'
	jle scan_label_end
	cmp al, 'A'
	jl scan_hex_end
	cmp al, 'F'
	jle scan_mhex
	cmp al, 'Z'
	jle scan_ident
	cmp al, '_'
	je scan_ident
	cmp al, 'a'
	jl scan_hex_end
	cmp al, 'f'
	jle scan_mhex
	cmp al, 'z'
	jle scan_ident
	jmp scan_hex_end

scan_hex:
	inc r12
	cmp r12, rbx
	jge scan_hex_end
	mov al, [r12]
	cmp al, '0'
	jl scan_hex_end
	cmp al, '9'
	jle scan_hex
	cmp al, 'A'
	jl scan_hex_end
	cmp al, 'F'
	jle scan_hex
	cmp al, 'a'
	jl scan_hex_end
	cmp al, 'f'
	jle scan_hex
scan_hex_end:
	mov rax, 0x0
	ret

scan_ident:
	inc r12
	cmp r12, rbx
	jge scan_ident_end
	mov al, [r12]
	cmp al, '0'
	jl scan_ident_end
	cmp al, '9'
	jle scan_ident
	cmp al, ':'
	je scan_label_end
	cmp al, 'A'
	jl scan_ident_end
	cmp al, 'Z'
	jle scan_ident
	cmp al, '_'
	je scan_ident
	cmp al, 'a'
	jl scan_ident_end
	cmp al, 'z'
	jle scan_ident
scan_ident_end:
	; mov rax, 0x1
	; mov rdi, 0x1
	; mov rsi, r13
	; mov rdx, r12
	; sub rdx, r13
	; syscall
	; call println
	mov r14, 0x0 ; initialize table index
table_loop:
	cmp r14, row_c
	jge end_table_loop

	mov rdx, r12
	sub rdx, r13

	; convert table index into row address
	mov r15, r14
	imul r15, row_w
	add r15, table

	cmp rdx, [r15 + 8] ; length of instruction entry
	jne loop_continue
	mov rdi, [r15]     ; table instruction string
	mov rsi, r13       ; actual instruction string
	call strncmp
	test rax, rax
	jne loop_continue

	; mov rdi, r15    ; int_to_str argument
	; call print_int
	; call print_tab

	; mov rdi, [r15]
	; call print_int
	; call print_tab

	; mov rdi, [r15 + 8]
	; call print_int
	; call print_tab

	; ; print the instruction
	; mov rsi, [r15]        ; buf
	; mov rdx, [r15 + 8]    ; len
	; mov rax, 0x1          ; write()
	; mov rdi, 0x1          ; STDOUT
	; syscall

	; call println

	mov rax, r14
	add rax, 0x3
	ret

loop_continue:
	inc r14
	jmp table_loop

end_table_loop:
	mov rax, 0x2
	ret

scan_label_end:
	mov rax, 0x1
	ret

scan_comment:
	inc r12
	cmp r12, rbx
	jl scan_comment0
	ret
scan_comment0:
	mov al, [r12]
	cmp al, `\n`
	je scan
	cmp al, `\r`
	je scan
	jmp scan_comment

exit:
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
	jl int_to_str_end
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

print_int:
	call int_to_str
	mov rdx, rax    ; len
	mov rax, 0x1    ; write()
	mov rdi, 0x1    ; STDOUT
	mov rsi, int_to_str_buf
	syscall
	ret

println:
	mov rax, 0x1
	mov rsi, s_endl
	mov rdx, 0x1
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
	jne strncmp2
	jmp strncmp5
strncmp1:
	cmp cl, r8b
	jne strncmp3
	inc rax
	cmp rdx, rax
	je strncmp4
strncmp2:
	movzx ecx, BYTE [rdi + rax]
	movzx r8d, BYTE [rsi + rax]
	test cl, cl
	jne strncmp1
strncmp3:
	movzx eax, cl
	sub eax, r8d
	ret
strncmp4:
	xor eax, eax
	ret
strncmp5:
	ret