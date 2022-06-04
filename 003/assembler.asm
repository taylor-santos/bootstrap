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

	err_label_msg: db 'error: no label found: '
	err_label_msg_l: equ $-err_label_msg
	err_keyword_ident: db 'error: expected section name', `\n`
	err_keyword_ident_l: equ $-err_keyword_ident
	err_no_section: db 'error: code must begin with a `section` declaration', `\n`
	err_no_section_l: equ $-err_no_section
	newline: db `\n`
	newline_l: equ $-newline
	section_text: db '.text'
	section_text_l: equ $-section_text
	section_rodata: db '.rodata'
	section_rodata_l: equ $-section_rodata

	shstrtab:
		db 0x0
		sh_shstrtab_id: equ $-shstrtab
		sh_shstrtab: db ".shstrtab", 0
		sh_text_id: equ $-shstrtab
		sh_text: db ".text", 0
		sh_rodata_id: equ $-shstrtab
		sh_rodata: db ".rodata", 0
		shstrtab_len: equ $-shstrtab

	padbuflen: equ 256
	padbuf: times padbuflen db 0



section .bss
	brkinc:         equ 256
	inst_offset:    equ 4


; r12 - Current source code pointer
; r13 - Start of current token
; r14 - End of output buffer
; r15 - Current output buffer address
; rbx - Source code end pointer

; stack:
; [ end of input buffer / start of output ]
; [ end of output buffer                  ]
; [ current section ID                    ]
; [ .text start address                   ]
; [ .text end address                     ]
; [ .rodata start address                 ]
; [ .rodata end address                   ]

section .text
_start:
	push rbp
	mov rbp, rsp
	call stdin_to_heap
	push rbx                     ; store output buffer address on stack
	sub rsp, 8 * 6               ; reserve stack space
	mov QWORD [rbp - 3*8], -1    ; initialize section ID to -1
	lea rdi, [rbx + 0x1000]      ; increment brk by 0x1000
	mov rax, 0x0c                ; SYS_brk
	syscall
	mov r14, rax                 ;
	mov r10, rbx                 ;
fill_loop:
	mov QWORD [r10], -1
	add r10, 8
	cmp r10, rdi
	jl NEAR fill_loop            ;
	mov r10, rbx                 ;

	mov DWORD [r10 + 0x00], 0x464c457f          ; EI_MAG:        ELF Magic Number
	mov BYTE  [r10 + 0x04], 0x02                ; EI_CLASS:      64-bit
	mov BYTE  [r10 + 0x05], 0x01                ; EI_DATA:       Little-Endian
	mov BYTE  [r10 + 0x06], 0x01                ; EI_VERSION:    ELF Version
	mov BYTE  [r10 + 0x07], 0x00                ; EI_OSABI:      System V
	mov BYTE  [r10 + 0x08], 0x00                ; EI_ABIVERSION: ABI Version
	mov QWORD [r10 + 0x09], 0x00000000000000    ; EI_PAD:        Padding
	mov WORD  [r10 + 0x10], 0x0002              ; e_type:        ET_EXEC
	mov WORD  [r10 + 0x12], 0x003e              ; e_machine:     AMD x86-64
	mov DWORD [r10 + 0x14], 0x00000001          ; e_version:     ELF Version 1
	mov QWORD [r10 + 0x18], 0x0000000000401000  ; e_entry:     * Entry Point Address
	mov QWORD [r10 + 0x20], 0x0000000000000040  ; e_phoff:       Program Header Table Offset
	mov QWORD [r10 + 0x28], -1                  ; e_shoff:     * Section Header Table Offset
	mov DWORD [r10 + 0x30], 0x00000000          ; e_flags
	mov WORD  [r10 + 0x34], 0x0040              ; e_ehsize:      ELF Header Size
	mov WORD  [r10 + 0x36], 0x0038              ; e_phentsize:   Program Header Table Entry Size
	mov WORD  [r10 + 0x38], 0x0003              ; e_phnum:       Program Header Table Entry Count
	mov WORD  [r10 + 0x3a], 0x0040              ; e_shentsize:   Section Header Table Entry Size
	mov WORD  [r10 + 0x3c], 0x0004              ; e_shnum:       Section Header Table Entry Count
	mov WORD  [r10 + 0x3e], 0x0003              ; e_shstrndx:    Name Table Section Header Index

	add r10, 0x40 ; Program Header 0 - ELF and Program Headers
	mov DWORD [r10 + 0x00], 0x00000001          ; # p_type:        PT_LOAD Loadable Segment
	mov DWORD [r10 + 0x04], 0x00000004          ; # p_flags:       PF_R - Read
	mov QWORD [r10 + 0x08], 0x0000000000000000  ; # p_offset:      Segment Offset
	mov QWORD [r10 + 0x10], 0x0000000000400000  ; # p_vaddr:       Segment Virtual Address
	mov QWORD [r10 + 0x18], 0x0000000000400000  ; # p_paddr:       Segment Physical Address
	mov QWORD [r10 + 0x20], 0x00000000000000e8  ; # p_filesz:    * Size of Segment in File Image
	mov QWORD [r10 + 0x28], 0x00000000000000e8  ; # p_memsz:     * Size of Segment in Memory
	mov QWORD [r10 + 0x30], 0x0000000000001000  ; # p_align:       Alignment

	add r10, 0x38 ; Program Header 1 - .text Section
	mov DWORD [r10 + 0x00], 0x00000001          ; # p_type:        PT_LOAD Loadable Segment
	mov DWORD [r10 + 0x04], 0x00000005          ; # p_flags:       PF_R - Read
	mov QWORD [r10 + 0x08], 0x0000000000001000  ; # p_offset:      Segment Offset
	mov QWORD [r10 + 0x10], 0x0000000000401000  ; # p_vaddr:       Segment Virtual Address
	mov QWORD [r10 + 0x18], 0x0000000000401000  ; # p_paddr:       Segment Physical Address
	mov QWORD [r10 + 0x20], -1                  ; # p_filesz:    * Size of Segment in File Image
	mov QWORD [r10 + 0x28], -1                  ; # p_memsz:     * Size of Segment in Memory
	mov QWORD [r10 + 0x30], 0x0000000000001000  ; # p_align:       Alignment

	add r10, 0x38 ; Program Header 2 - .rodata Section
	mov DWORD [r10 + 0x00], 0x00000001          ; # p_type:        PT_LOAD Loadable Segment
	mov DWORD [r10 + 0x04], 0x00000004          ; # p_flags:       PF_R - Read
	mov QWORD [r10 + 0x08], 0x0000000000002000  ; # p_offset:      Segment Offset
	mov QWORD [r10 + 0x10], 0x0000000000402000  ; # p_vaddr:       Segment Virtual Address
	mov QWORD [r10 + 0x18], 0x0000000000402000  ; # p_paddr:       Segment Physical Address
	mov QWORD [r10 + 0x20], -1                  ; # p_filesz:    * Size of Segment in File Image
	mov QWORD [r10 + 0x28], -1                  ; # p_memsz:     * Size of Segment in Memory
	mov QWORD [r10 + 0x30], 0x0000000000001000  ; # p_align:       Alignment


	mov r15, rdi

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

scan_loop3: ; `section` keyword?
	cmp rax, 0x3
	jne NEAR scan_loop4
	; scanner returned `section` keyword
	call scan
	cmp rax, 0x2 ; check that scan() returned an identifier
	je NEAR process_section0
	mov rsi, err_keyword_ident   ; buf
	mov rdx, err_keyword_ident_l ; len
	mov rax, 0x1                 ; SYS_write
	mov rdi, 0x1                 ; STDOUT
	syscall
	jmp QWORD exit_failure
process_section0:
	call finish_section
	mov rdi, r13                 ; found ident str1
	mov rdx, r12                 ;
	sub rdx, r13                 ; calculate ident width
	cmp rdx, section_text_l      
	jne NEAR process_section1         
	mov rsi, section_text        ; str2
	call strncmp
	test rax, rax
	je NEAR process_section_text
process_section1:
	cmp rdx, section_rodata_l
	jne NEAR process_section2
	mov rsi, section_rodata      ; str2
	call strncmp
	test rax, rax
	je NEAR process_section_rodata
process_section2:
	mov rsi, err_keyword_ident   ; buf
	mov rdx, err_keyword_ident_l ; len
	mov rax, 0x1                 ; SYS_write
	mov rdi, 0x1                 ; STDOUT
	syscall
	jmp QWORD exit_failure

process_section_text:
	mov QWORD [rbp-24], 0x0
	mov QWORD [rbp-32], r15
	jmp QWORD scan_loop
process_section_rodata:
	mov QWORD [rbp-24], 0x1
	mov QWORD [rbp-48], r15
	jmp QWORD scan_loop

scan_loop4: ; instruction
	; scanner returned instruction
	sub rax, inst_offset    ; adjust id so it works as instruction index
	imul rax, row_w         ; adjust for table row width
	add rax, table          ; adjust for table start offset

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
	cmp al, 's'
	je NEAR scan_msection
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

scan_msection: ; scan maybe `section` keyword, starts with 's'
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; E
	movzx rax, BYTE [r12]
	cmp al, 'e'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; C
	movzx rax, BYTE [r12]
	cmp al, 'c'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; T
	movzx rax, BYTE [r12]
	cmp al, 't'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; I
	movzx rax, BYTE [r12]
	cmp al, 'i'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; O
	movzx rax, BYTE [r12]
	cmp al, 'o'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	; N
	movzx rax, BYTE [r12]
	cmp al, 'n'
	jne NEAR scan_ident_cmp
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end  ; TODO - does this count as a complete `section` keyword???
	mov rax, 0x3             ; return token ID 3 - `section` keyword
	ret


scan_ident:
	inc r12
	cmp r12, rbx
	jge NEAR scan_ident_end
	movzx rax, BYTE [r12]
scan_ident_cmp:
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

; check if identifier matches known instruction, otherwise return IDENT token
table_loop:
	cmp dl, [r15 + 8]            ; get length from table and compare to strlen
	jne NEAR table_loop_continue ; continue if lengths are different
	mov rdi, [r15]               ; strncmp str1 arg: table instruction string
	call strncmp
	test rax, rax                ;
	jne NEAR table_loop_continue ; continue if token doesn't match table entry
	mov rax, r14 ; 
	add rax, inst_offset         ; return instruction table index offset by other token types
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
	lea r12, [rbp - 8*8]     ; ident symbol table pointer, 8 * 8-byte values on stack before table
ident_loop:
	cmp r12, rsp
	jle NEAR ident_loop_end

	mov rdx, [r12]          ; get flag/ident length
	test rdx, 1             ; check ident flag
	je NEAR ident_loop_continue
	shr rdx, 1              ; remove flag bit
	mov rdi, [r12 - 8]      ; ident text pointer

	lea r13, [rbp - 8*8]     ; label symbol table pointer, 8 * 8-byte values on stack before table
label_loop:
	cmp r13, rsp
	jle NEAR label_loop_end

	mov r10, [r13]               ; get flag/ident length
	test r10, 1                  ; check ident flag
	jne NEAR label_loop_continue ; continue if not a label
	shr r10, 1                   ; remove flag bit
	cmp r10, rdx                 ; compare label length with ident length
	jne NEAR label_loop_continue ; continue if lengths differ
	mov rsi, [r13 - 8]           ; label text into strncmp str2 arg
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
	mov r13, rdx             ; save label length

	mov rax, 0x1             ; SYS_write
	mov rdi, 0x2             ; STDERR
	mov rsi, err_label_msg   ; buf
	mov rdx, err_label_msg_l ; len
	syscall

	mov rax, 0x1             ; SYS_write
	mov rsi, [r12 - 8]       ; label text
	mov rdx, r13             ; label length
	syscall

	mov rax, 0x1             ; SYS_write
	mov rsi, newline         ; buf
	mov rdx, newline_l       ; len
	syscall
	jmp QWORD exit_failure        ; no labels matching ident found

ident_loop_continue:
	sub r12, 3*8            ; increment ident symbol table pointer
	jmp QWORD ident_loop

ident_loop_end:
	jmp QWORD exit


finish_section:
	cmp BYTE [rbp-24], 0x0   ; check if previous section is .text
	jne NEAR finish_section1
	mov QWORD [rbp-40], r15  ; set end of .text address to current output address
	jmp NEAR finish_section2
finish_section1:
	cmp BYTE [rbp-24], 0x1   ; check if previous section is .rodata
	jne NEAR finish_section2
	mov QWORD [rbp-56], r15  ; set end of .rodata address to current output address
finish_section2:
	ret

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

; rdi - number of bytes to write, must be greater than zero
write_padding:
	mov r10, rdi
	mov rdi, 0x1       ; STDOUT
	mov rsi, padbuf    ; buf
	mov rdx, padbuflen ; len
write_padding1:
	mov rax, 0x1       ; SYS_write
	cmp r10, padbuflen ;
	cmovle rdx, r10    ;
	sub r10, padbuflen ;
	syscall
	test r10, r10
	jg NEAR write_padding1
	ret

; rsi - pointer to start
; rdx - total size
flush:
	mov rax, 0x1       ; SYS_write
	mov rdi, 0x1       ; STDOUT
	syscall
	ret

exit:
	call finish_section

	mov rsi, [rbp - 8]          ; start of output buffer on heap

	mov r10, [rbp - 40]         ; end of .text
	sub r10, [rbp - 32]         ; start of .text
	mov [rbp - 40], r10         ; save .text size to stack
	mov QWORD [rsi + 0x98], r10 ;
	mov QWORD [rsi + 0xa0], r10 ; write .text size to program header

	mov r10, [rbp - 56]         ; end of .rodata
	sub r10, [rbp - 48]         ; start of .rodata
	mov [rbp - 56], r10         ; save .rodata size to stack
	mov QWORD [rsi + 0xd0], r10 ;
	mov QWORD [rsi + 0xd8], r10 ; write .rodata size to program header

	mov eax, r10d
	mov edx, 0                  ;
	mov ecx, 0x100              ;
	div ecx                     ; divide size of .rodata by 0x100, saving result in rdx
	mov rdi, 0x100              ;
	sub rdi, rdx                ; calculate necessary padding after .rodata to align to 0x100
	push rdi                    ; save padding size to stack

	add rdi, 0x2000             ;
	add rdi, r10                ;
	mov QWORD [rsi + 0x28], rdi ; write address of .rodata section to entry in ELF header

	mov rax, 0x1                ; SYS_write
	mov rdi, 0x1                ; STDOUT
	mov rdx, 0x40 + 3*0x38      ; length of ELF header and program table
	syscall

	mov rdi, 0x1000 - (0x40 + 3*0x38)
	call write_padding

	mov rax, 0x1
	mov rdi, 0x1
	mov QWORD rsi, [rbp - 32]   ; start of .text
	mov QWORD rdx, [rbp - 40]   ; length of .text
	syscall

	mov rdi, 0x1000             ;
	sub rdi, rdx                ;
	call write_padding          ; padding for .rodata section

	mov rax, 0x1
	mov rdi, 0x1
	mov QWORD rsi, [rbp - 48]   ; start of .rodata
	mov QWORD rdx, [rbp - 56]   ; length of .rodata
	syscall

	pop r12                     ;
	mov rdi, r12
	call write_padding          ; padding for section header table

	mov r13, [rbp - 40]         ; size of .text section
	mov r14, [rbp - 56]         ; size of .rodata section
	lea r15, [0x2000 + r14 + 4*0x40] ; start of .rodata + length + size of section header table
	add r15, r12                     ; add padding

	mov QWORD r10, [rbp - 16]   ; end of output buffer
	lea rdi, [r10 + 4*0x40]     ; adjust brk to fit section table headers
	mov rax, 0x0c               ; SYS_brk
	syscall



	mov r11, r10
	; Section Table 0 (Reserved)
	mov DWORD [r11 + 0x00], 0x00000000         ; sh_name
	mov DWORD [r11 + 0x04], 0x00000000         ; sh_type
	mov QWORD [r11 + 0x08], 0x0000000000000000 ; sh_flags
	mov QWORD [r11 + 0x10], 0x0000000000000000 ; sh_addr
	mov QWORD [r11 + 0x18], 0x0000000000000000 ; sh_offset
	mov QWORD [r11 + 0x20], 0x0000000000000000 ; sh_size
	mov DWORD [r11 + 0x28], 0x00000000         ; sh_link
	mov DWORD [r11 + 0x2c], 0x00000000         ; sh_info
	mov QWORD [r11 + 0x30], 0x0000000000000000 ; sh_addralign
	mov QWORD [r11 + 0x38], 0x0000000000000000 ; sh_entsize
	add r11, 0x40
	; Section Table 1 (.text)
	mov DWORD [r11 + 0x00], sh_text_id         ; sh_name:        ".text"
	mov DWORD [r11 + 0x04], 0x00000001         ; sh_type:        SHT_PROGBITS - Program Data
	mov QWORD [r11 + 0x08], 0x0000000000000006 ; sh_flags:       SHF_ALLOC|SHF_EXECINSTR - Occupies Memory and is Executable
	mov QWORD [r11 + 0x10], 0x0000000000401000 ; sh_addr:      * Virtual address in memory if loaded
	mov QWORD [r11 + 0x18], 0x0000000000001000 ; sh_offset:    * Offset in File Image
	mov QWORD [r11 + 0x20], r13                ; sh_size:      * Size in File Image
	mov DWORD [r11 + 0x28], 0x00000000         ; sh_link:        Associated Section Index
	mov DWORD [r11 + 0x2c], 0x00000000         ; sh_info:        Extra Info
	mov QWORD [r11 + 0x30], 0x0000000000000010 ; sh_addralign:   Alignment
	mov QWORD [r11 + 0x38], 0x0000000000000000 ; sh_entsize:     Fixed Size Entry Size
	add r11, 0x40
	; Section Table 2 (.rodata)
	mov DWORD [r11 + 0x00], sh_rodata_id       ; sh_name         ".rodata"
	mov DWORD [r11 + 0x04], 0x00000001         ; sh_type         SHT_PROGBITS - Program Data
	mov QWORD [r11 + 0x08], 0x0000000000000002 ; sh_flags        SHF_ALLOC - Occupies Memory
	mov QWORD [r11 + 0x10], 0x0000000000402000 ; sh_addr       * Virtual Address
	mov QWORD [r11 + 0x18], 0x0000000000002000 ; sh_offset     * Offset in File Image
	mov QWORD [r11 + 0x20], r14                ; sh_size       * Size in File Image
	mov DWORD [r11 + 0x28], 0x00000000         ; sh_link         
	mov DWORD [r11 + 0x2c], 0x00000000         ; sh_info         
	mov QWORD [r11 + 0x30], 0x0000000000000004 ; sh_addralign    
	mov QWORD [r11 + 0x38], 0x0000000000000000 ; sh_entsize      
	add r11, 0x40
	; Section Table 3 (.shstrtab)
	mov DWORD [r11 + 0x00], sh_shstrtab_id     ; sh_name:        ".shstrtab"
	mov DWORD [r11 + 0x04], 0x00000003         ; sh_type:        SHT_STRTAB - String Table
	mov QWORD [r11 + 0x08], 0x0000000000000000 ; sh_flags:       None
	mov QWORD [r11 + 0x10], 0x0000000000000000 ; sh_addr:        Virtual address in memory if loaded
	mov QWORD [r11 + 0x18], r15                ; sh_offset:    * Offset in File Image
	mov QWORD [r11 + 0x20], shstrtab_len       ; sh_size:        Size in File Image
	mov DWORD [r11 + 0x28], 0x00000000         ; sh_link:        Associated Section Index
	mov DWORD [r11 + 0x2c], 0x00000000         ; sh_info:        Extra Info
	mov QWORD [r11 + 0x30], 0x0000000000000001 ; sh_addralign:   Alignment
	mov QWORD [r11 + 0x38], 0x0000000000000000 ; sh_entsize:     Fixed Size Entry Size

	mov rax, 0x1
	mov rdi, 0x1
	mov rsi, r10
	mov rdx, 4*0x40
	syscall

	mov rax, 0x1
	mov rdi, 0x1
	mov rsi, shstrtab
	mov rdx, shstrtab_len
	syscall

	mov rax, 0x3c   ; SYS_exit
	mov rdi, 0x0    ; return code
	syscall

exit_failure:
	mov rax, 0x3c      ; SYS_exit
	mov rdi, 0x1       ; return code
	syscall