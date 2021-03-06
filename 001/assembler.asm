; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .bss
	insz:  equ 64
	inbuf:  resb insz
	outsz: equ 64
	outbuf: resb outsz

; r12    in index
; r13    in size
; r14    out index
; r15    out ptr

section .text
_start:
	mov r12, insz   ; in buf index
	mov r13, insz   ; read in count
	xor r14, r14    ; out buf index
	mov r15, outbuf ; out buf pointer
prompt:
	call gethex     ; read the next hex value into rax
	mov bl, al      ; copy digit into rbx
	shl bl, 0x4     ; left shift digit by 4
	call gethex     ; read the next hex value into rax
	add bl, al      ; add the two digits together
	mov [r15], bl   ; copy digit into buffer at current index
	inc r15         ; increment buffer pointer
	inc r14         ; increment buffer index
	cmp r14, outsz
	jl NEAR continue
	call flush      ; if the output buffer is full, flush it
continue:
	jmp QWORD prompt
gethex:
	call getchar
	cmp al, '#'
	je NEAR comment
	cmp al, '0'
	jl NEAR gethex
	cmp al, '9'
	jg NEAR gethex1
	sub al, '0'
	jmp QWORD rethex
gethex1:
	cmp al, 'A'
	jl NEAR gethex
	cmp al, 'F'
	jg NEAR gethex2
	sub al, 'A'-0xA
	jmp QWORD rethex
gethex2:
	cmp al, 'a'
	jl NEAR gethex
	cmp al, 'f'
	jg NEAR gethex
	sub al, 'a'-0xA
rethex:
	ret
comment:
	call getchar
	cmp al, `\n`
	je NEAR gethex
	cmp al, `\r`
	je NEAR gethex
	jmp QWORD comment
getchar:
	cmp r12, r13    ; check if index has reached end of input buffer
	jl NEAR nextchar
	xor rax, rax    ; read()
	xor rdi, rdi    ; STDIN
	mov rsi, inbuf  ; buf
	mov edx, insz   ; count
	syscall
	cmp rax, 0x0    ; if read() returned 0...
	je NEAR done    ; ...flush and exit
	mov r13, rax
	xor r12, r12    ; reset input buf index
nextchar:
	mov rax, [inbuf + r12]
	inc r12
	ret
done:
	call flush
	jmp QWORD exit
flush:
	mov eax, 0x1    ; write()
	mov edi, 0x1    ; STDOUT
	mov rsi, outbuf ; buf
	mov rdx, r14    ; len
	syscall
	xor r14, r14    ; buffer index
	mov r15, outbuf ; buffer pointer
	ret
exit:
	mov rax, 0x3c   ; exit()
	mov rdi, 0x0    ; return code
	syscall
