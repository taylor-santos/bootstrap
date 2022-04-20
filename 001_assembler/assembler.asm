; assembler.asm
bits    64
global  _start

section .bss
	bsz: equ 64
	buf: resb bsz

section .text
_start:
	xor r12, r12    ; EOF flag
	xor r13, r13    ; buffer index
	mov r14, buf    ; buffer pointer
	sub rsp, 1
	mov rsi, rsp

prompt:
	call gethex     ; read the next hex value into [rsp+1]
	mov r9, [rsi]   ; store [rsp] into r9
	shl r9, 0x4     ; left shift r9 by 4
	call gethex     ; read the next hex value into [rsp+2]
	add r9, [rsi]   ;
	mov [r14], r9b  ; copy r9 into buffer at current index
	inc r14         ; increment buffer pointer
	inc r13         ; increment buffer index
	cmp r13, bsz
	jl continue
	call flush
continue:
	mov rsi, rsp
	inc rsi
	jmp prompt

gethex:
	call getchar
	mov r8b, [rsi]
	cmp r8, '#'
	je comment
	cmp r8, '0'
	jl gethex
	cmp r8, '9'
	jg gethex1
	sub r8, '0'
	jmp rethex
gethex1:
	cmp r8, 'A'
	jl gethex
	cmp r8, 'F'
	jg gethex2
	sub r8, 'A'-0xA
	jmp rethex
gethex2:
	cmp r8, 'a'
	jl gethex
	cmp r8, 'f'
	jg gethex
	sub r8, 'a'-0xA
rethex:
	mov [rsi], r8b
	ret
comment:
	call getchar
	mov r8b, [rsi]
	cmp r8, `\n`
	je gethex
	cmp r8, `\r`
	je gethex
	jmp comment

getchar: ; read one 8bit char into [rsi]
	xor eax, eax    ; read()
	xor rdi, rdi    ; STDIN
	mov edx, 0x1    ; count
	syscall
	cmp rax, 0x0    ; check EOF
	je done
	ret
done:
	call flush
	jmp exit
flush:
	mov eax, 0x1    ; write()
	mov edi, 0x1    ; STDOUT
	mov rsi, buf    ; buf
	mov rdx, r13    ; len
	syscall
	xor r13, r13    ; buffer index
	mov r14, buf    ; buffer pointer
	ret
exit:
	mov rax, 0x3c   ; exit()
	mov rdi, 0x0    ; return code
	syscall
