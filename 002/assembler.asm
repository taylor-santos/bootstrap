; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .rodata
table:
        endl: db `\n`

section .bss
	brkinc:  equ 64

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
	jmp scan

scan_restart:
	inc r12
scan:
	cmp r12, rbx
	jge exit
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
	mov rax, 0x1
	mov rdi, 0x1
	mov rsi, r13
	mov rdx, r12
	sub rdx, r13
	syscall
	mov rax, 0x1
	mov rsi, endl
	mov rdx, 1
	syscall
	jmp scan

scan_ident:
	inc r12
	cmp r12, rbx
	jge scan_ident_end
	mov al, [r12]
	cmp al, '0'
	jl scan_ident_end
	cmp al, '9'
	jle scan_ident
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
	mov rax, 0x1
	mov rdi, 0x1
	mov rsi, r13
	mov rdx, r12
	sub rdx, r13
	syscall
	mov rax, 0x1
	mov rsi, endl
	mov rdx, 1
	syscall
	jmp scan

scan_comment:
	inc r12
	cmp r12, rbx
	jge exit
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



; 	mov r12, insz   ; in buf index
; 	mov r13, insz   ; read in count
; 	xor r14, r14    ; out buf index
; 	sub rsp, 8      ; instruction count on stack
; 	xor rdi, rdi    ; arg <- 0
; 	mov rax, 0x0c   ; brk()
; 	syscall         ; call brk(0)
; 	push rax        ; push current brk address to stack

; 	xor r15, r15    ; set current brk size to 0
; prompt:
; 	jmp scanstart

; scanrestart:
; 	call getchar             ;
; scanstart:
; 	xor rbx, rbx             ; reset tok buffer index
; 	call peekchar            ;
; 	cmp al, '#'              ;
; 	je scan_comment          ; start of comment
; 	cmp al, '.'              ;
; 	je scan_ident            ; '.', ident
; 	cmp al, '0'              ;
; 	jl scanrestart           ; [,'0'), restart
; 	cmp al, '9'              ;
; 	jle scan_hex             ; ['0', '9'], definitely hex
; 	cmp al, 'A'              ;
; 	jl scanrestart           ; ('9', 'A'), restart
; 	cmp al, 'F'              ;
; 	jle scan_maybehex        ; ['A', 'F'], maybe hex
; 	cmp al, 'Z'              ;
; 	jle scan_ident           ; ('F', 'Z'], ident
; 	cmp al, '_'              ;
; 	je scan_ident            ; '_', ident
; 	cmp al, 'a'              ;
; 	jl scanrestart             ; ('Z', 'a'), restart
; 	cmp al, 'f'              ;
; 	jle scan_maybehex        ; ['a', 'f'], maybe hex
; 	cmp al, 'z'              ;
; 	jle scan_ident           ; ('f', 'z'], ident
; 	jmp scanrestart          ; ('z',), restart

; scan_maybehex:
; 	call getchar             ;
; 	mov rdi, [rsp]           ; store current break in rdi
; 	call storebrk            ; store the current char in brk
; 	call peekchar            ;
; 	cmp al, '0'              ;
; 	jl scan_hex_end          ; [,'0'), restart
; 	cmp al, '9'              ;
; 	jle scan_hex             ; ['0', '9'], definitely hex
; 	cmp al, 'A'              ;
; 	jl scan_hex_end          ; ('9', 'A'), restart
; 	cmp al, 'F'              ;
; 	jle scan_maybehex        ; ['A', 'F'], maybe hex
; 	cmp al, 'Z'              ;
; 	jle scan_ident           ; ('F', 'Z'], ident
; 	cmp al, '_'              ;
; 	je scan_ident            ; '_', ident
; 	cmp al, 'a'              ;
; 	jl scan_hex_end          ; ('Z', 'a'), restart
; 	cmp al, 'f'              ;
; 	jle scan_maybehex        ; ['a', 'f'], maybe hex
; 	cmp al, 'z'              ;
; 	jle scan_ident           ; ('f', 'z'], ident
; 	jmp scan_hex_end         ; ('z',), restart


; scan_hex:
; 	call getchar             ; store current char in rax
; 	mov rdi, [rsp]           ; store current break in rdi
; 	call storebrk            ; store the current char in brk
; 	call peekchar            ;
; 	cmp al, '0'              ;
; 	jl scan_hex_end          ; [,'0'), restart
; 	cmp al, '9'              ;
; 	jle scan_hex             ; ['0', '9'], definitely hex
; 	cmp al, 'A'              ;
; 	jl scan_hex_end          ; ('9', 'A'), restart
; 	cmp al, 'F'              ;
; 	jle scan_hex             ; ['A', 'F'], maybe hex
; 	cmp al, 'a'              ;
; 	jl scan_hex_end          ; ('F', 'a'), restart
; 	cmp al, 'f'              ;
; 	jle scan_hex             ; ['a', 'f'], maybe hex
; 	jmp scan_hex_end         ; ('f',), restart

; scan_hex_end: ; all scanned chars are hex, parse the buffer
; 	mov r10, 2               ; current brk index
; 	mov rdi, [rsp]           ; brk base pointer
; scan_hex_end_loop:
; 	cmp r10, rbx
; 	jg scan_hex_end_finish
; 	mov al, [rdi]
; 	shl rax, 4
; 	add al, [rdi + 1]
; 	call putchar
; 	add rdi, 2
; 	add r10, 2
; 	jmp scan_hex_end_loop
; scan_hex_end_finish:
; 	xor rbx, rbx             ; reset brk index
; 	jmp scanstart

; scan_ident:
; 	call getchar         ;
; 	mov rdi, [rsp]           ; store current break in rdi
; 	call storebrk            ; store the current char in brk

; scan_comment:
; 	call getchar     ;
; 	cmp al, `\n`     ;
; 	je scanstart     ;
; 	cmp al, `\r`     ;
; 	je scanstart     ;
; 	jmp scan_comment ;


; ; rax - input char
; hex_to_byte:
; 	cmp rax, '0'
; 	jge hex_to_byte0
; 	mov rax, -1
; 	ret
; hex_to_byte0:
; 	cmp rax, '9'
; 	jg hex_to_byte1
; 	sub rax, '0'
; 	ret
; hex_to_byte1:
; 	cmp rax, 'A'
; 	jge hex_to_byte2
; 	mov rax, -1
; 	ret
; hex_to_byte2:
; 	cmp rax, 'F'
; 	jg hex_to_byte3
; 	sub rax, 'A'-0xA
; 	ret
; hex_to_byte3:

 
; ; args:
; ;   rax - char to be stored
; ;   rdi - base of current break
; ;   r15 - current size of break, may be increased
; ;   rbx - index of current space in break
; storebrk:
; 	cmp rbx, r15
; 	jl storebrk0
; 	add r15, brkinc     ; increment brk size
; 	push rdi            ; save old brk address
; 	add rdi, r15        ; calc new brk address
; 	push rax            ; save input char
; 	mov rax, 0x0c       ; brk()
; 	syscall
; 	pop rax             ; restore char
; 	pop rdi             ; restore old brk address
; storebrk0:
; 	mov [rdi + rbx], al ; store char in brk
; 	inc rbx             ; increment index
; 	ret

; peekchar:
; 	cmp r12, r13    ; check if index has reached end of input buffer
; 	jl peeknextchar
; 	xor rax, rax    ; read()
; 	xor rdi, rdi    ; STDIN
; 	mov rsi, inbuf  ; buf
; 	mov edx, insz   ; count
; 	syscall
; 	mov r13, rax
; 	xor r12, r12    ; reset input buf index
; 	test rax, rax
; 	jne peeknextchar; if not EOF, peek next char
; 	ret             ; if EOF, return '\0'
; peeknextchar:
; 	xor rax, rax
; 	mov al, [inbuf + r12]
; 	ret

; getchar:
; 	cmp r12, r13    ; check if index has reached end of input buffer
; 	jl nextchar
; 	xor rax, rax    ; read()
; 	xor rdi, rdi    ; STDIN
; 	mov rsi, inbuf  ; buf
; 	mov edx, insz   ; count
; 	syscall
; 	test rax, rax   ;
; 	je done         ; if read() returned 0 flush and exit
; 	mov r13, rax
; 	xor r12, r12    ; reset input buf index
; nextchar:
; 	xor rax, rax
; 	mov al, [inbuf + r12]
; 	inc r12
; 	ret
; done:
; 	call flush
; 	jmp exit

; ; rax - input char
; ; r14 - current index
; putchar:
; 	mov [outbuf + r14], al
; 	inc r14
; 	cmp r14, outsz
; 	jge flush
; 	ret

; flush:
; 	mov eax, 0x1    ; write()
; 	mov edi, 0x1    ; STDOUT
; 	mov rsi, outbuf ; buf
; 	mov rdx, r14    ; len
; 	syscall
; 	xor r14, r14    ; buffer index
; 	ret

; ; %rdi - pointer to str1
; ; %rsi - pointer to str2
; ; 
; ; %rax - return value:
; ;        <0 the first character that does not match has a lower value in ptr1 than in ptr2
; ;        0  the contents of both strings are equal
; ;        >0 the first character that does not match has a greater value in ptr1 than in ptr2
; strcmp:                   ; 
; 	xor eax, eax          ; init output to 0
; 	jmp _strcmp1          ; 
; _strcmp0:                 ; :current str1 char is not null
; 	add rax, 1            ; increment index
; 	cmp dl, cl            ; compare current str1 and str2 chars
; 	jne _strcmp2          ; if they aren't equal, jump to _strcmp2, otherwise continue
; _strcmp1:                 ; :start the loop
; 	mov dl, [rdi+rax]     ; get next str1 char
; 	mov cl, [rsi+rax]     ; get next str2 char
; 	test dl, dl           ; check c1...
; 	jne _strcmp0          ; ...if it isn't null, jmp to _strcmp0
; 	mov al, cl            ; str1 ran out of chars, so return negative of current str2 char
; 	neg eax               ; ~
; 	ret                   ; ~
; _strcmp2:                 ; :current str1 and str2 don't match
; 	movzx eax, dl         ; set eax to current char1
; 	sub eax, ecx          ; subtract current char2
; 	ret                   ; 
