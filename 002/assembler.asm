; Copyright (c) 2022 Taylor Santos
; MIT License

; assembler.asm
bits    64
global  _start

section .rodata
table:
        dd 'call', 0x0
        dd 0xE8

section .bss
	insz:    equ 64
	outsz:   equ 64
	brkinc:  equ 64
	inbuf:   resb insz
	outbuf:  resb outsz

; rbx    brk index
; r12    in index
; r13    in size
; r14    out index
; r15    

; stack:
;     [ instruction counter ]
;     [ brk pointer         ]
;     [ brk size            ]


section .text
_start:
	mov r12, insz   ; in buf index
	mov r13, insz   ; read in count
	xor r14, r14    ; out buf index
	sub rsp, 8      ; instruction count on stack
	xor rdi, rdi    ; arg <- 0
	mov rax, 0x0c   ; brk()
	syscall         ; call brk(0)
	mov rdi, rax    ; set arg to current break
	add rdi, brkinc ; increment break by brkinc
	mov rax, 0x0c   ; brk()
	syscall         ; call brk(scansz)
	push rax        ; push current brk address to stack
	push brkinc     ; 
prompt:
	jmp scanstart

scanrestart:
	call getchar             ;
scanstart:
	xor rbx, rbx             ; reset tok buffer index
	call peekchar            ;
	cmp al, '#'              ;
	je scan_comment          ; start of comment
	cmp al, '.'              ;
	je scan_ident            ; '.', ident
	cmp al, '0'              ;
	jl scanrestart           ; [,'0'), restart
	cmp al, '9'              ;
	jle scan_hex             ; ['0', '9'], definitely hex
	cmp al, 'A'              ;
	jl scanrestart           ; ('9', 'A'), restart
	cmp al, 'F'              ;
	jle scan_maybehex        ; ['A', 'F'], maybe hex
	cmp al, 'Z'              ;
	jle scan_ident           ; ('F', 'Z'], ident
	cmp al, '_'              ;
	je scan_ident            ; '_', ident
	cmp al, 'a'              ;
	jl scanrestart             ; ('Z', 'a'), restart
	cmp al, 'f'              ;
	jle scan_maybehex        ; ['a', 'f'], maybe hex
	cmp al, 'z'              ;
	jle scan_ident           ; ('f', 'z'], ident
	jmp scanrestart          ; ('z',), restart

scan_maybehex:
	call getchar             ;
	pop rsi                  ; get current brk size from stack
	mov rdi, [rsp]           ; store current break in rdi
	call storebrk            ; store the current char in brk
	push rsi                 ; store new brk size on stack
	call peekchar            ;
	cmp al, '0'              ;
	jl scan_hex_end          ; [,'0'), restart
	cmp al, '9'              ;
	jle scan_hex             ; ['0', '9'], definitely hex
	cmp al, 'A'              ;
	jl scan_hex_end          ; ('9', 'A'), restart
	cmp al, 'F'              ;
	jle scan_maybehex        ; ['A', 'F'], maybe hex
	cmp al, 'Z'              ;
	jle scan_ident           ; ('F', 'Z'], ident
	cmp al, '_'              ;
	je scan_ident            ; '_', ident
	cmp al, 'a'              ;
	jl scan_hex_end          ; ('Z', 'a'), restart
	cmp al, 'f'              ;
	jle scan_maybehex        ; ['a', 'f'], maybe hex
	cmp al, 'z'              ;
	jle scan_ident           ; ('f', 'z'], ident
	jmp scan_hex_end         ; ('z',), restart


scan_hex:
	call getchar             ; store current char in rax
	pop rsi                  ; get current brk size from stack
	mov rdi, [rsp]           ; store current break in rdi
	call storebrk            ; store the current char in brk
	push rsi                 ; store new brk size on stack
	call peekchar            ;
	cmp al, '0'              ;
	jl scan_hex_end          ; [,'0'), restart
	cmp al, '9'              ;
	jle scan_hex             ; ['0', '9'], definitely hex
	cmp al, 'A'              ;
	jl scan_hex_end          ; ('9', 'A'), restart
	cmp al, 'F'              ;
	jle scan_hex             ; ['A', 'F'], maybe hex
	cmp al, 'a'              ;
	jl scan_hex_end          ; ('F', 'a'), restart
	cmp al, 'f'              ;
	jle scan_hex             ; ['a', 'f'], maybe hex
	jmp scan_hex_end         ; ('f',), restart

scan_hex_end: ; all scanned chars are hex, parse the buffer
	mov eax, 0x1         ; write()
	mov edi, 0x1         ; STDOUT
	mov rsi, [rsp + 8]   ; buf
	mov rdx, rbx         ; len
	syscall
	jmp scanstart

scan_ident:
	call getchar         ;
	pop rsi                  ; get current brk size from stack
	mov rdi, [rsp]           ; store current break in rdi
	call storebrk            ; store the current char in brk
	push rsi                 ; store new brk size on stack

scan_comment:
	call getchar     ;
	cmp al, `\n`     ;
	je scanstart     ;
	cmp al, `\r`     ;
	je scanstart     ;
	jmp scan_comment ;


; args:
;   rax - char to be stored
;   rdi - base of current break
;   rsi - current size of break, may be increased
;   rbx - index of current space in break
storebrk:
	cmp rbx, rsi
	jl storebrk0
	add rsi, brkinc     ; increment brk size
	push rdi            ; save old brk address
	add rdi, rsi        ; calc new brk address
	push rax            ; save input char
	mov rax, 0x0c       ; brk()
	syscall
	pop rax             ; restore char
	pop rdi             ; restore old brk address
storebrk0:
	mov [rdi + rbx], al ; store char in brk
	inc rbx             ; increment index
	ret

; gethex:
; 	call getchar
; 	cmp al, '#'
; 	je comment
; 	cmp al, '0'
; 	jl gethex
; 	cmp al, '9'
; 	jg gethex1
; 	sub al, '0'
; 	jmp rethex
; gethex1:
; 	cmp al, 'A'
; 	jl gethex
; 	cmp al, 'F'
; 	jg gethex2
; 	sub al, 'A'-0xA
; 	jmp rethex
; gethex2:
; 	cmp al, 'a'
; 	jl gethex
; 	cmp al, 'f'
; 	jg gethex
; 	sub al, 'a'-0xA
; rethex:
; 	ret
; comment:
; 	call getchar
; 	cmp al, `\n`
; 	je gethex
; 	cmp al, `\r`
; 	je gethex
; 	jmp comment

peekchar:
	cmp r12, r13    ; check if index has reached end of input buffer
	jl peeknextchar
	xor rax, rax    ; read()
	xor rdi, rdi    ; STDIN
	mov rsi, inbuf  ; buf
	mov edx, insz   ; count
	syscall
	mov r13, rax
	xor r12, r12    ; reset input buf index
	test rax, rax
	jne peeknextchar; if not EOF, peek next char
	ret             ; if EOF, return '\0'
peeknextchar:
	xor rax, rax
	mov al, [inbuf + r12]
	ret

getchar:
	cmp r12, r13    ; check if index has reached end of input buffer
	jl nextchar
	xor rax, rax    ; read()
	xor rdi, rdi    ; STDIN
	mov rsi, inbuf  ; buf
	mov edx, insz   ; count
	syscall
	test rax, rax   ;
	je done         ; if read() returned 0 flush and exit
	mov r13, rax
	xor r12, r12    ; reset input buf index
nextchar:
	xor rax, rax
	mov al, [inbuf + r12]
	inc r12
	ret
done:
	call flush
	jmp exit

; rax - input char
putchar:


flush:
	mov eax, 0x1    ; write()
	mov edi, 0x1    ; STDOUT
	mov rsi, outbuf ; buf
	mov rdx, r14    ; len
	syscall
	xor r14, r14    ; buffer index
	ret
exit:
	mov rax, 0x3c   ; exit()
	mov rdi, 0x0    ; return code
	syscall


; %rdi - pointer to str1
; %rsi - pointer to str2
; 
; %rax - return value:
;        <0 the first character that does not match has a lower value in ptr1 than in ptr2
;        0  the contents of both strings are equal
;        >0 the first character that does not match has a greater value in ptr1 than in ptr2
strcmp:                   ; 
	xor eax, eax          ; init output to 0
	jmp _strcmp1          ; 
_strcmp0:                 ; :current str1 char is not null
	add rax, 1            ; increment index
	cmp dl, cl            ; compare current str1 and str2 chars
	jne _strcmp2          ; if they aren't equal, jump to _strcmp2, otherwise continue
_strcmp1:                 ; :start the loop
	mov dl, [rdi+rax]     ; get next str1 char
	mov cl, [rsi+rax]     ; get next str2 char
	test dl, dl           ; check c1...
	jne _strcmp0          ; ...if it isn't null, jmp to _strcmp0
	mov al, cl            ; str1 ran out of chars, so return negative of current str2 char
	neg eax               ; ~
	ret                   ; ~
_strcmp2:                 ; :current str1 and str2 don't match
	movzx eax, dl         ; set eax to current char1
	sub eax, ecx          ; subtract current char2
	ret                   ; 
