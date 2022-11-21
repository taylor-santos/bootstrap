ASMBIN=/usr/bin/nasm
CC=/usr/bin/gcc

all: assembler

c_assembler: assembler.c
	$(CC) -o $@ -nostdlib -nostartfiles -g -O0 $<

assembler: assembler.o assembler.lst
	$(CC) -m64 -nostartfiles -no-pie -o $@ $<

assembler.o assembler.lst: assembler.asm $@
	$(ASMBIN) -g -f elf64 -F dwarf -l $(basename $@).lst -o $(basename $@).o $<

clean:
	rm -f assembler.o assembler.lst assembler c_assembler
