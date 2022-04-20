assembler1: assembler0 001_assembler/assembler.bin
	./assembler0 < 001_assembler/assembler.bin > $@

assembler0: assembler 001_assembler/assembler.bin
	./assembler < 001_assembler/assembler.bin > $@

assembler: assembler.o
	ld -s -o $@ $<

assembler.o: 001_assembler/assembler.asm
	nasm -f elf64 -o $@ $<

clean:
	@rm -f assembler.o assembler assembler0 assembler1