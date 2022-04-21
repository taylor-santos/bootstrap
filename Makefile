assembler1: assembler0 001_assembler/assembler.hex
	./assembler0 < 001_assembler/assembler.hex > $@

assembler0: assembler.o
	ld -s -o $@ $<

assembler.o: 001_assembler/assembler.asm
	nasm -f elf64 -o $@ $<

clean:
	@rm -f assembler.o assembler0 assembler1