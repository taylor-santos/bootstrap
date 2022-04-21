assembler0: assembler 001_assembler/assembler.hex
	$(info $@)
	@./assembler < 001_assembler/assembler.hex > $@
	@./$@ < 001_assembler/assembler.hex | diff $@ -
	$(info  - $@ bootstraps itself)

assembler: assembler.o
	$(info $@)
	@ld -s -o $@ $<

.INTERMEDIATE: assembler.o
assembler.o: 000_assembler/assembler.asm
	$(info $@)
	@nasm -f elf64 -o $@ $<

clean:
	@rm -f assembler.o assembler0