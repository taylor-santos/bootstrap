assembler1: 001/assembler.hex assembler
	$(info $@)
	@./assembler < $< > $@
	@./$@ < $< | diff $@ -
	$(info  - $@ bootstraps itself)

assembler: assembler.o
	$(info $@)
	@ld -s -o $@ $<

.INTERMEDIATE: assembler.o
assembler.o: 000/assembler.asm
	$(info $@)
	@nasm -f elf64 -o $@ $<

clean:
	@rm -f assembler1