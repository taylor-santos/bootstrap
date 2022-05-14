assembler003: assembler002
assembler002: assembler001


assembler%: %/assembler.hex
	@./$$(printf "assembler%03d" $$(($* - 1))) < $< > $@ || (echo "[ERROR] $@ failed to compile"  && exit 1)
	@./$@ < $< | diff $@ -                               || (echo "[ERROR] $@ failed to boostrap" && exit 1)

assembler001: assembler001.o
	@ld -s -o $@ $<

.INTERMEDIATE: assembler001.o
assembler001.o: 001/assembler.asm
	@nasm -f elf64 -o $@ $<

clean:
	@find -maxdepth 1 -name "assembler*" ! -name "assembler001" -exec rm -f {} +
