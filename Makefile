assembler003: assembler002
assembler002: assembler001

assembler%: %/assembler.hex %/self.hex
	./$$(printf "assembler%03d" $$(($* - 1))) < $< > $@ || (echo "[ERROR] $@ failed to compile"  && exit 1)
	./$@ < $*/self.hex | diff $@ - || (echo "[ERROR] $@ failed to self-host" && exit 1)

assembler001: assembler001.o
	ld -s -o $@ $<
	./$@ < 001/self.hex | diff $@ - || (echo "[ERROR] $@ failed to self-host" && exit 1)

.INTERMEDIATE: assembler001.o
assembler001.o: 001/assembler.asm
	nasm -f elf64 -o $@ $<

.PHONY: clean
clean:
	@find -maxdepth 1 -name "assembler*" ! -name "assembler001" -exec rm -f {} +
