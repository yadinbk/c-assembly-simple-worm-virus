# Tool invocations

all: pHead skeleton

skeleton: skeleton.o
	ld -m elf_i386 skeleton.o -o skeleton

pHead: pHead.o
	gcc -g -Wall -m32 pHead.o -o pHead

pHead.o: pHead.c
	gcc -g -Wall -m32 -c -o pHead.o pHead.c

skeleton.o: skeleton.s
	nasm -f elf -o skeleton.o skeleton.s



.PHONY : clean
clean :
	-rm -f *.o
