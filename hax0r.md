# Fundamentals of Hacking
## Notes from: Hacking: The Art of Exploitation 2E

## Memory and Machine Instructions
Assembler Dump
```assembly
	0000000000400526 <main>:
 		 400526:	55                   	push   %rbp
 		 400527:	48 89 e5             	mov    %rsp,%rbp
 		 40052a:	bf c4 05 40 00       	mov    $0x4005c4,%edi
		 40052f:	e8 cc fe ff ff       	callq  400400 <puts@plt>
 		 400534:	b8 00 00 00 00       	mov    $0x0,%eax
 		 400539:	5d                   	pop    %rbp
 		 40053a:	c3                   	retq   
 		 40053b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

	0000000000400540 <__libc_csu_init>:
 		 400540:	41 57                	push   %r15
 		 400542:	41 56                	push   %r14
 		 400544:	41 89 ff             	mov    %edi,%r15d
 		 400547:	41 55                	push   %r13
 		 400549:	41 54                	push   %r12
 		 40054b:	4c 8d 25 be 08 20 00 	lea    0x2008be(%rip),%r12        # 600e10 <__frame_dummy_init_array_entry>
 		 400552:	55                   	push   %rbp
 		 400553:	48 8d 2d be 08 20 00 	lea    0x2008be(%rip),%rbp        # 600e18 <__init_array_end>
 		 40055a:	53                   	push   %rbx
 		 40055b:	49 89 f6             	mov    %rsi,%r14
```

+ Each **byte** is represented in **hex** notation (base 16)
+ 1 byte = 8 bits
+ A bit can be either `TRUE` or `FALSE`, `1` or `0`
	+ So, there are 8 bits, each having 2 possinilities
	+ 2^(8) = 256 possible values can be achieved using 8 bits
+ For brevity, each byte would be easier to write as 2 **hex** digits instead of 8 binary digits
+ For each 1 byte -> 2 **hex** digits
	+ For each **hex** digit you have 4 bits
	+ Therefore, 4 + 4 = 8 bits, 2 **hex** digits are 1 byte
	+ Since for 4 bits, 2^(4) = 16 possibilities and for *base-16* -> [0 - F]

## Review of Assembler Dump
### Left Most HEX Values
+ Represent **memory addresses**
	+ Memory is a collection of **bytes** of temporary storage space
	+ This temporary storage space is numbered with **addresses**
+ Think of **memory** as a **row of bytes**, where each **byte** has its own **address**
+ Each byte of memory can be accessed by its address
+ The CPU accesses memory at **specific** addresses to retrieve **machine language instructions**


### Middle HEX Values
+ Represent the machine language instructions
+ Easier to understand as compared to binary bytes


### Right Most HEX Values
+ Assembly Language
+ *Mnemonics* for the corresponding machine language instructions


### Processors
+ Posses special variables called **registers**
+ Instructions use them to read data from and write data to them


### Assembly Syntax
`operation	<destination>, <source>`

`<dest>` and `<src>` can be a register, memory address or value

Example
```assembly
	8048375		89 e5		mov rbp,rsp
	8048377		83 ec 08	sub rsp,0x8
```

+ At the memory address 8048375, the instruction to move the value in the `rsp` to `rbp` is executed


## Brief guide on using GDB
+ Compile your C programs with the `-g` flag: `$gcc -g myprog.c -o myprog`
+ To debug your program: `gdb -q ./myprog`
+ To view disassembled program using **intel** syntax: `(gdb) set disassembly intel`
+ To log **gdb** output to a file: `(gdb) set logging <file>` then `(gdb) set logging on`
+ To set **breakpoints** in program execution: `(gdb) break <function name|line number>`


## Registers
```assembly
	(gdb) break main
	(gdb) set disassembly intel
	(gdb) run
	(gdb) info registers

	rax            0x400526	4195622
	rbx            0x0	0
	rcx            0x0	0
	rdx            0x7fffffffdf18	140737488346904
	rsi            0x7fffffffdf08	140737488346888
	rdi            0x1	1
	rbp            0x7fffffffde20	0x7fffffffde20
	rsp            0x7fffffffde20	0x7fffffffde20
	r8             0x4005b0	4195760
	r9             0x7ffff7de7ac0	140737351940800
	r10            0x846	2118
	r11            0x7ffff7a2d740	140737348032320
	r12            0x400430	4195376
	r13            0x7fffffffdf00	140737488346880
	r14            0x0	0
	r15            0x0	0
	rip            0x40052a	0x40052a <main+4>
	eflags         0x246	[ PF ZF IF ]
	cs             0x33	51
	ss             0x2b	43
	ds             0x0	0
	es             0x0	0
	fs             0x0	0
	gs             0x0	0
```

+ General Purpose registers: rax, rcx, rdx, rbx
	+ These act as temporary variables

| Register Name   | Full Name     | Function 		     |
|:---------------:|---------------|--------------------------|
| rax	 	  | accumalator   | temp variable	     |
| rcx   	  | counter       | temp variable	     |
| rdx	          | data	  | temp variable	     |
| rbx		  | base 	  | temp variable	     |
| rsp		  | stack pointer | store mem address	     | 
| rbp		  | base pointer  | store mem address 	     |
| rsi		  | source index  | source location of read  |
| rdi		  | dest index    | dest location of write   |
