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
+ Pointer registers: rsp, rbp, rsi, rdi
+ To retrieve infomation about a particular register
	+ `(gdb) info register $<register>`
	+ or `(gdb) i r $<register>`

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


## Examining Memory
### Compiling Code for debugging (RECAP)
`$gcc -g -o myprog myprog.c`

### Debugging Code
`$gdb -q ./myprog`

### Disassembling Code using GDB
```Assembly
	(gdb) break main
	(gdb) run
	(gdb) set disassembly intel
	(gdb) disassemble main

	0x0000000000400526 <+0>:     push   rbp
 	0x0000000000400527 <+1>:     mov    rbp,rsp
   	0x000000000040052a <+4>:     sub    rsp,0x10
   	0x000000000040052e <+8>:     mov    DWORD PTR [rbp-0x4],0x0
   	0x0000000000400535 <+15>:    jmp    0x400545 <main+31>
   	0x0000000000400537 <+17>:    mov    edi,0x4005e4
   	0x000000000040053c <+22>:    call   0x400400 <puts@plt>
   	0x0000000000400541 <+27>:    add    DWORD PTR [rbp-0x4],0x1
   	0x0000000000400545 <+31>:    cmp    DWORD PTR [rbp-0x4],0x9
   	0x0000000000400549 <+35>:    jle    0x400537 <main+17>
   	0x000000000040054b <+37>:    mov    eax,0x0
   	0x0000000000400550 <+42>:    leave
   	0x0000000000400551 <+43>:    ret
```

+ All code prior to address <+8> is known as the **function prologue**
+ It is generated by the compiler to reserve memory for the function
+ **NB**: Breakpoints are set so that when the program is run through the debugger, it will pause just before the breakpoint


### Examining Memory
+ The `x` command is used to directly examine memory
+ Syntax `x/[number]<format>[size] <register|memory addr>`
+ [number] refers to how many units of memory you want to view
+ <format>:
	+ o - octal
	+ x - hexadecimal
	+ u - decimal
	+ t - binary
+ [size]:
	+ b - BYTE
	+ h - HALF WORD - 2 BYTES
	+ w - WORD - 4 BYTES
	+ g - GIANT WORD - 8 BYTES

### Examples
If `$rip` points to the memory address located at `<+8>`
+ `x/12x $rip examines 12 hexadecimal values from the target memory address <+8>
+ `rip` refers to the **instruction pointer**, points to the current instruction to be executed by the program

```Assembly
	(gdb) i r $rip
rip            0x40052e	0x40052e <main+8>
(gdb) x/12x $rip
0x40052e <main+8>:	0x00fc45c7	0xeb000000	0x05e4bf0e	0xbfe80040
0x40053e <main+24>:	0x83fffffe	0x8301fc45	0x7e09fc7d	0x0000b8ec
0x40054e <main+40>:	0xc3c90000	0x1f0f2e66	0x00000084	0x1f0f0000
```
+ Useful to note that memory is **BYTE Addressable**
	+ Each memory address is 1 byte apart
+ The default size of a unit examined at the target address is 4 BYTES - **WORD**
+ If a **WORD** is 4 bytes then 0x00fc45c7:
	+ 00 (1 BYTE)
	+ fc (1 BYTE)
	+ 45 (1 BYTE)
	+ c7 (1 BYTE)
	+ Thus 4 BYTES
+ So when `x/12x` is used to read 12 hex values of defualt size WORD = 4 bytes then:
	+ We read a total of 12 * 4 = 48 bytes from `<main+8>`
+ Such that:
	+ `<main+8>  0x00fc45c7`
	+ `<main+12> 0xeb000000`
	+ `<main+16> 0x05e4bf0e`
	+ `<main+20> 0xbfe80040`
	+ `<main+24> 0x83fffffe`
+ Where the next address is 4 bytes apart, since we a viewing our units in the size of a WORD = 4 bytes

+ When examining memory now using the size as b - BYTE
+ We examine memory addresses in increments of 1 instead of 4 (WORD)
+ So we can only see 1 byte of the machine instructions located at a given memory address

Example
```Assembly
	(gdb) x/4xb $rip
	0x40052e <main+8>:      0xc7    0x45    0xfc    0x00
```
+ Notice when we examine individual bytes, the order of the hex bytes are in reverse as compared to veiwing the same address as a WORD (4 bytes)
+ This is because the x86 processor values are *stored* in **little endian** byte order, that is, the **Least Significant Byte** is stored first
+ LSB -> MSB
+ However, when we view memory in sizes other than BYTE, GDB reverses the order so that we view it in its proper byte order
+ Which is MSB -> LSB
+ Since when in this (**big endian**) byte order, from right to left we can multiply the digits by 16^(digit pos) to convert it to the appropriate decimal, thus confirming the reversal gdb does

+ So, x86 stores bytes in **little endian** byte order
	+ LSB - c7 45 fc 00 - MSB
+ And, gdb reverses the order, to correct reading order
	+ MSB - 00 fc 45 c7 - LSB

### Examining Assembly
+ GDB allows us to examine memory in human readable assembly
	+ `(gdb) x/i <address>`
	+ `(gdb) x/3i <address>` views the next 3 assembly instructions
	+ Therefore it is not the same as viewing other <formats> with a size
	+ Since assembly instructions do not have a **size**

```Assembly
	(gdb) x/3i $rip
		=> 0x40052e <main+8>:	mov    DWORD PTR [rbp-0x4],0x0
   		   0x400535 <main+15>:	jmp    0x400545 <main+31>
  		   0x400537 <main+17>:	mov    edi,0x4005e4
	(gdb) x/7xb $rip
		   0x40052e <main+8>:	0xc7	0x45	0xfc	0x00	0x00						0x00	0x00
```		      
+ Notice above that the 7 bytes examined at <main+8> corresponds to the assembly instruction examined at <main+8>
	+ Since the next instruction `jmp` is located at <main+15> which is 7 adaddress spaces from <main+8>
	+ Remember, memory addresses are **byte addressable**
+ `0x40052e <main+8>:   mov    DWORD PTR [rbp-0x4],0x0`
	+ Zeroing out the variable `i` in our program so it is used for the loop counter

```C
	int i;
	for (i = 0; i < 10; i++) {
		printf("Hello, World!\n");
	}
```
+ Remember, we set a **break point** at main, so the program has not yet executed
+ So if we examine the memor at `rbp-0x4` now it will just be **garbage**
+ We can then use `nexti` to execute the current instruction, that is the instruction **rip** is currently pointing to

```Assembly
	(gdb) x/i $rip
		=> 0x40052e <main+8>:	mov    DWORD PTR [rbp-0x4],0x0
	(gdb) nexti
		0x0000000000400535	6		for (i = 0; i < 10; i++) {
	(gdb) x/i $rip
		=> 0x400535 <main+15>:	jmp    0x400545 <main+31>
```
+ **rip** is then advanced to the next instruction and the address `rbp-0x4` has its memory zeroed out to make space for the integer `i` (loop counter)
+ the if - else, used in the for loop header to check if `i < 10`:
```Assembly
	0x400535 <main+15>:	jmp    0x400545 <main+31>
   	0x400537 <main+17>:	mov    edi,0x4005e4
  	0x40053c <main+22>:	call   0x400400 <puts@plt>
   	0x400541 <main+27>:	add    DWORD PTR [rbp-0x4],0x1
   	0x400545 <main+31>:	cmp    DWORD PTR [rbp-0x4],0x9
   	0x400549 <main+35>:	jle    0x400537 <main+17>
```

+ Compare the value in `i` (rbp-0x4) with 0x9
	+ Jump to `<main+17>` if less than or equal
+ This continues until the loop is complete
+ Now notice the instruction before the `call`
```Assembly
	0x400537 <main+17>:	mov    edi,0x4005e4
   	0x40053c <main+22>:	call   0x400400 <puts@plt>

``` 
+ Moving the contents located at address `0x4005e4` to `edi` register
+ Examine the contents at `0x4005e4`
```Assembly
	(gdb) x/4xu 0x4005e4
		0x4005e4:	72	101	108	108

```

+ These numbers fall within the **ascii** range
+ Find out more using `$man ascii`

```Assembly
(gdb) x/6ub 0x4005e4
	0x4005e4:	72	101	108	108	111	44
	(gdb) x/12cb 0x4005e4
		0x4005e4:	72 'H'	101 'e'	108 'l'	108 'l'	111 'o'	44 ','32 				' '	87 'W'
		0x4005ec:	111 'o'	114 'r'	108 'l'	100 'd'


```

+ We can use `c` to examine ascii character values as bytes
+ The string found at `0x4005e4` is the argument passed to the `printf()` function
+ And used in the subsequent `call` instruction in previous assembly instructions

## Fundamentals of C
### Strings
+ A string is an array of characters
+ `char str[10]` allocates 10 bytes to a string
+ Each string should be terminated by the null byte `0`
	+ This tells C that the end of a string has been reached
	+ For security purposes
+ Use of the `strcpy()` function

```C
	#include <stdio.h>
	#include <string.h>
	
	int main()
	{	
		char str[20]; //Allocate 20 bytes to char array called string
		strcpy(str, "Hello, World!\n"); //Copy the contents of the string into the str[]
		printf(str); //print the contents of the character array (string)
	
		return 0;
	}
```

+ Note when debugging that `rip` can travel through different functions
	+ So when strcpy() is called, `rip` moves into strcpy() to execute the code in that function that allows the contents of a string to be copied into a character array
	+ Each time a new function is called, a record of `rip` is kept on s structure called the **stack**
	+ This allows `rip` to return to where it last was before the very first function call
+ The `bt` command in gdb allows us to print the backtrace which shows us the backtrace of the stack, that is the stack of function calls


### Numerical Values
+ Integers, and short can be **signed** -> +ve/-ve
+ Or **unsigned** -> only positive

| Data Type       | Size (bytes)   |
|-----------------|:--------------:|
| int             | 4		   |
| unsigned int    | 4              |
| short int       | 2              |
| long int        | 8              |
| long long int   | 8              |
| float		  | 4              | 
| char		  | 1              |


### Pointers
+ Instead of copying large blocks of memory, it is much easier to pass around the address of the beginning of that memory block
+ A **pointer** is defined as something that points to data of a specific type
+ The **rip** is a pointer that *points* 
	+ to the current instruction duriing a program's execution
	+ by containing a **memory address**

Example
```C
#include <stdio.h>
#include <string.h>

int main()
{
        char str[20]; //20 byte array
        char *pointer; //Pointer meant for a character array
        char *pointer2;

        strcpy(str, "Hello, World!\n");
        pointer = str;
        printf(pointer);

        pointer2 = pointer + 2; // Set the second pointer 2 bytes further in than the first
        printf(pointer2);
        strcpy(pointer2, "y you guys!\n"); // Copy into that spot
        printf(pointer);
        return 0;
}
```

Output
```
	$ ./exe 
		Hello, World!
		llo, World!
		Hey you guys!
```
+ `pointer` is set to the beginning of the character array
	+ When the character array is referenced like this it is actually a pointer itself
+ This is how the `str` **buffer** was passed to `printf()` and `strcpy()` - it was passed as a pointer to the beginning of the **buffer**
+ `pointer2` is set to the address of the `pointer` + 2 (bytes), since `pointer2` and `pointer` points to characters with size 1 byte each
+ `strcpy()` overwrites the string already pointed to by `pointer2`

GDB debugging
```
(gdb) list
	11		pointer = str;
	12		printf(pointer);
	13	
	14		pointer2 = pointer + 2; // Set the second pointer 2 bytes further in than the first
	15		printf(pointer2);
	16		strcpy(pointer2, "y you guys!\n"); // Copy into that spot
	17		printf(pointer);
	18		return 0;
	19	}
(gdb) break 12
	Breakpoint 1 at 0x4005d7: file pointers.c, line 12.
(gdb) run
	Starting program: /home/it2901/Desktop/Source/Source-Code-Tutorials/hacking/[0]excutables/exe 

	Breakpoint 1, main () at pointers.c:12
	12		printf(pointer);
(gdb) x/xw pointer
	0x7fffffffde00:	0x6c6c6548
(gdb) x/s pointer
	0x7fffffffde00:	"Hello, World!\n"

```
+ We examine the `pointer`
	+ `pointer` is pointing to the string
	+ The string is located at `0x7fffffffde00`
	+ The string itself isn't stored in the `pointer` variable
	+ Only the memory address `0x7fffffffde00` is stored int the `pointer` variable
+ That means that a pointer holds the address of the content that it points to
+ To see the actual contents of what the pointer points to - that is the data located at the address stored in the pointer variable - Then use must use the `address-of-operator` -> `&`
+ This returns the address the pointer and not the pointer itself
+ That means `&pointer` -> address of pointer (where in memory the pointer is located) and
+ `pointer` -> address of the content `pointer` points to

```
	(gdb) print &pointer
		$1 = (char **) 0x7fffffffddf0
	(gdb) print pointer
		$2 = 0x7fffffffde00 "Hello, World!\n"

```
+ To allow a `pointer` to point to a value and not another pointer (another pointer contains the address of what it is pointing to)
	+ You need to let the `pointer` point to the **address of** the value

```C
	int int_var = 5;
	int *int_p = &int_var;	
```
+ In the above example:
	+ An `int` variable called `int_var` is declared and assigned the value `5`
	+ Then a `pointer` called `int_p` is assigned the **address of** the `int` value `int_var`

+ To return the data **located** at the **address** a `pointer` is pointing to
	+ You use the **dereference** operator

```
	(gdb) print *pointer
		$3 = 72 'H'
```
+ In the above example, `pointer` is dereferenced and the value located at the address `pointer` is pointing to is returned
+ In this case, since `pointer` was pointing to the beginninf of the character array (string), only the value of `'H'` is returned


### Format Strings

