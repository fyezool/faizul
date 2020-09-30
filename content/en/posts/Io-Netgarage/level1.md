---
author: "faizul"
title: "Io-Netgarage Level 1"
date: 2020-09-30T12:00:06+09:00
description: "Io-Netgarage Level 1"
draft: false
hideToc: false
enableToc: true
enableTocContent: false
image: images/protostar/protostar.jpeg
tags: 
- reverse-engineering
- io-netgarage
- binary-exploit
categories:
- writeup
- reverse-engineering
series:
- io-netgarage
---

# Level 1

For netgarage.io first challenge , there is no source code provided so we need to reverse engineer the binary to understand how is the program work and what it does. 

Before that, a bit introduction to netgarage.io is reverse engineer challenge available online as wargames, just like overthewire. 

In order to advanced to next level, player have to exploit the binary provided in `/levels` directory. 

Successfull exploit will shows the exact location of password located for next level.

To do the challenge, ssh into the machine first. The password for first level is 'level1'

```bash
ssh level1@io.netgarage.org
```

Then cd into `levels` directory and we can list out the file needed for the challenge.

```bash
level1@io:/levels$ ls -l level01*
-r-sr-x--- 1 level2 level1 1184 Jan 13  2014 level01
```

File command will provide us information of the binary. For this challenge, the file is ELF 32 bit for Intel CPU. 


## File analysis

### File command
```bash
level1@io:/levels$ file level01
level01: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```
### Strings command
Without running the binary, we can dig out all the stored strings on the binary. 

```bash
level1@io:/levels$ strings level01
,0<	w
Enter the 3 digit passcode to enter: Congrats you found it, now read the password for level2 from /home/level2/.pass
/bin/sh
.symtab
.strtab
.shstrtab
.text
.lib
.data
level01.asm
fscanf
skipwhite
doit
exitscanf
YouWin
exit
puts
main
prompt1
prompt2
shell
_start
__bss_start
_edata
_end
```

After done most of the possible command for file analysis, now we run this file to inspect what behaviour after we insert something as input. 


```bash
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: 111
```

## Radare2 
Ionetgarage has installed a very useful command line reversing framework. This allows us to do static analysis easier than plain `gdb` or `objdump`.

Radare2 is more like vim of the Ghidra and IDA. It is very lightweight and can run fully on terminal which is very suitble for doing challenge like netgarage.io. 

### Static analysis

```bash
level1@io:/levels$ r2 level01
Warning: Cannot initialize dynamic strings
 -- Use rarun2 to launch your programs with a predefined environment.
[0x08048080]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
```
`aaa` will run radare2's auto analysis. This will help analyse functions and autorename functions for us.

```bash
[0x08048080]> s main
[0x08048080]> VV
```
we can proceed to seek to main function and `VV` trigger a visual graph mode.

![visual-mode](/images/io-netgarage/visual-mode.png)


In intel x86 architecture, the convention for function is to pass arguments via the stack and pass the return value to register `eax`. From here, we can see a `cmp` instruction, followed by a `je YouWin` which means jump to the function YouWin() if the content of register `eax` is equal to the value `0x10f`. 

You should notice the `0x` prefix. This means that this is a hexadecimal representation.

```bash
level1@io:/levels$ rax2 0x10f
271
level1@io:/levels$ python
Python 2.7.13 (default, Nov 24 2017, 17:33:09) 
[GCC 6.3.0 20170516] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x10f
271
```
One can convert a hexadecimal to a decimal value by the above 2 methods.

```bash
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: 271
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.3$ id    
uid=1001(level1) gid=1001(level1) euid=1002(level2) groups=1001(level1),1029(nosu)
sh-4.3$ cat /home/level2/.pass
XXXXXXXXXXXXXXXXXXXXXX
```

we are now successfully poped up shell and we can get the password for level2.
