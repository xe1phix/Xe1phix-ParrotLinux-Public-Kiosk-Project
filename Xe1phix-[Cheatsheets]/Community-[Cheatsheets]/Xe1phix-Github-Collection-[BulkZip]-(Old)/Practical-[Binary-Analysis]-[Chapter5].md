

----
Share via ## Techniques

## Tools
* file
* xxd
* nm
* readelf

## Procedure

1) **Setup**
   Let's m ake a new working directory:
   ```bash
   $ mkdir ~/PBA
   $ cd ~/PBA
   ```
   And now let's download the example payload file:
   ```bash
   $ wget https://practicalbinaryanalysis.com/file/pba-code.tar.gz  
   ```
   Unzip and expand the archive andchange into chapter5
   ```bash
   $ tar xzf pba-code.tar.gz
   
   $ cd code/chapter5
   ```

1) **Determine the file type**

   We'll start by using the `file` command to determine the filetype:
   ```bash
   $ file payload
   payload: ASCII text
   ```
   Looks like an ASCII file. Let's see what the ASCII content looks like:
   ```bash
   $ cat payload
   H4sIABzY61gAA+xaD3RTVZq/Sf+lFJIof1r+2aenKKh0klJKi4MmJaUvWrTSFlgR0jRN20iadpKX
   UljXgROKjbUOKuOfWWfFnTlzZs/ZXTln9nTRcTHYERhnZ5c/R2RGV1lFTAFH/DNYoZD9vvvubd57
   ...
   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODbbqzb
   /Q4AWAwA
   ```
   We can see both lowercase (26) and uppercase (26) characters as well as the `+` and `/` characters for a total character set of 64. Best guess is that it's a base64 encoded file. Let's move the payload to a more descriptive name:
   ```bash
   $ mv payload payload.base64
   ```
   And now lets go ahead and decode the base64 encoded file:
   ```bash
   $ base64 -d payload.base64 > payload.decoded
   ```
   And use `file` again to determine the filetype of the decoded content:
   ```bash
   $ file payload.decoded
   payload.decoded: gzip compressed data, last modified: Mon Apr 10 19:08:12 2017, from Unix, original size 808960
   ```
   Looks like a gzip file. Let's use the `file` command to look inside the gzip file:**
   ```bash
   $ file -z payload.decoded
   payload.decoded: POSIX tar archive (GNU) (gzip compressed data, last modified: Mon Apr 10 19:08:12 2017, from Unix)
   ```
   *Looks like a tar archive inside the gzip file, making this a .tgz file*. Let's move it to something more expressive:
   ```bash
   $ mv payload.decoded payload.tgz
   ```

1) **Examine the gzip'd tar archive**

   Start by decompressing and extracting the contents of the tar archive:
   ```bash
   $ tar xvzf payload.tgz
   ctf
   67b8601
   ```
   There appears to be 2 files in the archvie. Let's determine the filetypes of these 2 files:
   ```bash
   $ file ctf
   ctf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=29aeb60bcee44b50d1db3a56911bd1de93cd2030, stripped

   $ file 67b8601
   67b8601: PC bitmap, Windows 3.x format, 512 x 512 x 24
   ```
   Looks like we have an ELF binary named `ctf` and a Windows bitmap graphic named `67b8601`.

1) **Examine the `ctf` ELF binary file**

   Let's start by running the binary. Typically you would not just run this mysterious binary anywhere and would instead do it in a more controlled and ideally air-gapped environment. Because this binary comes from "No Starch Press" as part of their "Practical Binary Analysis* book we will go ahead and run it:
   ```bash
   $ ./ctf
   ./ctf: error while loading shared libraries: lib5ae9b7f.so: cannot open shared object file: No such file or directory
   ```
   Interesting. Looks like the binary is missing a library when looking for dependencies. Let's take a closer look with the `ldd` tool and see what libraries it is looking for and which ones it can and can't find:
   ```bash
   $ ldd ctf
   linux-vdso.so.1 (0x00007ffeddb8a000)
   lib5ae9b7f.so => not found
   libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007fe4e276f000)
   libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fe4e2755000)
   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe4e2594000)
   libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fe4e2411000)
   /lib64/ld-linux-x86-64.so.2 (0x00007fe4e2921000)
   ```
   Notice that we are missing a library named `lib5ae9b7f.so`, so we'll likely need to address that. This is not a standard library file, so it likely came with files in the tar archive. GIven this is an ELF binary, let's search for the string `ELF` in the files we have:
   ```bash
   $ grep ELF *
   Binary file 67b8601 matches
   Binary file ctf matches
   ```
   Looks like both the ELF binary (which  we expected) and the Windows bitmap file contain the string. Let's take a closer look at the bitmap file.

1) **Examine the `67b8601` Windows bitmap file**

   Let's start by taking a look at the first 10 lines of the bitmap file:
   ```bash
   $ xdd 67b8601 | head
   00000000: 424d 3800 0c00 0000 0000 3600 0000 2800  BM8.......6...(.
   00000010: 0000 0002 0000 0002 0000 0100 1800 0000  ................
   00000020: 0000 0200 0c00 c01e 0000 c01e 0000 0000  ................
   00000030: 0000 0000 7f45 4c46 0201 0100 0000 0000  .....ELF........
   00000040: 0000 0000 0300 3e00 0100 0000 7009 0000  ......>.....p...
   00000050: 0000 0000 4000 0000 0000 0000 7821 0000  ....@.......x!..
   00000060: 0000 0000 0000 0000 4000 3800 0700 4000  ........@.8...@.
   00000070: 1b00 1a00 0100 0000 0500 0000 0000 0000  ................
   00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
   00000090: 0000 0000 f40e 0000 0000 0000 f40e 0000  ................
   ```
   We can see the `ELF` string is on the 4th line. We want to grab everything from the `ELF` string forward, and drop everything leading up to it. This means we want to skip a specific number of bytes so we can create a new file that begins with the ELF header.
   
   In the output of `xxd` above, every 2 digits represents a single byte, and each line represents 16 bytes. That means the first 3 lines represent 48 bytes, and the 8 characters leading up to `7f45` (`ELF`) represent 4 bytes, for a total offset of 52 bytes before we get to the `ELF` string.
   
   Let's pull the ELF header out by skipping the first 52 bytes and then dumping the next 64 bytes into a new file. We have no idea how much to grab, so we'll grab 64 bytes for now and adjust later.
   
   ```bash
   $ dd if=67b8601 \
        of=67b8601.elf_header \
        skip=52 \
        count=64 \
        bs=1
   64+0 records in
   64+0 records out
   64 bytes copied, 0.000683955 s, 93.6 kB/s
   ```
   Let's check out the contents of the ELF header file we jsut created:
   ```bash
   $ xxd 67b8601.elf_header 
   00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
   00000010: 0300 3e00 0100 0000 7009 0000 0000 0000  ..>.....p.......
   00000020: 4000 0000 0000 0000 7821 0000 0000 0000  @.......x!......
   00000030: 0000 0000 4000 3800 0700 4000 1b00 1a00  ....@.8...@.....
   ```
   Looks like we got the right stuff. Our file now begins with the ELF header :)

1) **Examine the ELF header file**

   ```bash
   $ readelf -h 67b8601.elf_header
   ELF Header:
     Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
     Class:                             ELF64
     Data:                              2's complement, little endian
     Version:                           1 (current)
     OS/ABI:                            UNIX - System V
     ABI Version:                       0
     Type:                              DYN (Shared object file)
     Machine:                           Advanced Micro Devices X86-64
     Version:                           0x1
     Entry point address:               0x970
     Start of program headers:          64 (bytes into file)
     
     Start of section headers:          8568 (bytes into file)
     
     Flags:                             0x0
     Size of this header:               64 (bytes)
     Size of program headers:           56 (bytes)
     Number of program headers:         7
     
     Size of section headers:           64 (bytes)
     Number of section headers:         27
     
     Section header string table index: 26
   readelf: Error: Reading 1728 bytes extends past end of file for section headers
   readelf: Error: Too many program headers - 0x7 - the file is not that big
   ```
   Looks like we can read the file, but there are some errors at the bottom because we guessed 64 bytes and were wrong. Let's determine the exact size of the ELF file embedded in the bitmap file.
   
   Start by multiplying the values of the `Size of section headers` and `Number of section headers` fields and then add the result to the `Start of section headers` field. In this case, we can represent our specific formula as `64 * 27 + 8568`. Let's use the `expr` command to determine the result:
   ```bash
   $ expr 64 \* 27 + 8568
   10296
   ```
   Let's use the result of `10296` along with our ELF header offset of 52 bytes to grab the exact bytes we need from the original `ctf` binary. Let's also change the output filename to the name of the missing library (`lib5ae9b7f.so`), given we know we are missing an ELF library:
   ```bash
   $ dd if=67b8601 \
        of=lib5ae9b7f.so \
        skip=52 \
        count=10296 \
        bs=1
   10296+0 records in
   10296+0 records out
   10296 bytes (10 kB, 10 KiB) copied, 0.0466762 s, 221 kB/s
   ```
   Let's take another look with the `readelf` command and see if we still get those errors:
   ```bash
   $ readelf -hs lib5ae9b7f.so
   ELF Header:
     Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
     Class:                             ELF64
     Data:                              2's complement, little endian
     Version:                           1 (current)
     OS/ABI:                            UNIX - System V
     ABI Version:                       0
     Type:                              DYN (Shared object file)
     Machine:                           Advanced Micro Devices X86-64
     Version:                           0x1
     Entry point address:               0x970
     Start of program headers:          64 (bytes into file)
     Start of section headers:          8568 (bytes into file)
     Flags:                             0x0
     Size of this header:               64 (bytes)
     Size of program headers:           56 (bytes)
     Number of program headers:         7
     Size of section headers:           64 (bytes)
     Number of section headers:         27
     Section header string table index: 26

   Symbol table '.dynsym' contains 22 entries:
      Num:    Value          Size Type    Bind   Vis      Ndx Name
        0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
        1: 00000000000008c0     0 SECTION LOCAL  DEFAULT    9 
        2: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
        3: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _Jv_RegisterClasses
        4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _ZNSt7__cxx1112basic_stri@GLIBCXX_3.4.21 (2)
        5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5 (3)
        6: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
        7: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
        8: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (3)
        9: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (4)
       10: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND _ZSt19__throw_logic_error@GLIBCXX_3.4 (5)
       11: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (6)
       12: 0000000000000bc0   149 FUNC    GLOBAL DEFAULT   12 _Z11rc4_encryptP11rc4_sta
       13: 0000000000000cb0   112 FUNC    GLOBAL DEFAULT   12 _Z8rc4_initP11rc4_state_t
       14: 0000000000202060     0 NOTYPE  GLOBAL DEFAULT   24 _end
       15: 0000000000202058     0 NOTYPE  GLOBAL DEFAULT   23 _edata
       16: 0000000000000b40   119 FUNC    GLOBAL DEFAULT   12 _Z11rc4_encryptP11rc4_sta
       17: 0000000000000c60     5 FUNC    GLOBAL DEFAULT   12 _Z11rc4_decryptP11rc4_sta
       18: 0000000000202058     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
       19: 00000000000008c0     0 FUNC    GLOBAL DEFAULT    9 _init
       20: 0000000000000c70    59 FUNC    GLOBAL DEFAULT   12 _Z11rc4_decryptP11rc4_sta
       21: 0000000000000d20     0 FUNC    GLOBAL DEFAULT   13 _fini
   ```
   Excellent! It looks like we cut out the right number of bytes from the right offset and now have a complete ELF library anmed after the missing library we found in the `ldd` command earlier. Let's try the `ldd` command again to see if it finds the library:
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) ldd ctf
   LD_LIBRARY_PATH=$(pwd) ldd ctf
   linux-vdso.so.1 (0x00007fffb7d10000)
   lib5ae9b7f.so => /usr/home/example/PBA/C5/lib5ae9b7f.so (0x00007fb82e09a000)
   libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007fb82deea000)
   libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fb82ded0000)
   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb82dd0f000)
   libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fb82db8c000)
   /lib64/ld-linux-x86-64.so.2 (0x00007fb82e29f000)
   ```
   Looks like the binary can find all of its libraries now :) Let's try to run it again with this new library file:
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) ./ctf
   $ echo $?
   1
   ```
   Success! The binary can now run but returns no output. Checking the exit code (`$?`) reveals an exit code of `1`. Non-zero exit codes repsent failure, so while the binary can now run it is not completing successfully. Time for further analysis.

1) **Demangling the function names**

   Let's take a closer look at the function names of this binary and see if we can better understand what this program is used for. We'll use the `nm` command to take a look at function names:
   ```bash
   $ nm lib5ae9b7f.so 
   nm: lib5ae9b7f.so: no symbols
   ```
   Looks like this binary has been stripped of symbols, so we'll need to pass the `-D` flag to `nm` in order to show dynamic symbols:
   ```bash
   $ nm -D lib5ae9b7f.so
   0000000000202058 B __bss_start
                    w __cxa_finalize
   0000000000202058 D _edata
   0000000000202060 B _end
   0000000000000d20 T _fini
                    w __gmon_start__
   00000000000008c0 T _init
                    w _ITM_deregisterTMCloneTable
                    w _ITM_registerTMCloneTable
                    w _Jv_RegisterClasses
                    U malloc
                    U memcpy
                    U __stack_chk_fail
   0000000000000c60 T _Z11rc4_decryptP11rc4_state_tPhi
   0000000000000c70 T _Z11rc4_decryptP11rc4_state_tRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
   0000000000000b40 T _Z11rc4_encryptP11rc4_state_tPhi
   0000000000000bc0 T _Z11rc4_encryptP11rc4_state_tRNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
   0000000000000cb0 T _Z8rc4_initP11rc4_state_tPhi
                    U _ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm
                    U _ZSt19__throw_logic_errorPKc
   ```
   That helps a bit, but we still have mangled funciton names. Let's pass the `--demangle` flag to `nm` and see fi that cleans things up:
   ```bash
   $ nm -D --demangle lib5ae9b7f.so
   0000000000202058 B __bss_start
                    w __cxa_finalize
   0000000000202058 D _edata
   0000000000202060 B _end
   0000000000000d20 T _fini
                    w __gmon_start__
   00000000000008c0 T _init
                    w _ITM_deregisterTMCloneTable
                    w _ITM_registerTMCloneTable
                    w _Jv_RegisterClasses
                    U malloc
                    U memcpy
                    U __stack_chk_fail
   0000000000000c60 T rc4_decrypt(rc4_state_t*, unsigned char*, int)
   0000000000000c70 T rc4_decrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
   0000000000000b40 T rc4_encrypt(rc4_state_t*, unsigned char*, int)
   0000000000000bc0 T rc4_encrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)
   0000000000000cb0 T rc4_init(rc4_state_t*, unsigned char*, int)
                    U std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_create(unsigned long&, unsigned long)
                    U std::__throw_logic_error(char const*)
   ```
   Much better. Its now easier to see that this appears to be an encryption/decryption tool of some sort, likely using the rc4 encryption scheme.
   
   Here's another way to demangle  C++ function names from a binary using the `c++filt` command to turn a mangled function name into a demangled function name:
   ```bash
   $ c++filt _Z11rc4_decryptP11rc4_state_tPhi
   rc4_decrypt(rc4_state_t*, unsigned char*, int)
   ```
   This works well, but requires you to do it for each function name, rather than the `nm` command that lets you demangle all of them at once.

1) **Look for intersting strings in the binary**

   The `strings` command makes it easy to dump all of the strings where there are N number of contiguous ASCII characters. The default number is 4 but can be tuned using CLI options.
   ```bash
   $ strings ctf
   /lib64/ld-linux-x86-64.so.2
   ...
   DEBUG: argv[1] = %s
   checking '%s'
   show_me_the_flag
   ...
   flag = %s
   guess again!
   It's kinda like Louisiana. Or Dagobah. Dagobah - Where Yoda lives!
   ...
   GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
   .shstrtab
   ...
   ```
   I've omitted all but the most intersting strings to make it easier to see what might be useful.
   
   The `DEBUG: argv[1] = %s` string is especially interesting as it implies that this binary accepts an argument. Then we see `checking '%s'` which is probably output to the screen to let the user know it is now checking the argument. The next string is `show_me_the_flag` which might be the argument value expected by the binary. Let's give it a try:
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) ./ctf show_me_the_flag
   checking 'show_me_the_flag'
   ok
   
   $ echo $?
   1
   ```
   This looks like progress :) Right away we see the `checking 'show_me_the_flag'` which matches the `checking '%s'` string we saw before in the output of the `strings` command. And then we check the exit code and see that it is still non-zero, implying we have more work to do. Let's also try sending the wrong argument and see how it differs, if at all:
```bash
   $ LD_LIBRARY_PATH=$(pwd) ./ctf WRONG_ARGUMENT
   checking 'WRONG_ARGUMENT'
   
   $ echo $?
   1
   ```
   And we can now confirm that you need the specific arg `show_me_the_flag` in order to get the `ok` response in STDOUT.

1) **Trace the libraries of the ctf binary**

   Let's use the `ltrace` command to trace the execution of the ctf binary:
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) ltrace -i -C ./ctf show_me_the_flag
   [0x400fe9] __libc_start_main(0x400bc0, 2, 0x7ffda203f098, 0x4010c0 <unfinished ...>
   [0x400c44] __printf_chk(1, 0x401158, 0x7ffda203f4e7, 128checking 'show_me_the_flag'
   )       = 28
   [0x400c51] strcmp("show_me_the_flag", "show_me_the_flag")       = 0
   [0x400cf0] puts("ok"ok
   )                                           = 3
   [0x400d07] rc4_init(rc4_state_t*, unsigned char*, int)(0x7ffda203ee60, 0x4011c0, 66, 0x7fb67be48504) = 0
   [0x400d14] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::assign(char const*)(0x7ffda203eda0, 0x40117b, 58, 3) = 0x7ffda203eda0
   [0x400d29] rc4_decrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)(0x7ffda203ee00, 0x7ffda203ee60, 0x7ffda203eda0, 0x7e889f91) = 0x7ffda203ee00
   [0x400d36] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_assign(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)(0x7ffda203eda0, 0x7ffda203ee00, 0x7ffda203ee10, 0) = 0x7ffda203edb0
   [0x400d53] getenv("GUESSME")                                    = nil
   [0xffffffffffffffff] +++ exited (status 1) +++
   ```
   Notice the `getenv("GUESSME")` towards the bottom of the output. This implies an environment variable named `GUESSME` can be set and might affect the operation of the binary. Let's try to set it to something:
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) GUESSME=1 ./ctf show_me_the_flag
   checking 'show_me_the_flag'
   ok
   guess again!
   ```
   
   ```bash
   $ LD_LIBRARY_PATH=$(pwd) GUESSME=1 ltrace -i -C ./ctf show_me_the_flag
   ...
   [0x400d53] getenv("GUESSME")                                    = "1"
   [0x400d6e] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::assign(char const*)(0x7ffd9e729a70, 0x401183, 5, 0xffffffe0) = 0x7ffd9e729a70
   [0x400d88] rc4_decrypt(rc4_state_t*, std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&)(0x7ffd9e729ad0, 0x7ffd9e729b10, 0x7ffd9e729a70, 0x401183) = 0x7ffd9e729ad0
   [0x400d9a] std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::_M_assign(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)(0x7ffd9e729a70, 0x7ffd9e729ad0, 0x23382f0, 0) = 0x23382a0
   [0x400db4] operator delete(void*)(0x23382f0, 0x23382f0, 21, 0)  = 0
   [0x400dd7] puts("guess again!"guess again!
   )                                 = 13
   [0x400c8d] operator delete(void*)(0x23382a0, 0x2337e70, 0x7f0f285a68c0, 0x7f0f284d3504) = 0
   [0xffffffffffffffff] +++ exited (status 1) +++
   ```
   While we can trace the execution of each function, we still can't get to the expected value.

1) **Determine the expected value of GUESSME**

   ```bash
   $ 
   ```