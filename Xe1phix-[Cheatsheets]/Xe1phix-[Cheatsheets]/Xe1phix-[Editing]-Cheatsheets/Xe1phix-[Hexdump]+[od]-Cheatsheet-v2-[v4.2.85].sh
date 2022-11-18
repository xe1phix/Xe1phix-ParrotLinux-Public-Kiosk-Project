Display the contents of file.txt in octal format (one byte per integer)
$ od -b file1
0000000 061 056 040 101 163 151 141 072 012 062 056 040 101 146 162 151
0000020 143 141 072 012 063 056 040 105 165 162 157 160 145 072 012 064
0000040 056 040 116 157 162 164 150 040 101 155 145 162 151 143 141 072
0000060 012
0000061
Display the contents of file.txt in ASCII (character) format, with byte offsets displayed as hexadecimal.
$ od -Ax -c file1
000000   1   .       A   s   i   a   :  \n   2   .       A   f   r   i
000010   c   a   :  \n   3   .       E   u   r   o   p   e   :  \n   4
000020   .       N   o   r   t   h       A   m   e   r   i   c   a   :
000030  \n
000031
