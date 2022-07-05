## Bandit

### Level 1

```sh
ph3㉿jump-windows:~$ ssh bandit0@bandit.labs.overthewire.org -p 2220
bandit0@bandit.labs.overthewire.org's password: bandit0

bandit0@bandit:~$ ls
readme

bandit0@bandit:~$ cat readme 
boJ9jbbUNNfktd78OOpsqOltutMc3MY1
```

### Level 2

```sh
ph3㉿jump-windows:~$ ssh bandit1@bandit.labs.overthewire.org -p 2220
bandit1@bandit.labs.overthewire.org's password: boJ9jbbUNNfktd78OOpsqOltutMc3MY1

bandit1@bandit:~$ ls
-

bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
```

### Level 3

```sh
ph3㉿jump-windows:~$ ssh bandit2@bandit.labs.overthewire.org -p 2220
bandit2@bandit.labs.overthewire.org's password: CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

bandit2@bandit:~$ ls
spaces in this filename

bandit2@bandit:~$ cat 'spaces in this filename'
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK
```

### Level 4

```sh
ph3㉿jump-windows:~$ ssh bandit3@bandit.labs.overthewire.org -p 2220
bandit3@bandit.labs.overthewire.org's password: UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

bandit3@bandit:~$ ls
inhere

bandit3@bandit:~$ cd inhere/ && ls -la
total 12
drwxr-xr-x 2 root    root    4096 May  7  2020 .
drwxr-xr-x 3 root    root    4096 May  7  2020 ..
-rw-r----- 1 bandit4 bandit3   33 May  7  2020 .hidden

bandit3@bandit:~/inhere$ cat .hidden 
pIwrPrtPN36QITSp3EQaw936yaFoFgAB
```

### Level 5

```sh
ph3㉿jump-windows:~$ ssh bandit4@bandit.labs.overthewire.org -p 2220
bandit4@bandit.labs.overthewire.org's password: pIwrPrtPN36QITSp3EQaw936yaFoFgAB

bandit4@bandit:~$ ls
inhere

bandit4@bandit:~$ cd inhere/ && ls
-file00  -file02  -file04  -file06  -file08
-file01  -file03  -file05  -file07  -file09

bandit4@bandit:~/inhere$ for f in $(ls); do file ./$f; done;
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data

bandit4@bandit:~/inhere$ cat ./-file07
koReBOKuIDDepwhWk7jZC0RTdopnAYKh
```

### Level 6

```sh
ph3㉿jump-windows:~$ ssh bandit5@bandit.labs.overthewire.org -p 2220
bandit5@bandit.labs.overthewire.org's password: koReBOKuIDDepwhWk7jZC0RTdopnAYKh

bandit5@bandit:~$ ls
inhere

bandit5@bandit:~$ cd inhere/ && ls
maybehere00  maybehere04  maybehere08  maybehere12  maybehere16
maybehere01  maybehere05  maybehere09  maybehere13  maybehere17
maybehere02  maybehere06  maybehere10  maybehere14  maybehere18
maybehere03  maybehere07  maybehere11  maybehere15  maybehere19

bandit5@bandit:~/inhere$ find . -type f -size 1033c -readable
./maybehere07/.file2

bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7
```

### Level 7

```sh
ph3㉿jump-windows:~$ ssh bandit6@bandit.labs.overthewire.org -p 2220
bandit6@bandit.labs.overthewire.org's password: DXjZPULLxYr17uwoI01bNLQbtFemEgo7

bandit6@bandit:~$ find / -group bandit6 -user bandit7
find: ‘/root’: Permission denied
...
/var/lib/dpkg/info/bandit7.password
...

bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs
```

### Level 8

```sh
ph3㉿jump-windows:~$ ssh bandit7@bandit.labs.overthewire.org -p 2220
bandit7@bandit.labs.overthewire.org's password: HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

bandit7@bandit:~$ ls
data.txt

bandit7@bandit:~$ cat data.txt | grep millionth
millionth       cvX2JJa4CFALtqS87jk27qwqGhBM9plV
```

### Level 9

```sh
ph3㉿jump-windows:~$ ssh bandit8@bandit.labs.overthewire.org -p 2220
bandit8@bandit.labs.overthewire.org's password: cvX2JJa4CFALtqS87jk27qwqGhBM9plV

bandit8@bandit:~$ ls
data.txt

bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR
```

### Level 10

```sh
ph3㉿jump-windows:~$ ssh bandit9@bandit.labs.overthewire.org -p 2220
bandit9@bandit.labs.overthewire.org's password: UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

bandit9@bandit:~$ ls
data.txt

bandit9@bandit:~$ strings data.txt | grep =
========== the*2i"4
=:G e
========== password
<I=zsGi
Z)========== is
A=|t&E
Zdb=
c^ LAh=3G
*SF=s
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
S=A.H&^
```

### Level 11

```sh
ph3㉿jump-windows:~$ ssh bandit10@bandit.labs.overthewire.org -p 2220
bandit10@bandit.labs.overthewire.org's password: truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

bandit10@bandit:~$ ls
data.txt

bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==

bandit10@bandit:~$ cat data.txt | base64 -d
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
```

### Level 12

```sh
ph3㉿jump-windows:~$ ssh bandit11@bandit.labs.overthewire.org -p 2220
bandit11@bandit.labs.overthewire.org's password: IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

bandit11@bandit:~$ ls
data.txt

bandit11@bandit:~$ cat data.txt 
Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh

bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu
```

### Level 13

```sh
ph3㉿jump-windows:~$ ssh bandit12@bandit.labs.overthewire.org -p 2220
bandit12@bandit.labs.overthewire.org's password: 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

bandit12@bandit:~$ ls
data.txt

bandit12@bandit:~$ cat data.txt 
00000000: 1f8b 0808 0650 b45e 0203 6461 7461 322e  .....P.^..data2.
00000010: 6269 6e00 013d 02c2 fd42 5a68 3931 4159  bin..=...BZh91AY
00000020: 2653 598e 4f1c c800 001e 7fff fbf9 7fda  &SY.O...........
00000030: 9e7f 4f76 9fcf fe7d 3fff f67d abde 5e9f  ..Ov...}?..}..^.
00000040: f3fe 9fbf f6f1 feee bfdf a3ff b001 3b1b  ..............;.
00000050: 5481 a1a0 1ea0 1a34 d0d0 001a 68d3 4683  T......4....h.F.
00000060: 4680 0680 0034 1918 4c4d 190c 4000 0001  F....4..LM..@...
00000070: a000 c87a 81a3 464d a8d3 43c5 1068 0346  ...z..FM..C..h.F
00000080: 8343 40d0 3400 0340 66a6 8068 0cd4 f500  .C@.4..@f..h....
00000090: 69ea 6800 0f50 68f2 4d00 680d 06ca 0190  i.h..Ph.M.h.....
000000a0: 0000 69a1 a1a0 1ea0 194d 340d 1ea1 b280  ..i......M4.....
000000b0: f500 3406 2340 034d 3400 0000 3403 d400  ..4.#@.M4...4...
000000c0: 1a07 a832 3400 f51a 0003 43d4 0068 0d34  ...24.....C..h.4
000000d0: 6868 f51a 3d43 2580 3e58 061a 2c89 6bf3  hh..=C%.>X..,.k.
000000e0: 0163 08ab dc31 91cd 1747 599b e401 0b06  .c...1...GY.....
000000f0: a8b1 7255 a3b2 9cf9 75cc f106 941b 347a  ..rU....u.....4z
00000100: d616 55cc 2ef2 9d46 e7d1 3050 b5fb 76eb  ..U....F..0P..v.
00000110: 01f8 60c1 2201 33f0 0de0 4aa6 ec8c 914f  ..`.".3...J....O
00000120: cf8a aed5 7b52 4270 8d51 6978 c159 8b5a  ....{RBp.Qix.Y.Z
00000130: 2164 fb1f c26a 8d28 b414 e690 bfdd b3e1  !d...j.(........
00000140: f414 2f9e d041 c523 b641 ac08 0c0b 06f5  ../..A.#.A......
00000150: dd64 b862 1158 3f9e 897a 8cae 32b0 1fb7  .d.b.X?..z..2...
00000160: 3c82 af41 20fd 6e7d 0a35 2833 41bd de0c  <..A .n}.5(3A...
00000170: 774f ae52 a1ac 0fb2 8c36 ef58 537b f30a  wO.R.....6.XS{..
00000180: 1510 cab5 cb51 4231 95a4 d045 b95c ea09  .....QB1...E.\..
00000190: 9fa0 4d33 ba43 22c9 b5be d0ea eeb7 ec85  ..M3.C".........
000001a0: 59fc 8bf1 97a0 87a5 0df0 7acd d555 fc11  Y.........z..U..
000001b0: 223f fdc6 2be3 e809 c974 271a 920e acbc  "?..+....t'.....
000001c0: 0de1 f1a6 393f 4cf5 50eb 7942 86c3 3d7a  ....9?L.P.yB..=z
000001d0: fe6d 173f a84c bb4e 742a fc37 7b71 508a  .m.?.L.Nt*.7{qP.
000001e0: a2cc 9cf1 2522 8a77 39f2 716d 34f9 8620  ....%".w9.qm4.. 
000001f0: 4e33 ca36 eec0 cd4b b3e8 48e4 8b91 5bea  N3.6...K..H...[.
00000200: 01bf 7d21 0b64 82c0 3341 3424 e98b 4d7e  ..}!.d..3A4$..M~
00000210: c95c 1b1f cac9 a04a 1988 43b2 6b55 c6a6  .\.....J..C.kU..
00000220: 075c 1eb4 8ecf 5cdf 4653 064e 84da 263d  .\....\.FS.N..&=
00000230: b15b bcea 7109 5c29 c524 3afc d715 4894  .[..q.\).$:...H.
00000240: 7426 072f fc28 ab05 9603 b3fc 5dc9 14e1  t&./.(......]...
00000250: 4242 393c 7320 98f7 681d 3d02 0000       BB9<s ..h.=...
```