## Hashing Step by Step with the Blowfish Cipher

**Example password:** `Joel2004@` **Example salt:** `$2b$10$/MysxsJcpbv/MXvWnzbJZ.`

> Note: the salt is [16 bytes] 22 characters long: `/MysxsJcpbv/MXvWnzbJZ.`

### Step 1: Password Bytes

**Why bytes?** A computer doesn't understand letters, only numbers. Blowfish takes every 4 bytes as one 32-bit "word", so first we convert `Joel2004@` into numbers.

**Why 10 bytes?** `Joel2004@` has 9 characters, plus 1 NUL (`00`) byte that bcrypt (`$2b$`) adds at the end of the password.

| Character | Decimal | Hex  | Binary     |
| --------- | ------: | ---- | ---------- |
| J         |      74 | `4a` | `01001010` |
| o         |     111 | `6f` | `01101111` |
| e         |     101 | `65` | `01100101` |
| l         |     108 | `6c` | `01101100` |
| 2         |      50 | `32` | `00110010` |
| 0         |      48 | `30` | `00110000` |
| 0         |      48 | `30` | `00110000` |
| 4         |      52 | `34` | `00110100` |
| @         |      64 | `40` | `01000000` |

**Why do we need the NUL byte?** The key bytes repeat in a cycle. Without NUL, the passwords `ab` and `abab` would produce the same key stream. With a `00` at the end, they become different. This comes from C-style strings, which end with NUL.

**Maximum length:** 18 words × 4 bytes = 72 bytes. Our 10 bytes is far below that, so the key simply repeats (cycles) until it fills all 72 bytes.

```
Bytes: 4a 6f 65 6c 32 30 30 34 40 00
```

### Step 2: Salt Bytes

**Why a salt?** Even if two people use the same password, a different salt gives a different hash. This is why a hacker's rainbow table doesn't work.

**Why do 22 characters become 16 bytes?** bcrypt's Base64 alphabet has 64 symbols, so 1 character = 6 bits. 22 × 6 = 132 bits. bcrypt uses only the first 128 bits (16 bytes) and ignores the last 4 bits.

bcrypt's alphabet is not the normal Base64 order:

```
./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
```

The index of a character is its position in this alphabet, counting from 0.

| Char | Index                          | 6-bit  |
| ---- | ------------------------------ | ------ |
| /    | 1                              | 000001 |
| M    | 14                             | 001110 |
| y    | 52                             | 110100 |
| s    | 46                             | 101110 |
| x    | 51                             | 110011 |
| s    | 46                             | 101110 |
| ...  | the same for all 22 characters |        |

First 36 bits:

```
000001 001110 110100 101110 110011 101110
```

Regroup in 8s:

```
00000100 11101101 00101110 11001110 1110
= 04 ed 2e ce ...
```

**16 bytes = 4 words:**

```
04ed2ece e2deaddc 41399c58 a7574b6c
```

**About the 22nd character:** only 2 of its 6 bits are used, so the only valid last characters are `.`, `O`, `e` and `u` (index 0, 16, 32, 48). Our salt ends with `.`, which is valid.

### Step 3: Initial State from the Digits of π

**Why π?** The starting values should look random, but everyone must start from the same values, otherwise the same password would not give the same hash. π is a "nothing up my sleeve" number: its digits are public, so nobody can claim the constants were rigged. We convert the fractional part 0.14159... of π into hexadecimal.

**Why does the P-array have 18 entries?** 16 rounds use 1 entry each, plus 2 entries at the end: 16 + 2 = 18 words.

**Why 4 S-boxes of 256 entries?** The F function takes one byte (0 to 255) and looks it up in a table. It uses 4 bytes, so we need 4 tables × 256 entries × 32 bits. In total: 18 + 1,024 = 1,042 words.

**How to get a hex digit:** multiply the fraction by 16. The whole part is the next hex digit; the remaining fraction is used for the next step. Repeat.

| #   | Fraction     | × 16    | Digit |
| --- | ------------ | ------- | ----- |
| 1   | 0.1415926536 | 2.2655  | 2     |
| 2   | 0.2654824574 | 4.2477  | 4     |
| 3   | 0.2477193190 | 3.9635  | 3     |
| 4   | 0.9635091038 | 15.4161 | f     |
| 5   | 0.4161456607 | 6.6583  | 6     |
| 6   | 0.6583305710 | 10.5333 | a     |
| 7   | 0.5332891366 | 8.5326  | 8     |
| 8   | 0.5326261849 | 8.5220  | 8     |
| 9   | 0.5220189586 | 8.3523  | 8     |
| 10  | 0.3523033376 | 5.6369  | 5     |
| 11  | 0.6368534013 | 10.1897 | a     |
| 12  | 0.1896544214 | 3.0345  | 3     |
| 13  | 0.0344707429 | 0.5515  | 0     |
| 14  | 0.5515318868 | 8.8245  | 8     |
| 15  | 0.8245101893 | 13.1922 | d     |
| 16  | 0.1921630285 | 3.0746  | 3     |

Digits: `243f6a8885a308d3`

8 hex digits = 32 bits = 1 word:

```
P[0] = 243f6a88
P[1] = 85a308d3
```

Continuing the same way: P[2] = `13198a2e`, P[3] = `03707344`, ... P[17] = `8979fb1b`. After that come the S-box values: S0[0] = `d1310ba6`, S0[1] = `98dfb5ac`, and so on (8,336 hex digits in total).

```
P[0]=243f6a88  P[1]=85a308d3  P[2]=13198a2e  P[3]=03707344  P[4]=a4093822
P[5]=299f31d0  P[6]=082efa98  P[7]=ec4e6c89  P[8]=452821e6  P[9]=38d01377
P[10]=be5466cf P[11]=34e90c6c P[12]=c0ac29b7 P[13]=c97c50dd P[14]=3f84d5b5
P[15]=b5470917 P[16]=9216d5d9 P[17]=8979fb1b
```

### Step 4: XOR the Password Key into the P-array

**Why XOR?** XOR is cheap, reversible and mixes bits (same bits give 0, different bits give 1). This is how the password enters the P-array, so the final hash depends on the password.

**How do we get the key words?** The 10 key bytes must fill 18 words. Take 4 bytes at a time, and when the bytes run out, start again from the beginning.

```
Key stream: 4a6f656c323030344000 (repeats)
word0 = 4a 6f 65 6c
word1 = 32 30 30 34
word2 = 40 00 4a 6f   (the NUL byte is in the middle, then the key wraps around)
...
```

Example, i = 0:

```
243f6a88 = 0010010000111111 0110101010001000
4a6f656c = 0100101001101111 0110010101101100
XOR      = 0110111001010000 0000111111100100  = 6e500fe4
```

| i   | P[i]     | Key word | P[i] XOR key |
| --- | -------- | -------- | ------------ |
| 0   | 243f6a88 | 4a6f656c | 6e500fe4     |
| 1   | 85a308d3 | 32303034 | b79338e7     |
| 2   | 13198a2e | 40004a6f | 5319c041     |
| 3   | 03707344 | 656c3230 | 661c4174     |
| 4   | a4093822 | 30344000 | 943d7822     |
| 5   | 299f31d0 | 4a6f656c | 63f054bc     |
| 6   | 082efa98 | 32303034 | 3a1ecaac     |
| 7   | ec4e6c89 | 40004a6f | ac4e26e6     |
| 8   | 452821e6 | 656c3230 | 204413d6     |
| 9   | 38d01377 | 30344000 | 08e45377     |
| 10  | be5466cf | 4a6f656c | f43b03a3     |
| 11  | 34e90c6c | 32303034 | 06d93c58     |
| 12  | c0ac29b7 | 40004a6f | 80ac63d8     |
| 13  | c97c50dd | 656c3230 | ac1062ed     |
| 14  | 3f84d5b5 | 30344000 | 0fb095b5     |
| 15  | b5470917 | 4a6f656c | ff286c7b     |
| 16  | 9216d5d9 | 32303034 | a026e5ed     |
| 17  | 8979fb1b | 40004a6f | c979b174     |

### Step 5: The Feistel Idea and the F Function

**Analogy:** Imagine two bowls, Left (L) and Right (R). Mix one bowl using a function (F), blend the result into the other bowl, then swap the bowls. Do this 16 times. Because every step can be undone in reverse order, decryption can reuse the same structure, which is why the Feistel design is so good.

```
for i = 1 to 16:
    L = L XOR P[i-1]
    R = R XOR F(L)
    swap(L, R)
after the loop: swap back, then R = R XOR P[16] and L = L XOR P[17]
```

**F(x):** split the 32-bit value x into 4 bytes a, b, c, d. Each byte is used as an index into one S-box.

```
F(x) = ((S0[a] + S1[b]) XOR S2[c]) + S3[d]    (mod 2^32)
```

**Why add, XOR, then add?** Addition (with carries) and XOR are two different kinds of math. Mixing them makes the result very hard to reverse. "mod 2^32" means that anything above 32 bits is dropped, so the result always fits in one word.

### Step 6: Round Calculations

Every round follows the same sub-steps (a to h). Round 1 uses P[0] = `6e500fe4`, which is the XOR result from Step 4.

The S-box lookups come from the original S-boxes (the π digits from Step 3), because during the first block the S-boxes have not been changed yet. Everything below is the **first block** only (the first of 521 encryptions).

#### Round 1 of 16

**Input:** L = 0 XOR salt word 0 = `04ed2ece`, R = 0 XOR salt word 1 = `e2deaddc` (in the salted key setup, the all-zero block is XORed with the salt words first).

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[0] = 04ed2ece XOR 6e500fe4       | 6abd212a                                     |
| b   | Split into bytes                         | a=6a b=bd c=21 d=2a                          |
| c   | Lookups: S0[6a], S1[bd], S2[21], S3[2a]  | db0fead3<br>34c6ffea<br>d7486900<br>4ba99586 |
| d   | S0 + S1 = db0fead3 + 34c6ffea            | 0fd6eabd                                     |
| e   | XOR S2 = 0fd6eabd XOR d7486900           | d89e83bd                                     |
| f   | + S3 = d89e83bd + 4ba99586 = F           | 24481943                                     |
| g   | R XOR F = e2deaddc XOR 24481943          | c696b49f                                     |
| h   | Swap: new L = c696b49f, new R = 6abd212a | Used in the next round                       |

#### Round 2 of 16

**Input:** the (L, R) from the previous round = (`c696b49f`, `6abd212a`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[1] = c696b49f XOR b79338e7       | 71058c78                                     |
| b   | Split into bytes                         | a=71 b=05 c=8c d=78                          |
| c   | Lookups: S0[71], S1[05], S2[8c], S3[78]  | b6794c3b<br>49a7df7d<br>6842ada7<br>dda26a7e |
| d   | S0 + S1 = b6794c3b + 49a7df7d            | 00212bb8                                     |
| e   | XOR S2 = 00212bb8 XOR 6842ada7           | 6863861f                                     |
| f   | + S3 = 6863861f + dda26a7e = F           | 4605f09d                                     |
| g   | R XOR F = 6abd212a XOR 4605f09d          | 2cb8d1b7                                     |
| h   | Swap: new L = 2cb8d1b7, new R = 71058c78 | Used in the next round                       |

#### Round 3 of 16

**Input:** the (L, R) from the previous round = (`2cb8d1b7`, `71058c78`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[2] = 2cb8d1b7 XOR 5319c041       | 7fa111f6                                     |
| b   | Split into bytes                         | a=7f b=a1 c=11 d=f6                          |
| c   | Lookups: S0[7f], S1[a1], S2[11], S3[f6]  | af5ebd09<br>19bdf0ca<br>96b591af<br>01c36ae4 |
| d   | S0 + S1 = af5ebd09 + 19bdf0ca            | c91cadd3                                     |
| e   | XOR S2 = c91cadd3 XOR 96b591af           | 5fa93c7c                                     |
| f   | + S3 = 5fa93c7c + 01c36ae4 = F           | 616ca760                                     |
| g   | R XOR F = 71058c78 XOR 616ca760          | 10692b18                                     |
| h   | Swap: new L = 10692b18, new R = 7fa111f6 | Used in the next round                       |

#### Round 4 of 16

**Input:** the (L, R) from the previous round = (`10692b18`, `7fa111f6`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[3] = 10692b18 XOR 661c4174       | 76756a6c                                     |
| b   | Split into bytes                         | a=76 b=75 c=6a d=6c                          |
| c   | Lookups: S0[76], S1[75], S2[6a], S3[6c]  | 5e5c9ec2<br>5266c825<br>647d0862<br>a2ae0810 |
| d   | S0 + S1 = 5e5c9ec2 + 5266c825            | b0c366e7                                     |
| e   | XOR S2 = b0c366e7 XOR 647d0862           | d4be6e85                                     |
| f   | + S3 = d4be6e85 + a2ae0810 = F           | 776c7695                                     |
| g   | R XOR F = 7fa111f6 XOR 776c7695          | 08cd6763                                     |
| h   | Swap: new L = 08cd6763, new R = 76756a6c | Used in the next round                       |

#### Round 5 of 16

**Input:** the (L, R) from the previous round = (`08cd6763`, `76756a6c`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[4] = 08cd6763 XOR 943d7822       | 9cf01f41                                     |
| b   | Split into bytes                         | a=9c b=f0 c=1f d=41                          |
| c   | Lookups: S0[9c], S1[f0], S2[1f], S3[41]  | d542a8f6<br>9e447a2e<br>e9b66dfb<br>e019a5e6 |
| d   | S0 + S1 = d542a8f6 + 9e447a2e            | 73872324                                     |
| e   | XOR S2 = 73872324 XOR e9b66dfb           | 9a314edf                                     |
| f   | + S3 = 9a314edf + e019a5e6 = F           | 7a4af4c5                                     |
| g   | R XOR F = 76756a6c XOR 7a4af4c5          | 0c3f9ea9                                     |
| h   | Swap: new L = 0c3f9ea9, new R = 9cf01f41 | Used in the next round                       |

#### Round 6 of 16

**Input:** the (L, R) from the previous round = (`0c3f9ea9`, `9cf01f41`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[5] = 0c3f9ea9 XOR 63f054bc       | 6fcfca15                                     |
| b   | Split into bytes                         | a=6f b=cf c=ca d=15                          |
| c   | Lookups: S0[6f], S1[cf], S2[ca], S3[15]  | f6e8def7<br>3d816250<br>4a99a025<br>468dde7d |
| d   | S0 + S1 = f6e8def7 + 3d816250            | 346a4147                                     |
| e   | XOR S2 = 346a4147 XOR 4a99a025           | 7ef3e162                                     |
| f   | + S3 = 7ef3e162 + 468dde7d = F           | c581bfdf                                     |
| g   | R XOR F = 9cf01f41 XOR c581bfdf          | 5971a09e                                     |
| h   | Swap: new L = 5971a09e, new R = 6fcfca15 | Used in the next round                       |

#### Round 7 of 16

**Input:** the (L, R) from the previous round = (`5971a09e`, `6fcfca15`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[6] = 5971a09e XOR 3a1ecaac       | 636f6a32                                     |
| b   | Split into bytes                         | a=63 b=6f c=6a d=32                          |
| c   | Lookups: S0[63], S1[6f], S2[6a], S3[32]  | 56c16aa6<br>5a3e2ab3<br>647d0862<br>9b09e6ad |
| d   | S0 + S1 = 56c16aa6 + 5a3e2ab3            | b0ff9559                                     |
| e   | XOR S2 = b0ff9559 XOR 647d0862           | d4829d3b                                     |
| f   | + S3 = d4829d3b + 9b09e6ad = F           | 6f8c83e8                                     |
| g   | R XOR F = 6fcfca15 XOR 6f8c83e8          | 004349fd                                     |
| h   | Swap: new L = 004349fd, new R = 636f6a32 | Used in the next round                       |

#### Round 8 of 16

**Input:** the (L, R) from the previous round = (`004349fd`, `636f6a32`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[7] = 004349fd XOR ac4e26e6       | ac0d6f1b                                     |
| b   | Split into bytes                         | a=ac b=0d c=6f d=1b                          |
| c   | Lookups: S0[ac], S1[0d], S2[6f], S3[1b]  | e1ddf2da<br>75094c29<br>f33e8d1e<br>be5ee304 |
| d   | S0 + S1 = e1ddf2da + 75094c29            | 56e73f03                                     |
| e   | XOR S2 = 56e73f03 XOR f33e8d1e           | a5d9b21d                                     |
| f   | + S3 = a5d9b21d + be5ee304 = F           | 64389521                                     |
| g   | R XOR F = 636f6a32 XOR 64389521          | 0757ff13                                     |
| h   | Swap: new L = 0757ff13, new R = ac0d6f1b | Used in the next round                       |

#### Round 9 of 16

**Input:** the (L, R) from the previous round = (`0757ff13`, `ac0d6f1b`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[8] = 0757ff13 XOR 204413d6       | 2713ecc5                                     |
| b   | Split into bytes                         | a=27 b=13 c=ec d=c5                          |
| c   | Lookups: S0[27], S1[13], S2[ec], S3[c5]  | 63e81440<br>99f73fd6<br>86e3725f<br>9b992f2e |
| d   | S0 + S1 = 63e81440 + 99f73fd6            | fddf5416                                     |
| e   | XOR S2 = fddf5416 XOR 86e3725f           | 7b3c2649                                     |
| f   | + S3 = 7b3c2649 + 9b992f2e = F           | 16d55577                                     |
| g   | R XOR F = ac0d6f1b XOR 16d55577          | bad83a6c                                     |
| h   | Swap: new L = bad83a6c, new R = 2713ecc5 | Used in the next round                       |

#### Round 10 of 16

**Input:** the (L, R) from the previous round = (`bad83a6c`, `2713ecc5`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[9] = bad83a6c XOR 08e45377       | b23c691b                                     |
| b   | Split into bytes                         | a=b2 b=3c c=69 d=1b                          |
| c   | Lookups: S0[b2], S1[3c], S2[69], S3[1b]  | d07e9efe<br>e238cd99<br>95b794fd<br>be5ee304 |
| d   | S0 + S1 = d07e9efe + e238cd99            | b2b76c97                                     |
| e   | XOR S2 = b2b76c97 XOR 95b794fd           | 2700f86a                                     |
| f   | + S3 = 2700f86a + be5ee304 = F           | e55fdb6e                                     |
| g   | R XOR F = 2713ecc5 XOR e55fdb6e          | c24c37ab                                     |
| h   | Swap: new L = c24c37ab, new R = b23c691b | Used in the next round                       |

#### Round 11 of 16

**Input:** the (L, R) from the previous round = (`c24c37ab`, `b23c691b`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[10] = c24c37ab XOR f43b03a3      | 36773408                                     |
| b   | Split into bytes                         | a=36 b=77 c=34 d=08                          |
| c   | Lookups: S0[36], S1[77], S2[34], S3[08]  | 7a325381<br>9c10b36a<br>3a6efa74<br>d5118e9d |
| d   | S0 + S1 = 7a325381 + 9c10b36a            | 164306eb                                     |
| e   | XOR S2 = 164306eb XOR 3a6efa74           | 2c2dfc9f                                     |
| f   | + S3 = 2c2dfc9f + d5118e9d = F           | 013f8b3c                                     |
| g   | R XOR F = b23c691b XOR 013f8b3c          | b303e227                                     |
| h   | Swap: new L = b303e227, new R = 36773408 | Used in the next round                       |

#### Round 12 of 16

**Input:** the (L, R) from the previous round = (`b303e227`, `36773408`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[11] = b303e227 XOR 06d93c58      | b5dade7f                                     |
| b   | Split into bytes                         | a=b5 b=da c=de d=7f                          |
| c   | Lookups: S0[b5], S1[da], S2[de], S3[7f]  | ae909198<br>1462b174<br>006058aa<br>bf3c6f47 |
| d   | S0 + S1 = ae909198 + 1462b174            | c2f3430c                                     |
| e   | XOR S2 = c2f3430c XOR 006058aa           | c2931ba6                                     |
| f   | + S3 = c2931ba6 + bf3c6f47 = F           | 81cf8aed                                     |
| g   | R XOR F = 36773408 XOR 81cf8aed          | b7b8bee5                                     |
| h   | Swap: new L = b7b8bee5, new R = b5dade7f | Used in the next round                       |

#### Round 13 of 16

**Input:** the (L, R) from the previous round = (`b7b8bee5`, `b5dade7f`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[12] = b7b8bee5 XOR 80ac63d8      | 3714dd3d                                     |
| b   | Split into bytes                         | a=37 b=14 c=dd d=3d                          |
| c   | Lookups: S0[37], S1[14], S2[dd], S3[3d]  | 28958677<br>a1d29c07<br>c0f586e0<br>adf2b89b |
| d   | S0 + S1 = 28958677 + a1d29c07            | ca68227e                                     |
| e   | XOR S2 = ca68227e XOR c0f586e0           | 0a9da49e                                     |
| f   | + S3 = 0a9da49e + adf2b89b = F           | b8905d39                                     |
| g   | R XOR F = b5dade7f XOR b8905d39          | 0d4a8346                                     |
| h   | Swap: new L = 0d4a8346, new R = 3714dd3d | Used in the next round                       |

#### Round 14 of 16

**Input:** the (L, R) from the previous round = (`0d4a8346`, `3714dd3d`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[13] = 0d4a8346 XOR ac1062ed      | a15ae1ab                                     |
| b   | Split into bytes                         | a=a1 b=5a c=e1 d=ab                          |
| c   | Lookups: S0[a1], S1[5a], S2[e1], S3[ab]  | bbca58c8<br>dd433b37<br>2338ea63<br>27d9459c |
| d   | S0 + S1 = bbca58c8 + dd433b37            | 990d93ff                                     |
| e   | XOR S2 = 990d93ff XOR 2338ea63           | ba35799c                                     |
| f   | + S3 = ba35799c + 27d9459c = F           | e20ebf38                                     |
| g   | R XOR F = 3714dd3d XOR e20ebf38          | d51a6205                                     |
| h   | Swap: new L = d51a6205, new R = a15ae1ab | Used in the next round                       |

#### Round 15 of 16

**Input:** the (L, R) from the previous round = (`d51a6205`, `a15ae1ab`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[14] = d51a6205 XOR 0fb095b5      | daaaf7b0                                     |
| b   | Split into bytes                         | a=da b=aa c=f7 d=b0                          |
| c   | Lookups: S0[da], S1[aa], S2[f7], S3[b0]  | d6411bd3<br>95f7997e<br>6c51133c<br>fae59361 |
| d   | S0 + S1 = d6411bd3 + 95f7997e            | 6c38b551                                     |
| e   | XOR S2 = 6c38b551 XOR 6c51133c           | 0069a66d                                     |
| f   | + S3 = 0069a66d + fae59361 = F           | fb4f39ce                                     |
| g   | R XOR F = a15ae1ab XOR fb4f39ce          | 5a15d865                                     |
| h   | Swap: new L = 5a15d865, new R = daaaf7b0 | Used in the next round                       |

#### Round 16 of 16

**Input:** the (L, R) from the previous round = (`5a15d865`, `daaaf7b0`)

| #   | Calculation                              | Result                                       |
| --- | ---------------------------------------- | -------------------------------------------- |
| a   | L XOR P[15] = 5a15d865 XOR ff286c7b      | a53db41e                                     |
| b   | Split into bytes                         | a=a5 b=3d c=b4 d=1e                          |
| c   | Lookups: S0[a5], S1[3d], S2[b4], S3[1e]  | fd2183b8<br>3bea0e2f<br>5366f9c3<br>63ef8ce2 |
| d   | S0 + S1 = fd2183b8 + 3bea0e2f            | 390b91e7                                     |
| e   | XOR S2 = 390b91e7 XOR 5366f9c3           | 6a6d6824                                     |
| f   | + S3 = 6a6d6824 + 63ef8ce2 = F           | ce5cf506                                     |
| g   | R XOR F = daaaf7b0 XOR ce5cf506          | 14f602b6                                     |
| h   | Swap: new L = 14f602b6, new R = a53db41e | Goes to the final step below                 |

#### After Round 16: The Block Output Becomes the New P[0] and P[1]

**Why undo the last swap?** Round 16 swaps the halves like every other round, but the last round of a Feistel network should not swap. Undoing it keeps encryption and decryption identical in structure (decryption just uses the P-array in reverse order).

**Why XOR with P[16] and P[17]?** After the 16 rounds, the last two P entries are mixed in as a final step.

| Step                   | L        | R        |
| ---------------------- | -------- | -------- |
| After round 16         | 14f602b6 | a53db41e |
| Undo the last swap     | a53db41e | 14f602b6 |
| R XOR P[16] (a026e5ed) | a53db41e | b4d0e75b |
| L XOR P[17] (c979b174) | 6c44056a | b4d0e75b |

**Output = (6c44056a, b4d0e75b) = the new P[0], P[1]**

**What happens next:** the output is XORed with the next pair of salt words and encrypted again, which gives P[2] and P[3]. This continues until P[17] (9 blocks). Then the 4 S-boxes are replaced the same way: 4 S-boxes × 128 blocks = 512 blocks. In total: **9 + 512 = 521 encryptions**. After this, the whole P-array and all S-boxes are mixed with the password and the salt.

```
New P[0] = 6c44056a, P[1] = b4d0e75b, P[2] = d22afca7, P[3] = 58f463e7 ...
```

### Step 7: The Cost Loop

**Why?** If hashing were fast, a hacker could try lakhs of passwords per second. With cost 10, the expensive step is repeated 2^10 = 1,024 times, which makes every guess slow. Cost 11 is 2× slower, cost 12 is 4× slower, and so on.

```
repeat 1024 times:
    ExpandKey(state, password)   // 521 encryptions
    ExpandKey(state, salt)       // 521 encryptions
```

| Item                     | Count             |
| ------------------------ | ----------------- |
| Initial salted ExpandKey | 521               |
| 1,024 × 2 × 521          | 1,067,008         |
| Total block encryptions  | 1,067,529         |
| × 16 rounds each         | 17,080,464 rounds |

This is far too much to do by hand, so I ran it in code. P-array after the loop:

```
0cecb6f6 f208f92b 6d7c97f2 d439ddfd e11e706f 63ee9eab
455099d2 cf773e1f adf30349 8e4a81cb afb345ee 6bf31c3d
495adfa3 711b2acf 3288d497 d3233006 ae164c59 072214a4
```

### Step 8: Encrypt the Magic Text 64 Times

**Why a magic text?** This is the actual "content" of the hash. Only with the correct password (and salt) does this fixed text encrypt to the same result.

The text is fixed: `OrpheanBeholderScryDoubt`. It is 24 bytes = 192 bits = 3 blocks of 64 bits.

**Why 64 times?** To mix it even more and to add extra work against brute force.

| Chars | Hex word |
| ----- | -------- |
| Orph  | 4f727068 |
| eanB  | 65616e42 |
| ehol  | 65686f6c |
| derS  | 64657253 |
| cryD  | 63727944 |
| oubt  | 6f756274 |

There are 3 blocks: (w0, w1), (w2, w3), (w4, w5). Each block goes through Blowfish encryption (16 rounds) 64 times.

| After          | Words                                                 |
| -------------- | ----------------------------------------------------- |
| 1 encryption   | f934b446 aaed6553 4c0472d3 0c932248 1c892f01 f15d7dbe |
| 64 encryptions | f1d58aba 0cf62ade 89cd39d7 5f3d61e8 5c7db5f9 d16a13f6 |

### Step 9: Cut to 23 Bytes and Encode with bcrypt-Base64

**Why 23?** We drop the last of the 24 bytes (a historical quirk of bcrypt). 23 × 8 = 184 bits, and 184 / 6 ≈ 30.67, so the result is 31 characters. The full hash string is 7 characters of prefix (`$2b$10$`) + 22 characters of salt + 31 characters of hash = 60 characters.

```
f1 d5 8a ba 0c f6 2a de 89 cd 39 d7 5f 3d 61 e8 5c 7d b5 f9 d1 6a 13
```

3 bytes (24 bits) become 4 characters (6 bits each), using the bcrypt alphabet.

| Bytes    | 6-bit groups                | Indices        | Chars |
| -------- | --------------------------- | -------------- | ----- |
| f1 d5 8a | 111100 011101 010110 001010 | 60, 29, 22, 10 | 6bUI  |
| ba 0c f6 | 101110 100000 110011 110110 | 46, 32, 51, 54 | sex0  |
| 2a de 89 | 001010 101101 111010 001001 | 10, 45, 58, 9  | Ir4H  |
| cd 39 d7 | 110011 010011 100111 010111 | 51, 19, 39, 23 | xRlV  |
| 5f 3d 61 | 010111 110011 110101 100001 | 23, 51, 53, 33 | Vxzf  |
| e8 5c 7d | 111010 000101 110001 111101 | 58, 5, 49, 61  | 4Dv7  |
| b5 f9 d1 | 101101 011111 100111 010001 | 45, 31, 39, 17 | rdlP  |
| 6a 13    | 011010 100001 001100        | 26, 33, 12     | YfK   |

The last group has only 2 bytes = 16 bits. We add 2 zero bits to make 18 bits, which gives 3 characters. In total: 7 × 4 + 3 = 31 characters.

**Final hashed password:**

```
$2b$10$/MysxsJcpbv/MXvWnzbJZ.6bUIsex0Ir4HxRlVVxzf4Dv7rdlPYfK
```

This is how the password is hashed and saved in the database.
