---
author: 0x指纹
date: 2025-08-17 08:00+08:00
layout: post
title: "KCTF 2025 第二题 WriteUp - LLM 一击直解"
mathjax: true
categories:
- 竞技比赛
tags:
- ctf
- llm
- reverse
---

* content
{:toc}

LLM 对算法还是相当擅长的，哪怕是没有相关名称符号的情况下，也能精准识别，这给逆向工程带来了相当大的改变。

KCTF 2025 第二道逆向题，直接向三个 LLM(Gemini 2.5 Pro、Deepseek-V3、GPT-5) 提问反编译的功能函数，基本都能分析出实现的是一个三维迷宫，但不太能每次都准确判断出迷宫大小。后尝试，在单次提问中除提供关键反编译代码和数据外，再指出三维迷宫大小，Gemini 2.5 Pro 就直接给出了正确求解 flag 的 python 代码。几个 LLM 共迭代提问 10+ 次，历时 1h 左右即解决此题。

使用 LLM 进行问题解决时，添加一些已进行的确定性分析内容，会有更好的回答效果。






# 题目信息

地址：[https://ctf.kanxue.com/game-season_fight-256.htm](https://ctf.kanxue.com/game-season_fight-256.htm)
```
KCTF 2025

规则：5.1.1  Windows方案一

cm.exe文件的SHA1值为:db4b7754816c6ba61f8a9687feb2d50203941958

判胜条件：打开cm.exe,输入你的序列号,然后回车,如果结果显示“success.”表示成功,其他为失败。
```

拖进 IDA 简单分析定位到关键逻辑在 `.text:0070129F` 地址，可定义为函数。

# 问答过程

## Question

```
这是ctf逆向题目反编译的代码和数据，进行分析，如三维迷宫大小为10 x 9 x 3，并写出python解题代码

char __usercall sub_70129F@<al>(
        int a1@<eax>,
        int a2@<edx>,
        int a3@<ebp>,
        const char *a4@<esi>,
        int a5,
        int a6,
        int a7,
        int a8,
        int a9,
        int a10,
        int a11)
{
  int v11; // edi
  int v12; // ecx
  char *v13; // edx
  int v14; // ebx
  char v15; // al
  int v17; // esi
  char *v18; // ecx
  int v19; // edx
  int v20; // edi
  char *v21; // ecx
  char *retaddr; // [esp+0h] [ebp+0h]
  int v23; // [esp+4h] [ebp+4h]
  int v24; // [esp+8h] [ebp+8h]
  int v25; // [esp+Ch] [ebp+Ch]
  int v26; // [esp+10h] [ebp+10h]
  int v27; // [esp+14h] [ebp+14h]

  if ( a1 != a2 )
  {
    v11 = strlen(a4);
    v12 = 0;
    v13 = 0;
    v14 = 0;
    v23 = v11;
    v27 = 0;
    v26 = 0;
    v25 = 0;
    v24 = 0;
    retaddr = 0;
    if ( v11 > 0 )
    {
      while ( 1 )
      {
        v15 = a4[(_DWORD)v13];
        while ( byte_7020F8[v12] != v15 )
        {
          if ( byte_7020F9[v12] == v15 )
          {
            ++v12;
            break;
          }
          if ( byte_7020FA[v12] == v15 )
          {
            v12 += 2;
            break;
          }
          if ( byte_7020FB[v12] == v15 )
          {
            v12 += 3;
            break;
          }
          if ( byte_7020FC[v12] == v15 )
          {
            v12 += 4;
            break;
          }
          if ( byte_7020FD[v12] == v15 )
          {
            v12 += 5;
            break;
          }
          v12 += 6;
          if ( v12 >= 36 )
            return 0;
        }
        if ( v12 >= 36 )
          break;
        if ( v12 >= 12 )
          v17 = (v12 >= 24) + 1;
        else
          v17 = 0;
        if ( ((unsigned __int8)v13 & 1) != 0 )
        {
          v19 = v24 + 1;
          v20 = v12 % 12;
          v24 = v19;
          if ( v19 == 1 && dword_703020[80 * v17 + 10 * v17 + 10 * v14 + v20] != 11278 )
            return 0;
          v18 = retaddr;
          if ( retaddr == (char *)(v23 - 1) && dword_703020[80 * v17 + 10 * v17 + 10 * v14 + v20] != 8114 )
            return 0;
          if ( v19 > 1 )
          {
            if ( (int)retaddr < v23
              && (!(unsigned __int8)sub_7011C0(dword_703020[80 * v17 + 10 * v17 + 10 * v14 + v20], &a10, &a11)
               || a10 < 2
               || a11 < 2
               || a10 == a11)
              || abs32(v20 - v25) + abs32(v14 - v26) + abs32(v17 - v27) != 1 )
            {
              return 0;
            }
            v18 = retaddr;
          }
          v25 = v20;
          v26 = v14;
          v27 = v17;
          if ( v18 == (char *)(v23 - 1) && dword_703020[80 * v17 + 10 * v17 + 10 * v14 + v20] == 8114 )
            return 1;
          v11 = v23;
        }
        else
        {
          v14 = v12 % 12;
          v18 = retaddr;
        }
        v21 = v18 + 1;
        retaddr = v21;
        if ( (int)v21 >= v11 )
          return 0;
        a4 = *(const char **)(a3 + 8);
        v13 = v21;
        v12 = 0;
      }
    }
  }
  return 0;
}

char __cdecl sub_7011C0(int a1, int *a2, int *a3)
{
  double v4; // st7
  int v5; // edi
  int v6; // ecx
  double v7; // st7
  int v8; // esi
  int v10; // [esp+1Ch] [ebp-4h]
  int v11; // [esp+24h] [ebp+4h]

  if ( a1 < 4 )
    return 0;
  v4 = (double)a1;
  v5 = 2;
  v10 = 2;
  sub_701000(v4);
  v6 = (int)v4;
  v11 = (int)v4;
  if ( (int)v4 < 2 )
    return 0;
  while ( 1 )
  {
    if ( a1 % v5 || v5 < 2 )
      goto LABEL_10;
    v7 = (double)v10;
    v8 = 2;
    sub_701000(v7);
    if ( (int)v7 >= 2 )
    {
      while ( v5 % v8 )
      {
        if ( ++v8 > (int)v7 )
          goto LABEL_8;
      }
      goto LABEL_9;
    }
LABEL_8:
    if ( (unsigned __int8)sub_701170(a1 / v5) )
      break;
LABEL_9:
    v6 = v11;
LABEL_10:
    v10 = ++v5;
    if ( v5 > v6 )
      return 0;
  }
  if ( a2 )
    *a2 = v5;
  if ( a3 )
    *a3 = a1 / v5;
  return 1;
}

rdata:007020F8 ; char byte_7020F8[]
.rdata:007020F8 byte_7020F8 db 30h                      ; DATA XREF: sub_70129F:loc_7012D8↑r
.rdata:007020F9 ; char byte_7020F9[]
.rdata:007020F9 byte_7020F9 db 31h                      ; DATA XREF: sub_70129F+41↑r
.rdata:007020FA ; char byte_7020FA[]
.rdata:007020FA byte_7020FA db 32h                      ; DATA XREF: sub_70129F+49↑r
.rdata:007020FB ; char byte_7020FB[]
.rdata:007020FB byte_7020FB db 33h                      ; DATA XREF: sub_70129F+51↑r
.rdata:007020FC ; char byte_7020FC[]
.rdata:007020FC byte_7020FC db 34h                      ; DATA XREF: sub_70129F+59↑r
.rdata:007020FD ; char byte_7020FD[]
.rdata:007020FD byte_7020FD db 35h                      ; DATA XREF: sub_70129F+61↑r
.rdata:007020FE a6789abcdefghij db '6789abcdefghijklmnopqrstuvwxyz',0

.data:00703020 ; int dword_703020[272]
.data:00703020 dword_703020 dd 2C0Eh, 1312h, 7F44h, 4C2Bh, 966h, 1E12h, 1263h, 1828h, 31A1h, 52AEh
.data:00703020                                         ; DATA XREF: sub_70129F+100↑r
.data:00703020                                         ; sub_70129F+129↑r ...
.data:00703048 dd 1DC6h, 4019h, 3D89h, 614Dh, 1A4Ah, 3A24h, 5406h, 0E61h, 658h, 0D4Ch
.data:00703070 dd 5423h, 4860h, 7988h, 1FA3h, 705Bh, 4464h, 63EFh, 403Eh, 50CBh, 1676h
.data:00703098 dd 5132h, 68B5h, 4A38h, 6FF5h, 189Bh, 170Bh, 2704h, 20EDh, 4938h, 47F6h
.data:007030C0 dd 7512h, 5196h, 2B7Ch, 4A50h, 2E54h, 6FBEh, 3532h, 7B54h, 0ABDh, 2889h
.data:007030E8 dd 56C0h, 323Bh, 3698h, 31CFh, 435Ah, 75FAh, 0A2Bh, 200Bh, 45EDh, 163Fh
.data:00703110 dd 2554h, 62BBh, 3393h, 2A31h, 2956h, 3004h, 3684h, 3DEEh, 47ACh, 2267h
.data:00703138 dd 629Eh, 1E93h, 7943h, 661Bh, 7FB4h, 255Ah, 3D37h, 1804h, 69E1h, 312Ch
.data:00703160 dd 3999h, 293Fh, 2F0Eh, 743Ah, 117h, 64CDh, 7C76h, 5CBFh, 6AB0h, 585h
.data:00703188 dd 6CFCh, 3CE6h, 6FABh, 0F81h, 511Ch, 24E4h, 785h, 5AEBh, 2977h, 0BFBh
.data:007031B0 dd 55F8h, 39h, 29DDh, 4987h, 133Bh, 5E2Fh, 7F4Dh, 6497h, 62C2h, 3774h
.data:007031D8 dd 1826h, 78Ch, 20BBh, 5473h, 68B6h, 27FBh, 7321h, 1B0Eh, 6280h, 54E2h
.data:00703200 dd 5133h, 61E7h, 2F6Bh, 5AE2h, 1B09h, 64BBh, 71Bh, 6272h, 453Fh, 22BDh
.data:00703228 dd 0D68h, 52A9h, 3116h, 19ADh, 28F6h, 141Eh, 6B10h, 32ACh, 2394h, 353Dh
.data:00703250 dd 6A40h, 697h, 80Eh, 6883h, 4297h, 175Dh, 0B3Ah, 4584h, 4FB8h, 55D2h
.data:00703278 dd 2592h, 5F99h, 5986h, 5A84h, 71A3h, 3975h, 525h, 3E15h, 823h, 12D7h
.data:007032A0 dd 78EFh, 636Bh, 471Ah, 531Ch, 23F8h, 38D7h, 7E64h, 18DBh, 344Eh, 5655h
.data:007032C8 dd 1C69h, 0EE8h, 23Ch, 25C8h, 684h, 776Dh, 0B65h, 7855h, 602Dh, 277Eh
.data:007032F0 dd 60ACh, 1885h, 6E40h, 3EECh, 175Ch, 0D2Bh, 4F2Eh, 645h, 6C70h, 457Dh
.data:00703318 dd 5CD8h, 2B12h, 11Ch, 7AADh, 2E5Eh, 37CBh, 5CF8h, 5C48h, 648Fh, 3841h
.data:00703340 dd 6344h, 7F63h, 5C2h, 0BE2h, 717Ah, 7317h, 711Ah, 4344h, 319h, 756Eh
.data:00703368 dd 2F5Eh, 6EF2h, 23B0h, 1ED5h, 5A1Bh, 5FFFh, 7494h, 5C4Ch, 7D2Ch, 2C51h
.data:00703390 dd 4BE4h, 5197h, 2384h, 64DDh, 62E9h, 5019h, 447Eh, 1DA1h, 70B3h, 5B03h
.data:007033B8 dd 17BCh, 4ED4h, 3E1Fh, 26F8h, 2AF2h, 7B64h, 4634h, 69D9h, 75Ah, 344Bh
.data:007033E0 dd 27D0h, 0C9Ch, 385Eh, 2496h, 5635h, 57AAh, 44A8h, 62AFh, 65E7h, 3284h
.data:00703408 dd 7A73h, 1CCFh, 25F4h, 5DCDh, 5CDEh, 109Bh, 7890h, 45CFh, 5FEFh, 4ABBh
.data:00703430 dd 26h, 47Dh, 6121h, 3A42h, 5519h, 32AFh, 2096h, 18E7h, 4181h, 1FB2h, 0
.data:0070345C dd 0

```

## Gemini 2.5 Pro 

### Thought
```
Investigating the Program

I'm currently focused on the structure of the C-like pseudocode, specifically how the input 'a4' is handled. I'm digging into the loops and conditionals within 'sub_70129' to understand their roles in the program's logic. My goal is to determine the input validation process.
Deconstructing the Code

I've started by examining the pseudocode and data sections, zeroing in on how 'a4' is handled. Now, I'm analyzing the loops and conditionals in sub_70129 F to understand the maze's navigation, including coordinate calculations. I plan to identify any input validation in sub_7011C0 and analyze the data arrays for validation checks. I'll confirm the maze dimensions and then solve the challenge.
```

### Answer

```
好的，我们来分析这段反编译的代码和数据，并编写相应的 Python 解题脚本。

### 代码分析

这段代码是一个复杂的校验函数，其核心逻辑是验证输入字符串 `a4` 是否代表一个在三维迷宫中的有效路径。

#### `sub_70129F` 函数分析:

这是主校验函数，我们可以将其行为分解如下：

1.  **输入和初始化**:
    *   `a4`: 指向输入字符串的指针，代表迷宫的路径。
    *   函数首先计算输入字符串 `a4` 的长度 `v11`。
    *   初始化多个变量，其中 `v12`, `v13`, `v14` 等是循环和坐标计算的关键。`v24`, `v25`, `v26`, `v27` 用于记录路径的状态和当前坐标。

2.  **路径解码 (外层 `while` 循环)**:
    *   该循环逐个字符处理输入字符串 `a4`。
    *   `v15 = a4[(_DWORD)v13];`: 取出当前字符。

3.  **字符转索引 (内层 `while` 循环)**:
    *   `byte_7020F8` 到 `byte_7020FD` 以及 `a6789abcdefghij` 实际上构成了一个36进制的字符集（'0'-'5' 加上 '6'-'z'）。
    *   代码通过一系列的 `if` 判断，将输入的字符 `v15` 转换成一个0到35之间的索引 `v12`。这个转换过程比较奇特，但本质上是将一个字符映射到一个数字。

4.  **坐标计算**:
    *   `v17 = (v12 >= 24) + 1;` 如果 `v12 >= 12`，则计算 `v17`。这实际上是在计算三维坐标中的一个维度（可以看作是 Z 轴）。
        *   如果 `v12` 在 `[0, 11]`，`v17` (Z) = 0。
        *   如果 `v12` 在 `[12, 23]`，`v17` (Z) = 1。
        *   如果 `v12` 在 `[24, 35]`，`v17` (Z) = 2。
    *   `v14 = v12 % 12;`: 计算 X 轴坐标。
    *   `((unsigned __int8)v13 & 1) != 0`: 这个判断检查当前处理的字符位置 `v13` (从0开始) 是奇数还是偶数。
        *   **偶数位字符**: 只更新 `v14` (X 坐标)。
        *   **奇数位字符**: 更新 `v20` (Y 坐标)，并进行大量的路径校验。

5.  **路径校验 (奇数位字符)**:
    *   `v20 = v12 % 12;`: 计算 Y 轴坐标。
    *   **起点检查**: `if ( v19 == 1 && dword_703020[...] != 11278 ) return 0;`
        *   `v19` 是 `v24+1`，`v24` 初始为0，所以第一次进入（处理第二个字符时）`v19` 为1。
        *   这说明路径的第一个坐标点 `(v14, v20, v17)` 对应的值必须是 `11278` (0x2C0E)。
    *   **终点检查**: `if ( retaddr == (char *)(v23 - 1) && dword_703020[...] != 8114 ) return 0;`
        *   `retaddr` 是已处理的字符数，`v23` 是总长度。当处理到最后一个字符时，进行终点检查。
        *   终点坐标对应的值必须是 `8114` (0x1FB2)。
    *   **移动连续性检查**: `abs32(v20 - v25) + abs32(v14 - v26) + abs32(v17 - v27) != 1`
        *   `v25`, `v26`, `v27` 保存的是上一步的 (Y, X, Z) 坐标。
        *   这个条件判断当前步与上一步的曼哈顿距离是否为1，确保了每次移动只能在 X, Y, Z 轴上移动一个单位。
    *   **路径节点值校验**: `!(unsigned __int8)sub_7011C0(...) || a10 < 2 || a11 < 2 || a10 == a11`
        *   对于路径上的中间点，其在 `dword_703020` 数组中对应的值，必须满足 `sub_7011C0` 函数的校验。

6.  **成功条件**:
    *   `if ( v18 == (char *)(v23 - 1) && dword_703020[...] == 8114 ) return 1;`
    *   当处理完所有字符，并且最后一个坐标点的值为 `8114` 时，函数返回1，表示成功。

#### `sub_7011C0` 函数分析:

这个函数的作用是判断一个整数 `a1` 是否可以被分解为两个**不同**的**素数**的乘积。

*   它从 `v5 = 2` 开始遍历，找到 `a1` 的最小因子 `v5`。
*   然后它检查 `v5` 和 `a1 / v5` 是否都是素数。代码中判断一个数 `n` 是否为素数的方法是：从2遍历到 `sqrt(n)`，看是否存在因子。
*   如果 `a1` 可以分解为两个不同的素数 `v5` 和 `a1/v5` 的乘积，函数返回1，并将这两个素数存入 `a2` 和 `a3`。否则返回0。

#### 迷宫维度分析:

*   **Z 轴 (v17)**: `(v12 >= 24) + 1` 的计算结果是 0, 1, 2。所以 Z 轴大小为 **3**。
*   **X 轴 (v14)**: `v12 % 12` 的结果在 `[0, 11]` 之间。但是，代码中有一个索引计算：`80 * v17 + 10 * v17 + 10 * v14 + v20`。这里 `10 * v14` 暗示了 X 轴的范围可能与10有关。
*   **Y 轴 (v20)**: `v12 % 12` 的结果在 `[0, 11]` 之间。索引 `... + v20` 暗示了 Y 轴的大小。
*   **数组索引**: `dword_703020[80 * v17 + 10 * v17 + 10 * v14 + v20]` 这个索引可以简化为 `dword_703020[90 * v17 + 10 * v14 + v20]`。
    *   当 Z=0, X=9, Y=9 时，索引为 `90*0 + 10*9 + 9 = 99`。
    *   当 Z=1, X=0, Y=0 时，索引为 `90*1 = 90`。
    *   当 Z=2, X=8, Y=9 时，索引为 `90*2 + 10*8 + 9 = 180 + 80 + 9 = 269`。
    *   `dword_703020` 数组大小为272，所以 `270` 个元素（0-269）正好可以构成一个 `3 x 9 x 10` 或 `3 x 10 x 9` 的迷宫。
    *   从索引 `10 * v14 + v20` 来看，更像是 `Z * (10*9) + X * 10 + Y` 的结构，其中内层是 `10 x 9` 的平面。所以迷宫大小是 **Z=3, X=9, Y=10**。

**总结迷宫规则**:

1.  **迷宫大小**: 9 (X) x 10 (Y) x 3 (Z)。
2.  **路径表示**: 由 `0-9a-z` 构成的字符串，每两个字符代表一个坐标点 (X, Y, Z)。
3.  **起点**: 对应的值为 `11278`。
4.  **终点**: 对应的值为 `8114`。
5.  **路径点**: 对应的值必须能分解为两个不同的素数之积。
6.  **移动**: 每次只能在 X, Y, Z 轴上移动一格（曼哈顿距离为1）。

### Python 解题代码

根据以上分析，我们可以使用深度优先搜索（DFS）或广度优先搜索（BFS）来寻找路径。这里使用 BFS，因为它可以找到最短路径。

---python
import math

# .data:00703020
dword_703020 = [
    0x2C0E, 0x1312, 0x7F44, 0x4C2B, 0x0966, 0x1E12, 0x1263, 0x1828, 0x31A1, 0x52AE,
    0x1DC6, 0x4019, 0x3D89, 0x614D, 0x1A4A, 0x3A24, 0x5406, 0x0E61, 0x0658, 0x0D4C,
    0x5423, 0x4860, 0x7988, 0x1FA3, 0x705B, 0x4464, 0x63EF, 0x403E, 0x50CB, 0x1676,
    0x5132, 0x68B5, 0x4A38, 0x6FF5, 0x189B, 0x170B, 0x2704, 0x20ED, 0x4938, 0x47F6,
    0x7512, 0x5196, 0x2B7C, 0x4A50, 0x2E54, 0x6FBE, 0x3532, 0x7B54, 0x0ABD, 0x2889,
    0x56C0, 0x323B, 0x3698, 0x31CF, 0x435A, 0x75FA, 0x0A2B, 0x200B, 0x45ED, 0x163F,
    0x2554, 0x62BB, 0x3393, 0x2A31, 0x2956, 0x3004, 0x3684, 0x3DEE, 0x47AC, 0x2267,
    0x629E, 0x1E93, 0x7943, 0x661B, 0x7FB4, 0x255A, 0x3D37, 0x1804, 0x69E1, 0x312C,
    0x3999, 0x293F, 0x2F0E, 0x743A, 0x0117, 0x64CD, 0x7C76, 0x5CBF, 0x6AB0, 0x0585,
    0x6CFC, 0x3CE6, 0x6FAB, 0x0F81, 0x511C, 0x24E4, 0x0785, 0x5AEB, 0x2977, 0x0BFB,
    0x55F8, 0x0039, 0x29DD, 0x4987, 0x133B, 0x5E2F, 0x7F4D, 0x6497, 0x62C2, 0x3774,
    0x1826, 0x078C, 0x20BB, 0x5473, 0x68B6, 0x27FB, 0x7321, 0x1B0E, 0x6280, 0x54E2,
    0x5133, 0x61E7, 0x2F6B, 0x5AE2, 0x1B09, 0x64BB, 0x071B, 0x6272, 0x453F, 0x22BD,
    0x0D68, 0x52A9, 0x3116, 0x19AD, 0x28F6, 0x141E, 0x6B10, 0x32AC, 0x2394, 0x353D,
    0x6A40, 0x0697, 0x080E, 0x6883, 0x4297, 0x175D, 0x0B3A, 0x4584, 0x4FB8, 0x55D2,
    0x2592, 0x5F99, 0x5986, 0x5A84, 0x71A3, 0x3975, 0x0525, 0x3E15, 0x0823, 0x12D7,
    0x78EF, 0x636B, 0x471A, 0x531C, 0x23F8, 0x38D7, 0x7E64, 0x18DB, 0x344E, 0x5655,
    0x1C69, 0x0EE8, 0x023C, 0x25C8, 0x0684, 0x776D, 0x0B65, 0x7855, 0x602D, 0x277E,
    0x60AC, 0x1885, 0x6E40, 0x3EEC, 0x175C, 0x0D2B, 0x4F2E, 0x0645, 0x6C70, 0x457D,
    0x5CD8, 0x2B12, 0x011C, 0x7AAD, 0x2E5E, 0x37CB, 0x5CF8, 0x5C48, 0x648F, 0x3841,
    0x6344, 0x7F63, 0x05C2, 0x0BE2, 0x717A, 0x7317, 0x711A, 0x4344, 0x0319, 0x756E,
    0x2F5E, 0x6EF2, 0x23B0, 0x1ED5, 0x5A1B, 0x5FFF, 0x7494, 0x5C4C, 0x7D2C, 0x2C51,
    0x4BE4, 0x5197, 0x2384, 0x64DD, 0x62E9, 0x5019, 0x447E, 0x1DA1, 0x70B3, 0x5B03,
    0x17BC, 0x4ED4, 0x3E1F, 0x26F8, 0x2AF2, 0x7B64, 0x4634, 0x69D9, 0x075A, 0x344B,
    0x27D0, 0x0C9C, 0x385E, 0x2496, 0x5635, 0x57AA, 0x44A8, 0x62AF, 0x65E7, 0x3284,
    0x7A73, 0x1CCF, 0x25F4, 0x5DCD, 0x5CDE, 0x109B, 0x7890, 0x45CF, 0x5FEF, 0x4ABB,
    0x0026, 0x047D, 0x6121, 0x3A42, 0x5519, 0x32AF, 0x2096, 0x18E7, 0x4181, 0x1FB2
]

MAZE_X, MAZE_Y, MAZE_Z = 9, 10, 3
START_VALUE = 0x2C0E
END_VALUE = 0x1FB2

# 预计算素数，用于加速
prime_cache = {}
def is_prime(n):
    if n in prime_cache:
        return prime_cache[n]
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            prime_cache[n] = False
            return False
    prime_cache[n] = True
    return True

# 模拟 sub_7011C0 函数
def check_value(n):
    if n < 4:
        return False
    limit = int(math.sqrt(n))
    for i in range(2, limit + 1):
        if n % i == 0:
            p1 = i
            p2 = n // i
            if p1 != p2 and is_prime(p1) and is_prime(p2):
                return True
    return False

# 坐标与数组索引的转换
def get_maze_value(x, y, z):
    if not (0 <= x < MAZE_X and 0 <= y < MAZE_Y and 0 <= z < MAZE_Z):
        return -1 # 无效坐标
    # index = 90 * z + 10 * x + y  (错误的，根据ida看是10*y+x)
    index = z * MAZE_X * MAZE_Y + y * MAZE_X + x
    # 根据IDA的 80 * v17 + 10 * v17 + 10 * v14 + v20
    # 简化为 90*z + 10*x + y
    index = 90 * z + 10 * x + y
    return dword_703020[index]

# 找到起点和终点
start_pos, end_pos = None, None
for z in range(MAZE_Z):
    for y in range(MAZE_Y):
        for x in range(MAZE_X):
            val = get_maze_value(x, y, z)
            if val == START_VALUE:
                start_pos = (x, y, z)
            elif val == END_VALUE:
                end_pos = (x, y, z)

print(f"迷宫大小: X={MAZE_X}, Y={MAZE_Y}, Z={MAZE_Z}")
print(f"起点坐标: {start_pos}, 值: {hex(get_maze_value(*start_pos))}")
print(f"终点坐标: {end_pos}, 值: {hex(get_maze_value(*end_pos))}")

# 使用BFS求解
def solve_maze():
    queue = [(start_pos, [start_pos])] # (当前坐标, 路径)
    visited = {start_pos}

    while queue:
        (x, y, z), path = queue.pop(0)

        if (x, y, z) == end_pos:
            return path

        # 探索所有可能的移动方向 (上、下、左、右、前、后)
        for dx, dy, dz in [(0,0,1), (0,0,-1), (0,1,0), (0,-1,0), (1,0,0), (-1,0,0)]:
            nx, ny, nz = x + dx, y + dy, z + dz

            if (nx, ny, nz) in visited:
                continue

            # 检查坐标是否有效
            if not (0 <= nx < MAZE_X and 0 <= ny < MAZE_Y and 0 <= nz < MAZE_Z):
                continue
            
            val = get_maze_value(nx, ny, nz)

            # 检查节点是否可通行
            # 终点或满足特定条件的点
            if (nx, ny, nz) == end_pos or check_value(val):
                visited.add((nx, ny, nz))
                new_path = path + [(nx, ny, nz)]
                queue.append(((nx, ny, nz), new_path))
    return None

# 将坐标路径转换为最终的flag字符串
def path_to_flag(path):
    # 字符集: '0'...'5' 拼接 '6'...'z'
    charset = "0123456789abcdefghijklmnopqrstuvwxyz"
    
    flag = ""
    for i, (x, y, z) in enumerate(path):
        # 将 (x,y,z) 坐标反向编码为两个索引 v12
        # Z -> v12_base,  (X,Y) -> v12_offset
        v12_base = z * 12
        
        # 偶数位字符编码 X
        v12_x = v12_base + x
        flag += charset[v12_x]

        # 奇数位字符编码 Y
        v12_y = v12_base + y
        flag += charset[v12_y]
        
    return flag

# 求解并打印结果
solution_path = solve_maze()

if solution_path:
    print("\n找到路径!")
    print("坐标路径:", solution_path)
    flag = path_to_flag(solution_path)
    print("\n最终FLAG:", flag)
else:
    print("未找到路径。")

---

### 代码解释和运行

1.  **数据初始化**: 将 `dword_703020` 数组复制到 Python 列表中。
2.  **常量定义**: 定义迷宫大小、起点值和终点值。
3.  **`is_prime` 和 `check_value`**: 实现了与 C 代码中 `sub_7011C0` 等效的逻辑，用于检查路径点的值是否合法。
4.  **`get_maze_value`**: 根据 (x, y, z) 坐标计算其在 `dword_703020` 数组中的索引并返回值，这是逆向分析中最关键的一步。
5.  **寻找起止点**: 遍历整个迷宫，根据值找到起点和终点的坐标。
6.  **`solve_maze` (BFS)**:
    *   使用一个队列来进行广度优先搜索。队列中每个元素包含当前坐标和到达该坐标的路径。
    *   从起点开始，不断探索相邻的、未访问过的、且值合法的点。
    *   一个点是合法的，当且仅当它是终点，或者它的值可以通过 `check_value` 的校验。
    *   当搜索到达终点时，返回完整的路径。
7.  **`path_to_flag`**:
    *   这是编码的核心部分，它将求解出的坐标路径 `[(x0,y0,z0), (x1,y1,z1), ...]` 转换回符合原始校验逻辑的字符串。
    *   对于路径中的每一个坐标点 `(x, y, z)`，它会生成两个字符。
    *   根据 `v17 = (v12 >= 24) + 1` 和 `v14/v20 = v12 % 12` 的逆运算，可以推导出 `v12 = z * 12 + coord`。
    *   偶数位字符由 X 坐标编码，奇数位字符由 Y 坐标编码。
8.  **主逻辑**: 调用 `solve_maze` 求解，如果成功，则调用 `path_to_flag` 生成最终结果。

运行此 Python 脚本，即可自动完成迷宫求解，并输出正确的路径字符串。
```

解题代码运行输出：
```
迷宫大小: X=9, Y=10, Z=3
起点坐标: (0, 0, 0), 值: 0x2c0e
终点坐标: (8, 9, 2), 值: 0x1fb2

找到路径!
坐标路径: [(0, 0, 0), (0, 1, 0), (1, 1, 0), (1, 1, 1), (1, 2, 1), (1, 3, 1), (2, 3, 1), (3, 3, 1), (3, 2, 1), (3, 1, 1), (4, 1, 1), (5, 1, 1), (5, 2, 1), (5, 3, 1), (5, 3, 0), (6, 3, 0), (7, 3, 0), (7, 2, 0), (7, 
1, 0), (7, 1, 1), (7, 0, 1), (8, 0, 1), (8, 0, 2), (8, 1, 2), (8, 2, 2), (8, 3, 2), (8, 4, 2), (7, 4, 2), (6, 4, 2), (6, 4, 1), (6, 5, 1), (6, 6, 1), (6, 7, 1), (6, 7, 0), (5, 7, 0), (5, 6, 0), (5, 5, 0), (4, 5, 0), (3, 5, 0), (3, 5, 1), (3, 6, 1), (3, 7, 1), (2, 7, 1), (1, 7, 1), (1, 8, 1), (1, 8, 2), (2, 8, 2), (2, 9, 2), (3, 9, 2), (4, 9, 2), (5, 9, 2), (5, 8, 2), (6, 8, 2), (7, 8, 2), (8, 8, 2), (8, 9, 2)]

最终FLAG: 000111dddedfeffffefdgdhdhehf5363737271jdjckcwowpwqwrwsvsusigihiiij675756554535fhfifjejdjdkpwqwqxrxsxtxtwuwvwwwwx
```

# 总结感悟

就感觉到快，搜了下 Chagpt3.5 是 2022 年 11 月发布的，这才两年多时间。