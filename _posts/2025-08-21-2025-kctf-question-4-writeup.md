---
author: 0x指纹
date: 2025-08-21 08:00+08:00
layout: post
title: "KCTF 2025 第四题 WriteUp"
mathjax: true
categories:
- 竞技比赛
tags:
- ctf
- reverse
- veh
- aes
- base64
---

* content
{:toc}

题目的核心算法是通过修改的 Base64 和 AES 组合成的加密与解密算法，来验证用户输入的 UserName 和 Serial 是否匹配。在 main 函数执行前，利用 TLS 回调来完成加解密常量的初始化和反调试检查，在 main 函数中未直接调用核心算法函数，而是将其藏在向量化异常处理器（VEH）中，通过 int 3 指令主动触发异常来执行。








# 加密解密

使用 Resource Hacker 查看程序的字符串表：

```
STRINGTABLE
LANGUAGE LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED
{
  102, 	"SUCCESS"
  103, 	"FAILED"
  104, 	"IRq9quEgngSgKTq+M5+3038imAv9HEVFLeDEREYUoQG="
  105, 	"xn9aMR6l940QYqEQkCjRGQ=="
  106, 	"KfeXm13d+R+hqh6T/TUN3QCibwL4dz3/JyO9Bo2dnSM="
  107, 	"UserName: "
  108, 	"Serial: "
  109, 	"Pause"
}
```

TLS 函数中先初始化了一些加密常量:
- 主密钥: "ThisEncAndDecKey"
- Tweak 密钥: "tweakKey_2024521"
- 自定义 Base64 字符表: "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
- 正S盒 (Forward S-box) qword_14000D870，用于 AES 加密过程。
- 逆S盒 (Inverse S-box) qword_14000D878，用于 AES 解密过程。

对这些加密常量进行交叉引用和调试分析，可以确定：
- sub_1400012A8 为 Base64 编码
- sub_140001684 为 Base64 解码
- sub_140004BEC 为 AES 密钥拓展
- sub_140005684 为 AES 加密
- sub_14000593C 为 AES 解密，密钥拓展在外一层
- sub_140005B44 为使用 Tweak 密钥对固定序列常量进行 AES 加密
- sub_14000618C 是由以上组合起来的加密过程，先使用主密钥进行 AES 加密，结果和使用 Tweak 密钥对固定序列常量进行 AES 加密的结果进行异或，最后进行 Base64 编码
- sub_140005D6C 是 sub_14000618C 的逆向操作，先进行 Base64 解码，再使用主密钥进行 AES 解密，结果和使用 Tweak 密钥对固定序列常量进行 AES 加密的结果进行异或

经过尝试，发现 Base64 和 AES 的输出都和自己验证的代码输出对不上，猜测是进行了魔改。

对 Base64 相关函数进行调试分析，自己实现一下：

```py
def base64_encode(data: bytes) -> str:
    base64_chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
    result = []
    i = 0
    original_len = len(data)

    while i < original_len:
        # 1. 获取3字节的数据块
        chunk = data[i:i+3]
        
        # 如果不足3字节，用 b'\x00' 填充
        padding = 3 - len(chunk)
        chunk += b'\x00' * padding
        
        b0, b1, b2 = chunk[0], chunk[1], chunk[2]

        # 2. 将3个字节以“反向”顺序组合成一个24位整数 n
        # 标准方式是: n = (b0 << 16) + (b1 << 8) + b2
        # 自定义方式是:
        n = (b2 << 16) + (b1 << 8) + b0
        
        # 3. 从 n 中“反向”提取4个6位的索引，并查找对应字符
        # 标准提取是从高位到低位 (>> 18, >> 12, >> 6, & 63)
        # 自定义方式需要从低位到高位，以生成 c0, c1, c2, c3
        result.append(base64_chars[n & 63])             # i0 来自 n 的最低6位
        result.append(base64_chars[(n >> 6) & 63])      # i1 来自 n 的次低6位
        result.append(base64_chars[(n >> 12) & 63])     # i2 来自 n 的次高6位
        result.append(base64_chars[(n >> 18) & 63])     # i3 来自 n 的最高6位
        
        i += 3

    # 4. 根据原始数据长度，在末尾添加正确的 '=' 填充符
    if original_len % 3 == 1:
        result[-2] = '='
        result[-1] = '='
    elif original_len % 3 == 2:
        result[-1] = '='
        
    return "".join(result)

def base64_decode(s):
    base64_chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
    o = s
    s = s.rstrip('=')
    result = bytearray()
    i = 0
    while i < len(s):
        chunk = s[i:i+4]
        n = 0
        pad = 4 - len(chunk)
        chunk += 'A' * pad
        for c in chunk[::-1]:
            n = (n << 6) + base64_chars.index(c)
            
        result.append(n & 0xFF)
        if len(chunk) > 2:
            result.append((n >> 8) & 0xFF)
        if len(chunk) > 3:
            result.append((n >> 16) & 0xFF)

        i += 4
    if o.endswith('=='):
        return bytes(result[:-2])
    elif o.endswith('='):
        return bytes(result[:-1])
    return bytes(result)

```

AES 加解密的话，一步步对比着或调试分析魔改了哪里太费劲了，考虑到程序中加密和解密的算法是成对出现的，最后我选择直接调试修改加解密执行时候的数据，dump 出来执行结果，来获取自己想要的加解密数据，这样快得多。

# 程序流程

TLS 函数中出了除了初始化一些加密常量，还进行了动态 API 解析来反调试，先遍历 Ntdll.dll 的导出表动态加载所有以 "Zw" 开头的 API 函数，再解密出字符串表中的 `106, 	"KfeXm13d+R+hqh6T/TUN3QCibwL4dz3/JyO9Bo2dnSM="` 为 ZwQueryInformationProcess，可在 `.text:0000000140003693 call sub_140005D6C` 打断点执行查看，上面已分析出 sub_140005D6C 是组合的解密函数，后面的问 LLM 说是通过 syscall 直接调用 ZwQueryInformationProcess 检查 ProcessDebugPort 进行反调试，由于我是直接用 Windbg TTD 录制了程序执行过程（见<[TTD 调试与 ttd-bindings 逆向工程实践](https://bin4re.github.io/blog/2023/07/18/ttd-debugging-ttd-bindings-reverse-engineering-practice/)>），无视各种反调试，这段我就没具体验证和绕过了。

main 函数先通过 AddVectoredExceptionHandler 设置异常处理器，当程序发生异常时，请优先调用 sub_140006D40 这个函数来处理，再提示用户进行输入，随后程序会调用 sub_140007323 走到 int 3 主动触发断点异常，从而将执行权交给设置好的异常处理器。每次调用 sub_140007323 之前，程序会设置全局变量 dword_14000D890 的值作为传递给异常处理器的指令，告诉它该做什么，是处理 UserName 还是 Serial，最后在所有计算完成后，main 函数比较最终的计算结果和用户输入的 Serial，并输出验证成功或失败的消息。

sub_140006D40 先通过 `ExceptionInfo->ContextRecord->DrX = 0` 几行代码设置清除 CPU 的调试寄存器（Dr0-Dr3）来反硬件断点调试，再检查捕获到的异常码是否为断点异常（0x80000003），如果不是则不处理。随后将 RIP 加一，跳过导致异常的 int 3 指令，这样当异常处理返回后，程序就可以从下一条指令继续执行，而不是再次触发异常。随后就是通过 dword_14000D890 来控制执行，当 dword_14000D890 == 2 时会调用加密相关的流程，当 dword_14000D890 == 3 时，它会调用解密相关的流程。

分析和调试可知，会对 UserName 进行三次 Encrypt 操作（sub_14000618C），对 Serial 进行一次 Decrypt 操作（sub_140005D6C），最终在 main 函数进行 `Encrypt(Encrypt(Encrypt(UserName))) == Decrypt(Serial)` 的比较。

# 求解过程

user 指定为 KCTF，可以直接 main 函数的 `.text:0000000140003FD1 call cs:memcmp` 处 dump 三次 Encrypt 的结果，就是 `Decrypt(Serial)` 的值。

```
6C 2F 53 78 73 52 30 42 43 6A 52 5A 54 6D 63 37
58 57 73 63 72 4D 76 33 38 69 59 75 6F 69 55 45
43 76 69 39 54 75 76 69 2B 5A 69 4A 5A 6D 64 52
35 45 63 76 56 6E 54 5A 4F 5A 76 72 6E 4F 72 77
```

现在求 Serial 就是对这些数据进行 Encrypt 操作即可。

在上面对 sub_14000618C 的分析知道这是组合起来的加密过程，先使用主密钥进行 AES 加密，结果和使用 Tweak 密钥对固定序列常量进行 AES 加密的结果进行异或，最后进行 Base64 编码。

先调试 dump 下来使用 Tweak 密钥对固定序列常量进行 AES 加密的结果为：

```
A0 81 3E 4D 5B 6A D4 C2 7B A5 46 20 82 B5 1C EF
43 51 8B C3 5E 57 CC 04 F0 BC 43 85 1E 9C BB 51
ED 59 82 E8 1C 04 AC 0B E4 BA C2 BA 53 27 F0 1B
A1 35 01 DF BB 6F D2 83 EB 49 B5 4A F7 E5 40 4B
```

进行异或操作得到:
```
cc ae 6d 35 28 38 e4 80 38 cf 14 7a d6 d8 7f d8 
1b 06 f8 a0 2c 1a ba 37 c8 d5 1a f0 71 f5 ee 14
ae 2f eb d1 48 71 da 62 cf e0 ab f0 09 4a 94 49
94 70 62 a9 ed 01 86 d9 a4 13 c3 38 99 aa 32 3c
```

随后直接调试修改 AES 加密时候的执行时候的数据，得到结果为：
```
27 39 83 55 1C 16 AB 6C 35 55 6B 5C A7 A7 F4 E2
07 6D D1 00 E4 8B F9 39 FF 20 6D 91 1D AF D6 6C
52 41 67 A7 56 9E 58 72 0E 42 AF 37 F1 43 09 B3
09 CE CB DD 43 E4 BF D4 DE 85 A6 01 81 CB FF 23
```

最后执行 `base64_encode(bytes(arr))` 即可得到正确的 Serial 为 `tSzQkyqcvZLgkwDltPF9RpInibA5fTpH/bJni2yvLzTKao2uL5eLZ5QIxPj8bsYWe48ZohC5/Jw3cNNAaX8/rA==`。

按理说直接 x64dbg 调试修改 Encryt 函数 sub_14000618C 的输入可以直接得到结果，不过我没给 x64dbg 过反调试，为了方便直接改的是 TLS 函数中解密函数调用，`.text:0000000140003693 call sub_140005D6C` -> 使用 Tweak 密钥对固定序列常量进行 AES 加密 `.text:0000000140005F99 call sub_140005B44` -> 修改过的 AES 加密函数 `.text:0000000140005C75 call fn_140005684`，在反调试操作之前可以直接走到这里，解出 flag 后就没再继续折腾了。