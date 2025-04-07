---
author: 0x指纹
date: 2020-07-07 08:00+08:00
layout: post
title: "SCTF2020 逆向出题与解题思路"
mathjax: true
categories:
- 竞技比赛
tags:
- ctf-re
---

* content
{:toc}

SCTF 2020 是作为第六届XCTF国际联赛的第三场分站赛，由我们 Syclover 小组的师傅们为本次大赛提供了出题，7 月 4 日上午九点开始，7 月 6 日上午九点结束，时长两天。
 
两天的比赛战况可以说是动荡起伏，激烈程度也出乎了我们出题师傅的意料，尤其是排行榜前三名一直风云变幻。第一天上午还比较平静，到了中午时候各大强队就开始陆续发力了，后面随着题目地不断放出，比赛排行榜也在一直更迭。
 
第二天的夜里各大战队都还在肝题目，排名第一的 W&M 战队的师傅最后一天通宵肝出来了两个题目的一血，直到最后一个小时排名第二的 L3H Sec 战队还丢出来了一道 Web 题目的一血，让人在想他们是不是要翻盘了。
 
关于比赛更详细的情况可以看下 XCTF 社区的这篇文章，[《SCTF 2020 W&M高位出圈丨5元代打出题人，冲鸭！》](https://mp.weixin.qq.com/s/RaVHGqCr-MPCAeusFQvGig)。






![](/assets/images/2020-07-07/1.png) 
 
和学弟们一起出了比赛的逆向方向题目，其中 Orz 题目是我出的，作为出题人之一，在两天的观战过程中的体验可以说也是很独特的，时时刻刻关注着战队的解题情况，尤其是自己的题目。一方面担心自己的题目没有人做，另一方面也会担心自己的题目是不是过于简单了。在比赛结束的那天早上起床去看各大战队的解题记录，发现有战队夜里一点多甚至是早上五点多解出来了我的题目，这是通宵做了吗，真是太强了，Orz 膜...
 
虽然两天都作为出题方在观战，但是还是学到了很多东西。一来是对各大战队的实力有了最直观的感受，比如 Whitzard 战队逆向题目拿下了五个一血和一个三血，解题速度和解题数量都力压其他战队。二来就是被参赛师傅们的竞赛精神给折服了，不到比赛结束绝不停止做题，无论是凌晨一点钟，还是早上五点半，还是比赛最后一小时。像这样拼尽全力不轻易言弃的精神无论是在什么时候和地点都是难能可贵的，值得深刻地思考与学习。

# 出题思路
开始说下我的 Orz 题目的出题思路，就是很直来直去的算法逆向题目，没加什么混淆，只用了 Visual Studio 的 release 优化，算法和加密总共两部分。

## 第一部分
第一部分，首先判断输入是否为 32 位，接着根据输入的第七位、第十六位、第三十位生成一个值 seed，然后生成一个大小为 33 的数组 a，使用这个数组中的值和输入进行计算，得到大小为 64 的数组 b，数据类型是 unsigned int，得到数组 b 的这个计算过程其实类似于多元一次方程组的计算。
 
第一部分题目代码如下。

```cpp
        char *input = (char*)malloc(33);
        scanf("%s", input);
        int length = strlen(input);
        if (length != 32) {
               exit(0);
        }
 
        int value = (input[6] + input[15] + input[29]) * 53;    
        unsigned int *tmp = myrandint((~value)&0xfff, input);
        unsigned long long int * tmp2 = (unsigned long long int *)tmp;
 
        unsigned long long int * data = (unsigned long long int *)malloc(sizeof(unsigned
long long int) * 32);
```

```cpp
unsigned int * myrandint(unsigned int seed, char * input)
{
        unsigned long long int a = 32310901;
        unsigned long long int b = 1729;
        unsigned int c = seed;
        int m = 254;
        unsigned int * ret1 = (unsigned int*)malloc(33 * sizeof(int));
        memset(ret1, 0, 33 * sizeof(int));
        for (int i = 0; i < 33; i++) {
               ret1[i] = (a * c + b) % m;
               c = ret1[i];
 
        }
 
        unsigned int  * ret2 = (unsigned int*)malloc(64 * sizeof(int));
        memset(ret2, 0, 64 * sizeof(unsigned int));
 
        for (int i = 0; i < 32; i++)
 
        {
 
               for (int j = 0; j < 33; j++)
 
               {
                       unsigned int tmp = (unsigned int)input[i] ^ ret1[j];
                       ret2[i + j] += tmp;
               }
 
        }
        return ret2;
}
```
第一部分反编译结果如下。
 ![](/assets/images/2020-07-07/2.png) 

![](/assets/images/2020-07-07/3.png) 



## 第二部分
第二部分，使用 unsigned long long int 类型指针指向数组 b，可以理解为把数组 b 转化为大小为 32、数据类型为 unsigned long long int 的数组 c，接着就是进一步处理和加密数组 c。每次处理数组 c 两个值，第一个当作 key，第二个当作 data。
 
接着的处理，首先是比较常见的算法套路，如果不熟悉或者是没见过就一定花时间学习下了，就是 64 重循环中对 key 不断乘二，并且对乘二后的值进行判断，如果溢出了 key 就异或一个奇数，逆向的时候从 key 异或奇数这里入手，因为乘二后一定是偶数，偶数异或奇数后一定是奇数。
 
我在这里的基础上加了 DES 加密，用了两种模式。如果没有溢出就使用 key 对 data 进行 DES-ECB 加密，如果溢出了就使用 key 对 data 进行 DES-CBC 加密，最后再对得到的32位数据进行比较。DES-CBC 加密的 iv 是“syclover”。
 
第二部分题目代码如下。

```cpp
        unsigned long long int * tmp2 = (unsigned long long int *)tmp;
 
        unsigned long long int * data = (unsigned long long int *)malloc(sizeof(unsigned
long long int) * 32);
 
        for (int i = 0; i < 16; i++) {
               unsigned long long int* ret = encrypt(tmp2[2 * i], tmp2[2 * i + 1]);
               data[2 * i] = ret[0];
               data[2 * i + 1] = ret[1];
        }
 
        unsigned long long int cmp_data[32] = {
2153387829194836539,4968037865209379450,8168265158727502467,7752938936513403525,14501680424383085918,17239894214146562937,8631814439533536846,14038875394924393076,4195845133744611697,5882449358190368069,16593579054240177091,6042071195929524833,4901359238874180132,5391991813165233830,1262912001997768975,10592048914693378762,16027373129319566784,8683865403612614472,1074685249143409626,14830847864020240442,839851004411889868,6756767667889788695,10980352984506363454,15143378206568444148,9137722182184199592,16483482195781840874,213411729123350449,8809840326310832316,6556887299588007217,4475244256249997594,4953583337191211260,6316604661095411857 };
 
        for (int i = 0; i < 32; i++) {
               if (cmp_data[i] != data[i]) {                            
                       exit(0);
               }
        }
        printf("Success!\n");
```

编译的话是用 Visual Studio 2017 进行的 release x86 方式进行的编译，优化得还是比较厉害的，比如CBC模式加密的 iv 我本来藏得还是比较深的，然后程序生成后进行反编译是能直接看到的，还有就是 unsigned long long int 会使用两个寄存器来表示等等。
 
第二部分反编译结果如下。
 
 ![](/assets/images/2020-07-07/4.png) 
 
![](/assets/images/2020-07-07/5.png) 

![](/assets/images/2020-07-07/6.png) 


# 解题思路
然后说下我自己的解题思路。
 
第一部分我自己的逆向解题思路是爆破中使用 z3，因为在计算值 seed 时候最后有 &0xfff，范围就这么大，大小 33 的数组 a 是根据 seed 生成的，可以爆破所有可能的 seed，生成数组 a ，然后剩下的计算就交给 z3 来求解。
 
z3 是约束求解器，能够解决很多种情况下的给定部分约束条件寻求一组满足条件的解的问题，如果不太熟悉这个强大又方便的工具一定要学习下。
 
听别的师傅说这个题被花样爆破了，甚至是用汇编爆破的，真是太强了，期待看到师傅们分享出来不同的解题思路...
 
然后第二部分就是直接逆了，前面有说到 64 重循环 key 乘二从异或奇数入手，然后进行 DES 的两种模式解密。
 
放出我自己的解题脚本，python3 装下 z3-solver 和 pycryptodome 库就可以运行了。

```python
from Crypto.Cipher import DES
import struct
from z3 import *
import time
 
def des_ecb_decrypt(cipher,key):
    des = DES.new(key, mode=DES.MODE_ECB)
    cipher = bytes(cipher)
    if (len(cipher) != 8):
        cipher = b'\0' * (8 - len(cipher)) + cipher
    plain = des.decrypt(cipher)
    return plain
 
def des_cbc_decrpt(cipher,key):
    iv = b"syclover"
    des = DES.new(key, mode=DES.MODE_CBC, iv=iv)
    if (len(cipher) != 8):
        cipher = b'\0' * (8 - len(cipher)) + cipher
    cipher = bytes(cipher)
    plain = des.decrypt(cipher)
    return plain
 
def myfun(key,data):
    data = struct.pack(">Q", data)[::-1].strip()
 
    for i in range(64):
        if(key%2==0):
            ckey = struct.pack(">Q", key)[::-1]
            data = des_ecb_decrypt(data,ckey)
            key = key // 2
 
        else:
            ckey = struct.pack(">Q", key)[::-1]
            data = des_cbc_decrpt(data,ckey)
            key ^= 0x3FD99AEBAD576BA5
            key = (key // 2) + (0xffffffffffffffff - 1) // 2 + 1
 
    key_str = "%x"%key
    if(len(key_str)%2 !=0):
        key_str = "0"+key_str
 
    key_arr = list(bytes.fromhex(key_str))[::-1]
    for i in range(8-len(key_arr)):
        key_arr.append(0)
 
    tmp = []
    tmp+=key_arr
    tmp+=list(data)
    return tmp
 
 
def myrandint( start,end,seed):
    a=32310901
    b=1729
    rOld=seed
    m=end-start
    while True:
        rNew=int((a*rOld+b)%m)
        yield rNew
        rOld = rNew
 
 
def Z3(xor_data,cmp_data):
    s = Solver()
    flag =  [BitVec(('x%d' % i),8) for i in range(32) ]
 
    xor_result = [0 for i in range(64)]
    for i in range(32):
        for j in range(33):
            a = flag[i] ^ xor_data[j]
            xor_result[i + j] += a
 
    for i in range(0,64):
        s.add(xor_result[i] == cmp_data[i])
 
    if s.check() == sat:
        model = s.model()
        str = [chr(model[flag[i]].as_long().real) for i in range(32)]
        print( "".join(str))
        time.sleep(5)
        exit()
    else:
        print ("unsat")
 
if __name__ == "__main__":
    key = 2153387829194836539
    data = 4968037865209379450
    cmp_data = [2153387829194836539,4968037865209379450,8168265158727502467,7752938936513403525,14501680424383085918,17239894214146562937,8631814439533536846,14038875394924393076,4195845133744611697,5882449358190368069,16593579054240177091,6042071195929524833,4901359238874180132,5391991813165233830,1262912001997768975,10592048914693378762,16027373129319566784,8683865403612614472,1074685249143409626,14830847864020240442,839851004411889868,6756767667889788695,10980352984506363454,15143378206568444148,9137722182184199592,16483482195781840874,213411729123350449,8809840326310832316,6556887299588007217,4475244256249997594,4953583337191211260,6316604661095411857]
    sum = []
    for i in range(16):
        sum+=(myfun(cmp_data[2*i],cmp_data[2*i+1]))
    value = []
    for i in range(len(sum)//4):
        value.append(sum[4*i]+0x100*sum[4*i+1]+0x1000*sum[4*i+2]+0x10000*sum[4*i+3])
 
    for seed in range(0xfff):
        print(seed)
        xor_data = []
        #r = myrandint(1, 255, 99)
        r = myrandint(1, 255, seed)
        for i in range(33):
            xor_data.append(next(r))
        Z3(xor_data,value)
```

爆破到 99 时候就出来 flag 了，flag 为 SCTF{b5c0b187fe309af0f4d35982fd}。
 
![](/assets/images/2020-07-07/7.png) 

# 结语
这次作为出题一方实在是学到了很多，有了不同的体验，在很多方面给自己带来了新的思考，经过这次比赛，在平时需要进行更多的思考与沉淀，多想多试。