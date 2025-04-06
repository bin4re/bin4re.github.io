---
author: 0x指纹
date: 2024-08-29 08:00+08:00
layout: post
title: "VisualNDepend 逆向工程"
mathjax: true
categories:
- 逆向工程
tags:
- .net
---

* content
{:toc}


搜 .Net Assembly Diff 工具时候，在 StackOverflow 一个回答中了解到 NDepend 工具，可以试用 14 天，试了下 diff 效果还不错，别的功能也很丰富，下载到的版本是 2024.1.1.9735。

```
.NET Assembly Diff / Compare Tool - What's available? [closed]
https://stackoverflow.com/questions/1280252/net-assembly-diff-compare-tool-whats-available
```

将程序断网后点击 Start Evaluation 会进入 NDepend manual server access 流程，自动生成了 Date Request text，到网站可以获取到 Data Response text，输入后即可激活。

![](/assets/images/2024-08-29/1.png)

程序联网的话，应该是后台直接发起请求验证结果完成激活，对程序断网可以方便分析，并且程序会随时联网发送消息，比如 patch 造成或修改授权造成的运行异常报告，还是给断了好。





# 展开分析
14 天后，打开 dnspy 开始看下，大部分函数名、变量名、字符串都被混淆了，程序流程还是好的。注意有弹窗，试着断在 MessageBox.Show，运行断下来了，看下调用堆栈回溯，可以以此展开调试分析。

![](/assets/images/2024-08-29/2.png)


# 授权文件
经过一番杂乱但并不复杂的调试分析，知道程序解密验证服务器返回的数据后，将进行加密保存为 `C:\ProgramData\NDepend\ActivationEval` 文件，程序每次启动都会解析此文件进行验证。

断在 NDpend.Core.dll 的 oJX.xJg 函数中，调试可知前半部分是读 ActivationEval 文件内容，在 kSx.cSZ 函数中解密文件。

![](/assets/images/2024-08-29/3.png)

![](/assets/images/2024-08-29/4.png)

# 内容解密
跟进 kSx.cSZ 函数，看到函数调用链中出现 RijndaelManaged、Rfc2898DeriveBytes、CpherMode.CBC、PaddingMode.PKCS7 等字样，可知主体上是 PKCS7 填充 AES-CBC 解密的 C# 调用。

先进入 CSq 函数，m4f 是 key 和 iv 的长度，程序会用 256 和 128 都试一下，前者会解密失败，再用 128 进行解密。

![](/assets/images/2024-08-29/5.png)

进入 jSp，先对文件内容进行 base64 解密，随后分为 `[:0x10]`、`[0x10:0x20]` 和 `[0x20:]` 三部分。第一部分用来作为 password，和 salt 字符串传入 Rfc2898DeriveBytes 初始化，随后生成 AES 解密的 key，第二部分是 AES 解密的 iv，第三部分是密文。

![](/assets/images/2024-08-29/6.png)

AES 解密完后会进入 YSA 函数，可以看到又进行了一遍 base 解密，随后解压操作，即可得到授权数据的明文。

![](/assets/images/2024-08-29/7.png)

# 签名验证
可以看到末尾段是有一段签名信息的，根据判断会使用 rsa-sha1 验签。

![](/assets/images/2024-08-29/8.png)

根据调用堆栈，回溯到 HIc 函数，再进入 X2t.k2x 函数，根据局部变量内容，我们可以看到从 HadrwareID 提取出了要验签的内容，加载了 RSAKeyValue 并进行了哈希验证，最后进入 l4h.M4D 函数开始验签。

![](/assets/images/2024-08-29/9.png)

调试进入 c4S 函数中，根据局部变量的信息，可以判断 Y4y 是 `rsaCryptoPublic.VerifyData(hashToSignBytes,signature)` 函数。

![](/assets/images/2024-08-29/10.png)

RsaCryptoPublic 实例的初始化是 c4X 函数。

![](/assets/images/2024-08-29/11.png)

调试看到从 RSAKeyValue 中初始化了 Modulus 和 Exponent，是模数和公钥指数。

![](/assets/images/2024-08-29/12.png)

模数是两个大素数的乘积，到 factordb.com 上分解下，未果，那只能 patch 过掉了。

![](/assets/images/2024-08-29/13.png)

# 信息校验
查看调用堆栈回溯到 G1Z4 函数，进入 EIx 函数，便是信息校验部分。分为两部分，一部分是本机 HardwareID 信息是否和解密的授权数据匹配，另一部分是检查授权相关日期相关信息。

![](/assets/images/2024-08-29/14.png)

HardwareID 部分信息我们可以解密软件生成的 data request text 数据获取，授权信息日期中日期相关部分内容如下，可以猜测信息有注册时间、到期时间、多少天后弹出激活、多少天后弹出请求更多试用、过期后多少内还能再请求更多试用。
```
<DateRegister>23 Aug 2024</DateRegister>
<DateExpire>07 Sep 2024</DateExpire>
<MoreEvalAlreadyAsked>False</MoreEvalAlreadyAsked>
<EvalNbDaysLeftToShowActivationForm>6</EvalNbDaysLeftToShowActivationForm>
<EvalNbDaysLeftToShowAskForMoreEvalButton>4</EvalNbDaysLeftToShowAskForMoreEvalButton>
<CanReEvalNbDaysAfterEvalExpiration>240</CanReEvalNbDaysAfterEvalExpiration>
<EvalRegisteredWithProductVersion>2024.1.1.9735</EvalRegisteredWithProductVersion>
```
可以看到程序对几个日期有一些比较，我们在构造授权文件时候，几个日期的大小可以按照服务器真正返回的内容来。

![](/assets/images/2024-08-29/15.png)

# 生成授权
思路是先解密软件手动激活时候弹窗里面的 data request text，得到 HardwareID 部分信息，构造出授权信息明文，修改过期时间，再加密生成 ActivationEval 文件放在 `C:\ProgramData\NDepend\` 目录下即可。

整个过程并不复杂，简单提一下使用python实现的点。
1.C# 实现 AES 加解密，是传入 password 和 salt 生成 Rfc2898DeriveBytes 实例再生成的 key，加解密时的 salt 是不同的，可以调试获取。

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password, salt, iterations, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)
```

2.C# 的解压缩数据格式是 Raw Deflate，不能直接用 python 的 zlib 处理。

```python
#解压
plaintext = zlib.decompress(compress_data, -zlib.MAX_WBITS)

#压缩
compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
compress_data = compressor.compress(plaintext.encode("utf-8"))+compressor.flush()       
```

授权生成的 pthon 简单实现如下
```python
import random
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import zlib

def pkcs7padding(text):
    bs = 16
    length = len(text)
    bytes_length = len(text)
    padding_size = length if (bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    padding_text = padding.to_bytes(1,'little') * padding
    return text + padding_text


def data_response_decrypt(key,iv,ciphertext):
    base64text = AES.new(key, AES.MODE_CBC,iv).decrypt(ciphertext)
    compress_data = base64.b64decode(base64text)
    plaintext = zlib.decompress(compress_data, -zlib.MAX_WBITS)
    return plaintext

def data_response_encrypt(key,iv,plaintext):
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    compress_data = compressor.compress(plaintext.encode("utf-8"))+compressor.flush()
    base64_cipher = base64.b64encode(compress_data)
    return AES.new(key, AES.MODE_CBC,iv).encrypt(pkcs7padding(base64_cipher))

def derive_key(password, salt, iterations, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)
def decrypt_server_data(cipher):
    text = base64.b64decode(cipher)
    key = derive_key("N|[%^^m@#ç:!Ah*~".encode("utf-8"),text[:0x10],1000,0x10)
    iv = text[0x10:0x20]
    ciphertext = text[0x20:]
    plaintext = data_response_decrypt(key, iv, ciphertext)
    return plaintext.decode("utf-8")
def decrypt_data_request(cipher):
    text = base64.b64decode(cipher)
    key = derive_key("j%*£$[8f3Kv'{^ç\\".encode("utf-8"),text[:0x10],1000,0x10)
    iv = text[0x10:0x20]
    ciphertext = text[0x20:]
    plaintext = data_response_decrypt(key, iv, ciphertext)
    return plaintext.decode("utf-8")

def generateActivationEval():
    random_bytes = bytes(random.getrandbits(8) for _ in range(32))
    key = derive_key("N|[%^^m@#ç:!Ah*~".encode("utf-8"),random_bytes[:0x10],1000,0x10)
    iv = random_bytes[0x10:0x20]
    with open("licenseData.txt","r") as f:
        plaintext = f.read()
    all = random_bytes + data_response_encrypt(key, iv, plaintext)
    with open("ActivationEval","wb") as f:
        f.write(base64.b64encode(all))

# data_request = decrypt_data_request("xxxxxxxx")
# print(data_request)

# data_response = decrypt_server_data("xxxxxxxx")
# print(data_response)

generateActivationEval()
```

# 篡改检测
除了生成授权文件，前面提到在 factordb.com 上分解 rsa 验签的模数，没成功，没有私钥无法签名，只能 patch 下过掉验签。可以在 c4S 函数中 `rsaCryptoPublic.VerifyData(hashToSignBytes,signature)` 函数调用那里 patch 直接返回 true。

![](/assets/images/2024-08-29/16.png)

随后可以进入软件界面，但是发现 diff 功能无法正常使用，经过一番杂乱的调试分析，先后找到多个暗桩，其中 yTf 和 P39 两个是检测我们过 rsa 验签 patch 的 NDepend.Core.dll，继续 patch 直接过掉。

![](/assets/images/2024-08-29/17.png)

![](/assets/images/2024-08-29/18.png)

随后发现 diff 功能还是不能正常使用，有暗桩没找到，真是明枪易躲暗箭难防。

# 无限试用
不想花过多时间耗在庞杂的软件功能中调试以求寻出所有暗桩，就试着换下思路。经尝试，删除 `C:\ProgramData\NDepend下的ActivationEval` 文件，再随意修改 `NDepend_2024.1.1.9735\Lib\DownloadInfo.xml` 中的邮箱地址，可获取新的 14 天试用，猜测和服务端没有仔细校验软件生成的 data request 信息有关。