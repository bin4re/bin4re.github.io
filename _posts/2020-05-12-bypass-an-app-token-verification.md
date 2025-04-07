---
author: 0x指纹
date: 2020-05-12 08:00+08:00
layout: post
title: "对抗一款 App 的 token 验证"
mathjax: true
categories:
- 逆向工程
tags:
- android
- frida
- smali
---

* content
{:toc}

最近又找了个不符合核心价值观的 App 练手，比上篇帖子中的那个还要过分，本来还在犹豫要不要写帖子发出来，后 @r0ysue 巨佬说这是伸张正义打击违法犯罪的事情表彰还来不及，遂仔细整理了下分析思路和经验来发帖子了，给像我一样的入门者提供一个完整的案例来分析练手，以提升巩固学习到的零碎的技术，顺便打击下违法犯罪。

由于这个 App 的每一个界面都十分违规就不展示了，这里让我们脱离 App 的内容本身，把重点放在技术方向上。

![img](/assets/images/2020-05-12/802108_ZGM4HTWNUP8UVC2.png)

当我们看到这里时候，第一直觉是以破解内购的思路去购买 vip，本地修改观影次数改成无限次，但是这样是不行通的，在分析过程中逐步会发现这个 App 的防护工作做的蛮好的，首先是加了壳，然后通信过程中给数据进行了加密，最重要的是这个 App 是在服务器进行了 token 的管理和验证的，和简单内购就可以破解的 App 呈现截然不同的样子，下面让我们通过一点点分析这个 App，来熟悉 App 的一些简单的防护策略和对应的逆向思路。





# 脱壳

## 脱壳的一些说明

首先是脱壳，App 是加了梆梆的免费版壳，我们这里依然可以采用 frida-unpack 来直接脱壳，关于 frida-unpack 的使用以及使用过程中碰到的问题解决，具体操作可以看我的[上一篇帖子](https://bbs.pediy.com/thread-258776.htm)的脱壳部分，这里不详细说了，直接放出代码。

```python
#-*- coding:utf-8 -*-
import frida
import sys
 
def on_message(message, data):
    if message['type'] == 'send':
        base = message['payload']['base']
        size = int(message['payload']['size'])
        print(hex(base), size)
    elif message['type'] == 'error':
        for i in message:
            if i == "type":
                print("[*] %s" % "error:")
                continue
            if type(message[i]) is str:
                print("[*] %s" %
                      i + ":\n    {0}".format(message[i].replace('\t', '    ')))
            else:
                print("[*] %s" %
                      i + ":\n    {0}".format(message[i]))
    else:
        print(message)
    # print session
    # dex_bytes = session.read_bytes(base, size)
    # f = open("1.dex","wb")
    # f.write(dex_bytes)
    # f.close()
 
    #
 
# 9.0 arm 需要拦截　_ZN3art13DexFileLoader10OpenCommonEPKhjS2_jRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE
# 7.0 arm：_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_
 
package = "com.hello.qqc"
print( "dex 导出目录为: /data/data/%s"%(package))
device = frida.get_usb_device()
pid = device.spawn(package)
session = device.attach(pid)
src = """
var exports = Module.enumerateExportsSync("libart.so");
    for(var i=0;i<exports.length;i++){
        if(exports[i].name == "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"){
            var openMemory = new NativePointer(exports[i].address);
            }
     }
 
Interceptor.attach(openMemory, {
    onEnter: function (args) {
 
        var begin = args[1]
 
        console.log("magic : " + Memory.readUtf8String(begin))
 
        var address = parseInt(begin,16) + 0x20
 
        var dex_size = Memory.readInt(ptr(address))
 
        console.log("dex_size :" + dex_size)
 
        var file = new File("/data/data/%s/" + dex_size + ".dex", "wb")
        file.write(Memory.readByteArray(begin, dex_size))
        file.flush()
        file.close()
 
        var send_data = {}
        send_data.base = parseInt(begin,16)
        send_data.size = dex_size
        send(send_data)
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
        }
    }
});
"""%(package)
 
script = session.create_script(src)
 
script.on("message" , on_message)
 
script.load()
device.resume(pid)
sys.stdin.read()
```

要提一下的是我这里的环境是 夜神模拟器 Android 7.1.2 版本，其他的安卓版本可能跑不了这个脚本，需要进行修改或者找其他的 hook 点，比如 Android 8.1 版本的可以去 hook OpenCommon 函数，再比如Android 9.0 的 OpenMemroy 的参数不一样，arg[1] 不是 dex 的内存地址，是 dex 的大小等等。这些问题如果碰到的话，就需要自己去探索原理解决了，上篇帖子的评论区的一些讨论很有参考价值，如果不熟悉或者碰到 的话可以去看一下。

## 脱壳后重打包

现在我们成功脱壳，并且可以在 `/data/data/com.hello.qqc` 目录下找到 4 个脱出来的 dex 文件，下面我们进行脱壳后的重打包操作。

 

![img](/assets/images/2020-05-12/802108_72FGZME9QSMZ47D.png)

 

![img](/assets/images/2020-05-12/802108_53U7KZKJNMPHV9X.png)

 

首先把四个 dex 文件改名为 classes.dex，classes2.dex，classes3.dex，classes4.dex，然后替换掉原来加壳 apk 中的 classes.dex 文件。

 

然后就是修改 AndroidManifest.xml 文件中 application 节点下的 android:name 属性，原来的是 `android:name="com.SecShell.SecShell.ApplicationWrapper"`，这是梆梆壳启动的地方，现在我们需要修改为脱壳后的 dex 中继承了 Application 的类，我们搜索 `extends Appliaction`，可以找到是 `cn.net.tokyo.ccg.base.App`。

 

![img](/assets/images/2020-05-12/802108_FQ4XB7WSAMBMQKC.png)

 

![img](/assets/images/2020-05-12/802108_T2W6QB3DN4NKS5Y.png)

 

现在我们改成 `android:name="cn.net.tokyo.ccg.base.App"`，然后进行签名后安装，可以发现能够正常运行。

# 抓包

## Aes 加密

当我们尝试用 Charles 开启 https 代理然后抓包时候，发现数据被加密了。



![img](/assets/images/2020-05-12/802108_QNEXQA9REHMMQWA.png)

 

例如这个，我们注意到加密数据都是以 “d”开头的，值得注意的是第一个加密数据“d:xxxxxxxxxxxx”是在 https 请求报文头里面的，每个 https 请求的报文头都会写入一个这样的加密数据，我们猜测它是和用户的身份认证有关。像第二个和第三个加密数据就分别是请求参数和返回数据的加密了。

## 代码解密数据

我们进行分析寻找，在 `cn.net.tokyo.ccg.base.encrypt.EncryUtil` 找到加解密代码部分，可以发现是 Aes 加密，key 和 iv 也能找到。

 

![img](/assets/images/2020-05-12/802108_XVKKNPQJYCRBWW2.png)

 

![img](/assets/images/2020-05-12/802108_QCEZ3BBDGR4GT7X.png)

 

![img](/assets/images/2020-05-12/802108_BCEJXDG2CNK65K9.png)

 

我们可以写出 Aes 解密的 Java 代码来解密我们想要解密的数据，代码如下，我们先来解密一下刚才我们好奇的每个 https 请求的报文头都写入的加密数据是什么。

```java
package AesDecrypt;
 
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.util.Base64;
 
public class EncryUtil {
 
    public static void main(String []args) throws Exception {
        String str ="suh8B7nUE/BRq3WsTT1R7YpRKA8PfI7xAnwisnYUT2I/Agp8iMWbc7ihFNosWg7oqn/g5Zw/fPqxTUjRvcO5CigHWtsR2KRL6pOTxu9IXufRGafuHOLLFU1bLOpAqW2Y0lPG5L2PjyW1tXM5ZaXs9m3wfV5nTbRWe+hcNom+1Ly2yQwiXFBBEnl5QOH78j3ow2Ho7qx5i2Gfr5fJTgb3jtmJT7qtep7FMeJoqzdotNVdiRPrG/yShHe1blD2KmK6+3CfxdzqNyvd6OcxpnS+n52LvAerjDwVA5I0Nlgxj94qZ4I0rpl99vr97Yc2lmszjICIJUPx0+/XyjjonCAZO99AklJCtgguCeQxwDKP4x86mNLB498ckcLPxFD+gARWujdeG9K3t1cGpm35rz+1SgOc0qnZA59SHmssxn50MKsYeY1t7JM8gopFO+e8EFHiqjZ19EPVq+RdnKIWrBG2DzWg7WX25d3MKg8IiqU7ZUseWwg1u/SW6ufAuuDhJva2MunqhBJNVky4E4NyzTe5jg==";
      System.out.println(decryptFromBase64(str));
    }
 
    public static String decryptFromBase64(String arg1) {
        String v0 = "UTF-8";
        try {
            Base64.Decoder decoder = Base64.getDecoder();
            return new String(decrypt( decoder.decode(arg1.getBytes())), v0);
        }
        catch(UnsupportedEncodingException v1) {
            throw new RuntimeException("decrypt fail!", ((Throwable)v1));
        }
    }
    public static byte[] decrypt(byte[] arg3) {
        String v0 = "AES";
 
        byte[] arg4 = "xPxo2S5uGPhKHx5g".getBytes();
        byte[] arg5 = "0a1b2c3d4e5f6789".getBytes();
        if(arg4.length == 16) {
            try {
                SecretKeySpec v1 = new SecretKeySpec(new SecretKeySpec(arg4, v0).getEncoded(), v0);
                Cipher v4 = Cipher.getInstance("AES/CBC/PKCS5Padding");
                v4.init(2, ((Key)v1), new IvParameterSpec(arg5));
                return v4.doFinal(arg3);
            }
            catch(Exception v3) {
                v3.printStackTrace();
                throw new RuntimeException("decrypt fail!", ((Throwable)v3));
            }
        }
 
        throw new RuntimeException("Invalid AES key length (must be 16 bytes)");
    }
}
```

解密的结果是

```
{"Connection":"close","app":"3","platform":"1","s":"cd551ab25dc5c0e93def7b9bd42df473","t":"22430220186106","token":"LzF2SHp6NldrVmVBaHFobmVMVys3RFZ3VkxVRnFMYSs4akRYUGlrRnlLL05lTXBPblp6YUJVekxxTjBERG9xNktDVzRackxhY3hCeTdyaWdsVDMyejMxa05oQmVLa2l0UDU4NjZLSWlzN0YzRzZ0V2dDWnM1UmFsbUxGSnNVUW1XWlYvMnp0SldvWUNJKzFjdHlvbFo0c2VYcHMyMERreWFOMUt6b1d0enVpWno1QnIxcXI4TWY2NGQ4NVZpdlVF","version":"1.2.5"}
```

 

可以看到有个 `token`，让我们记住它。

## frida 进行模拟抓包

同时我们还可以使用 frida 来模拟抓包，当我们在寻找 hook 点时候，会发现这个 App 发送请求和接收数据的地方也要比上个帖子中的 App 复杂很多。

### hook 请求

分析过程发现请求都被很规范地被封装到了接口类 `cn.net.tokyo.ccg.dagger.Apis` 中，

 

![img](/assets/images/2020-05-12/802108_H4W8GD6WN3C82HF.png)

 

不断地寻找 hook 点，我们在 `cn.net.tokyo.ccg.dagger.module.ApiModule` 类中找到了 https 请求封装的地方，

 

![img](/assets/images/2020-05-12/802108_GPKT6WTPF2WPQP4.png)

 

这里我们可以看到熟悉的字符串，就是刚才我们解密的每个 https 请求的报文头都写入的数据，里面的 token 尤其显眼。我们把这里作为打印请求数据的一个 hook 点，hook `static Response a(Interceptor$Chain arg1)`，
在hook函数时候主动调用传入参数的方法`arg1.request().url().toString()`，即可打印出请求 url。然后在 Aes 加密的地方作为另一个 hook 点，可以打印出加密的请求数据。

```javascript
var ApiModule = Java.use("cn.net.tokyo.ccg.dagger.module.ApiModule");
ApiModule.a.overload('okhttp3.Interceptor$Chain').implementation = function(arg1){
    send("发送请求**********************************************")
    send("request_url："+arg1.request().url().toString());
    return this.a(arg1);
}
 
var EncryUtil = Java.use("cn.net.tokyo.ccg.base.encrypt.EncryUtil")
var GsonTools = Java.use("cn.net.tokyo.ccg.base.helper.GsonTools")
EncryUtil.encryptAes.overload("java.util.Map").implementation = function(arg1){
    send("请求加密数据：")
    send(GsonTools.createGsonString(arg1));
    return this.encryptAes(arg1);
}
```

### hook 数据接收

不断寻找，数据接收的 hook 点我们选择在 “cn.net.tokyo.ccg.dagger.MoreBaseUrlInterceptor”类中的 intercept 方法，它的参数一是相应报文的一些信息，我们同样可以打印出来。

```javascript
var MoreBaseUrlInterceptor = Java.use("cn.net.tokyo.ccg.dagger.MoreBaseUrlInterceptor");
MoreBaseUrlInterceptor.getResponseString.implementation = function(arg1){
    var result = this.getResponseString(arg1);
    send("接收数据**********************************************");
    send(""+ arg1);
    send(result)
    return result;
}
```

### 效果

比如我们注册一个账号，抓包效果如图。

 

![img](/assets/images/2020-05-12/802108_4UPHXVYS3T4V44G.png)

 

![img](/assets/images/2020-05-12/802108_WQRKWF5ZQFDTW92.png)

# token 验证

## hook 修改的失败与 token 验证

在开始的时候说到，一般的破解思路首先是尝试内购破解，修改本地的 App 端数据然后更新到服务器，按着这个来的话，我们首先找到存储用户信息的类“cn.net.tokyo.ccg.bean.User”，可以看到里面有很多数据，并且有相应的 getXxx（）和 SetXxx（）方法。

 

![img](/assets/images/2020-05-12/802108_BV9DM5ECD9TDY3Q.png)

 

然后当我们尝试 hook 去修改 is_vip 和 view_limit_today，也就是 vip 和 每天限制观看次数，发现修改没有作用，观看后还是弹出窗口提示观看次数已看完让充值 vip。

 

![img](/assets/images/2020-05-12/802108_QPSVXZVGMC5AKCV.png)

 

问题出在哪里了呢，我们在 App 内部尝试搜索这些字符串，没有搜索结果，说明可能是服务器返回的，那就抓包看一下，当弹出这个窗口时候发生了什么。

 

![img](/assets/images/2020-05-12/802108_Q3NVQ3QQX398R7J.png)

 

![img](/assets/images/2020-05-12/802108_QKDCRR69S7GKNEZ.png)

 

![img](/assets/images/2020-05-12/802108_EJ4HB6E3WSBKW3W.png)

 

可以看到弹出窗口中的字符串确实是服务器返回的，那么服务器是通过什么来知道用户观看次数已经用完了呢？

 

我们观察附近的请求的参数，能够判断服务器是通过 token 来知道用户观看的次数，不仅是观看次数，用户的各种信息如是否是 vip 服务器都能通过 token 确认，所以现在问题清晰了，由于服务器存在 token 验证，所以一般的内购破解思路是不起效果的。

## token 及其他一些数据的存储—— SPHelper

现在我们就具体分析下 token，首先我们找到一处获得 token 的地方作为一个点开始分析，以“cn.net.tokyo.ccg.dagger.module.ApiModule”为例。

 

![img](/assets/images/2020-05-12/802108_ZUKFAN3JXPQ8WX9.png)

 

我们可以看到用到了 SPHelper 类中的 getString（）方法，我们具体看下。

 

![img](/assets/images/2020-05-12/802108_A6CY6BEMU9TWVDU.png)

 

可以看到最终调用的是 getSharedPreferences（）方法，也就是从本地存储的数据中获取的，同时我们还可以看到 SPHelper 类中还有着其他的一些数据存储方法。

 

![img](/assets/images/2020-05-12/802108_673VD7B9NNCZKCQ.png)

 

作为验证，我们去本地文件查看一下，打开“/data/data/com.hello.qqc/shared_prefs/config.xml”文件，我们可以看到，不仅是 token，其他很多信息也都存储在了这个文件里面，我们需要着重关注的就是 token 和 key_uuid。

 

![img](/assets/images/2020-05-12/802108_M4AHCHAK68SEFF8.png)

## token 的获取—— bootstrap 请求与 android_id

现在已经知道 token 是怎么在本地存储的了，然后就是继续分析寻找 tokne 是怎么获取的了，既然 token 肯定是服务器返回的，那么我们就从抓包入手。

 

![img](/assets/images/2020-05-12/802108_36FCN9DEUP9VFGP.png)

 

![img](/assets/images/2020-05-12/802108_NEBBRF2VPMHQJH4.png)

 

![img](/assets/images/2020-05-12/802108_CHQC9CJKZ9GX6EA.png)

 

我们可以看到了这里服务器返回了 token，这条请求的 url 是 https://jk.py49ri..com/api/v2/bootstrap，并且能够看到请求的一些参数，然后我们可以在 App 中搜索这些参数来定位相关代码处。

 

![img](/assets/images/2020-05-12/802108_J6YNEWCZD8SRN2R.png)

 

然后我们要做什么呢，需要确定是请求中的什么参数影响了服务器返回了 token，观察可以发现 android_id、deviceid 和 mac_address 是一个东西， 而 device_uuid 呢，分析代码可以知道最后也是要有 android_id 影响生成的。

 

![img](/assets/images/2020-05-12/802108_94C6V7EVTTF3NWM.png)

 

![img](/assets/images/2020-05-12/802108_X66EAHNKDX74AQM.png)

 

所以我们现在可以初步判断 token 是由 android_id 生成的。

# 对抗 token 验证

## 对抗思路——“无限 token”

当我们发现服务器会进行 token 验证的时候，可能会觉得很棘手，因为这意味在本地的修改似乎没什么用了，像 vip 除了掏真金白银去购买让服务器认可这个 token 是 vip，好像没什么别的办法了。

 

但是，如果根据我们前面的分析仔细思考下的话，可以发现是有对抗思路的，既然 token 是由每台设备的 android_id 得到的，而每台设备的都有唯一的一个 android_id，并且每天都能免费观看一次，那么我们是不是可以对 app 进行修改，每看完一个视频，就可以产生一个新的随机的 android_id，然后获得一个新的 token，就可以继续观看视频了，这样我们相当于有了无数多的 token 了。

## 添加生成随机 android_id 的 smali 代码

现在按着上面的对抗思路来行动，我们需要每次观看一个视频就要要重新生成一个新的随机的 android_id，可以选择在 App 中添加一些新的 smali 代码然后调用。

 

首先用 Java 写一个生成16位十六进制的随机数的类。

```
package fingerprint.me;
 
public class getRandomDeviceId {
    public static String getString(){
        String str = "";
        for (int i = 0; i < 16; i++) {
            char temp = 0;
            int key = (int) (Math.random() * 2);
            switch (key) {
                case 0:
                    temp = (char) (Math.random() * 10 + 48);//产生随机数字
                    break;
                case 1:
                    temp = (char) (Math.random() * 6 + 'a');//产生a-f
                    break;
                default:
                    break;
            }
            str = str + temp;
        }
        return str;
    }
}
```

然后我们编译得到相应的 smali 代码。

```
.class public Lfingerprint/me/getRandomDeviceId;
.super Ljava/lang/Object;
.source "getRandomDeviceId.java"
 
 
# direct methods
.method public constructor <init>()V
    .registers 1
 
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
 
    return-void
.end method
 
.method public static getString()Ljava/lang/String;
    .registers 8
 
    .line 5
    const-string v0, ""
 
    .line 6
    .local v0, "str":Ljava/lang/String;
    const/4 v1, 0x0
 
    .local v1, "i":I
    :goto_3
    const/16 v2, 0x10
 
    if-ge v1, v2, :cond_48
 
    .line 7
    const/4 v2, 0x0
 
    .line 8
    .local v2, "temp":C
    invoke-static {}, Ljava/lang/Math;->random()D
 
    move-result-wide v3
 
    const-wide/high16 v5, 0x4000000000000000L  # 2.0
 
    mul-double v3, v3, v5
 
    double-to-int v3, v3
 
    .line 9
    .local v3, "key":I
    if-eqz v3, :cond_28
 
    const/4 v4, 0x1
 
    if-eq v3, v4, :cond_17
 
    goto :goto_36
 
    .line 14
    :cond_17
    invoke-static {}, Ljava/lang/Math;->random()D
 
    move-result-wide v4
 
    const-wide/high16 v6, 0x4018000000000000L  # 6.0
 
    mul-double v4, v4, v6
 
    const-wide v6, 0x4058400000000000L  # 97.0
 
    add-double/2addr v4, v6
 
    double-to-int v4, v4
 
    int-to-char v2, v4
 
    .line 15
    goto :goto_36
 
    .line 11
    :cond_28
    invoke-static {}, Ljava/lang/Math;->random()D
 
    move-result-wide v4
 
    const-wide/high16 v6, 0x4024000000000000L  # 10.0
 
    mul-double v4, v4, v6
 
    const-wide/high16 v6, 0x4048000000000000L  # 48.0
 
    add-double/2addr v4, v6
 
    double-to-int v4, v4
 
    int-to-char v2, v4
 
    .line 12
    nop
 
    .line 19
    :goto_36
    new-instance v4, Ljava/lang/StringBuilder;
 
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V
 
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
 
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
 
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
 
    move-result-object v0
 
    .line 6
    .end local v2  # "temp":C
    .end local v3  # "key":I
    add-int/lit8 v1, v1, 0x1
 
    goto :goto_3
 
    .line 21
    .end local v1  # "i":I
    :cond_48
    return-object v0
.end method
```

然后我们向有着代码逻辑的 dex 文件中添加新的类。

 

![img](/assets/images/2020-05-12/802108_KASNY2TENFFNW4M.png)

 

![img](/assets/images/2020-05-12/802108_XYVP7XZAYE5Z8Z5.png)

 

然后我们将 “cn/net/tokyo/ccg/base/helper/DeviceHelper”类中的 getDeviceID 方法的 smali 代码替换成调用我们加入的“fingerprint.me.getRandomDeviceId”类中的 getString（）方法的 smali 代码。

```
.method public static getDeviceID(Landroid/content/Context;)Ljava/lang/String;
    .registers 2
 
    invoke-static {}, Lfingerprint/me/getRandomDeviceId;->getString()Ljava/lang/String;
 
    move-result-object p0
 
    return-object p0
.end method
```

![img](/assets/images/2020-05-12/802108_6FAHU8Y6A7QCWU3.png)

## 请求 token 的逻辑

好了，现在我们已经完成了第一步，能够生成随机的 android_id 了，然后我们需要思考就是怎么在观看一部视频前或者观看后根据随机生成的 android_id 主动请求一个新的 token，我们先看请求 token 的逻辑。

 

前面我们已经找到了 bootstrap 请求的相关代码，在“cn.net.tokyo.ccg.util.f”类中的 a 方法，我们从这个点往回溯源寻找调用，先是“b.a.a.a.d.a.m0”类中 h 方法，最后是“cn.net.tokyo.ccg.ui.activity.MainActivity”类中的 onEventReceived 方法。

 

![img](/assets/images/2020-05-12/802108_TVF3PVD3Z5YUAQ8.png)

 

![img](/assets/images/2020-05-12/802108_2BKYP4FNNWGMZH3.png)

 

也就是说请求 token 的逻辑是 onEventReceived 方法接收一个 TaskEvent 并且 action 属性的值是 401，这样就好办了，我们对 TaskEvent 进行交叉索引，然后找到一处发送 TaskEvent 的代码进行观察。

 

![img](/assets/images/2020-05-12/802108_MWY686N8PQTE672.png)
现在问题变得很简单了，我们已经知道怎么发送 TaskEvent 了，是通过 “org.greenrobot.eventbus.c.c().b()”方法来进行的，相应的 smali 代码我们也可以很容易写出来，并提供给我们进行主动调用。

```
new-instance v1, Lcn/net/tokyo/ccg/base/Event$TaskEvent;
 
   invoke-direct {v1}, Lcn/net/tokyo/ccg/base/Event$TaskEvent;-><init>()V
 
   const/16 v2, 401
 
   iput v2, v1, Lcn/net/tokyo/ccg/base/Event$TaskEvent;->action:I
 
   invoke-static {}, Lorg/greenrobot/eventbus/c;->c()Lorg/greenrobot/eventbus/c;
 
   move-result-object v2
 
   invoke-virtual {v2, v1}, Lorg/greenrobot/eventbus/c;->b(Ljava/lang/Object;)V
```

## 在 Activity 生命周期主动更新 token

然后差不多大功告成了，我们只剩下找到合适的点根据随机生成的 android_id 主动请求一个新的 token，以达到我们点击一部视频就能观看的目的，经过分析后选择在视频播放的 VideoDetailActivity 的生命周期中的 onPause（） 和 onDestory（）开头添加 smali 代码进行主动请求新的 token，然后需要注意的就是我们需要在请求新的 token 前，把本地存储文件也就是“/data/data/com.hello.qqc/shared_prefs/config.xml”中的 “token”给清空，“key_uuid”也给写入一个随机生成的16位十六进制字符串，以及在添加 smali 代码后注意修改寄存器数量，也就是 .registers，不然如果数量不够的重编译打包签名后运行，程序可能会崩溃，添加的 smali 代码如下。

```
const-string v0, "token"
 
    const-string v1, ""
 
    invoke-static {p0, v0, v1}, Lcn/net/tokyo/ccg/base/helper/SPHelper;->saveString(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
 
    const-string v0, "key_uuid"
 
    invoke-static {}, Lfingerprint/me/getRandomDeviceId;->getString()Ljava/lang/String;
 
    move-result-object v1
 
    invoke-static {p0, v0, v1}, Lcn/net/tokyo/ccg/base/helper/SPHelper;->saveString(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V
 
    new-instance v1, Lcn/net/tokyo/ccg/base/Event$TaskEvent;
 
    invoke-direct {v1}, Lcn/net/tokyo/ccg/base/Event$TaskEvent;-><init>()V
 
    const/16 v2, 0x191
 
    iput v2, v1, Lcn/net/tokyo/ccg/base/Event$TaskEvent;->action:I
 
    invoke-static {}, Lorg/greenrobot/eventbus/c;->c()Lorg/greenrobot/eventbus/c;
 
    move-result-object v2
 
    invoke-virtual {v2, v1}, Lorg/greenrobot/eventbus/c;->b(Ljava/lang/Object;)V
```

添加完 smali 代码后我们重编译打包签名，然后就算完工了，这时候就可以不限次数观看视频了，广告和弹窗也是可以自行去掉的。

# 后记

需要说一下的是，这个 app 下载之后可能会被杀毒软件杀掉，分析过程中没有看到什么可疑的地方，用某安全卫士查了下，具体原因是“包含插件：Riskware.Cloud.Generic.558926 该软件存在危险行为代码，警惕该软件私自下载安装软件，窃取用户隐私信息，造成用户隐私泄露资费消耗。”，应该不算木马，如果想尝试分析下的话，务必在模拟器或其他沙盒环境下进行。

 

完整的分析案例总是可遇不可求的，事无巨细地写这么多分享出来，希望能帮助到像我一样正在学习的人学到一些有用的东西，就像我在论坛上跟着很多优秀的帖子学习到了很多那样，当然如果能点个赞就更好了（逃