---
author: 0x指纹
date: 2020-04-12 08:00+08:00
layout: post
title: "记一次 frida 实战"
mathjax: true
categories:
- 逆向工程
tags:
- android
- frida
---

* content
{:toc}

frida 是一个十分强大的工具，已经学习它有一段时间了，但也只是零零碎碎的练习与使用。最近在对一个 APP 进行分析的过程中，使用 frida 完成了脱壳、hook 破解、模拟抓包、协议分析的操作，可以说是一条龙服务了， 感觉十分有意义，学到了很多，对 frida 的理解和掌握程度也提高了不少，记录下来这次实战分享给各位正在学习 frida 的看雪用户。（在看雪上论坛水了这么久，也该反馈些东西了，逃


frida 入门这里就不多说了，论坛已经有很多优秀的入门帖子了，我也是看着这些帖子一点一点学习的。不过提一下我在安装时候踩的坑，当时折腾很久也安装不上心态被搞得有点爆炸。。







开始 python3.7 直接 `pip install frida` 和 `pip install frida-tools`一直卡在 `Running setup.py install for frida ... –` 了，最后的解决好的办法是到 [https://pypi.org/project/frida/#files](https://pypi.org/project/frida/#files) 下载 frida-xx.x.xx-py3.7-win-amd64.egg，并把它放到安装的python目录的 `\Python37\Lib\site-packages` 中。


然后找到对应的 frida-tools 版本`pip3 install frida-tools`执行即可安装，如果不对应，执行命令可能会把`frida-xx.x.xx-py3.7-win-amd64.egg`删掉又卡在`Running setup.py install for frida ... –`地方，可以根据发布日期来判断相应的 frida-tools 版本。

然后 python3.7 安装 easy_install，执行`easy_install frida-xx.x.xx-py3.7-win-amd64.egg`，即可在 python 中 import frida了。

# App 简单分析

这是一个视频播放的 APP，里面有着各种卫视和CCTV的在线播放，其他栏中是一些新闻栏目和电影。

 

这些都是免费播放的，但是我们注意到了右上角的“积分：0”字样，说明情况不简单，我们点开个人栏，查看发现“在线吧”、“在线吧2”里面需要积分消费才能进去。



而成人台里面又有一系列的栏目，每个进去都需要积分消费，点进去后会发现每个栏目里面都有一堆不可描述、胡里花哨、不符合核心价值观的影片或者直播分类，说明这是一个邪恶的APP。



在获取积分里面，可以购买 Vip 和 积分。

 

![img](/assets/images/2020-04-12/802108_PPJ9KUNCBEW942E.png)

 

然后经过简单测试发现加了 360 壳，并且使用 Charles抓不到包，我们先使用 firda 脱壳拿到 DEX 文件，抓包问题后面再解决。

# 脱壳

既然是 frida 的一条龙服务，我们尝试用 frida 来进行脱壳，这里我们直接使用 [frida-unpack](https://github.com/dstmath/frida-unpack)。

## 关于frida-unpack

firda-unpack 原理是利用frida hook libart.so中的OpenMemory方法，拿到内存中dex的地址，计算出dex文件的大小，从内存中将dex导出，我们可以查看项目中的 OpenMemory.js 文件中的代码更清晰直观地了解。

```javascript
'use strict';
/**
 * 此脚本在以下环境测试通过
 * android os: 7.1.2 32bit  (64位可能要改OpenMemory的签名)
 * legu: libshella-2.8.so
 * 360:libjiagu.so
 */
Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"), {
    onEnter: function (args) {
 
        //dex起始位置
        var begin = args[1]
        //打印magic
        console.log("magic : " + Memory.readUtf8String(begin))
        //dex fileSize 地址
        var address = parseInt(begin,16) + 0x20
        //dex 大小
        var dex_size = Memory.readInt(ptr(address))
 
        console.log("dex_size :" + dex_size)
        //dump dex 到/data/data/pkg/目录下
        var file = new File("/data/data/xxx.xxx.xxx/" + dex_size + ".dex", "wb")
        file.write(Memory.readByteArray(begin, dex_size))
        file.flush()
        file.close()
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            /* do something */
        }
    }
});
```

## frida-unpack 使用报错及解决方案

### 使用

firda-unpack 的使用方法在项目的 README.md 中，其中查看 `OpenMemory` 的导出名称，我们在 `/system/lib` 中找到 libart.so 后，还可以拖进 IDA 然后在 Exports 窗口搜索到后点击查看。

 

![img](/assets/images/2020-04-12/802108_MMQXRCNCNA4HQZU.png)

 

![img](/assets/images/2020-04-12/802108_4CDMVXFX6QY7Y4M.png)

 

虽然怎么操作在项目中的 README.md 写得十分简单易懂，如果上手就能直接脱壳最好，但是我在使用的时候还是出现了错误。。

 

这里详细说下我的碰到的报错和解决方案。

### KeyError 报错

首先我直接运行出现的错误是 `KeyError: 'payload'`，查看错误的代码行。

 

![img](/assets/images/2020-04-12/802108_MFTUH8BRATEZW36.png)

 

![img](/assets/images/2020-04-12/802108_7ZG4HSUZZDT22VC.png)

 

报错提示没有 'payload' 这个 key，我们加上一句 `print(mesaage)` 把 message 值打印出来，发现 message 是一个字典，里面确实没有 'payload' 这个key，并且可以看到类型是 'error'。

```
{'type': 'error', 'description': "TypeError: cannot read property 'readU8' of null", 'stack': "TypeError: cannot read property 'readU8' of null\n at [anon] (../../../frida-gum/bindings/gumjs/duktape.c:56648)\n at frida/runtime/core.js:386\n at /script1.js:29", 'fileName': '/_frida.js', 'lineNumber': 1480, 'columnNumber': 1}
```

 

我们重新写一个 on_message 即可。

```python
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
```

### readU8 报错

运行发现这个报错的问题解决了，但是又出现了新的问题。

 

![img](/assets/images/2020-04-12/802108_AJA8VNZR5HNR3JZ.png)

 

不清楚是为什么，而且报错行数是 js 代码的最后一行，对报错进行搜索在 [frida hook so问题](https://bbs.pediy.com/thread-250815.htm) 这个帖子里面看到一个大佬说
用 Module.getExportByName 替换 Module.findExportByName 就会得到具体的报错原因了，尝试在 js 代码中替换发现果然有更具体的报错原因了，感谢大佬。。


![img](/assets/images/2020-04-12/802108_Y367KKWEWA45PKZ.png)

 

可以看到错误是因为在 libart.so 中不能通过 OpenMemory 的导出函数名找到它，这个十分奇怪，我们再写个 frida 脚本把内存中 liart.so 的导出函数名和地址都打印出来看看有没有 OpenMemory的。

```python
import frida
import sys
 
jscode = """
 
  var exports = Module.enumerateExportsSync("libart.so");
    for(var i=0;i<exports.length;i++){
        send("name:"+exports[i].name+"  address:"+exports[i].address);
     }
 
"""
 
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
 
process = frida.get_usb_device().attach("com.cz.babySister") 
script = process.create_script(jscode) 
script.on('message', on_message) 
script.load() 
sys.stdin.read()
```

我们发现是有的，这就十分让人迷惑了，只能想想别的办法了解决。。

 

![img](/assets/images/2020-04-12/802108_6ZPKX6RSBHER525.png)

### 修改代码

我们可以看到是由 OpenMemory 函数的地址的，因此想到尝试下直接 hook 这个地址会怎么样，需要先使用 new NativePointer 转换一下，试了是可行的，十分感动。。

 

这里直接放出修改后的 OpenMemory.js 代码。

```python
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
```

## 顺利脱壳

我们重新运行，非常激动地发现 frida-unpack 运行成功了。

 

![img](/assets/images/2020-04-12/802108_2KSQ9K2JFTCQANH.png)

 

去对应的文件目录查看，可以看到被脱掉后的两个 dex 文件。

 

![img](/assets/images/2020-04-12/802108_5F5FGWJGHSFHGKU.png)

 

都拖进 JEB 中看下，发现 APP 的逻辑代码都在 5619552.dex 中了，至此第一步脱壳完成。

# Hook 进行破解

有了反编译的代码后相信各位破解积分和 vip 充值是手到擒来了，不然都不好意思在看雪吱声了，这里只简单说下我一般的处理思路和方法，如果不行就要具体情况具体分析了。

 

我通常都会先在有使用到用户数据的 activity 中查看下代码，看有没有导入 UserInfo 这种类，然后如果有的话直接找到这个类，积分、vip、到期时间等等这些一般都会有相应的 getXxx（） 和 setXxx（）方法，然后就可以随意 hook了。

## 积分

![img](/assets/images/2020-04-12/802108_N24GWG795G3MGG4.png)

 

直接上相应的 js 代码，逻辑就是 hook 住 UserInfo 类中 getJifen（）方法，然后随便设置返回积分。

```javascript
var userinfo = Java.use("com.cz.babySister.javabean.UserInfo");
userinfo.getJifen.implementation  = function(){   
    return "100000";
}
```

![img](/assets/images/2020-04-12/802108_X6WSDCJCSYBRAY6.png)

 

值得一提的是，hook 后在测试过程中发现本地修改的数据会上传到服务器，因为发现换一个模拟器登录账号积分还是那么多，这个在后面的模拟抓包中会具体看下怎么回事。

## vip

破解 vip 时候发现尝试 hook getIsvip（） 和 setIsvip（）没有效果，猜测应该是内购之后向服务器进行请求成为 vip 用户，然后服务器返回自己账号 vip 用户数据，我们现在换下思路破解 vip，就是经常看到的破解内购。

 

![img](/assets/images/2020-04-12/802108_44WJDQ2BZTJ8BKS.png)

 

破解内购应该也都是看雪用户的起手水平了，这个分析过程也不多说了，直接上 js 代码。

```javascript
var pay = Java.use("com.cz.babySister.alipay.q");
pay.b.implementation = function(){    return "9000"}
```

逻辑就是把支付时候下面的代码的支付失败流程变成支付成功流程，然后就会向服务器发送购买类型的请求。

 

![img](/assets/images/2020-04-12/802108_R6G9XNXC28VYTWA.png)

 

这样 hook 之后购买积分也是可以的。

 

![img](/assets/images/2020-04-12/802108_HNFN4245WAS2FCV.png)

## android_id

android_id 是在设备首次启动时，系统随机生成的一个64位的数字，并把这个数字以16进制字符串的形式保存下来，这个16进制的字符串就是 android_id，当设备被wipe后该值会被重置。

 

但是为我们什么要 hook 这个呢，是因为因为我测试了两个账号都被封了。。没错，就是被封了，而且被封后我发现重新注册的号就不能看那些不可描述的视频和直播了，但是换一个模拟器登录新注册的账号就又可以看了。

 

因为使用的模拟器配置了 frida 和 Charles 环境及安装了别的分析工具，不想再换个模拟器重新配置了，就找了下为什么不能看了。在写出模拟抓包代码打印出注册账号的请求后，发现了原因，注册请求上传的一个参数是 memi1，找到对应 Java 代码赋值处溯源了下发现是获取的是 android_id，当账号被封后带有这个用户注册所用安卓机的 android_id 的请求都不会被处理，这也就是为什么重新注册账号后不能再看不可描述的东西了。

 

![img](/assets/images/2020-04-12/802108_38V4TQUNGYWRUWU.png)

 

这个时候 hook 了一下返回 android_id 字符串的函数，随便改一下，然后这个模拟器就能重新用了。

 

直接上 js 代码，要提一下的就是，Secure 类是 android.provider.Settings 的一个内部类，我们要 hook 的 getString（）方法在 Secure 类中，hook 类时候写成“ Java.use("android.provider.Settings$Secure"就不会报错。

```javascript
var sec = Java.use("android.provider.Settings$Secure");
sec.getString.implementation = function(arg1,arg2){
    return "5c80b60fc1f73307";
}
```

运行之后，模拟器登录后就又可以重新看了。

# 模拟抓包

## Charles 抓不到包的原因

在开始 APP 分析时候我们提到使用 Charles 抓不到包，设置了 SSL 代理也没有用，当我们反编译分析脱壳后的dex找到构造请求的地方时，发现了真相，和 SSL 没有关系，是因 openConnection(Proxy.NO_PROXY)
，更详细的可以看这篇文章 [Android 开发之避免被第三方使用代理抓包](https://www.cnblogs.com/c-x-a/p/9174663.html)。

 

![img](/assets/images/2020-04-12/802108_8D9GHPSBHTCDECX.png)

## 模拟抓包

使用 Charles 抓不到包怎么办呢，我们有 frida！可以通过 frida 来 hook 住 APP 构造网络请求和接收数据地方的代码，然后打印出来请求和返回数据，这样 APP 向服务器进行的网络请求和接收的数据便一览无余了。

 

一般网络请求和接收数据的代码都会写在一个类中，我们只要找到一个点来追踪去找到这个类就可以了。

 

我们将 LoginActivity 作为这个点，也就是登录界面的 activity 的代码中找到获取用户账号和密码的地方，然后通过 JEB 的交叉索引功能进行分析追踪，可以找到网络请求的地方都在一个类中，并且请求的方法有三个。

 

![img](/assets/images/2020-04-12/802108_HUBJY7SWXE7UTBE.png)

 

![img](/assets/images/2020-04-12/802108_YM4MS2VJ5Z6K3VQ.png)

 

![img](/assets/images/2020-04-12/802108_D2VK6EVYF8PVBCH.png)

 

可以看到都使用了openConnection(Proxy.NO_PROXY)，Charles 当然抓不到包，每个方法传入的参数即是网络请求，返回的参数是接收的数据，然后我们通过 frida 来 hook 住这三个方法打印出来。

 

直接放上 js 代码。

```javascript
Java.perform(function(){
 
    /*
    * 模拟抓包
    */
 
    var client = Java.use("com.cz.babySister.c.a")
    client.a.overload("java.lang.String","java.lang.String").implementation = function(arg1,arg2){
        send("抓包**********************************************")
        send("request_url："+arg1+arg2);
        var response_data1 = this.a(arg1,arg2);
        send("response_data：");
        send(response_data1)
        return response_data1;
    }
 
 
    client.a.overload("java.lang.String").implementation = function(arg1){
        send("抓包**********************************************")
        send("request_url："+arg1);
        var response_data2 = this.a(arg1);
        send("response_data：");
        send(response_data2)
        return response_data2;
    }
 
     client.b.overload("java.lang.String").implementation = function(arg1){
        send("抓包**********************************************")
        send("request_url："+arg1);
        var response_data3 = this.b(arg1);
        send("response_data：");
        send(response_data3)
        return response_data3;
    }
```

需要提下的是有些返回的是一行 json 数据，我们可以在 on_message 函数里面解析一下把它优雅地打印出来，还有就是有些 json 解析会出错，on_message 函数定义如下。

```python
def on_message(message, data):
    if message['type'] == 'send':
        try:
           print(json.dumps(json.loads(message['payload'].encode('utf8')), sort_keys=True, indent=4, separators=(', ', ': '), ensure_ascii=False))
        except:
            print("[*] {0}".format(message['payload']))
 
 
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
```



我们运行 frida 脚本，然后登录账号查看下效果。

 

这是登录时的网络请求和返回数据，

 

![img](/assets/images/2020-04-12/802108_SZB5ZH6M8HSG7NV.png)

 

登录后 APP 初始化过程中又会进行一些网络请求来接收各大卫视和栏目的资源信息，以及关于 APP 的信息。

 

![img](/assets/images/2020-04-12/802108_Z5NXE6ARJDW527A.png)

 

![img](/assets/images/2020-04-12/802108_52RPTNXTRJ4S65W.png)

## 使用Drony配合Charles抓包

我们可以看到 frida 完美地模拟了抓包分析的效果，就算抓不到包我们也不怕了。

 

其实针对由于 openConnection(Proxy.NO_PROXY) 引起的抓不到包问题，我们可以通过使用 Drony 来配合 Charles 来抓，Charles 和 Drony 配置的具体操作可以参考这两篇文章，[使用Charles抓包安卓模拟器（MuMu）](https://www.jianshu.com/p/1d0360e50a01)和[Drony配合Charles实现App定向抓包](https://www.jianshu.com/p/75b3ad732183)。

 

![img](/assets/images/2020-04-12/802108_XANA9DU7WCG4M45.png)

 

Drony 使用的话就是把最下面状态由 OFF 点击一下切换到 ON 就开始运行打印 Log了，我们向左滑就可以切换到 Setting 页面，配置好后开始抓包，我们来看一下 Charles 的效果。

 

抓到的登录请求和返回数据的包

 

![img](/assets/images/2020-04-12/802108_7MXQXY88HUH5YUB.png)

 

![img](/assets/images/2020-04-12/802108_C6CMMKWAY7MWN7R.png)

 

![img](/assets/images/2020-04-12/802108_75NZ33T2DXAD4DP.png)

 

经过分析可以看到我们使用 frida 来模拟抓包的效果十分好。

## firda Hook 完整代码

```python
import frida
import sys
import json
 
jscode = """
function log(){
    var Log = Java.use("android.util.Log");
    var Throwable = Java.use("java.lang.Throwable");
    console.log(Log.getStackTraceString(Throwable.$new()));
}
 
 
Java.perform(function(){
 
    /*
    * 模拟抓包
    */
    var client = Java.use("com.cz.babySister.c.a")
    client.a.overload("java.lang.String","java.lang.String").implementation = function(arg1,arg2){
        send("抓包**********************************************")
        send("request_url："+arg1+arg2);
        var response_data1 = this.a(arg1,arg2);
        send("response_data：");
        send(response_data1)
        return response_data1;
    }
 
    client.a.overload("java.lang.String").implementation = function(arg1){
        send("抓包**********************************************")
        send("request_url："+arg1);
        var response_data2 = this.a(arg1);
        send("response_data：");
        send(response_data2)
        return response_data2;
    }
 
     client.b.overload("java.lang.String").implementation = function(arg1){
        send("抓包**********************************************")
        send("request_url："+arg1);
        var response_data3 = this.b(arg1);
        send("response_data：");
        send(response_data3)
        return response_data3;
    }
 
 
    /*
    * hook UserInfo修改积分，积分修改之后消费一次积分会上传到服务器更新
    */
    var userinfo = Java.use("com.cz.babySister.javabean.UserInfo");
    userinfo.getJifen.implementation  = function(){
        return "100000";
    }
 
 
    /*
    * hook修改返回值，支付失败变成成功
    */
    var pay = Java.use("com.cz.babySister.alipay.q");
    pay.b.implementation = function(){
        return "9000"
    }
 
 
    /*
    * 修改vip会出现封号，服务器除了禁账号也会禁android_id，hook修改android_id
    */
    var sec = Java.use("android.provider.Settings$Secure")
    sec.getString.implementation = function(arg1,arg2){
        return "9774d56d682e549a"
    }
 
});
"""
 
 
def on_message(message, data):
    if message['type'] == 'send':
        try:
           print(json.dumps(json.loads(message['payload'].encode('utf8')), sort_keys=True, indent=4, separators=(', ', ': '), ensure_ascii=False))
        except:
            print("[*] {0}".format(message['payload']))
 
 
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
 
 
process = frida.get_usb_device().attach('com.cz.babySister')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

# 协议分析

当我们使用 frida 能模拟抓到清楚地看到网络请求后，协议分析也便不再话下了。一般的思路是抓包查看网络请求参数，然后在反编译的代码中搜索字符串定位相关代码，继而分析协议。

 

这里我们简单地分析下注册账号、登录账号、更新积分、注册 vip 的协议。

## 注册账号

我们注册一个账号并抓包，注册成功后查看。

 

![img](/assets/images/2020-04-12/802108_K59V9367A2GZAG9.png)

 

我们可以看到两条网络请求，注册请求就是第二条，我们分析一下参数有 name、pass、memi1、key、rightkey，我们可以找到 apk 构造请求地方的代码。

 

![img](/assets/images/2020-04-12/802108_AY574HXU8S64VWS.png)

 

前两个就是账号密码，memi1 我们前面在说过是 android_id，如果账号被封的话，这个也会一起被拉入黑名单，也就是这台设备不能再看不可描述的东西了。

 

key是什么呢，我们来看一下生成的代码，可以看出来是获取 APP 的签名，会在服务器进行验证，是对付修改 APP 二次打包的。

 

![img](/assets/images/2020-04-12/802108_5W2KKTS9R9GARQQ.png)

 

再看下 right_key 生成的代码，可以发现是获取公钥证书 X509Certificate 的序列号。

 

![img](/assets/images/2020-04-12/802108_BMZCJY24YWYHT3D.png)

 

可以发现注册账号的协议十分简单，前三个我们可以随便拟造，后两个是固定的。

## 登录账号

同理分析登录账号的请求，可以看到只是比注册请求多了一个 login 参数。

 

![img](/assets/images/2020-04-12/802108_V3EVV4H37VJ7QYU.png)

## 更新积分

在进行积分消费的时候，观察到现有积分扣除后，会向服务器发送一次积分更新请求，抓包数据如下，发现有个 time 和 sign，猜测根据 time 生成 sign，然后会在服务器进行验证。

 

![img](/assets/images/2020-04-12/802108_7J6NP46P6PNQX5F.png)

 

找到构造请求的代码处。

 

![img](/assets/images/2020-04-12/802108_5VWT5HNFTNTU5Q2.png)

 

可以看到 sign 是根据 time 生成的，我们通过交叉索引找到生成 sign 的算法，可以发现只是简单的 base64 加密。

 

![img](/assets/images/2020-04-12/802108_744W47JNEHENBJK.png)

## 注册 vip

上面我们提到怎么按破解内购的思路来 hook 改变支付逻辑，我们尝试一次并抓包。

 

![img](/assets/images/2020-04-12/802108_ADQMV6XHYP6SFYG.png)

 

可以看到第二个请求便是注册 vip，我们找到相应的代码处。

 

![img](/assets/images/2020-04-12/802108_2HUWFEY69A9HUA4.png)

 

请求参数分别是 name、endviptime、startviptime、memi1、verson、viptime、key、rightkey，十分简单。

## 写一份协议

然后很自然的，我们可以轻松地自己写一份简单地协议，尝试过程中发现 memi1 也就是 android_id 非常容易被封，需要不断更换。。以及尝试了很久写注册 vip 的请求都没有成功，可能在服务器还有别的验证。

```python
import base64
import time
 
import requests
requests.packages.urllib3.disable_warnings()
 
class tv:
    def __init__(self):
        self.root = 'http://39.108.64.125/WebRoot/superMaster/Server'
        self.memi1 = "9774d56d682e549c"
        self.rightkey = "376035775"
        self.key = "308202d5308201bda00302010202041669d9bf300d06092a864886f70d01010b0500301b310b3009060355040613023836310c300a06035504031303776569301e170d3136303731383038313935395a170d3431303731323038313935395a301b310b3009060355040613023836310c300a0603550403130377656930820122300d06092a864886f70d01010105000382010f003082010a028201010095f85892400aae03ca4ed9dcd838d162290ae8dd51939aac6ecfde8282f207c4cd9e507929a279e0a36f1e4847330cb53908c92915b2c6a93d7064be452d073a472093f7ca14f4ab68f827582fe0988e9e4bc8a6ea3b56001cbbbb760f9eec571b0bbc97392e65aaf08c686f0e2ba353896d48a37c36716239977bd0e4dd878025cab497d8164537aec9f6599eefb98577dce972a1b794e211226520e23497beec3fd8548bb5b4d263120d40115cca28116bac32378df5033f536a0d7367fef78c587fefed28c5c9b35ba684ed6e46d9369c40950cf7ad7236d10b7a51dfd2a8f218db72323bbd19f46947410b1191f263012ad4ba8f749223e37591254ee7f50203010001a321301f301d0603551d0e041604143d43284bd5e4b0d322c9962a5b70aad4dcbc3634300d06092a864886f70d01010b050003820101000f04c51ff763311aa011777ba2842b441b15c316373d1e1ed4116cf86e29d55c6ed3fa4c475251b1fb4fac57195dbca0166ebe565d9834552a3758b97c4528bab1f7ab82bb3a9faa932f5bc10943f3daf52e0fe5889ffb58a6be67ea1c9a2fb37dc8aa6f3af476039a467336991a4e52dccd520195cd473eb5b984e702ed9ff638a14c3abb575a7a80ae4062084d1138a06a20e173be9df32df631311b07352898706198ddebaaa011f0da8e5f288f7cfb77505bc943f6476d6cc1feef56b68137aad91f23c4bb772169539d05653a6f0d75f7192164e822b934322f3a975df677903b1667f5dc1e9ddb185da3281d31bfb8f67a84bd23bbcb398f8bb637dd72"
 
    def post(self, data=None):
        if data is None:
            data = {}
        return requests.post(url=self.root,data=data)
 
    def register(self, name, password):
        ret = self.post({'name': name, 'pass': password, 'memi1': self.memi1, 'key': self.key, 'rightkey': self.rightkey})
        print("Register response data: ")
        print(ret.content.decode('utf-8'))
 
 
    def login(self, name, password ):
        ret = self.post({'name': name, 'pass': password, 'memi1': self.memi1, 'key': self.key, 'rightkey': self.rightkey, 'login' : 'login'})
        print("Login response data: ")
        print(ret.content.decode('utf-8'))
 
    def updateSocre(self,name,password,jifen):
        t = int(round(time.time() * 1000))
        sign = base64.b64encode(str(5 * t).encode('utf-8')).decode('utf-8')
        ret = self.post({'name' : name, 'pass' : password, 'jifen' : jifen, 'time' : t, 'sign' : sign})
        print("UpdataScore response data: ")
        print(ret.content.decode('utf-8'))
 
if __name__ == "__main__":
    tv = tv()
    # 注册账号
    print(tv.register("mee4", "mee4"))
 
    # 登录账号
    print(tv.login("mee4","mee4"))
 
    # 更新积分
    print(tv.updateSocre("mee4","mee4","1000"))
```

# 结语

整个 frida 使用过程就是这样子，花时间整理不太容易，希望各位可以学到有用的东西能顺便点个赞就更好了（逃

------

 

更：评论区有问到 APP 要防止内购破解，可以做什么操作，简单写了些自己的看法，如果哪里有什么误解和偏见还请各位大佬指点下..

 

个人认为像这个 APP 虽然加了壳，也有根据 time 生成 sign 的算法然后把这两个值传到服务器去验证，也有获取 APP 的签名信息传到服务器防二次打包，还使用了防抓包的编程写法，但是都十分简单，一一解决起来十分容易，如果想防止内购破解，这些点都是必要的点，是都需要加强对抗的，根据木桶效应，一只水桶能装多少水取决于它最短的那块木板，APP 对抗同样也是。

 

首先是加的壳比较简单，dex 文件全部加载到内存中了轻松地可以 dump 出来，这样 APP 布置的第一道最重要的防线就没多少防护意义了，下面更是一败而溃了。

 

然后根据 time 生成 sign 的这么重要的算法不可放在 Java 层中去调用，不然反编译出来十分容易被分析出来利用构造协议，这个 APP 里面不仅放在 Java 层算法还只是简单的 base64 加密。逆过的一些防护优秀的 APP 是不加壳的，仅仅把根据 time 生成 sign 的算法放在 native 层进行对抗，分析起来难度十分大。

 

获取签名信息防二次打包这种重要的东西同样也是和生成 sign 算法一样不应该放在 Java 层的，应放在 native 层去对抗，以及获取签名的方式应该多样化，最好避免最常用的那种。

 

还有防抓包，感觉最好的解决方式还是对数据进行加密传输，加密算法放在 native 层。

 

还有反调试、防模拟器等等各种其他风险控制都要随着 APP 的防护需求去布置。

 

其实这样分析一下，很多时候不用对整个 APP 大动干戈地加壳，只需要对几个关键的点进行优雅地高强度对抗就能满足防护需求了。