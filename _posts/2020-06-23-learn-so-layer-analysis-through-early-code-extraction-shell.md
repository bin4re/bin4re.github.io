---
author: 0x指纹
date: 2020-06-23 08:00+08:00
layout: post
title: "通过一款早期代码抽取壳入门学习 so 层分析"
mathjax: true
categories:
- 逆向工程
tags:
- android
- protect
---

* content
{:toc}


文章开始需要提下的就是，在如今看雪论坛的用户一发关于安卓加固的文章动辄就是有关脱壳机、vmp、函数级指令抽取或者各大厂商的加固等技术的情况下，为何我要发一个代码抽取壳的分析，并且还是早期的那种整体抽取、整体还原回去、没有混淆、代码风格十分民风淳朴的那种壳...


原因是我开始尝试复现论坛中一些很优秀的关于 so 层的分析帖子时候，尽管很多帖子都力所能及进行了十分详细的说明，可是有些步骤我复现起来还是觉得不太理解或者有点力不从心，很多时候也是因为一些知识点和操作对大佬来说是比较简单的事情，说起来比较琐碎大佬就给一笔带过略了。

然后自己也尝试着去找一些 App 的 so 文件或者厂商加固的 App 进行分析，但是移动安全毕竟发展了这么多年，很多保护对抗技术都很成熟了，结果就是很多时候分析计划首先卡在了混淆上了...

混淆是件很头疼的事，变量函数名混淆、汇编指令的混淆、ollvm 混淆等这些都很好地阻碍了入门分析者的脚步，很多时候我们只是刚入门的新手，so 层的分析还不太熟练，壳和加固原理也没有那么的清晰，去混淆也没有那么手到擒来，很多文章能浅显的读懂但是没有碰到过一个很好的分析案例来帮我们巩固等等...一言以蔽之，段位太低了。

 

然后问题就出现了，刚入门想提高，然后去找 App 练手分析，结果一看首先就是各种胡里花哨的混淆甚至连 JNI_Onload 函数都找不到，但是想着逆向分析要有耐心，更是想到了看没几天的四哥 scz 刚发的文章 **《有技术追求的人应该去挑战那些崇山峻岭》**，里面说到：

> **“对于某些志存高远的逆向工程爱好者来说，或者对于一些永远充满好奇心的人们来说，破解如果只是拼手速，显得没劲。我要是你们，我就去剁一下Burp企业版。”。**

 








然后给自己打了打鸡血就硬着皮头去怼壳怼加固怼混淆，过了几天因为没啥进展就心灰意冷地放弃了。然后过了些时间感觉自己又可以了，给自己打了鸡血又硬着皮头去怼壳怼加固怼混淆，然后又心灰意冷地放弃...

 

这样重复了几次后我开始意识到问题，进行了深刻的反思，想到自己并没有经历安卓加固从最初开始演变的这个过程，对加固和壳的原理还都还不太熟悉，然后作为入门者一分析就去搞加固很成熟的 App 当然会处处碰壁。但是放弃是不可能放弃了，想了想还是要分析体验一下早期的壳，并以此积累 so 层的分析技术，然后我就开始大量地搜索寻找早期的加固和壳的分析了。

 

啰里啰唆说了这么多，现在回头来看一下，这个决定还是很正确的，这篇文章的代码抽取壳就是找到的一个很好的入门练手案例，以前看过的很多文章但是浅显理解的，都在这次分析过程中给加深了很多理解。以及在分析过程中不理解的努力去搜索都是可以从前人的文章中找到答案，然后再进行深入的分析，整个过程下来自己还是十分有成就感的，同时在搜索过程中也是不断接触新的知识。

 

总的来说，对这个代码抽取壳的分析中学到了太多，这也是我写这篇文章最重要的原因，分享给和我一样 so 层分析入门的新手，用一个很好的案例当作 so 层分析的敲门砖来走出困境、迷惑。

# 关于 App

App 来自一位大佬的[博客](https://blog.csdn.net/m0_37344790/article/details/79102031)，是加了腾讯御的壳，大佬在博客中进行了对反调试和脱壳的操作说明，我在找到了这篇博客和里面的 App 后进行了简单的分析后心情十分激动，因为十分适合练手分析！

 

一直以来虽然我会不少整体脱壳的操作，但是我对壳原理实现还是很感兴趣的，一直苦于找不到合适的案例，这个 App 就是极佳的练手的对象！并且开始以为这是个一代壳，后面深入分析后发现是二代抽取壳，更是学到了不少。然后很重要的一点就是这个壳几乎没有啥混淆，代码十分民风淳朴，甚至在 so 层的注释都没去掉，很利于分析，让我们把重心放在原理实现上面。

 

然后就是因为是很早的 App 了，我在 Android 8.1 真机上没有跑起来，然后大佬博客里面是用 IDA 在
dvmDexFileOpenPartial 下断脱壳的，这个是 Dalvik 虚拟机的脱壳点，所以用的应该是 Adroid 4.x 的版本。我尝试了几款 Android 4.4 模拟器 App 都没有运行成功 ，最后是在逍遥模拟器 Android 5.1.1 版本成功运行了 App。所以此文的分析是基于 IDA 7.0 和逍遥模拟器 Android 5.1.1 版本。

# 一些知识点

在开始分析壳之前让我们先了解学习一些基础知识点，虽然仅仅看着多少会觉得有点模糊，但是没关系，后面会结合具体实例分析来加深理解。

## 壳的代理 Application 机制

关于壳的一般性介绍就不多说了，我直接说下我在分析过程对壳加深理解的部分——壳的代理 Application 机制。

 

需要理解的是，壳的目的除了保护代码和对抗逆向分析，还有就是要加载目标 App 的功能 dex 文件或者指令。在这里就涉及到了一个过程，就是应用的运行环境的改变，当加壳的 App 启动后，首先运行起来的是壳的代码，整个应用的运行环境也是属于壳的，然后就引出来的一个很有趣的问题，如何进行改变应用的运行环境呢？

 

现在我们把改变应用运行环境的问题抽象一下，壳的 Application 我们称为 ProxyApplication，我们的目标应用的 Application 称为 DelegateApplication，现在问题就变成了 ProxyApplication 如何替换为 DelegateApplication，这也就是我们要说的壳的代理 Application 机制。

 

如何进行替换了就不详细分析了，在文章最后会给出前人们总结的优秀的相关学习文章和博客链接，以及在后面的分析过程也会结合壳的实现来验证这一部分，这里只简单说下替换的两大步骤。

 

首先要生成用户 Application 的实例，也就是 DelegateApplication，然后获得壳的 baseContext 进行 attach，这时候就是将控制权交给了 DelegateApplication。

 

然后就是要替换掉 API 层的所有 Application 引用，通过反射把 API 层所有保存的 ProxyApplication 对象，都替换成 DelegateApplication 对象，需要替换的部分如下：

- baseContext.mOuterContext
- baseContext.mPackageInfo.mApplication
- baseContext.mPackageInfo.mActivityThread.mInitialApplication
- baseContext.mPackageInfo.mActivityThread.mAllApplications

还有需要妥善处理的部分就是，当应用注册有 ContentProvider 时候，ContentProvider:onCreate()调用优先于Application:onCreate()。

 

当我们在学习了解这些的时候，切莫忘掉 ProxyApplication 替换为 DelegateApplication 过程中的重头戏——Classloader 和 mCookie 与内存加载 Dex 文件部分。

## ClassLoader 和 Cookie

让我们先简单地说一下 Dex 文件和 ClassLoader 的关系。

 

我们知道 App 能够运行起来一定因为是我们写的代码编译成的 Apk、Dex 文件或者是 jar 文件被安卓系统加载起来了，知道这个有助于我们理解 ClassLoader 的存在，ClassLoder 负责加载这些文件，就包括我们要重点要说的 Dex 文件。

 

需要知道的是 DexClassLoader 和 PathClassLoader，前者能够加载 jar/apk/dex，而后者只能加载系统中已经安装的 Apk 中的 Dex。两者都有共同的父类 BaseDexClassLoader，在 BaseDexClassLoader 的构造方法中，有一个核心功能的类 DexPathList，负责解析加载文件的类。

 

在 DexPathList 的构造方法中，有一个方法 makeDexElements，makeDexElements 方法判断文件后缀名是否是“dex”，如果是就调用 LoadDexFile 方法加载文件，并且返回一个 DexFile 对象。

 

而我们的 Dex 文件就是在生成这个 DexFile 对象调用它的构造方法时候，被更具体和底层地进行了加载。在 DexFile 的构造方法中调用了一个 native 方法 openDexFile。这个 native 方法返回了一个极为重要的值，让我们记住它并在不断地学习中加深对它的理解，这个值就是 cookie。

 

cookie 在 Java 层就是虚拟机的 cookie 值，在 so 层它是 pDexOrJar 指针，虚拟机在进行查找 Dex 文件中的类方法时候，都是需要对 cookie 进行操作的。

 

查找的过程是，BaseClassLoader类 的 findClass 方法，调用 DexPathList类 的 findClass 方法，然后调用刚才说到的返回的 DexFile 对象的 loadClassBinaryName 方法。在 loadClassBinaryName 方法中把查找的类方法名称、类加载器、cookie 值，作为三个参数传进了最后的 defineClass 方法，这个方法调用了 native 函数来返回一系列调用想要查找的 class。然后就是 loadClass 和 defineClass 的操作。

 

理解 cookie 有助于我们理解很多壳一系列操作的本质。

## 内存加载 Dex 文件

不知不觉已经说完了 ClassLoader 加载 Dex 文件得到 cookie 的部分，下面就开始进入到五花八门的壳各显神通的地方了，就是我们常看到的不落地加载 Dex 文件部分，也就是内存加载 Dex 文件，这一部分每种壳实现的多少都会不一样，有自己的方式，我说说我学习到和理解到的东西。

 

内存加载 Dex 文件方式的存在是因为不落地加载 Dex 文件方式的不安全性，如果我们想通过加壳来保护 Dex 文件，总会有一个时间点加载去 Dex 文件，如果直接使用 DexClassLoader 或者 PathClassLoader 去加载指定目录下解密好的 Dex 文件肯定是极度不安全的，同时也是相当于加载 Dex 文件到内存中两次，降低了效率。

 

我们当然期望用更安全和高效的方式来加载 Dex 文件，就是在内存中加载 Dex 文件。这样子首先加载到内存中的就是加密了的数据，然后在 Dex 文件加载之前进行解密即可，这样子就避免了不落地加载 Dex 文件的尴尬之处。然后需要知道的就是内存加载 Dex 文件主要是是分为 Dalvik 和 Art 虚拟机两种，两种虚拟机对应的 so 库 lidbvm.so 和 libart.so 底层实现函数是不一样的。[《Android ART运行时无缝替换Dalvik虚拟机的过程分析》](https://blog.csdn.net/luoshengyang/article/details/18006645?_t_t_t=0.4508641392433683)这篇文章可以帮我们更好地理解两种虚拟机，了解两种虚拟机加载 Dex 文件的过程则有助于我们理解内存加载 Dex 文件，同样的，我会在文末放上学习了解到的一些关于这些的很好的文章博客链接。

 

先说下这篇文章我们要分析的 App 加的壳是怎么实现内存加载 Dex 文件，然后再提下我通过搜索了解到的大佬实现和使用的方式。

### 分析的壳的实现

在开始分析这个壳的时候，我注意到它是自己自定义了一个 CustomerClassLoader，并且是继承了 PathClassLoader。

![img](/assets/images/2020-06-23/802108_X3RQ4QKF5W8NQH2.png)

 

前面我们有说到 PathClassLoader 只能加载系统中已经安装的 Apk 中的 Dex，这是一个十分迷惑人的地方，这是不是意味着我们分析的壳是落地加载 Dex 文件呢？

 

带着这个疑问开始分析壳的 so 文件，不断的分析发现壳是在 so 层调用了 Java 层 MultiDex 类的 installDexes 方法来加载两个 Dex，关于MultiDex 类后面分析中我们再具体看下。

 

然后我尝试在 MultiDex 类的 installDexes 方法处设下断点，当断点停在这里的时候，我去相应的文件夹路径去查看这两个 Dex 文件，发现这两个文件居然是空的！

 

为什么自定义的 PathClassLoader 加载了两个空的 Dex 文件，App 还能正常运行呢，开始的时候被这个问题困惑了很久。

 

在后面持续不断分析和调试中，找到了问题的答案，原来在 so 层对 fstat、mmap 和 munmap 三个系统函数进行了 hook！这样在 libart.so 底层函数的代码中对文件进行内存映射的时候，返回的内存地址就是已经在内存中解密好的 Dex 文件的存放地址，而不是空的 Dex 文件。这样就通过 hook 系统函数做到了替换，ClassLoader 在底层函数中加载的不是空 Dex 文件，而是目标 Dex 文件。

 

![img](/assets/images/2020-06-23/802108_53WT64XUXBCJ9N2.png)

 

我们在三个 hook 替换的函数设下断点停下来的时候可以查看栈空间，发现返回地址在 libart.so 中的函数，从而可以验证我们的猜测。

### 别的实现方式

在大量的搜索中还了解到的一类方式是，通过调用 Dalvik 和 Art 虚拟机的底层函数加载 Dex 文件拿到 cookie，然后通过反射进行替换操作。

 

以 @寒号鸟二代 大佬一篇帖子中给出的[项目](https://bbs.pediy.com/thread-225303.htm)为例。

 

mem_loadDex 函数中判断 Dalvik 和 Art 虚拟机调用相应的函数加载 Dex 文件获得 cookie，然后进行替换。

 

![img](/assets/images/2020-06-23/802108_JYH9F22WEC68JX8.png)

 

replace_cookie 函数具体实现了 cookie 替换。

 

![img](/assets/images/2020-06-23/802108_YJVG8TGP76ZZHY7.png)

# 开始分析

好了，终于要开始分析了，我们下面要做的就是在实战分析中去加深理解上面的部分！

## IDA 分析调试 so 文件准备

壳的入口是 MyWrapperProxyApplication，继承了父类 WrapperProxyApplication，并且实现了父类中的方法 initProxyApplication。

 

![img](/assets/images/2020-06-23/802108_XUGZXY5T6B64AK8.png)

 

我们找到父类 WrapperProxyApplication，首先找到最先执行的 attachBaseContext 方法。

 

![img](/assets/images/2020-06-23/802108_DUHWMS9S3R2M6QX.png)

 

可以看到首先获得了 basContext，这个 baseContext 变量会在后面 so 层中获取，进行 attach 新的 DelegateApplication。然后是给 shellApp 赋值，在调用 initProxyApplication，就是上面图中 MyWrapperProxyApplication 中实现的 initProxyApplication，可以看到是为了获取 libtosprotection 的 so 文件路径进行 System.load 加载。

 

前面说到我们的分析环境是逍遥模拟器 Android 5.1.1 版本，是 x86 架构，所以选择分析调试的 so 文件是 libtosprotection.x86.so。

 

如果不会调试 so 文件的话可以看论坛这篇[帖子](https://bbs.pediy.com/thread-259633.htm)，十分详细。

 

在模拟器设置的开发者选项里面勾上等待调试器，然后选择我们的待调试应用。

 

![img](/assets/images/2020-06-23/802108_VHH77XPV5KUV259.png)

 

然后打开 apk，选择待调试应用。

 

![img](/assets/images/2020-06-23/802108_2GMZUVHUCUMCVMR.png)

 

然后先打开 DDMS。

 

IDA 部分提一下的就是 Debugger->Debugger Options... 选项勾上 Suspend on debugging message 选项即可。

 

![img](/assets/images/2020-06-23/802108_M6KKQQVW8JJG5YT.png)

 

调试器选择 Remote Linux debugger，adb shell 后运行 android_x86_server 文件，不要忘记端口转发 `adb forward tcp:23946 tcp:23946`， 然后选择 attach to process，选择我们要调试的 apk 进程。

 

![img](/assets/images/2020-06-23/802108_R2PRV5AF32UJ486.png)

 

随后会断在 libc.so，我们直接按 f9，然后在命令行中输入 `jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700`，IDA 会断在 linker.so，这时候我们要调试的 so 文件还没有加载，我们再按一次 f9，可以看到 module 窗口中出现了我们要调试的 so 文件。

 

![img](/assets/images/2020-06-23/802108_CS4XQMYZYVEPCJY.png)

 

进行双击我们可以看到 JNI_OnLoad 函数，再双击后就可以到达函数的汇编指令处。

 

![img](/assets/images/2020-06-23/802108_W5W2F8CS3N97PDP.png)

 

![img](/assets/images/2020-06-23/802108_77XFCAEVVF7CEQT.png)

## JNI_OnLoad——几个重要函数

在反编译 JNI_OnLoad 函数后，可以看到首先注册了两个 Java 类中的原生函数，

 

![img](/assets/images/2020-06-23/802108_C3GHPU4UAFK5AHC.png)

 

![img](/assets/images/2020-06-23/802108_2V5TMNQ2FMW5VHN.png)

 

分别是 WrapperProxyApplication 类中的 Ooo0ooO0oO 方法，和 CustomerClassLoader 类中的 ShowLogs 方法。

 

![img](/assets/images/2020-06-23/802108_A59HSAUFM3HG2AP.png)

 

![img](/assets/images/2020-06-23/802108_AWXE3MWF35Q8P7D.png)

 

sub_30E0 函数对应着 Ooo0ooO0oO 方法，在 ProxyApplication 替换为 DelegateApplication 的过程起着很重要的作用，等到调用的时候我们再具体看下。

 

在 JNI_OnLoad 函数需要关注的有三个重要的调用函数。

 

首先是 sub_C9E0 函数，在这个函数里面对壳运行环境数据的初始化和获取，以及最重要的是找到被抽取的 Dex 文件压缩后的数据，并释放到内存中。

 

![img](/assets/images/2020-06-23/802108_7NBZCRPA7F2JNF9.png)

 

然后是 sub_1C540 函数，这个函数中进行的反调试操作。

 

![img](/assets/images/2020-06-23/802108_M6UUMJ83URKVVJG.png)

 

最后是 sub_5800 函数，实现了非常多的功能，完成了对系统函数的 hook，加载 Dex 文件，进行对 ProxyApplication 到 DelegateApplication 的替换。

 

![img](/assets/images/2020-06-23/802108_UK37E2C58FKFQPV.png)

## sub_C9E0——数据初始化

我们首先来分析 sub_C9E0 函数，先把第三个参数改名为 info，它指向一个结构体，在 sub_C9E0 函数反编译的伪代码中，我们看到会获取各种各样的数据和变量参数放在结构体中。

 

![img](/assets/images/2020-06-23/802108_MRKYHAP382D8NSU.png)

 

![img](/assets/images/2020-06-23/802108_NPHZUMT4XKMCE9N.png)

 

我们慢慢分析来整理一下。

- info+149：当前系统 SDK 版本
- info+151：系统虚拟机，值为1时是 Dalvik 虚拟机，值为2时是 Art 虚拟机
- info+129：变量 WrapperProxyApplication.baseContext，壳 apk 的 context
- info+130：变量 WrapperProxyApplication.baseContext.mPackageInfo
- info+131：变量 WrapperProxyApplication.baseContext.mPackageInfo.mActivityThread 当前 Activity 线程
- info+133：类 com/wrapper/proxyapplication/WrapperProxyApplication
- info+166：MethodID，com/wrapper/proxyapplication/WrapperProxyApplication->init()
- info+134：类 dalvik/system/DexFile
- info+135：变量 WrapperProxyApplication.shellApp，壳的 Application
- info+138：变量 壳的ClassLoader
- info+150：机器架构 值为1时是 arm 架构，值为3时是 x86 架构。

随后打开了文件“/data/data/com.tencent.qqpimsecure.sc/files/prodexdir/o0oooOO0ooOo.dat”并映射到内存中，在 sub_3F70 函数中进行 lib iv check 时候用到。

 

然后中间的很大的一部分都是在走 Dalvik 虚拟机模式处理的流程，简单分析的话可以看出来是在获取 Dalvik_dalvik_system_DexFile_openDexFile_bytearray 方法指针和 Dalvik_dalvik_system_DexFile_openDexFile 指针，分别保存在了 info+161 和 info+162 两处。

 

![img](/assets/images/2020-06-23/802108_4QJ99AZV2NEQFYW.png)

 

![img](/assets/images/2020-06-23/802108_9KV84FZMK48ARBA.png)

 

![img](/assets/images/2020-06-23/802108_EYUJHCPKT2YKT2W.png)

 

猜测 Dalvik 模式是用 Dalvik_dalvik_system_DexFile_openDexFile_bytearray 方法或者 Dalvik_dalvik_system_DexFile_openDexFile 方法来解析 Dex 数据，我们的安卓 5.5.1 模拟器走的是 Art 模式，就不再深入分析 Dalvik 模式内存加载 Dex 文件的流程，如果能在 Dalvik 虚拟机上跑起这个 App 可以仔细看下这篇翻译的文章来分析，[《Android4.0内存Dex数据动态加载技术》](https://blog.csdn.net/androidsecurity/article/details/9674251)

 

让我们来看下 Art 模式下走的流程，

 

![img](/assets/images/2020-06-23/802108_NEU94UE3UU6GRMM.png)

 

获取了 Ooo0ooO0oO 方法的 MethodID，然后传进了 sub_14140 函数，返回的值放在 info+151 处，通过调试我们可以得到这个返回值是0x28。

 

然后就是 sub_B110 和 sub_B960 这两个比较重要的函数，说去来我在刚开始碰到这两个函数的时候，看得一头雾水，索性就跳过了，结果在后面的分析发现不对劲，遇到了关键的变量和数据找不到，于是又回过头来仔细分析调试这两个函数......这说明当我们碰到看不到的指令代码时候不要轻易选择跳过，有可能跳过的就是重要的地方。

## sub_B110——从内存中的 Oat 文件拿到 Dex 的地址

还记得开始时候我们用 IDA 进行调试时候的那张截图中的 Modules 视图吗？

 

![img](/assets/images/2020-06-23/802108_B7K2UAQNM93NC99.png)

 

我们可以看到第三个是 `/data@app@com.tencent.qqpimsecure.sc-1@base.apk@classes.dex`，这是什么呢，是 Art 虚拟机模式下壳 Apk 中的 Dex 文件优化后的 Oat 文件。Oat 文件本质上就是一个 ELF 文件，它将 OAT 文件格式内嵌在了 ELF 文件里，在它的 oatdata 段中，包含了原 Dex 文件的完整内容。

 

![img](/assets/images/2020-06-23/802108_MJJ75JC39PD8KH6.png)

 

我们双击点进去可以看出来是 OAT 文件的结构。

 

![img](/assets/images/2020-06-23/802108_9PG88FU8PMNUH89.png)

 

sub_B110 函数实现的就是找到内存中已经加载了的壳 Dex 优化后的 Oat 文件，然后再找到 Oat 文件中的 Dex 文件，最后返回 Dex 文件在内存中的地址。

 

让我们来具体分析一下是怎么实现的，先看前半部分代码，进行了 SDK 版本和虚拟机模式的判断，我们是 Android 5.1.1，只走圈出来的部分。

 

![img](/assets/images/2020-06-23/802108_C44ZW4BZ6EF8GEE.png)

 

sub_B800 函数得到了 Oat 文件加载到内存中的名称，即`/data@app@com.tencent.qqpimsecure.sc-1@base.apk@classes.dex`，并放在了第一个参数中，然后传给了函数 sub_8D10。

 

在看 sub_8D10 之前我们需要知道的是，可以利用/proc/pid/maps可以查看进程的虚拟空间布局,从而获知当前使用内存的具体分布情况。

 

![img](/assets/images/2020-06-23/802108_8HX8RS2UH4FB33J.png)

 

每一行数据中我们需要关注的是：在内存空间中的起始地址和结束地址、此段地址空间的属性和映射的文件名。

 

我们现在来看下 sub_8D10 函数，可以就是通过打开 /proc/pid/maps 文件进行读操作然后寻找包含 Oat 的文件数据，再通过切割字符串和 strtoul 操作得到 Oat 文件内存中映射的起始和结束地址，最后放在传入的参数三和参数四。

 

![img](/assets/images/2020-06-23/802108_VBVMAYX87MVU5T2.png)

 

![img](/assets/images/2020-06-23/802108_NV5FFW93ED2ZTS5.png)

 

![img](/assets/images/2020-06-23/802108_USHCVQHN6NP3WNX.png)

 

我们调试可以查看执行完这个函数后的参数三和参数四存放的地址，可以发现是和 /proc/pid/maps 中一致的。

 

![img](/assets/images/2020-06-23/802108_2DMXGV4DCR869UV.png)

 

![img](/assets/images/2020-06-23/802108_C5XKKQSXCEWPMNH.png)

 

再下面会执行 sub_AD10 函数，会得到壳 Dex 文件在内存中的地址，这里就不再多说，sub_B110 就分析这么多，最后返回了壳 Dex 文件在内存中的地址。

## sub_B960——解压指令抽取的 Dex 到内存中

然后就是 sub_B960 函数，下面的分析就要清晰多了，函数的第二个参数就是上面得到的壳 Dex 文件在内存中的地址。

 

先要说下就是加固 App 的所有 Dex 文件抽取加密压缩后的数据都放在了壳 Dex 文件中的 link_off处。

 

然后 sub_B960 函数完成的操作是将压缩的抽取指令后的两个 Dex 文件解压到内存中，并将解压的地址存放到 info 结构体中给后面使用。除此之外，还记录了 data1、data2、data3、data4 在内存中的地址，也都放到了 info 结构体中，这四个数据是用来干什么的呢？是用来后面还原抽取的指令的。

 

现在我们开始看一下。

 

![img](/assets/images/2020-06-23/802108_S7GN9EYWBGEQWJR.png)

 

![img](/assets/images/2020-06-23/802108_Q92XSPP749QQ5R3.png)

 

info+152 保存的是加固 App 的 Dex 文件数量，这里为2。然后 info+156，info+157，info+158，info+159 处都申请分配了 4 * Dex文件数量的大小空间。

 

然后看下 sub_A700。

 

![img](/assets/images/2020-06-23/802108_KB74UB5YXC6FHMP.png)

 

在第一个 do-while 循环中，sub_96C0 是调用了 uncompress 函数对数据进行解压，分别解压得到两个 Dex 文件，但都是被抽取的，我们进行动态调试在这里设下断点，执行完 sub_96C0 函数，然后 dump 下来看看。

 

IDC-dump脚本如下。

```
static main(void)``  ``{``    ``auto fp, base, end, dexbyte;``    ``fp ``=` `fopen(``"d:\\指令抽取Dex.dex"``, ``"wb"``); ``/``/``打开或创建一个文件``    ``base ``=` `0xA2800000``;      ``    ``end ``=` `base``+``0x30cf88``;     ``    ``for` `( dexbyte ``=` `base; dexbyte < end;dexbyte ``+``+` `)``    ``{``      ``fputc(Byte(dexbyte), fp);   ``/``/``按字节将其dump到本地文件中``    ``}``  ``}
```

![img](/assets/images/2020-06-23/802108_4XV8F2E7AFX47PA.png)

 

dump 下来之后我们用 010 Editor 将前16个字节删除，然后拖入 Jeb 即可进行反编译。

 

![img](/assets/images/2020-06-23/802108_QRD988R4B2HAWBR.png)

 

![img](/assets/images/2020-06-23/802108_W78QZDMUK5X73N3.png)

 

可以发现 dump 的两个 Dex 文件指令都是被抽取了的。

 

最后 sub_A700 函数还进行了些其他操作。

 

![img](/assets/images/2020-06-23/802108_W426F922VZN9EW7.png)

 

dex1 和 dex2 文件及4个 data 数据在壳 Dex 文件中的偏移及长度记录如下。

- dex1：0x85d0 length：0xa7ee9
- dex2：0xb04c9 length：0xc397
- data1：0xbc860 length：0x19a05
- data2：0xd6269 length：0x20e9
- data3：0xd8356 length：0x5abf3
- data4：0x132f4d length：0x9bcf

## sub_58000——进行的重要操作

在说 sub_58000 函数前要提下的就是，sub_1C540 是反调试函数，我们在调试时候可以直接 nop 掉。以及 sub_4A10 函数中进行了证书校验操作，如果进行二次打包要注意这里。由于篇幅原因，不再详细分析这两个函数，然后我们来看 JNI_OnLoad 函数中最后的 sub_5800 函数。

 

sub_5800 函数主要进行了三部分操作。

 

sub_35E0 中调用 Java 层的 MultiDex 类中的 installDexes 方法装载 Dex 文件，并且前面我们有说到，在进行装载之前是对系统函数进行了 hook 操作，让 PathClassLoader 装载的是加载到内存中的指令被抽取了 Dex 文件。

 

然后就是 sub_6DC0 函数还原填充了内存中 Dex 文件被抽取的指令。

 

最后创建了 DelegateApplication 的实例，完成 ProxyApplication 替换 DelegateApplication 过程中的 basecontext 的 attach 操作。

## sub_4F80—— hook 和 InstallDexes

sub_58000 函数前面部分进行的主要是文件和文件夹路径操作，通过调试还是很容易理解的，我们现在来看 art 虚拟机模式要走的 sub_4F80函数。

 

![img](/assets/images/2020-06-23/802108_346NHQYVU88Y8NT.png)

 

进入之后看到的圈出来的地方就是对 "fstat"、“mmap”和“munmap" 进行的 hook。

 

![img](/assets/images/2020-06-23/802108_YUDMV9JRPFDMTA6.png)

 

三个函数 hook 操作的目的都是使函数作用的对象变成内存中已经加载好的 Dex 文件，如 mmap 函数 hook 为返回地址是 info+160 存放的地址，即是前面保存的解压到内存中两个指令被抽取了的 Dex 文件的地址。

 

如果我们对三个 hook 替换的函数设下断点，运行后停下来，会发现调用的地方在 libart.so 中，所以可以猜测最终会影响到 ClassLoader 在底层函数中加载 Dex 文件的过程。

 

![img](/assets/images/2020-06-23/802108_6DKU4NTUESKR9ZT.png)

 

起先我看到这里的时候并不知道是进行了 hook 操作，在进行不断搜索的过程找到了一位大佬的博客（[https://www.cnblogs.com/xiaobaiyey/p/6557854.html](https://bbs.kanxue.com/elink@6d9K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6%4N6%4N6Q4x3X3g2U0L8X3u0D9L8$3N6K6i4K6u0W2j5$3!0E0i4K6u0r3P5r3W2S2L8$3u0S2K9i4W2W2P5g2)9J5c8Y4m8Q4x3V1j5$3y4e0f1%4z5o6f1@1i4K6u0W2K9s2c8E0L8l9%60.%60.)）和他的 github项目（[https://github.com/xiaobaiyey/dexload/blob/master/dexload/README.md](https://bbs.kanxue.com/elink@3ffK9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6Y4K9i4c8Z5N6h3u0Q4x3X3g2U0L8$3#2Q4x3V1k6^5K9h3q4G2j5X3q4A6P5h3g2&6i4K6u0r3k6r3g2^5L8r3!0S2k6q4)9J5c8X3u0D9L8$3u0Q4x3V1k6E0j5i4y4@1k6i4u0Q4x3V1k6V1k6i4S2D9L8$3q4V1i4K6u0r3f1V1g2m8c8p5#2q4i4K6u0W2L8h3b7`.)）。

 

![img](/assets/images/2020-06-23/802108_3E48YRU3DMEZ6AQ.png)

 

进行了一番学习和分析后，才确定这里是进行了 hook 操作，感谢大佬们的无私分享精神！有空要花时间好好研究下 ELF 文件的 hook。

 

然后再往下面分析，会走到调用 sub_35E0 函数的地方，里面就是调用 Java 层中 MultiDex 类中的 installDexes 地方。我们可以通过调试很容易判断要走哪些代码。

 

![img](/assets/images/2020-06-23/802108_XVRREYP8G5AFC7X.png)
然后来看 installDexes 方法，

 

![img](/assets/images/2020-06-23/802108_DFWX624HURGYYNH.png)

 

![img](/assets/images/2020-06-23/802108_8B5KMYBG5NSP88U.png)

 

看到会调用到 install 方法，然后可以看到又调用了 V19.makeDexElements，查看方法具体实现就是通过反射调用了 makeDexElements 方法来加载 Dex 文件，再后面的过程就是在前面说 ClassLoader 已经说到了的。

 

ClassLoader 加载了两个 Dex 文件，前面也说到实际上加载的这两个文件是空文件，但是由于进行了 hook 操作，ClassLoader 在底层函数会加载前面再内存中解压出来的抽取了指令的 Dex 文件。

## sub_6DC0——抽取指令还原

下面让我们回过头看 sub_58000 函数中调用 sub_6DC0 的地方，也就是我们说到的还原填充了内存中 Dex 文件被抽取的指令的地方。

 

![img](/assets/images/2020-06-23/802108_BZWK57V9H9HG3Y8.png)

 

这个函数很长，描述起来多少会比较模糊，慢慢调试分析可能会感受得更清晰些。函数可以分为三部分，先提下的就是 salsa20 加密函数，我是搜索后进行确认的，具体的加密可以看大佬的这篇博客（[https://www.cnblogs.com/aquar/p/8437172.html](https://bbs.kanxue.com/elink@d87K9s2c8@1M7s2y4Q4x3@1q4Q4x3V1k6Q4x3V1k6%4N6%4N6Q4x3X3g2U0L8X3u0D9L8$3N6K6i4K6u0W2j5$3!0E0i4K6u0r3j5i4q4#2j5i4u0Q4x3V1k6H3i4K6u0r3z5o6b7K6y4K6p5%4x3W2)9J5k6h3S2@1L8h3H3%60.)）。

 

第一部分是处理前面说的 data1 和 data2 数据。

 

![img](/assets/images/2020-06-23/802108_7AP6PZS57BEJBWJ.png)

 

![img](/assets/images/2020-06-23/802108_UWKQT4MKDNJ8GBP.png)

 

数据解压后还会进行读取，得到指导抽取指令数据进行填充的重要数据。

 

![img](/assets/images/2020-06-23/802108_XBKC84FGBEASV3M.png)

 

![img](/assets/images/2020-06-23/802108_CZBPNVTQK4DPRB5.png)

 

第二部分是处理前面说的 data3 和 data4 数据。

 

![img](/assets/images/2020-06-23/802108_V7FMDP9D8XD24AJ.png)

 

第三部分就是通过 memcpy 在 do-while 循环中根据得到的指导数据和解压数据，进行对内存中被抽取指令的 Dex 文件的填充了。

 

![img](/assets/images/2020-06-23/802108_WYSAKPRXU2TQMYW.png)

 

sub_6DC0 到此结束，当执行完这个函数后，我们再对内存中的 Dex 进行 dump 的时候，就会发现指令已经被还原了！

 

![img](/assets/images/2020-06-23/802108_R3439VUYUNEUP6V.png)

## 完成 Application 的替换

Orz 终于要结束了，现在已经完成了抽取指令的还原了，让我们来看 sub_58000 最后一部分吧，就是完成 ProxyApplication 到 DelegateApplication 的替换过程。

 

![img](/assets/images/2020-06-23/802108_GJFCPD56MQGWVGR.png)

 

主要进行了三个操作，设置 ClassLoader、创建 DelegateApplication 的实例和进行 baseContext 的 attach 操作，这时候控制权就已经从 ProxyApplication 交给 DelegateApplication 了，具体的函数我们就不细看了。

 

然后整个 JNI_OnLoad 函数要做的事情差不多就做完了，但是 Application 的替换还没结束。

 

别忘了 Java 层执行了的只是 attachBaseContext，还有 onCreate 要执行。

 

![img](/assets/images/2020-06-23/802108_9TWHJMUEYSN7JWR.png)

 

我们来看下发现执行了原生函数 Ooo0ooO0oO，也就是在开始注册的 so 层中的 sub_30E0 函数。

 

![img](/assets/images/2020-06-23/802108_FMRSB2VRAGQJWGH.png)

 

看下 sub_A380 函数，可以看出是替换了 API 层的所有 Application 引用。

 

![img](/assets/images/2020-06-23/802108_SUJAM2WQQ296XSU.png)

 

随后 sub_A2F0 中又处理 ContentProviders，最后调用了我们的 DelegateApplication 的 onCreate 方法，也就是用户 Application。

 

到此壳的运行结束了。

# 结语

写到这里其实已经写不动什么了，写文章总结纪录不是一件容易的事，十分地消耗精力和时间...

 

希望这篇文章能帮助像我一样入门学习 so 层分析的新手，如果觉得学习到了有用的东西，请务必点赞，也不枉我写了这么多。

