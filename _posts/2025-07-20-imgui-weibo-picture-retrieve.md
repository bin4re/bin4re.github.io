---
author: 0x指纹
date: 2025-07-20 08:00+08:00
layout: post
title: "海外 CDN 图片恢复"
mathjax: true
categories:
- 软件开发
tags:
- cpp
- imgui
---

* content
{:toc}


懂的都懂。[https://github.com/bin4re/IMWeiboPicRetrieve](https://github.com/bin4re/IMWeiboPicRetrieve)

![](/assets/images/2025-07-20/1.png)






# 编译

项目由 `C++` 开发编译， Windows 系统运行，使用的库有：[imgui](https://github.com/ocornut/imgui)、[stb](https://github.com/nothings/stb)和[curl](https://github.com/curl/curl)，为方便编译，头文件和依赖都下载好放入在了Lib文件夹中，可打开sln文件一键编译。

# 使用

1. 图片时间越近，浏览人数越多，成功恢复几率越高。
2. 初始请求或点击 CDN 会获取图床海外 CDN IP，验证更新到 ips.txt 文件中。
3. 在浏览器中右击目标图片，选择“复制图片链接”并粘贴到输入框。


