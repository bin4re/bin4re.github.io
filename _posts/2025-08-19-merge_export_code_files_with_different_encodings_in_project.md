---
author: 0x指纹
date: 2025-08-19 08:00+08:00
layout: post
title: "合并导出项目不同编码代码文件"
mathjax: true
categories:
- 软件开发
tags:
- cpp
- llm
- encoding
---

* content
{:toc}

更新：20251218

# 项目说明

仓库地址：[https://github.com/bin4re/SmartCharsetMerger](https://github.com/bin4re/SmartCharsetMerger)

有提取项目代码到同一个文本文件中再给 LLM 问答使用的场景，但碰到了项目有不同编码的文件导致提取内容部分乱码问题，为解决此问题二开了 [SmartCharsetConverter](https://github.com/tomwillow/SmartCharsetConverter)，原项目具体信息可前往主页查看。

![](/assets/images/2025-08-19/1.png)







# 功能特性

我在原项目基础上：

* 添加了“合并导出”的功能按钮，可将文件列表中的文件转换统一编码后，合并内容导出保存到一个文本文件中，使用文件相对文件夹的路径来分隔不同文件内容。
* 解耦了设置文件过滤和智能识别模式的耦合。
* 添加Ctrl+A或右键点击“全选”进行批量设置编码的功能。




# 构建方法

推荐配置系统代理打开Developer Powershell for VS2022，进入到项目目录，执行config_on_win.bat，会自动安装vcpkg中的依赖，并进行cmake配置，首次下载要等待一段时间。

完毕后进入build目录打开SmartCharsetConverter.sln，选择SmartCharsetConverter项目右击“生成”。
