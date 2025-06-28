---
author: 0x指纹
date: 2025-04-11 08:00+08:00
layout: post
title: "LiteSQL 在 Windows11 系统启动服务失败"
mathjax: true
categories:
- 杂项记录
tags:
- sqlserver
- database
- win11
---

* content
{:toc}

一老哥使用 LiteSQL2014 在 Windows 11 系统启动数据库服务失败，辗转找到我这里来解决。可以看到点击启动后，运行日志的异常输出为“`启动服务 [发生错误]`”和“`sqlserver [异常终止]`”，并且伴随一个错误弹窗 “`System Error. Code:232. 管道正在被关闭`”。 








![img](/assets/images/2025-04-11/1.png)

# 定位问题

开始先直接搜索弹窗中的报错，搜到的内容乱七八槽，有些甚至说什么和网卡驱动有关，想想不太对劲。琢磨了会注意到有个“`SQL日志`”栏，点击翻了下发现里面这么一行：

> There have been 256 misaligned log IOs which required falling back to synchronous IO. The current IO is on file  xxx\xxx\MSSQL\DATA\master.mdf

搜下这个错误信息发现算是找到正主了，在微软论坛一个问题 [SQL Server 2022 installation error on windows 11 with error "Could not find the database engine startup handle"](https://learn.microsoft.com/en-us/answers/questions/1288063/sql-server-2022-installation-error-on-windows-11-w) 下有用户回答说是因为磁盘扇区大小原因，并说微软专门发了一篇此问题说明和解决方案的文章 [Troubleshoot errors related to system disk sector size greater than 4 KB](https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/database-file-operations/troubleshoot-os-4kb-disk-sector-size?WT.mc_id=DP-MVP-5440&tabs=registry-editor)。

![img](/assets/images/2025-04-11/2.png)


# 问题解决

读一下这篇文章可以知道，SQL Server 启动时会进行文件系统一致性检查，目前仅支持 512 字节和 4 KB 扇区大小。一些新存储设备如 NVMe 的扇区大小大于 4 KB，在 Windows 11 上原生 NVMe 驱动会直接给出实际扇区大小，就导致 SQL Server 不支持启动失败报错，而在 Windows 10 上驱动不会获取物理存储的扇区大小，会模拟成 4 KB 就没事。

![img](/assets/images/2025-04-11/4.png)

按文章所说可以执行下 `fsutil fsinfo sectorinfo <volume pathname>` 来看到当前操作系统获取的扇区大小，能看到 16 KB。

```
> fsutil fsinfo sectorinfo D:
LogicalBytesPerSector :                                 512
PhysicalBytesPerSectorForAtomicity :                    16384
PhysicalBytesPerSectorForPerformance :                  16384
FileSystemEffectivePhysicalBytesPerSectorForAtomicity : 4096
设备校准 :                                        已校准(0x000)
设备上的分区校准:                                  已校准(0x000)
无搜寻惩罚
支持剪裁
不支持 DAX
未精简预配
```

官方提供的解决方案有两种：

1. 添加注册表项 `ForcedPhysicalSectorSizeInBytes`，设置值为 `* 4095`，强制模拟4KB扇区大小。操作注册表有风险，具体命令或执行怎么弄可以去官网看下，让提前备份注册表，还提供了如果注册表弄坏了怎么恢复的链接 [How to back up and restore the registry in Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users#back-up-the-registry)。

2. 如果不想修改注册表，可以将数据库文件放在扇区大小符合要求的其他驱动器上。

![img](/assets/images/2025-04-11/5.png)

试了第一种方案，重启后配置生效，再运行数据库服务成功。

# 其他发现

搜到 Reddit 论坛也有个帖子 [SQL Server LocalDB Startup Failure on Windows 11 - Process Fails to Start](https://www.reddit.com/r/SQL/comments/1abpe05/sql_server_localdb_startup_failure_on_windows_11/) 碰到了类似问题，这哥们用的是三星 SSD，说添加注册表现值填的 `* 4096` 才有用，而不是微软官方给出的 `* 4095`，不知道是不是和三星硬盘的驱动有关。

![img](/assets/images/2025-04-11/3.png)