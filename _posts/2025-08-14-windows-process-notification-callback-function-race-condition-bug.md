---
author: 0x指纹
date: 25-08-14 08:00+08:00
layout: post
title: "Windows 内核驱动进程通知回调函数的竟态 Bug"
mathjax: true
categories:
- 杂项记录
tags:
- windows
- kernel
- process
- bug
---

* content
{:toc}

前段时间在一个群里有群友说自己写的 Windows 内核驱动老是莫名蓝屏，不盯着就很突然来一下，看崩溃调用栈，显示错误在使用 `PsSetCreateProcessNotifyRoutineEx` 注册的进程通知回调函数 `CreateNotifyRoutine` 中，指向 `ExFreePoolWithTag(Msg, msg_tag)` 一句，但他使用内核校验器和调试了很久都没排查到哪里有问题。

后面我断续看了两次，比照着自己写的驱动代码，发现判断这应该是个竟态条件（Race Condition）问题，如此也比较符合描述的不稳定蓝屏现象，改了下就正常了。这算是我第一次排查到竟态条件问题，之前只在看相关的漏洞分析利用碰到的多，感觉还是比较有意思的，记录一下。





# 问题分析

驱动的进程监控模块代码如下，通过注册进程通知回调来监控系统进程创建和终止事件，并构造消息包通过内核通信发送给用户层。可以看到 `Msg` 和 `Msg_Size` 都是静态变量，但当系统中多个进程同时创建时，Windows会并发调用 `CreateNotifyRoutine` 回调函数，进而竞争使用两个变量，回调函数中存在的时间窗口有：
1. 计算 `Msg_Size` 
2. 分配内存
3. 初始化内存
4. 填充数据
5. 发送消息
6. 释放内存

这么多时间窗口可能会出现的问题就会相当多，`Double Free` 导致的蓝屏只是比较容易被观测到的严重事件，不容易注意到的还有内存泄漏、消息数据丢失混乱和非法使用内存等等。

```c
//process.h
#pragma once
#include "head.h";

namespace Process_Monior {
	bool Init();
	void Uninstall();
	static size_t Msg_Size = 0;
}
```

```c
//process.cpp
#include "process.h"
#define msg_tag 'FIRE'
namespace Process_Monior {
	bool Process_Monior_Install_State = false;
	_Msg_ProcessCreate* Msg = nullptr;
	void CreateNotifyRoutine(PEPROCESS Process, HANDLE Process_Id, PPS_CREATE_NOTIFY_INFO Create_Info) {
		bool isCreate = Create_Info != nullptr;
		if (isCreate) {
			DbgPrint("Process Create PID: %d File: %wZ \n", (ULONG)Process_Id, Create_Info->ImageFileName);
			Msg_Size = sizeof(_Msg_ProcessCreate);
			Msg_Size += (size_t)Create_Info->ImageFileName->Length + sizeof(wchar_t);
			Msg_Size += (size_t)Create_Info->CommandLine->Length + sizeof(wchar_t);
			Msg = static_cast<_Msg_ProcessCreate*>(ExAllocatePoolWithTag(PagedPool, Msg_Size, msg_tag));
			do {
				if (Msg == nullptr) {
					break;
				}
				memset(Msg, 0, Msg_Size);
				Msg->packet.magic_num = 0x1337;
				Msg->packet.type = _Client_Msg_Type::kCreateProcess;
				Msg->pid = reinterpret_cast<uint32_t>(Process_Id);
				Msg->ppid = reinterpret_cast<uint32_t>(Create_Info->ParentProcessId);
				Msg->path_size = (size_t)Create_Info->ImageFileName->Length+sizeof(wchar_t);
				Msg->commandsize = (size_t)Create_Info->CommandLine->Length + sizeof(wchar_t);
				memcpy(Msg->path, Create_Info->ImageFileName->Buffer,Create_Info->ImageFileName->Length);
				Msg->commandoffset = sizeof(_Client_Msg_Packet)+sizeof(uint32_t) + sizeof(uint32_t) + sizeof(size_t) + sizeof(size_t) + sizeof(size_t) + Msg->path_size;
				memcpy((void*)((uint64_t)Msg + Msg->commandoffset), Create_Info->CommandLine->Buffer, Create_Info->CommandLine->Length);
				DbgPrint("[+]magic_num: %x path:%wZ \n", Msg->packet.magic_num,Create_Info->ImageFileName);
				if(kernel_msg::SendCreateProcessEvent(Msg, Msg_Size) == false) {
					DbgPrint("[+]R0 Send Msg Fail. \n");
					break;
				}
				DbgPrint("[+]R0 Send Msg Success! \n");
			} while (false);
			if (Msg!=nullptr) {
				ExFreePoolWithTag(Msg, msg_tag);
				Msg = nullptr;
				Msg_Size = 0;
			}
		}
		else {
			DbgPrint("Process End PID: %d \n",(ULONG)Process_Id);
		}
	}
	bool Init() {
		bool status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateNotifyRoutine, false);
		do {
			if (NT_SUCCESS(status) == false) {
				NT_ASSERT(false);
				break;
			}
			Process_Monior_Install_State = true;
		} while (false);
		DbgPrint("[%s] Status : %08d \n", __FUNCTION__, status);
		return NT_SUCCESS(status);
	}
	void Uninstall() {
		if (Process_Monior_Install_State) {
			PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateNotifyRoutine, true);
			Process_Monior_Install_State = false;
		}
	}
}
```

# 解决方案

只考虑解决静态条件问题的话，有两种方案：

1. 使用局部变量替代静态变量， `Msg` 和 `Msg_Size` 定义在 `CreateNotifyRoutine` 函数中。

2. 使用同步机制，比如可以加个快速互斥锁
```c
namespace Process_Monior {
    FAST_MUTEX msg_fast_mutex;  // 声明快速互斥体
    
    // 在Init函数中初始化
    bool Init() {
        ExInitializeFastMutex(&msg_fast_mutex);
        // 其余初始化代码...
    }
    
    void CreateNotifyRoutine(...) {
        ExAcquireFastMutex(&msg_fast_mutex);
        // 临界区代码...
        ExReleaseFastMutex(&msg_fast_mutex);
    }
}
```