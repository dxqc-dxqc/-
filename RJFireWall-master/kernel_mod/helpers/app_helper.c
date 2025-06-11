/**
 * @file netlink_handler.c (Предполагаемое имя файла, так как оно не указано)
 * @brief 内核模块与用户空间应用程序通信处理逻辑。
 *
 * 主要功能：
 * 此文件实现了内核模块通过Netlink接收来自用户空间应用程序的请求，并对其进行处理的逻辑。
 * 同时，它也包含了内核模块向用户空间应用程序发送响应或消息的功能。
 *
 * 包含的主要函数有：
 * 1.  `sendMsgToApp`: 一个辅助函数，用于将简单的文本消息打包并通过Netlink发送给指定PID的用户空间进程。
 * 2.  `dealWithSetAction`: 当防火墙的默认动作被修改时（特别是从允许变为拒绝），此函数负责执行一些清理操作，
 *     例如清除所有现有的网络连接，以确保新的默认策略能够立即生效。
 * 3.  `dealAppMessage`: 这是核心的Netlink消息处理函数。它接收一个来自用户空间应用的消息 (`APPRequest`)，
 *     并根据请求类型 (`req->tp`) 分发到不同的处理分支。这些分支负责调用相应的内部函数来执行
 *     诸如获取规则/日志/连接、添加/删除规则、设置默认动作等操作。处理完毕后，它会调用
 *     `nlSend` (或 `sendMsgToApp`) 将结果或状态信息返回给用户空间应用程序。
 *
 * 此模块是实现用户空间配置和管理内核防火墙功能的关键接口。
 */
#include "helper.h" // 包含此文件中函数所需的各种声明和定义，例如：
                    // - 数据结构: APPRequest, KernelResponseHeader, IPRule, NATRecord
                    // - 常量: REQ_*, RSP_*, NF_ACCEPT, NF_DROP, ERROR_CODE_*
                    // - 函数声明: nlSend, formAllIPLogs, formAllConns, formAllIPRules,
                    //             addIPRuleToChain, delIPRuleFromChain, formAllNATRules,
                    //             addNATRuleToChain, delNATRuleFromChain, eraseConnRelated
                    // - 内核API: printk, kzalloc, kfree, GFP_ATOMIC, GFP_KERNEL, strlen, memcpy

// 外部变量声明，DEFAULT_ACTION 在其他文件中定义 (例如 hook_main.c 或主模块文件)
// 它存储了防火墙的默认处理动作 (NF_ACCEPT 或 NF_DROP)。
extern unsigned int DEFAULT_ACTION;

/**
 * @brief 将文本消息通过Netlink发送给指定PID的用户空间应用程序。
 *
 * @param pid 目标用户空间应用程序的进程ID。
 * @param msg 指向要发送的以null结尾的C字符串消息的指针。
 * @return int 返回发送的消息的总长度 (包括头部和消息体)，如果内存分配失败则返回0。
 *
 * @功能描述:
 *   1.  计算响应消息的总长度，包括 `KernelResponseHeader` 的大小和消息字符串的长度 (加1是为了null终止符)。
 *   2.  使用 `kzalloc` (以 `GFP_ATOMIC` 标志，表示在原子上下文中分配，不能睡眠) 分配内存来存储响应包。
 *   3.  如果内存分配失败，打印警告信息并返回0。
 *   4.  填充 `KernelResponseHeader`:
 *       -   将 `bodyTp` 设置为 `RSP_MSG`，表示消息体是文本消息。
 *       -   将 `arrayLen` 设置为消息字符串的实际长度 (不包括null终止符)。
 *   5.  使用 `memcpy` 将用户提供的消息字符串复制到响应包头部之后的数据体部分。
 *   6.  调用 `nlSend` 函数将构建好的响应包发送给指定PID的用户空间进程。
 *   7.  使用 `kfree` 释放之前分配的内存。
 *   8.  返回发送的总字节数。
 */
int sendMsgToApp(unsigned int pid, const char *msg) {
    void* mem;                          // 指向分配的内存块的通用指针
    unsigned int rspLen;                // 响应消息的总长度
    struct KernelResponseHeader *rspH;  // 指向响应头部的指针

    // 计算响应包总长度：头部大小 + 消息字符串长度 + 1 (为字符串末尾的 '\0')
    rspLen = sizeof(struct KernelResponseHeader) + strlen(msg) + 1;
    // 使用 kzalloc 分配内存，GFP_ATOMIC 表示在原子上下文分配，不能睡眠
    mem = kzalloc(rspLen, GFP_ATOMIC);
    if(mem == NULL) { // 检查内存分配是否成功
        printk(KERN_WARNING "[fw k2app] sendMsgToApp kzalloc fail.\n"); // 打印警告
        return 0; // 返回0表示失败
    }

    // 将分配的内存转换为 KernelResponseHeader 指针
    rspH = (struct KernelResponseHeader *)mem;
    rspH->bodyTp = RSP_MSG;             // 设置响应体类型为文本消息
    rspH->arrayLen = strlen(msg);       // 设置数组长度为消息字符串的长度

    // 将消息字符串复制到响应头之后的位置
    memcpy(mem+sizeof(struct KernelResponseHeader), msg, strlen(msg)); // 注意：这里没有复制 '\0'，但kzalloc已清零

    // 调用 nlSend (Netlink发送函数，未在此处定义，应在helper.h中声明并在其他地方实现)
    // 将构建好的消息发送给指定PID的用户空间进程
    nlSend(pid, mem, rspLen);

    kfree(mem); // 释放分配的内存
    return rspLen; // 返回发送的总字节数
}

/**
 * @brief 处理设置默认防火墙动作后的附加操作。
 *
 * @param action 新设置的默认防火墙动作 (NF_ACCEPT 或 NF_DROP)。
 * @return void 无返回值。
 *
 * @功能描述:
 *   当防火墙的默认动作被修改时，此函数被调用。
 *   主要逻辑是：如果新的默认动作不是 `NF_ACCEPT` (即通常是 `NF_DROP` 或其他限制性策略)，
 *   则调用 `eraseConnRelated` 函数来清除所有现有的网络连接。
 *   这样做的目的是确保新的、更严格的默认策略能够立即对所有流量生效，
 *   防止已建立的连接绕过新的默认丢弃策略。
 *   `eraseConnRelated` 的参数是一个特殊的 `IPRule`，其字段被设置为通配符值，
 *   以匹配并清除所有连接。
 */
void dealWithSetAction(unsigned int action) {
    if(action != NF_ACCEPT) { // 如果新的默认动作不是“允许” (例如，设置为“拒绝”)
        // 创建一个通配符IP规则，用于匹配所有连接
        struct IPRule rule = {
            .smask = 0,     // 源掩码为0，匹配任何源IP
            .dmask = 0,     // 目的掩码为0，匹配任何目的IP
            .sport = (unsigned int)-1, // 源端口为-1 (或全1)，通常表示匹配任何源端口 (具体依赖eraseConnRelated的实现)
            .dport = (unsigned int)-1  // 目的端口为-1，匹配任何目的端口
            // 其他字段 (saddr, daddr, protocol, name, action, log, nx) 会被默认初始化 (通常为0或NULL)
        };
        // 调用 eraseConnRelated 函数，使用这个通配符规则来清除所有相关的连接跟踪条目。
        // eraseConnRelated 函数未在此处定义，应在helper.h中声明并在其他地方实现。
        eraseConnRelated(rule);
    }
}

/**
 * @brief 处理从用户空间应用程序通过Netlink接收到的消息。
 *
 * @param pid 发送该消息的用户空间应用程序的进程ID。
 * @param msg 指向接收到的消息数据 (通常是一个 `struct APPRequest`) 的指针。
 * @param len 接收到的消息数据的长度 (字节数)。
 * @return int 返回响应给用户空间的消息的长度，或在某些情况下返回0或错误指示（尽管此函数主要通过发送消息来反馈）。
 *
 * @功能描述:
 *   此函数是内核模块中处理用户空间请求的核心分发器。
 *   1.  将接收到的原始消息数据 (`msg`) 转换为 `struct APPRequest *` 指针。
 *   2.  使用 `switch` 语句根据 `req->tp` (请求类型) 执行不同的操作：
 *       -   **获取数据请求 (REQ_GETAllIPLogs, REQ_GETAllConns, REQ_GETAllIPRules, REQ_GETNATRules)**:
 *           调用相应的 `formAll...` 函数 (例如 `formAllIPLogs`) 来准备包含所请求数据的数据包。
 *           如果准备失败 (例如内存分配失败)，则向用户空间发送一条错误消息。
 *           如果成功，则使用 `nlSend` 将数据包发送给用户空间，并释放临时分配的内存。
 *       -   **添加规则请求 (REQ_ADDIPRule, REQ_ADDNATRule)**:
 *           调用相应的 `add...RuleToChain` 函数 (例如 `addIPRuleToChain`) 将规则添加到内核的规则链表中。
 *           根据操作结果 (成功或失败)，通过 `sendMsgToApp` 向用户空间发送状态消息。
 *       -   **删除规则请求 (REQ_DELIPRule, REQ_DELNATRule)**:
 *           调用相应的 `del...RuleFromChain` 函数从规则链表中删除规则。
 *           构建一个只包含头部的响应 (`RSP_Only_Head`)，其中 `arrayLen` 字段存储实际删除的规则数量。
 *           将此响应发送给用户空间。
 *       -   **设置默认动作请求 (REQ_SETAction)**:
 *           根据请求中指定的动作 (`req->msg.defaultAction`) 更新全局的 `DEFAULT_ACTION` 变量。
 *           向用户空间发送一条确认消息。
 *           调用 `dealWithSetAction` 执行与默认动作更改相关的附加操作（如清除连接）。
 *       -   **默认/未知请求**: 如果请求类型未知，向用户空间发送 "No such req." 消息。
 *   3.  函数返回发送给用户空间响应的长度。
 *
 *   此函数大量使用了 `printk` 进行内核日志记录，`kzalloc` 和 `kfree` 进行内存管理，
 *   以及 `nlSend` 和 `sendMsgToApp` 与用户空间进行通信。
 */
int dealAppMessage(unsigned int pid, void *msg, unsigned int len) {
    struct APPRequest *req;             // 指向应用程序请求结构体的指针
    struct KernelResponseHeader *rspH;  // 指向内核响应头部的指针
    void* mem;                          // 通用内存指针，用于存储待发送的数据
    unsigned int rspLen = 0;            // 响应消息的长度

    req = (struct APPRequest *) msg;    // 将接收到的void*消息转换为APPRequest类型指针

    switch (req->tp) // 根据请求类型 (req->tp) 进行分支处理
    {
    case REQ_GETAllIPLogs: // 请求：获取所有IP日志
        // 调用 formAllIPLogs 准备包含所有IP日志的数据包
        // req->msg.num 指定要获取的日志数量 (0表示所有)
        // rspLen 会被 formAllIPLogs 更新为实际数据包的长度
        mem = formAllIPLogs(req->msg.num, &rspLen);
        if(mem == NULL) { // 如果准备数据失败 (例如内存不足)
            printk(KERN_WARNING "[fw k2app] formAllIPLogs fail.\n");
            sendMsgToApp(pid, "form all logs fail."); // 向用户空间发送错误消息
            break; // 退出switch语句
        }
        nlSend(pid, mem, rspLen); // 将日志数据发送给用户空间
        kfree(mem); // 释放为日志数据分配的内存
        break;

    case REQ_GETAllConns: // 请求：获取所有连接信息
        mem = formAllConns(&rspLen); // 准备包含所有连接信息的数据包
        if(mem == NULL) {
            printk(KERN_WARNING "[fw k2app] formAllConns fail.\n");
            sendMsgToApp(pid, "form all conns fail.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;

    case REQ_GETAllIPRules: // 请求：获取所有IP规则
        mem = formAllIPRules(&rspLen); // 准备包含所有IP规则的数据包
        if(mem == NULL) {
            printk(KERN_WARNING "[fw k2app] formAllIPRules fail.\n");
            sendMsgToApp(pid, "form all rules fail.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;

    case REQ_ADDIPRule: // 请求：添加一条IP规则
        // req->ruleName 是新规则要插入到其后的规则名称 (空表示头部)
        // req->msg.ipRule 是要添加的IPRule结构体
        if(addIPRuleToChain(req->ruleName, req->msg.ipRule)==NULL) { // 调用函数添加规则
            // 如果添加失败 (例如，指定的前置规则不存在，或内存分配失败)
            rspLen = sendMsgToApp(pid, "Fail: no such rule or retry it."); // 发送失败消息
            printk("[fw k2app] add rule fail.\n");
        } else { // 如果添加成功
            rspLen = sendMsgToApp(pid, "Success."); // 发送成功消息
            printk("[fw k2app] add one rule success: %s.\n", req->msg.ipRule.name);
        }
        break;

    case REQ_DELIPRule: // 请求：删除一条IP规则
        rspLen = sizeof(struct KernelResponseHeader); // 响应包至少包含一个头部
        // 使用 GFP_KERNEL 分配内存，因为这里可能不在原子上下文，且分配较小
        rspH = (struct KernelResponseHeader *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) { // 检查内存分配
            printk(KERN_WARNING "[fw k2app] kzalloc fail.\n");
            sendMsgToApp(pid, "form rsp fail but del maybe success."); // 即使响应构建失败，删除可能已成功
            break;
        }
        rspH->bodyTp = RSP_Only_Head; // 设置响应体类型为“仅头部”
        // 调用 delIPRuleFromChain 删除指定名称 (req->ruleName) 的规则，并返回实际删除的数量
        rspH->arrayLen = delIPRuleFromChain(req->ruleName);
        printk("[fw k2app] success del %d rules.\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen); // 发送响应
        kfree(rspH); // 释放为响应头分配的内存
        break;

    case REQ_GETNATRules: // 请求：获取所有NAT规则
        mem = formAllNATRules(&rspLen); // 准备包含所有NAT规则的数据包
        if(mem == NULL) {
            printk(KERN_WARNING "[fw k2app] formAllNATRules fail.\n");
            sendMsgToApp(pid, "form all NAT rules fail.");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;

    case REQ_ADDNATRule: // 请求：添加一条NAT规则
        // req->msg.natRule 是要添加的NATRecord结构体
        if(addNATRuleToChain(req->msg.natRule)==NULL) { // 调用函数添加NAT规则
            rspLen = sendMsgToApp(pid, "Fail: please retry it."); // 发送失败消息
            printk("[fw k2app] add NAT rule fail.\n");
        } else {
            rspLen = sendMsgToApp(pid, "Success."); // 发送成功消息
            printk("[fw k2app] add one NAT rule success.\n");
        }
        break;

    case REQ_DELNATRule: // 请求：删除一条NAT规则
        rspLen = sizeof(struct KernelResponseHeader);
        rspH = (struct KernelResponseHeader *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "[fw k2app] kzalloc fail.\n");
            sendMsgToApp(pid, "form rsp fail but del maybe success.");
            break;
        }
        rspH->bodyTp = RSP_Only_Head;
        // req->msg.num 是要删除的NAT规则的序号
        rspH->arrayLen = delNATRuleFromChain(req->msg.num);
        printk("[fw k2app] success del %d NAT rules.\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;

    case REQ_SETAction: // 请求：设置默认防火墙动作
        if(req->msg.defaultAction == NF_ACCEPT) { // 如果请求设置为“允许”
            DEFAULT_ACTION = NF_ACCEPT; // 更新全局默认动作变量
            rspLen = sendMsgToApp(pid, "Set default action to ACCEPT.");
            printk("[fw k2app] Set default action to NF_ACCEPT.\n");
        } else { // 否则 (通常请求设置为 NF_DROP)
            DEFAULT_ACTION = NF_DROP; // 更新全局默认动作变量
            rspLen = sendMsgToApp(pid, "Set default action to DROP.");
            printk("[fw k2app] Set default action to NF_DROP.\n");
        }
        dealWithSetAction(DEFAULT_ACTION); // 调用函数处理默认动作更改后的附加操作
        break;

    default: // 如果请求类型未知
        rspLen = sendMsgToApp(pid, "No such req."); // 发送未知请求消息
        break;
    }
    return rspLen; // 返回发送给用户空间响应的长度
}