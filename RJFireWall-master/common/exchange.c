#include "common.h"

/**
 * @brief 通过Netlink套接字与内核模块进行消息交换的核心函数
 * @param smsg 要发送到内核的消息数据指针
 * @param slen 发送消息数据的长度（字节）
 * @return struct KernelResponse 包含以下字段：
 *         - code: 正数表示响应体长度，负数表示错误码(ERROR_CODE_EXCHANGE)
 *         - data: 完整响应数据(包含头部+实际数据)
 *         - header: 指向响应头部的指针
 *         - body: 指向响应实际数据的指针
 * @note 函数执行流程：
 *       1. 创建并绑定Netlink套接字
 *       2. 构建Netlink消息头并填充发送数据
 *       3. 发送消息到内核并等待响应
 *       4. 解析响应数据并组织返回结构
 *       5. 错误处理贯穿整个流程，确保资源释放
 */
struct KernelResponse exchangeMsgK(void *smsg, unsigned int slen) {
    // 地址结构初始化
    struct sockaddr_nl local;  // 本地(用户空间)地址结构
    struct sockaddr_nl kpeer;  // 内核地址结构
    struct KernelResponse rsp; // 返回结果结构体
    int dlen;                 // 实际接收数据长度
    int kpeerlen = sizeof(struct sockaddr_nl); // 地址结构长度

    /* ---------- 1. 创建Netlink套接字 ---------- */
    // 创建NETLINK_MYFW协议的原始套接字
    int skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYFW);
    if (skfd < 0) {
        rsp.code = ERROR_CODE_EXCHANGE; // 套接字创建失败
        return rsp;
    }

    /* ---------- 2. 绑定本地地址 ---------- */
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;   // 协议族
    local.nl_pid = getpid();        // 使用当前进程ID作为标识
    local.nl_groups = 0;            // 不加入任何多播组
    
    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        close(skfd);
        rsp.code = ERROR_CODE_EXCHANGE; // 绑定失败
        return rsp;
    }

    /* ---------- 3. 配置内核地址结构 ---------- */
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;       // 内核端PID固定为0
    kpeer.nl_groups = 0;    // 无多播组

    /* ---------- 4. 构建发送消息 ---------- */
    // 分配消息内存(包含Netlink头和数据空间)
    struct nlmsghdr *message = (struct nlmsghdr *)malloc(NLMSG_SPACE(slen));
    if (!message) {
        close(skfd);
        rsp.code = ERROR_CODE_EXCHANGE; // 内存分配失败
        return rsp;
    }

    // 初始化消息头
    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(slen); // 总消息长度
    message->nlmsg_flags = 0;      // 无特殊标志
    message->nlmsg_type = 0;       // 消息类型(0表示无类型)
    message->nlmsg_seq = 0;        // 序列号(未使用)
    message->nlmsg_pid = local.nl_pid; // 发送方PID
    
    // 拷贝实际数据到消息体
    memcpy(NLMSG_DATA(message), smsg, slen);

    /* ---------- 5. 发送消息到内核 ---------- */
    if (!sendto(skfd, message, message->nlmsg_len, 0,
               (struct sockaddr *)&kpeer, sizeof(kpeer))) {
        close(skfd);
        free(message);
        rsp.code = ERROR_CODE_EXCHANGE; // 发送失败
        return rsp;
    }

    /* ---------- 6. 接收内核响应 ---------- */
    // 分配接收缓冲区(按最大负载预分配)
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh) {
        close(skfd);
        free(message);
        rsp.code = ERROR_CODE_EXCHANGE; // 内存分配失败
        return rsp;
    }

    // 阻塞接收内核响应
    if (!recvfrom(skfd, nlh, NLMSG_SPACE(MAX_PAYLOAD), 0,
                 (struct sockaddr *)&kpeer, (socklen_t *)&kpeerlen))) {
        close(skfd);
        free(message);
        free(nlh);
        rsp.code = ERROR_CODE_EXCHANGE; // 接收失败
        return rsp;
    }

    /* ---------- 7. 处理响应数据 ---------- */
    // 计算实际数据长度(减去Netlink头部)
    dlen = nlh->nlmsg_len - NLMSG_SPACE(0);
    
    // 分配存储空间
    rsp.data = malloc(dlen);
    if (!rsp.data) {
        close(skfd);
        free(message);
        free(nlh);
        rsp.code = ERROR_CODE_EXCHANGE; // 内存分配失败
        return rsp;
    }

    // 初始化并拷贝数据
    memset(rsp.data, 0, dlen);
    memcpy(rsp.data, NLMSG_DATA(nlh), dlen);

    // 设置返回结构字段
    rsp.code = dlen - sizeof(struct KernelResponseHeader); // 实际数据长度
    if (rsp.code < 0) {
        rsp.code = ERROR_CODE_EXCHANGE; // 长度异常处理
    }
    rsp.header = (struct KernelResponseHeader*)rsp.data; // 头部指针
    rsp.body = rsp.data + sizeof(struct KernelResponseHeader); // 数据指针

    /* ---------- 8. 资源清理 ---------- */
    close(skfd);      // 关闭套接字
    free(message);    // 释放发送缓冲区
    free(nlh);        // 释放接收缓冲区
    
    return rsp;       // 返回响应结构
}

/**
 * 关键数据结构说明：
 * 
 * 1. struct nlmsghdr (Netlink消息头)：
 *    - nlmsg_len:   消息总长度(含头部)
 *    - nlmsg_type:  消息类型(自定义)
 *    - nlmsg_flags: 标志位(NLM_F_*系列)
 *    - nlmsg_seq:   序列号(用于匹配请求响应)
 *    - nlmsg_pid:   发送方端口ID(通常为PID)
 * 
 * 2. struct KernelResponse：
 *    - code:     操作结果(正数为数据长度，负数为错误码)
 *    - data:     原始响应数据(包含自定义头部+实际数据)
 *    - header:   指向响应头部的指针
 *    - body:     指向实际数据部分的指针
 * 
 * 3. 内存布局示例：
 *    | Netlink头部 | 自定义头部 | 实际数据 |
 *       (nlmsghdr) (KernelResponseHeader) (response body)
 * 
 * 错误处理原则：
 * - 所有错误路径设置ERROR_CODE_EXCHANGE
 * - 保证已分配资源在返回前被释放
 * - 错误处理采用"短路返回"模式
 */