#include "helper.h" // 包含头文件 "helper.h"，可能定义了此文件中使用的某些结构或函数

// 定义一个静态的套接字指针 nlsk，用于 Netlink 通信。初始化为 NULL。
static struct sock *nlsk = NULL;

/**
 * @brief nlSend 函数用于通过 Netlink 向用户空间进程发送数据。
 *
 * @param pid 目标用户空间进程的ID。
 * @param data 指向要发送数据的指针。
 * @param len 要发送数据的长度。
 * @return int 发送成功则返回0或正数，失败则返回负数错误码。
 *
 * @功能描述:
 *   1. 分配一个新的 Netlink 消息缓冲区 (sk_buff)。
 *   2. 如果分配失败，则打印警告信息并返回 -1。
 *   3. 使用 nlmsg_put 构建 Netlink 消息头。
 *   4. 将要发送的数据 (data) 拷贝到 Netlink 消息的数据部分。
 *   5. 设置 Netlink 控制块 (NETLINK_CB) 的目标组为0 (表示单播)。
 *   6. 使用 netlink_unicast 将消息单播到指定 pid 的用户空间进程。
 *   7. 打印发送信息，包括目标PID、数据长度和发送结果。
 *   8. 返回 netlink_unicast 的结果。
 */
int nlSend(unsigned int pid, void *data, unsigned int len) {
	int retval; // 用于存储函数返回值
	struct nlmsghdr *nlh; // 指向 Netlink 消息头的指针
	struct sk_buff *skb; // 指向套接字缓冲区的指针

	// 初始化 sk_buff
	// nlmsg_new: 分配一个新的 Netlink 消息，参数 len 是数据负载的长度，GFP_ATOMIC 表示在原子上下文中分配内存，不能睡眠。
	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) { // 检查分配是否成功
		printk(KERN_WARNING "[fw netlink] alloc reply nlmsg skb failed!\n"); // 分配失败，打印警告
		return -1; // 返回错误码
	}

	// nlmsg_put: 向 sk_buff 中添加一个 Netlink 消息头。
	// skb: 套接字缓冲区。
	// 0: 发送进程的PID (内核通常为0)。
	// 0: 序列号。
	// 0: 消息类型 (这里未使用特定类型)。
	// NLMSG_SPACE(len) - NLMSG_HDRLEN: 数据负载的长度。NLMSG_SPACE(len) 计算包含头部的总长度。
	// 0: 消息标志。
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);

	// 发送数据
	// NLMSG_DATA(nlh): 获取 Netlink 消息数据部分的指针。
	// memcpy: 将用户提供的数据 (data) 拷贝到消息的数据区。
	memcpy(NLMSG_DATA(nlh), data, len);

    //NETLINK_CB(skb).portid = 0; // 通常用于设置源端口ID，这里注释掉了。
	NETLINK_CB(skb).dst_group = 0; // 设置目标组为0，表示这是一个单播消息，而不是多播到某个组。

	// netlink_unicast: 将 Netlink 消息单播到指定的用户空间进程。
	// nlsk: Netlink 套接字。
	// skb: 要发送的套接字缓冲区。
	// pid: 目标用户空间进程的PID。
	// MSG_DONTWAIT: 非阻塞发送。
	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);

	// 打印发送日志信息
	// nlh->nlmsg_len - NLMSG_SPACE(0): 计算实际发送的数据负载长度。NLMSG_SPACE(0) 实际上是 NLMSG_HDRLEN。
	printk("[fw netlink] send to user pid=%d,len=%d,ret=%d\n", pid, nlh->nlmsg_len - NLMSG_SPACE(0), retval);

	return retval; // 返回发送结果
}

/**
 * @brief nlRecv 函数是 Netlink 套接字接收到消息时的回调函数。
 *
 * @param skb 指向接收到的套接字缓冲区 (struct sk_buff) 的指针。
 * @return void 无返回值。
 *
 * @功能描述:
 *   1. 从 skb 中获取 Netlink 消息头 (nlh)。
 *   2. 校验接收到的 Netlink 数据包的合法性 (长度是否足够)。
 *   3. 如果数据包非法，则打印警告信息并返回。
 *   4. 从消息头中提取数据负载 (data)、发送方PID (pid) 和数据长度 (len)。
 *   5. 校验数据长度是否至少为一个 APPRequest 结构的大小。
 *   6. 如果数据长度不足，则打印警告信息并返回。
 *   7. 打印接收到的数据信息。
 *   8. 调用 dealAppMessage 函数处理来自用户空间应用的消息。
 */
void nlRecv(struct sk_buff *skb) {
	void *data; // 指向接收到的数据的指针
	struct nlmsghdr *nlh = NULL; // 指向 Netlink 消息头的指针
	unsigned int pid,len; // 用于存储发送方PID和数据长度

    // 检查 skb
    // nlmsg_hdr(skb): 从 skb 中获取 Netlink 消息头。
    nlh = nlmsg_hdr(skb);
	// 校验数据包长度是否合法
	// nlh->nlmsg_len: Netlink 消息头中记录的总长度 (包括头部和数据)。
	// NLMSG_HDRLEN: Netlink 消息头的标准长度。
	// skb->len: 套接字缓冲区中实际接收到的数据总长度。
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk(KERN_WARNING "[fw netlink] Illegal netlink packet!\n"); // 非法数据包，打印警告
		return; // 直接返回，不处理
	}

    // 处理数据
	// NLMSG_DATA(nlh): 获取 Netlink 消息数据部分的指针。
	data = NLMSG_DATA(nlh);
    // nlh->nlmsg_pid: 获取发送该 Netlink 消息的用户空间进程的PID。
    pid = nlh->nlmsg_pid;
    // nlh->nlmsg_len - NLMSG_SPACE(0): 计算数据负载的实际长度。
    len = nlh->nlmsg_len - NLMSG_SPACE(0); // NLMSG_SPACE(0) 实际上是 NLMSG_HDRLEN

	// 检查接收到的数据长度是否小于 APPRequest 结构体的大小
	// 假设 APPRequest 是一个定义在别处的结构体，用于用户空间和内核空间通信。
	if(len < sizeof(struct APPRequest)) {
		printk(KERN_WARNING "[fw netlink] packet size < APPRequest!\n"); // 数据包过小，打印警告
		return; // 直接返回
	}

	// 打印接收日志信息
	printk("[fw netlink] data receive from user: user_pid=%d, len=%d\n", pid, len);

	// 调用 dealAppMessage 函数处理从用户空间接收到的应用消息。
	// pid: 发送消息的用户进程ID。
	// data: 指向消息数据的指针。
	// len: 消息数据的长度。
	// (此函数 dealAppMessage 的定义不在此代码片段中)
	dealAppMessage(pid, data, len);
}

// 定义 Netlink 内核配置结构体 nltest_cfg
struct netlink_kernel_cfg nltest_cfg = {
	.groups = 0,         // 多播组掩码，0表示不加入任何预定义的多播组。
	.flags = 0,          // 配置标志，通常为0。
	.input = nlRecv,     // 指定接收到 Netlink 消息时的回调函数为 nlRecv。
	.bind = NULL,        // 当用户空间套接字绑定到此内核 Netlink 协议时调用的回调函数，这里为NULL。
	.unbind = NULL,      // 当用户空间套接字解绑时调用的回调函数，这里为NULL。
	// .cb_mutex: (较新内核中可能有) 用于保护回调函数的互斥锁，这里未指定，则使用默认。
	// .compare: (较新内核中可能有) 用于比较skb的函数，这里未指定。
};

/**
 * @brief netlink_init 函数用于初始化 Netlink 套接字。
 *
 * @param void 无参数。
 * @return struct sock* 初始化成功则返回创建的 Netlink 套接字指针，失败则返回 NULL。
 *
 * @功能描述:
 *   1. 调用 netlink_kernel_create 创建一个内核空间的 Netlink 套接字。
 *      - &init_net: 网络命名空间，通常是 init_net。
 *      - NETLINK_MYFW: 自定义的 Netlink 协议类型 (应在头文件中定义，例如 #define NETLINK_MYFW 30)。
 *      - &nltest_cfg: 指向 Netlink 内核配置结构体的指针。
 *   2. 检查套接字是否创建成功。
 *   3. 如果创建失败，打印警告信息并返回 NULL。
 *   4. 如果创建成功，打印成功信息和套接字指针地址。
 *   5. 将创建的套接字赋值给全局变量 nlsk。
 *   6. 返回创建的套接字指针。
 */
struct sock *netlink_init() {
    // netlink_kernel_create: 创建一个内核 Netlink 套接字。
    // &init_net: 指定网络命名空间，通常是默认的 init_net。
    // NETLINK_MYFW: 自定义的 Netlink 协议号 (例如 17, 18... 最大值通常是 MAX_LINKS-1，一般选择一个未被使用的值)。
    // &nltest_cfg: Netlink 内核配置，包含了输入回调函数等。
    nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsk) { // 检查套接字是否创建成功
		printk(KERN_WARNING "[fw netlink] can not create a netlink socket\n"); // 创建失败，打印警告
		return NULL; // 返回 NULL
	}
	printk("[fw netlink] netlink_kernel_create() success, nlsk = %p\n", nlsk); // 创建成功，打印信息
    return nlsk; // 返回创建的套接字
}

/**
 * @brief netlink_release 函数用于释放之前创建的 Netlink 套接字。
 *
 * @param void 无参数。
 * @return void 无返回值。
 *
 * @功能描述:
 *   调用 netlink_kernel_release 释放由 nlsk 指向的 Netlink 套接字。
 */
void netlink_release() {
    // netlink_kernel_release: 释放一个内核 Netlink 套接字。
    // nlsk: 要释放的套接字。
    netlink_kernel_release(nlsk);
}