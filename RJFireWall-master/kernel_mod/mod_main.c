/**
 * @file kernel_module_main.c (Предполагаемое имя файла, так как оно не указано)
 * @brief Linux内核防火墙与NAT模块的主体文件。
 *
 * 主要功能：
 * 此文件是Linux内核模块的入口点和出口点，负责初始化和清理防火墙及NAT功能所需的核心组件。
 * 它执行以下关键操作：
 * 1.  **定义Netfilter钩子操作**: 声明并初始化多个 `struct nf_hook_ops` 结构体。
 *     这些结构体定义了在网络协议栈的不同点（钩子点）应该执行哪些函数（钩子函数），
 *     以及它们的协议族（IPv4）和优先级。
 *     -   `nfop_in` 和 `nfop_out`: 用于主要的IP包过滤逻辑，分别注册在 `NF_INET_PRE_ROUTING`
 *         (数据包刚进入网络栈，路由决策之前) 和 `NF_INET_POST_ROUTING` (数据包在路由决策之后，
 *         即将离开本机之前) 钩子点，使用 `hook_main` 函数。
 *     -   `natop_in` 和 `natop_out`: 用于NAT（网络地址转换）逻辑，分别注册在
 *         `NF_INET_PRE_ROUTING` (用于DNAT，在路由前修改目的地址) 和 `NF_INET_POST_ROUTING`
 *         (用于SNAT，在路由后修改源地址) 钩子点，使用 `hook_nat_in` 和 `hook_nat_out` 函数，
 *         并具有特定的NAT优先级。
 * 2.  **模块初始化 (`mod_init`)**:
 *     -   在模块加载时被调用。
 *     -   打印模块加载信息到内核日志。
 *     -   使用 `nf_register_net_hook` 函数将上面定义的四个Netfilter钩子操作注册到内核网络栈中，
 *         使其能够拦截和处理网络数据包。
 *     -   调用 `netlink_init()` 初始化Netlink通信接口，用于内核模块与用户空间应用程序的交互。
 *     -   调用 `conn_init()` 初始化连接跟踪机制，用于管理和跟踪网络连接状态。
 * 3.  **模块退出 (`mod_exit`)**:
 *     -   在模块卸载时被调用。
 *     -   打印模块卸载信息到内核日志。
 *     -   使用 `nf_unregister_net_hook` 函数从内核网络栈中注销之前注册的四个Netfilter钩子，
 *         停止数据包拦截。
 *     -   调用 `netlink_release()` 释放Netlink通信资源。
 *     -   调用 `conn_exit()` 清理连接跟踪机制的资源。
 * 4.  **模块元数据**:
 *     -   使用 `MODULE_LICENSE("GPL")` 声明模块的许可证。
 *     -   使用 `MODULE_AUTHOR("jyq")` 声明模块的作者。
 *     -   使用 `module_init(mod_init)` 和 `module_exit(mod_exit)` 宏指定模块的初始化和退出函数。
 *
 * 此文件是整个内核防火墙/NAT模块能够工作的基石，它将自定义的数据包处理逻辑（通过钩子函数）
 * 插入到Linux内核的网络处理流程中。
 */
#include "dependency.h" // 可能包含一些共享的定义或内核头文件
#include "hook.h"       // 包含钩子函数 (hook_main, hook_nat_in, hook_nat_out) 的声明
#include "helper.h"     // 包含 netlink_init, netlink_release, conn_init, conn_exit 等辅助函数的声明
                        // 同时也需要包含 <linux/module.h>, <linux/kernel.h>, <linux/netfilter.h>,
                        // <linux/netfilter_ipv4.h> 等内核头文件，这些可能已包含在 "dependency.h" 中。

// ---- Netfilter 钩子操作结构体定义 ----

/**
 * @brief `nfop_in`: Netfilter钩子操作结构体，用于入站数据包的过滤 (在PRE_ROUTING点)。
 *        此钩子在数据包刚进入网络协议栈，进行路由决策之前被调用。
 */
static struct nf_hook_ops nfop_in={
	.hook		= hook_main,		// hook: 指定当数据包到达此钩子点时要调用的函数 (主要的过滤逻辑)。
	.pf		= PF_INET,		// pf (Protocol Family): 指定协议族为 PF_INET (IPv4)。
	.hooknum	= NF_INET_PRE_ROUTING,	// hooknum: 指定Netfilter的钩子点为 NF_INET_PRE_ROUTING。
	.priority	= NF_IP_PRI_FIRST	// priority: 指定此钩子在此钩子点的优先级。
						// NF_IP_PRI_FIRST 表示尽可能早地执行此钩子。
};

/**
 * @brief `nfop_out`: Netfilter钩子操作结构体，用于出站数据包的过滤 (在POST_ROUTING点)。
 *        此钩子在数据包经过路由决策，即将离开本机之前被调用。
 */
static struct nf_hook_ops nfop_out={
	.hook		= hook_main,		// hook: 同样使用 hook_main 函数进行过滤。
	.pf		= PF_INET,		// pf: 协议族为 IPv4。
	.hooknum	= NF_INET_POST_ROUTING,	// hooknum: 钩子点为 NF_INET_POST_ROUTING。
	.priority	= NF_IP_PRI_FIRST	// priority: 优先级为尽可能早。
};

/**
 * @brief `natop_in`: Netfilter钩子操作结构体，用于入站数据包的NAT处理 (主要用于DNAT，在PRE_ROUTING点)。
 *        此钩子在数据包路由决策之前被调用，允许修改目的地址/端口。
 */
static struct nf_hook_ops natop_in={
	.hook		= hook_nat_in,		// hook: 指定NAT入站处理函数 hook_nat_in。
	.pf		= PF_INET,		// pf: 协议族为 IPv4。
	.hooknum	= NF_INET_PRE_ROUTING,	// hooknum: 钩子点为 NF_INET_PRE_ROUTING。
	.priority	= NF_IP_PRI_NAT_DST	// priority: 指定优先级为 NF_IP_PRI_NAT_DST。
						// 这是Netfilter为DNAT操作定义的标准优先级，确保在其他过滤操作之前或合适的时机执行DNAT。
};

/**
 * @brief `natop_out`: Netfilter钩子操作结构体，用于出站数据包的NAT处理 (主要用于SNAT，在POST_ROUTING点)。
 *        此钩子在数据包路由决策之后，即将离开本机之前被调用，允许修改源地址/端口。
 */
static struct nf_hook_ops natop_out={
	.hook		= hook_nat_out,		// hook: 指定NAT出站处理函数 hook_nat_out。
	.pf		= PF_INET,		// pf: 协议族为 IPv4。
	.hooknum	= NF_INET_POST_ROUTING,	// hooknum: 钩子点为 NF_INET_POST_ROUTING。
	.priority	= NF_IP_PRI_NAT_SRC	// priority: 指定优先级为 NF_IP_PRI_NAT_SRC。
						// 这是Netfilter为SNAT操作定义的标准优先级。
};

/**
 * @brief 模块初始化函数 (`mod_init`)。
 *        当内核模块被加载 (例如通过 `insmod`) 时，此函数会被自动调用。
 *
 * @return int 返回0表示初始化成功，返回非0错误码表示初始化失败，模块将无法加载。
 *
 * @功能描述:
 *   1.  向内核日志打印一条消息，表明模块已加载。
 *   2.  调用 `nf_register_net_hook` 函数，将 `nfop_in`, `nfop_out`, `natop_in`, `natop_out`
 *       这四个Netfilter钩子操作注册到当前网络命名空间 (`&init_net`) 的IPv4协议栈中。
 *       注册成功后，这些钩子函数就能开始拦截和处理网络数据包。
 *   3.  调用 `netlink_init()` 来初始化Netlink套接字，以便内核模块可以与用户空间应用程序通信。
 *   4.  调用 `conn_init()` 来初始化连接跟踪系统所需的数据结构和定时器等。
 *   5.  返回0表示所有初始化步骤成功完成。
 */
static int mod_init(void){
	printk("my firewall module loaded.\n"); // 向内核日志输出模块加载信息

	// 注册Netfilter钩子
	// nf_register_net_hook(&init_net, &nf_hook_ops_struct)
	// &init_net: 指向默认网络命名空间的指针。
	nf_register_net_hook(&init_net,&nfop_in);   // 注册入站过滤钩子
	nf_register_net_hook(&init_net,&nfop_out);  // 注册出站过滤钩子
	nf_register_net_hook(&init_net,&natop_in);  // 注册入站NAT钩子 (DNAT)
	nf_register_net_hook(&init_net,&natop_out); // 注册出站NAT钩子 (SNAT)

	netlink_init(); // 初始化Netlink通信接口
	conn_init();    // 初始化连接跟踪系统

	return 0; // 返回0表示初始化成功
}

/**
 * @brief 模块退出函数 (`mod_exit`)。
 *        当内核模块被卸载 (例如通过 `rmmod`) 时，此函数会被自动调用。
 *
 * @return void 无返回值。
 *
 * @功能描述:
 *   1.  向内核日志打印一条消息，表明模块正在退出。
 *   2.  调用 `nf_unregister_net_hook` 函数，注销之前在 `mod_init` 中注册的四个Netfilter钩子。
 *       这会从网络协议栈中移除模块的数据包处理逻辑。
 *   3.  调用 `netlink_release()` 来关闭Netlink套接字并释放相关资源。
 *   4.  调用 `conn_exit()` 来清理连接跟踪系统的所有状态和资源，例如释放连接条目、停止定时器等。
 */
static void mod_exit(void){
	printk("my firewall module exit.\n"); // 向内核日志输出模块退出信息

	// 注销Netfilter钩子
	nf_unregister_net_hook(&init_net,&nfop_in);
	nf_unregister_net_hook(&init_net,&nfop_out);
	nf_unregister_net_hook(&init_net,&natop_in);
	nf_unregister_net_hook(&init_net,&natop_out);

	netlink_release(); // 释放Netlink资源
	conn_exit();       // 清理连接跟踪系统

}

// ---- 内核模块元数据 ----
MODULE_LICENSE("GPL");        // 声明模块的许可证为GPL。这是内核模块常用的许可证。
MODULE_AUTHOR("jyq");         // 声明模块的作者。
module_init(mod_init);        // 宏，用于注册 `mod_init` 函数作为模块的初始化入口点。
module_exit(mod_exit);        // 宏，用于注册 `mod_exit` 函数作为模块的退出清理入口点。