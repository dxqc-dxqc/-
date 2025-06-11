#include "tools.h"  // 包含自定义的工具函数头文件 (可能包含 getPort 等函数的定义)
#include "helper.h" // 包含之前注释过的 netlink_helper.h 或类似文件，定义了 IPRule, connNode, matchIPRules, hasConn, addConn, addLogBySKB 等
#include "hook.h"   // 包含此钩子函数自身相关的声明或 Netfilter 注册信息 (可能)

// 定义默认的防火墙动作，初始化为 NF_ACCEPT，表示默认允许所有数据包通过。
// NF_ACCEPT 和 NF_DROP 是 Netfilter 定义的宏，分别代表接受和丢弃数据包。
unsigned int DEFAULT_ACTION = NF_ACCEPT;

/**
 * @brief hook_main Netfilter 钩子函数
 *
 * @param priv 传递给钩子函数的私有数据指针 (在此示例中未使用)。
 * @param skb 指向当前正在被处理的网络数据包的套接字缓冲区 (struct sk_buff) 的指针。
 * @param state 指向 nf_hook_state 结构体的指针，包含了钩子操作的状态信息 (如钩子号、协议族等)。
 * @return unsigned int 返回对该数据包的处理决定，通常是 NF_ACCEPT (接受) 或 NF_DROP (丢弃)。
 *
 * @功能描述:
 *   此函数是注册到 Netfilter 指定钩子点（例如 PREROUTING, FORWARD, POSTROUTING 等）的处理函数。
 *   每当有网络数据包到达该钩子点时，此函数就会被调用。
 *   其主要逻辑是：
 *   1. 从数据包中提取源/目的IP地址和端口号。
 *   2. 检查连接池中是否已存在该数据包对应的连接记录。
 *      - 如果存在，并且该连接标记为需要日志，则记录日志，然后直接接受 (NF_ACCEPT) 该数据包，以提高效率。
 *   3. 如果连接池中不存在该连接，则尝试匹配已定义的IP防火墙规则。
 *      - 如果匹配到规则：
 *          - 根据规则设置处理动作 (action)，可能是接受或丢弃。
 *          - 如果规则要求记录日志，则记录日志。
 *   4. 如果最终的动作是接受 (NF_ACCEPT)，则将此新连接添加到连接池中，并标记是否需要日志。
 *   5. 返回最终确定的处理动作 (action)。
 */
unsigned int hook_main(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct IPRule rule;             // 用于存储匹配到的IP规则。
    struct connNode *conn;          // 指向连接池中查找到的连接节点的指针。
    unsigned short sport, dport;    // 分别存储源端口号和目的端口号。
    unsigned int sip, dip, action = DEFAULT_ACTION; // sip: 源IP, dip: 目的IP, action: 对数据包的最终处理动作，默认为 DEFAULT_ACTION。
    int isMatch = 0;                // 标志位，指示是否匹配到IP规则 (0: 未匹配, 1: 匹配)。
    int isLog = 0;                  // 标志位，指示此数据包是否需要记录日志 (0: 不需要, 1: 需要)。

    // 初始化
	// ip_hdr(skb): 从 sk_buff 中获取IP头部的指针。
	struct iphdr *header = ip_hdr(skb);
	// getPort(skb, header, &sport, &dport): 自定义函数 (可能在 tools.h 中定义)，
	// 用于从 skb 和 IP 头部中提取传输层 (TCP/UDP) 的源端口和目的端口。
	// 注意：此函数需要能正确处理不同协议 (如TCP, UDP, ICMP) 以及分片等情况。
	// 对于ICMP等没有端口的协议，sport 和 dport 可能会被设置为0或特定值。
	getPort(skb, header, &sport, &dport);
    // ntohl(header->saddr): 将IP头部中的源IP地址从网络字节序转换为主机字节序。
    sip = ntohl(header->saddr);
    // ntohl(header->daddr): 将IP头部中的目的IP地址从网络字节序转换为主机字节序。
    dip = ntohl(header->daddr);

    // 查询是否有已有连接
    // hasConn(sip, dip, sport, dport): 调用连接池的函数，检查是否存在与当前数据包五元组匹配的活动连接。
    conn = hasConn(sip, dip, sport, dport);
    if(conn != NULL) { // 如果找到了已存在的连接
        if(conn->needLog) { // 如果此连接被标记为需要记录日志
            // addLogBySKB(action, skb): 根据当前数据包和确定的动作 (这里因为是已有连接，通常是NF_ACCEPT) 记录日志。
            // 注意：这里的 action 还是初始的 DEFAULT_ACTION (NF_ACCEPT)。如果已有连接本身有特定策略，这里可能需要调整。
            // 但通常对于已建立的连接，快速路径是直接接受。
            addLogBySKB(NF_ACCEPT, skb); // 对于已存在的连接，我们通常直接接受它，并按需记录日志
        }
        // 对于已存在且活跃的连接，通常快速放行，不再进行规则匹配。
        // 同时，hasConn 内部可能已经刷新了该连接的超时时间。
        return NF_ACCEPT; // 返回接受，数据包继续在协议栈中处理。
    }

    // 如果没有找到已存在的连接，则需要进行规则匹配
    // matchIPRules(skb, &isMatch): 调用IP规则匹配函数。
    // skb: 当前数据包。
    // &isMatch: 输出参数，如果匹配到规则，*isMatch 会被设置为1。
    // 返回值: 如果匹配成功，返回匹配到的 IPRule 结构体副本；否则内容未定义或为特定初始值。
    rule = matchIPRules(skb, &isMatch);
    if(isMatch) { // 如果匹配到了一条规则
        // printk(KERN_DEBUG ...): 内核打印调试信息，显示匹配到的规则名称。
        printk(KERN_DEBUG "[fw netfilter] patch rule %s.\n", rule.name);
        // 根据匹配到的规则设置处理动作。
        // rule.action 存储的是规则定义的动作 (应该是 NF_ACCEPT 或 NF_DROP)。
        action = (rule.action == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
        if(rule.log) { // 如果规则要求记录日志
            isLog = 1; // 设置日志标记为1
            // addLogBySKB(action, skb): 根据当前数据包和规则决定的动作记录日志。
            addLogBySKB(action, skb);
        }
    }
    // 如果 isMatch 为 0 (即没有匹配到任何自定义规则)，action 将保持为 DEFAULT_ACTION。

    // 更新连接池
    if(action == NF_ACCEPT) { // 如果最终的处理动作是接受数据包
        // addConn(sip, dip, sport, dport, header->protocol, isLog):
        // 将这个新的连接添加到连接池中。
        // header->protocol: IP头部中的协议字段 (例如 IPPROTO_TCP, IPPROTO_UDP)。
        // isLog: 传递之前根据规则确定的日志标记，新连接将继承此日志属性。
        addConn(sip, dip, sport, dport, header->protocol, isLog);
    }

    // 返回最终的处理动作给Netfilter框架。
    // 如果是 NF_DROP，数据包将被丢弃。
    // 如果是 NF_ACCEPT，数据包将继续沿协议栈向上传递或转发。
    return action;
}