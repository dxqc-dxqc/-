/**
 * @file nat_hooks.c (Предполагаемое имя файла, так как оно не указано)
 * @brief Netfilter钩子函数实现，用于网络地址转换 (NAT)。
 *
 * 主要功能：
 * 此文件包含两个核心的Netfilter钩子函数：`hook_nat_in` 和 `hook_nat_out`。
 * 这些函数分别负责处理入站数据包的目的NAT (DNAT) 和出站数据包的源NAT (SNAT)。
 * 它们依赖于连接跟踪系统 (`connNode`, `hasConn`, `addConn`, `setConnNAT`) 和
 * NAT规则匹配 (`matchNATRule`, `getNewNATPort`, `genNATRecord`) 来实现有状态的NAT转换。
 *
 * - `hook_nat_in`: 注册在 `NF_INET_PRE_ROUTING` 钩子点，用于DNAT。
 *   它检查进入的数据包是否对应于一个已建立的、需要DNAT的连接。如果是，
 *   它会根据连接中存储的NAT记录修改数据包的目的IP地址和端口，并重新计算校验和。
 *
 * - `hook_nat_out`: 注册在 `NF_INET_POST_ROUTING` 钩子点，用于SNAT。
 *   对于出站数据包，它首先检查连接跟踪表中是否已存在SNAT记录。
 *   如果不存在，它会尝试匹配预定义的NAT规则。如果匹配成功，则会分配一个新的源端口，
 *   创建SNAT记录并存储在连接中，同时也会为返回流量创建相应的反向（DNAT）映射。
 *   然后，它修改数据包的源IP地址和端口，并重新计算校验和。
 *
 * 这两个函数是实现防火墙NAT功能的关键，它们确保了内部网络的主机能够通过
 * 单个公共IP地址访问外部网络，并且外部请求能够被正确地转发到内部网络的目标主机。
 */
#include "tools.h"  // 可能包含 getPort 等工具函数
#include "helper.h" // 包含连接跟踪 (connNode, hasConn, addConn, setConnNAT, addConnExpires, CONN_EXPIRES, CONN_NAT_TIMES),
                    // NAT规则处理 (NATRecord, matchNATRule, getNewNATPort, genNATRecord),
                    // 和常量 (NAT_TYPE_DEST, NAT_TYPE_SRC, NF_ACCEPT) 等的声明。
                    // 也需要 <linux/ip.h>, <linux/tcp.h>, <linux/udp.h>, <linux/icmp.h>,
                    // <linux/skbuff.h>, <net/checksum.h> (for ip_fast_csum, csum_tcpudp_magic, csum_partial),
                    // <linux/byteorder/generic.h> (for ntohs, htons, ntohl, htonl).
#include "hook.h"   // 可能包含这些钩子函数自身的声明。

/**
 * @brief Netfilter钩子函数，用于入站数据包的目的NAT (DNAT)。
 *        注册在 NF_INET_PRE_ROUTING 钩子点。
 *
 * @param priv 传递给钩子函数的私有数据指针 (在此示例中未使用)。
 * @param skb 指向当前正在被处理的网络数据包的套接字缓冲区 (`struct sk_buff`) 的指针。
 * @param state 指向 `struct nf_hook_state` 结构体的指针，包含了钩子操作的状态信息。
 * @return unsigned int 返回对该数据包的处理决定。
 *         - `NF_ACCEPT`: 表示数据包已被（可能）修改并允许继续在网络协议栈中处理。
 *         - (理论上可以是 `NF_DROP` 等，但此函数设计为修改后接受)。
 *
 * @功能描述:
 *   此函数处理入站数据包，执行DNAT操作。DNAT通常用于将公网IP和端口映射到内网服务器的私网IP和端口。
 *   1.  从 `skb` 中提取IP头部、源/目的IP地址、源/目的端口号和协议类型。
 *   2.  使用 `hasConn` 查找连接跟踪表中是否存在与此数据包（原始目的地址）匹配的连接。
 *       -   如果连接不存在，打印警告并直接返回 `NF_ACCEPT`。这通常不应该发生，因为DNAT
 *           的转换信息应该已经存储在为初始出站（或已配置的静态DNAT）连接创建的条目中，
 *           或者是在这里为返回流量查找反向映射时。对于一个全新的入站连接请求，除非有静态DNAT规则，
 *           否则它不会直接触发此处的DNAT逻辑（静态DNAT的匹配逻辑不在此函数中，此函数依赖连接跟踪）。
 *           此处的逻辑更像是处理一个已经通过SNAT出去的连接的返回包，其DNAT信息（即原始客户端的IP端口）
 *           已经记录在反向连接条目中。
 *   3.  如果连接存在，检查其 `natType` 是否为 `NAT_TYPE_DEST`。
 *       -   如果不是 `NAT_TYPE_DEST`，说明此连接不需要DNAT（或此方向的DNAT），直接返回 `NF_ACCEPT`。
 *   4.  如果 `natType` 是 `NAT_TYPE_DEST`，则从连接的 `nat` 字段获取 `NATRecord`。
 *       这条 `NATRecord` 中包含了原始的目的IP (`record.saddr` 在反向映射中) 和原始目的端口 (`record.sport` 在反向映射中)，
 *       以及此连接应该被DNAT到的新目的IP (`record.daddr`) 和新目的端口 (`record.dport`)。
 *       【修正理解】对于入站DNAT，`conn->nat` 应该存储的是：`saddr/sport`是公网被访问的IP/端口，`daddr/dport`是内网目标服务器的IP/端口。
 *   5.  **修改数据包**:
 *       -   将数据包IP头部的目的地址 (`header->daddr`) 修改为 `record.daddr` (内网目标IP)。
 *       -   重新计算IP头部的校验和 (`header->check`)。
 *       -   根据协议类型 (TCP或UDP):
 *           -   获取TCP/UDP头部指针。
 *           -   将TCP/UDP头部的目的端口修改为 `record.dport` (内网目标端口)。
 *           -   重新计算TCP/UDP校验和。
 *   6.  返回 `NF_ACCEPT`，允许修改后的数据包继续被路由到新的内部目的地。
 */
unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct connNode *conn;      // 指向连接跟踪条目的指针
    struct NATRecord record;    // 存储NAT转换记录
    unsigned short sport, dport;// 源端口和目的端口 (主机字节序)
    unsigned int sip, dip;      // 源IP和目的IP (主机字节序)
    u_int8_t proto;             // 协议类型
    struct tcphdr *tcpHeader;   // 指向TCP头的指针
    struct udphdr *udpHeader;   // 指向UDP头的指针
    int hdr_len, tot_len;       // IP头长度和IP总长度

    // 初始化：提取数据包信息
    struct iphdr *header = ip_hdr(skb); // 获取IP头指针
    getPort(skb,header,&sport,&dport);  // 获取源、目的端口
    sip = ntohl(header->saddr);         // 源IP (主机字节序)
    dip = ntohl(header->daddr);         // 目的IP (主机字节序)
    proto = header->protocol;           // 协议号

    // 查找连接池中是否有此连接的记录
    // 对于DNAT (入站)，我们期望找到一个已建立的映射关系
    conn = hasConn(sip, dip, sport, dport); // 使用原始的sip,dip,sport,dport查找
    if(conn == NULL) { // 如果连接表中不存在此连接
        // 这种情况理论上不应频繁发生，除非是未被跟踪的流量或连接已超时
        printk(KERN_WARNING "[fw nat] (in)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT; // 直接放行，不进行NAT
    }

    // 如果连接的NAT类型不是 NAT_TYPE_DEST，则此包不进行DNAT处理
    if(conn->natType != NAT_TYPE_DEST) {
        return NF_ACCEPT;
    }

    // 获取存储在连接条目中的DNAT转换记录
    record = conn->nat; // record.saddr/sport 是公网IP/端口, record.daddr/dport 是内网目标IP/端口

    // ---- 修改数据包目的地址和端口 ----
    // 1. 修改IP头部的目的地址
    header->daddr = htonl(record.daddr); // 将目的IP改为NAT记录中的目标内网IP (转换回网络字节序)

    // 2. 重新计算IP头部校验和
    hdr_len = header->ihl * 4;      // IP头部长度 (字节)
    tot_len = ntohs(header->tot_len); // IP数据包总长度 (主机字节序)
    header->check = 0;              // 清零校验和字段以便重新计算
    header->check = ip_fast_csum(header, header->ihl); // 计算IP头部校验和

    // 3. 修改传输层头部的目的端口并重新计算校验和
    switch(proto) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr *)(skb->data + hdr_len); // 获取TCP头部指针
            tcpHeader->dest = htons(record.dport); // 修改目的端口 (转换回网络字节序)
            // 重新计算TCP校验和
            tcpHeader->check = 0; // 清零校验和字段
            // 计算TCP伪头部校验和及数据部分校验和
            // skb->csum在这里用作临时存储部分校验和
            skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr, // 使用修改后(内网)的daddr
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case IPPROTO_UDP:
            udpHeader = (struct udphdr *)(skb->data + hdr_len); // 获取UDP头部指针
            udpHeader->dest = htons(record.dport); // 修改目的端口
            // 重新计算UDP校验和 (UDP校验和是可选的，但如果存在则必须正确)
            if (udpHeader->check) { // 仅当UDP校验和原先存在时才重新计算
                udpHeader->check = 0; // 清零
                skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
                udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                            tot_len - hdr_len, header->protocol, skb->csum);
                if (udpHeader->check == 0) udpHeader->check = CSUM_MANGLED_0; // RFC 768: 0表示无校验和，如果计算结果是0，则用0xFFFF表示
            }
            break;
        case IPPROTO_ICMP: // 对于ICMP，如果它封装了IP头部（例如错误消息），则内部IP头也可能需要NAT。
                           // 简单的ICMP请求/回应（如ping）通常不需要修改ICMP载荷，但ID字段可能与连接跟踪相关。
                           // 此处未处理ICMP载荷的修改。
        default:
            // 其他协议不修改传输层头部
            break;
    }
    // skb_clear_hash(skb); // 如果内核版本较高且使用了 offloading，可能需要清除硬件校验和标志
    return NF_ACCEPT; // 允许修改后的数据包通过
}

/**
 * @brief Netfilter钩子函数，用于出站数据包的源NAT (SNAT)。
 *        注册在 NF_INET_POST_ROUTING 钩子点。
 *
 * @param priv 传递给钩子函数的私有数据指针 (在此示例中未使用)。
 * @param skb 指向当前正在被处理的网络数据包的套接字缓冲区 (`struct sk_buff`) 的指针。
 * @param state 指向 `struct nf_hook_state` 结构体的指针，包含了钩子操作的状态信息。
 * @return unsigned int 返回对该数据包的处理决定。
 *         - `NF_ACCEPT`: 表示数据包已被（可能）修改并允许继续发送。
 *
 * @功能描述:
 *   此函数处理出站数据包，执行SNAT操作。SNAT通常用于将内网主机的多个私网IP地址映射到单个公网IP地址。
 *   1.  从 `skb` 中提取IP头部、源/目的IP地址、源/目的端口号和协议类型。
 *   2.  使用 `hasConn` 查找连接跟踪表中是否存在与此数据包匹配的连接。
 *       -   如果连接不存在，打印警告并直接返回 `NF_ACCEPT` (通常新连接应由 `hook_main` 创建)。
 *   3.  **确定NAT记录**:
 *       -   如果找到的连接 (`conn`) 的 `natType` 已经是 `NAT_TYPE_SRC`，说明此连接之前已经进行过SNAT，
 *           直接从 `conn->nat` 获取已有的 `NATRecord`。
 *       -   如果连接的 `natType` 不是 `NAT_TYPE_SRC` (例如是新连接或未NAT的连接):
 *           -   调用 `matchNATRule` 尝试匹配预定义的SNAT规则。
 *           -   如果未匹配到规则，或者规则指针为NULL，则此数据包不需要SNAT，返回 `NF_ACCEPT`。
 *           -   如果匹配到规则:
 *               -   如果源端口不为0 (即不是ICMP等无端口协议，或者需要端口转换)，调用 `getNewNATPort`
 *                   从匹配到的NAT规则的端口池中获取一个新的可用源端口。
 *               -   如果获取新端口失败 (例如端口耗尽)，打印警告并返回 `NF_ACCEPT` (放弃NAT)。
 *               -   使用 `genNATRecord` 创建一个新的 `NATRecord`，其中包含原始源IP/端口、
 *                   NAT规则中定义的转换后IP (通常是公网IP) 以及新分配的NAT端口。
 *               -   调用 `setConnNAT(conn, record, NAT_TYPE_SRC)` 将此SNAT记录与当前连接关联。
 *               -   更新NAT规则的 `nowPort` (如果 `getNewNATPort` 使用了某种状态来分配端口)。
 *   4.  **处理反向连接映射**: 为了让NAT的返回流量能够正确地被DNAT回原始内部主机：
 *       -   尝试使用转换后的五元组（原始目的IP/端口，新源NAT IP/端口）查找或创建反向连接条目。
 *           `reverseConn = hasConn(dip, record.daddr, dport, record.dport);`
 *           这里的 `record.daddr` 是SNAT后的源IP，`record.dport` 是SNAT后的源端口。
 *       -   如果反向连接条目不存在 (`reverseConn == NULL`):
 *           -   调用 `addConn` 创建这个反向连接条目。
 *           -   如果创建失败，打印警告并返回 `NF_ACCEPT` (SNAT可能已部分完成，但返回流量会出问题)。
 *           -   为这个反向连接条目设置NAT类型为 `NAT_TYPE_DEST`，并提供反向的NAT记录：
 *               `genNATRecord(record.daddr, sip, record.dport, sport)`，
 *               这个记录意味着当流量从外部到达 (SNAT后的源IP:SNAT后的源端口) 时，
 *               应将其目的地址改回原始内部主机的IP (`sip`) 和端口 (`sport`)。
 *   5.  更新原始连接 (`conn`) 和反向连接 (`reverseConn`) 的超时时间，NAT连接通常有较长的超时。
 *   6.  **修改数据包**:
 *       -   将数据包IP头部的源地址 (`header->saddr`) 修改为 `record.daddr` (SNAT后的公网IP)。
 *       -   重新计算IP头部的校验和。
 *       -   根据协议类型 (TCP或UDP):
 *           -   获取TCP/UDP头部指针。
 *           -   将TCP/UDP头部的源端口修改为 `record.dport` (SNAT后的新源端口)。
 *           -   重新计算TCP/UDP校验和。
 *   7.  返回 `NF_ACCEPT`，允许修改后的数据包从本机发出。
 */
unsigned int hook_nat_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct connNode *conn,*reverseConn; // 指向连接条目的指针 (当前连接和反向连接)
    struct NATRecord record;            // 存储SNAT转换记录
    int isMatch, hdr_len, tot_len;      // 规则是否匹配标志, IP头长度, IP总长度
    struct tcphdr *tcpHeader;           // 指向TCP头的指针
    struct udphdr *udpHeader;           // 指向UDP头的指针
    u_int8_t proto;                     // 协议类型
    unsigned int sip, dip;              // 源IP和目的IP (主机字节序)
    unsigned short sport, dport;        // 源端口和目的端口 (主机字节序)

    // 初始化：提取数据包信息
    struct iphdr *header = ip_hdr(skb);
    getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;

    // 查找连接池中是否有此连接的记录
    conn = hasConn(sip, dip, sport, dport);
    if(conn == NULL) { // 如果连接表中不存在此连接 (通常由hook_main创建)
        printk(KERN_WARNING "[fw nat] (out)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT; // 直接放行，不进行SNAT
    }

    // 确定SNAT记录
    if(conn->natType == NAT_TYPE_SRC) { // 如果此连接已经有SNAT记录 (例如，之前的数据包已触发SNAT)
        record = conn->nat; // 直接使用已有的记录
    } else { // 如果是新的需要SNAT的连接，或者之前未被SNAT的连接
        unsigned short newPort = 0; // 用于存储新分配的NAT端口
        // 尝试匹配SNAT规则 (基于原始源IP sip 和目的IP dip)
        struct NATRecord *rule = matchNATRule(sip, dip, &isMatch);
        if(!isMatch || rule == NULL) { // 如果没有匹配到SNAT规则
            return NF_ACCEPT; // 无需SNAT，直接放行
        }

        // 如果匹配到规则，需要为这个连接创建一个新的SNAT实例
        if(sport != 0) { // 对于有端口的协议 (TCP/UDP)
            newPort = getNewNATPort(*rule); // 从NAT规则的端口池中获取一个新端口
            if(newPort == 0) { // 如果获取新端口失败 (例如端口耗尽)
                printk(KERN_WARNING "[fw nat] get new port failed!\n");
                return NF_ACCEPT; // 放弃NAT
            }
        }
        // 生成SNAT记录：
        // rule->daddr 是NAT规则中定义的转换后的公网IP
        // newPort 是新分配的NAT端口
        record = genNATRecord(sip, rule->daddr, sport, newPort);

        // 将此SNAT记录与当前出向连接关联
        setConnNAT(conn, record, NAT_TYPE_SRC);
        // 更新NAT规则中当前已分配端口的记录 (如果getNewNATPort依赖此状态)
        // rule->nowPort = newPort; // 这行代码的实际作用取决于getNewNATPort和NATRecord规则的维护方式
                                  // 如果rule是共享的，这里修改可能会影响其他线程。通常端口分配应更原子化。
    }

    // ---- 处理/创建反向连接映射，用于返回流量的DNAT ----
    // 查找反向连接: (原始目的IP, SNAT后的源IP, 原始目的Port, SNAT后的源Port)
    // record.daddr 是SNAT后的IP, record.dport 是SNAT后的端口
    reverseConn = hasConn(dip, record.daddr, dport, record.dport);
    if(reverseConn == NULL) { // 如果反向连接条目不存在
        // 创建反向连接条目
        reverseConn = addConn(dip, record.daddr, dport, record.dport, proto, 0); // log=0，反向连接通常不主动记录日志
        if(reverseConn == NULL) { // 如果创建反向连接失败
            printk(KERN_WARNING "[fw nat] add reverse connection failed!\n");
            // SNAT本身可能已部分设置，但没有反向映射，返回流量会失败。
            // 理想情况下应回滚conn的NAT设置，但这里简单放弃。
            return NF_ACCEPT;
        }
        // 为反向连接设置DNAT信息：
        // 当流量从外部到达 (record.daddr:record.dport) 时，
        // 需要将其DNAT回原始内部主机的IP/端口 (sip:sport)。
        // genNATRecord(SNAT后的IP, 原始内部IP, SNAT后的Port, 原始内部Port)
        setConnNAT(reverseConn, genNATRecord(record.daddr, sip, record.dport, sport), NAT_TYPE_DEST);
    }

    // 更新原始连接和反向连接的超时时间，NAT连接通常需要更长的存活期
    addConnExpires(reverseConn, CONN_EXPIRES * CONN_NAT_TIMES);
    addConnExpires(conn, CONN_EXPIRES * CONN_NAT_TIMES);

    // ---- 修改数据包源地址和端口 ----
    // 1. 修改IP头部的源地址
    header->saddr = htonl(record.daddr); // record.daddr 是SNAT后的公网IP

    // 2. 重新计算IP头部校验和
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);

    // 3. 修改传输层头部的源端口并重新计算校验和
    switch(proto) {
        case IPPROTO_TCP:
            tcpHeader = (struct tcphdr *)(skb->data + hdr_len);
            tcpHeader->source = htons(record.dport); // record.dport 是SNAT后的新源端口
            tcpHeader->check = 0;
            skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
            // csum_tcpudp_magic 使用修改后的saddr (NAT IP) 和原始daddr
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case IPPROTO_UDP:
            udpHeader = (struct udphdr *)(skb->data + hdr_len);
            udpHeader->source = htons(record.dport);
            if (udpHeader->check) { // 仅当UDP校验和原先存在时才重新计算
                udpHeader->check = 0;
                skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
                udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                            tot_len - hdr_len, header->protocol, skb->csum);
                if (udpHeader->check == 0) udpHeader->check = CSUM_MANGLED_0;
            }
            break;
        case IPPROTO_ICMP: // 对于ICMP，特别是Echo Request/Reply，其ID字段可能被用于NAT会话匹配。
                           // 如果是封装了TCP/UDP的ICMP错误消息，内部的头部也需要修改。
                           // 此处未处理ICMP的特定NAT转换（如ID字段修改）。
        default:
            break;
    }
    // skb_clear_hash(skb);
    return NF_ACCEPT; // 允许修改后的数据包发出
}