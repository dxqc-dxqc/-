/**
 * @file common_app.h
 * @brief 公共头文件，定义用户空间应用程序与内核防火墙/NAT模块通信的协议、数据结构及接口函数。
 *
 * 主要功能：
 * 1. 定义用户空间应用程序与内核模块之间通过Netlink进行通信时所使用的请求类型、响应类型常量。
 * 2. 定义双方共享的数据结构，如IP规则 (IPRule)、IP日志 (IPLog)、NAT记录/规则 (NATRecord)、连接日志 (ConnLog)、应用请求包 (APPRequest) 和内核响应头 (KernelResponseHeader)。
 * 3. 定义NAT转换类型常量。
 * 4. 定义用户空间应用程序专用的常量，如Netlink协议号、最大负载大小、错误码等。
 * 5. 定义一个用于封装内核响应的数据结构 (KernelResponse)。
 * 6. 声明一个核心的与内核交换数据的函数 (exchangeMsgK)。
 * 7. 声明一系列封装好的与内核交互的接口函数，方便上层应用调用以管理防火墙规则、NAT规则、获取日志和连接信息等。
 * 8. 声明一些IP地址格式转换的工具函数。
 *
 * 此头文件旨在为用户空间应用程序提供一套完整的与内核模块交互的规范和便捷接口。
 */
#ifndef _COMMON_APP_H // 防止头文件被重复包含的预处理指令开始
#define _COMMON_APP_H // 定义宏 _COMMON_APP_H，表明该头文件已被包含

// ---- 标准库及系统库头文件 ----
#include <stdio.h>      // 标准输入输出库 (例如 printf)
#include <stdlib.h>     // 标准库 (例如 malloc, free, exit)
#include <string.h>     // 字符串处理库 (例如 memcpy, strcmp)
#include <time.h>       // 时间相关函数库 (例如 time_t)
#include <unistd.h>     // POSIX 操作系统API (例如 close, read, write)
#include <sys/types.h>  // 基本系统数据类型 (例如 pid_t, size_t)
#include <sys/socket.h> // 套接字接口 (例如 socket, send, recv)
#include <linux/types.h>  // Linux 特有的数据类型 (例如 __u8, __u32)
#include <linux/in.h>     // IP协议相关定义 (例如 struct sockaddr_in)
#include <linux/netfilter.h> // Netfilter 框架相关定义 (例如 NF_ACCEPT, NF_DROP)
#include <linux/netlink.h> // Netlink 套接字相关定义 (例如 struct sockaddr_nl, struct nlmsghdr)

// ---- APP 与 Kernel 通用协议 ------
// 这部分定义了用户空间应用程序 (APP) 与内核模块之间通信时使用的协议常量和数据结构。

#define MAXRuleNameLen 11 // 定义IP规则名称的最大长度为11个字符。

// 定义请求类型常量，用于APP向内核发送请求时标识操作类型。
#define REQ_GETAllIPRules 1  // 请求：获取所有IP规则
#define REQ_ADDIPRule 2      // 请求：添加一条IP规则
#define REQ_DELIPRule 3      // 请求：删除一条IP规则
#define REQ_SETAction 4      // 请求：设置默认防火墙动作 (允许/拒绝)
#define REQ_GETAllIPLogs 5   // 请求：获取所有IP日志
#define REQ_GETAllConns 6    // 请求：获取所有当前连接信息
#define REQ_ADDNATRule 7     // 请求：添加一条NAT规则
#define REQ_DELNATRule 8     // 请求：删除一条NAT规则
#define REQ_GETNATRules 9    // 请求：获取所有NAT规则

// 定义响应类型常量，用于内核向APP发送响应时标识消息体内容类型。
#define RSP_Only_Head 10     // 响应：仅包含头部信息 (通常表示操作成功或失败，无额外数据体)
#define RSP_MSG 11           // 响应：通用消息 (消息体可能包含字符串等，用于传递简单文本信息)
#define RSP_IPRules 12       // 响应：IP规则列表 (消息体是 IPRule 结构体数组)
#define RSP_IPLogs 13        // 响应：IP日志列表 (消息体是 IPLog 结构体数组)
#define RSP_NATRules 14      // 响应：NAT规则/记录列表 (消息体是 NATRecord 结构体数组)
#define RSP_ConnLogs 15      // 响应：连接日志/信息列表 (消息体是 ConnLog 结构体数组)

/**
 * @brief IP规则结构体 (IPRule)
 * @功能描述: 定义一条IP防火墙规则的各个属性。
 *           此结构体在用户空间和内核空间之间传递。
 */
struct IPRule {
    char name[MAXRuleNameLen+1]; // 规则名称，长度为 MAXRuleNameLen + 1 (用于存放字符串结束符'\0')
    unsigned int saddr;          // 源IP地址 (网络字节序)
    unsigned int smask;          // 源IP地址子网掩码 (网络字节序)
    unsigned int daddr;          // 目的IP地址 (网络字节序)
    unsigned int dmask;          // 目的IP地址子网掩码 (网络字节序)
    unsigned int sport;          // 源端口号范围。高2字节表示最小端口，低2字节表示最大端口。0表示任意端口。
    unsigned int dport;          // 目的端口号范围。同上。0表示任意端口。
    u_int8_t protocol;           // 协议类型 (例如 TCP, UDP, ICMP，通常使用 IPPROTO_* 常量)
    unsigned int action;         // 对匹配此规则的数据包采取的动作 (例如 NF_ACCEPT, NF_DROP)
    unsigned int log;            // 是否记录日志 (1表示记录，0表示不记录)
    struct IPRule* nx;           // 指向下一条IP规则的指针。主要用于内核内部形成链表，
                                 // 在用户空间接收到规则数组时，此字段可能为NULL或无意义。
};

/**
 * @brief IP日志结构体 (IPLog)
 * @功能描述: 定义一条IP包的日志记录信息。
 *           此结构体用于从内核传递日志信息到用户空间。
 */
struct IPLog {
    long tm;                     // 时间戳 (记录日志的时间，通常是自Epoch以来的秒数)
    unsigned int saddr;          // 源IP地址 (网络字节序)
    unsigned int daddr;          // 目的IP地址 (网络字节序)
    unsigned short sport;        // 源端口号 (网络字节序)
    unsigned short dport;        // 目的端口号 (网络字节序)
    u_int8_t protocol;           // 协议类型
    unsigned int len;            // IP数据包的负载长度 (IP总长度 - IP头长度)
    unsigned int action;         // 对该数据包采取的动作 (例如 NF_ACCEPT, NF_DROP)
    struct IPLog* nx;            // 指向下一条IP日志的指针。主要用于内核内部可能的链式存储，
                                 // 在用户空间接收到日志数组时，此字段可能为NULL或无意义。
};

/**
 * @brief NAT记录或规则结构体 (NATRecord)
 * @功能描述: 用于定义网络地址转换 (NAT) 的规则或已建立的NAT转换记录。
 *           注释中区分了作为“记录”和作为“规则”时字段的不同含义。
 *           此结构体在用户空间和内核空间之间传递。
 */
struct NATRecord {
    // 以下字段在作为“NAT记录”（已发生的转换）和“NAT规则”（待匹配的策略）时含义有所不同：
    unsigned int saddr;         // 作为记录: 原始源IP地址 | 作为规则: 匹配的原始源IP地址
    unsigned int smask;         // 作为记录: 无实际作用   | 作为规则: 匹配的原始源IP的子网掩码
    unsigned int daddr;         // 作为记录: 转换后的源IP地址 | 作为规则: 用于NAT转换的目标源IP地址 (即SNAT后的IP)

    unsigned short sport;       // 作为记录: 原始源端口   | 作为规则: NAT端口范围的最小端口 (用于SNAT端口选择)
    unsigned short dport;       // 作为记录: 转换后的源端口 | 作为规则: NAT端口范围的最大端口 (用于SNAT端口选择)
    unsigned short nowPort;     // 作为记录: 当前实际使用的转换后端口 | 作为规则: 无实际作用
    struct NATRecord* nx;       // 指向下一条NAT记录/规则的指针。主要用于内核内部可能的链式存储，
                                 // 在用户空间接收到数组时，此字段可能为NULL或无意义。
};

/**
 * @brief 连接日志/信息结构体 (ConnLog)
 * @功能描述: 定义一条网络连接的详细信息，包括可能的NAT转换。
 *           此结构体用于从内核传递当前活动连接的信息到用户空间。
 */
struct ConnLog {
    unsigned int saddr;         // 连接的源IP地址 (网络字节序)
    unsigned int daddr;         // 连接的目的IP地址 (网络字节序)
    unsigned short sport;       // 连接的源端口号 (网络字节序)
    unsigned short dport;       // 连接的目的端口号 (网络字节序)
    u_int8_t protocol;          // 连接的协议类型
    int natType;                // NAT转换类型 (参考下面的 NAT_TYPE_* 常量)
    struct NATRecord nat;       // 如果该连接经过了NAT，这里存储相关的NAT转换记录信息。
};

/**
 * @brief 应用程序请求结构体 (APPRequest)
 * @功能描述: 用户空间应用程序向内核发送请求时使用的数据结构。
 *           它包含一个请求类型和根据类型变化的联合体消息体。
 */
struct APPRequest {
    unsigned int tp;                          // 请求类型 (使用上面定义的 REQ_* 常量)
    char ruleName[MAXRuleNameLen+1];          // 规则名称，用于需要按名称操作的请求 (如删除IP规则)。
                                              // 对于其他请求，此字段可能未使用或有其他含义。
    union {                                   // 联合体，根据请求类型(tp)的不同，msg中存储不同的数据
        struct IPRule ipRule;                 // 当tp为 REQ_ADDIPRule 时，存储IP规则信息
        struct NATRecord natRule;             // 当tp为 REQ_ADDNATRule 时，存储NAT规则信息
        unsigned int defaultAction;           // 当tp为 REQ_SETAction 时，存储默认动作 (NF_ACCEPT 或 NF_DROP)
        unsigned int num;                     // 通用数字参数，例如 REQ_GETAllIPLogs 时用于指定获取日志数量
    } msg;                                    // 请求的具体消息内容
};

/**
 * @brief 内核响应头部结构体 (KernelResponseHeader)
 * @功能描述: 内核向用户空间应用程序发送响应时，数据包中通用的头部信息。
 *           此头部之后紧跟着实际的响应数据体（如果存在）。
 */
struct KernelResponseHeader {
    unsigned int bodyTp;     // 响应消息体的数据类型 (使用上面定义的 RSP_* 常量)
    unsigned int arrayLen;   // 如果消息体是数组 (如IPRule[], IPLog[]等), 则表示数组的长度 (元素个数)。
                             // 如果不是数组，此值通常为1或0。
};

// 定义NAT转换类型的常量
#define NAT_TYPE_NO 0      // 没有进行NAT转换
#define NAT_TYPE_SRC 1     // 源NAT (SNAT)，修改源IP和/或源端口
#define NAT_TYPE_DEST 2    // 目的NAT (DNAT)，修改目的IP和/或目的端口 (此项目中可能未完全实现或主要用于SNAT)

// ----- 上层应用专用 ------
// 这部分定义了用户空间应用程序特有的常量和数据结构。

#define uint8_t unsigned char // 为 u_int8_t 定义一个别名 (尽管 <linux/types.h> 中已有 __u8)
#define NETLINK_MYFW 17      // 自定义的Netlink协议类型编号。用户空间和内核空间必须使用相同的协议号进行通信。
#define MAX_PAYLOAD (1024 * 256) // 定义Netlink消息的最大负载大小 (256KB)。

// 定义应用程序层面的错误码
#define ERROR_CODE_EXIT -1         // 通用退出错误码
#define ERROR_CODE_EXCHANGE -2     // 与内核交换信息失败 (例如Netlink通信故障)
#define ERROR_CODE_WRONG_IP -11    // 提供的IP地址格式错误
#define ERROR_CODE_NO_SUCH_RULE -12 // 尝试操作一个不存在的规则

/**
 * @brief 内核回应包结构体 (KernelResponse)
 * @功能描述: 用于封装从内核接收到的响应数据。
 *           它包含了处理结果代码以及指向实际数据的指针。
 */
struct KernelResponse {
    int code;                            // 响应代码:
                                         //  - 如果 < 0, 表示请求失败，值为具体的错误码 (参考上面的ERROR_CODE_*或内核定义的其他错误)。
                                         //  - 如果 >= 0, 表示请求成功，值为响应数据体(body)的长度 (字节数)。
                                         //    如果响应仅有头部(如RSP_Only_Head)，则长度可能为0。
    void *data;                          // 指向从内核接收到的完整数据块的指针 (包含KernelResponseHeader和实际数据体)。
                                         // **重要**: 这个 `data` 指针指向的内存是由 `exchangeMsgK` 分配的，使用完毕后需要调用 `free(resp.data)` 来释放。
    struct KernelResponseHeader *header; // 指向 `data` 内存块中 KernelResponseHeader 部分的指针。
                                         // **注意**: 不需要单独释放 `header`，因为它指向 `data` 的一部分。
    void *body;                          // 指向 `data` 内存块中实际数据体 (KernelResponseHeader 之后的部分) 的指针。
                                         // **注意**: 不需要单独释放 `body`，因为它指向 `data` 的一部分。
};

/**
 * @brief 与内核交换数据 (通过Netlink)
 * @param smsg 指向要发送给内核的消息数据 (通常是一个 struct APPRequest) 的指针。
 * @param slen 要发送的消息数据的长度 (字节数)。
 * @return struct KernelResponse 返回一个 KernelResponse 结构体，包含了内核的响应。
 *         调用者需要检查 `resp.code` 来判断操作是否成功，并负责在处理完响应后 `free(resp.data)`。
 * @功能描述:
 *   此函数负责通过Netlink套接字向内核模块发送请求消息，并接收内核模块的响应。
 *   它处理Netlink消息的封装、发送、接收和初步解析，并将结果包装在 KernelResponse 结构体中返回。
 */
struct KernelResponse exchangeMsgK(void *smsg, unsigned int slen);

// ----- 与内核交互函数 -----
// 以下函数是对 exchangeMsgK 的进一步封装，提供了更语义化的接口来执行特定操作。
// 它们内部会构建相应的 APPRequest 结构体，调用 exchangeMsgK，并返回 KernelResponse。

/**
 * @brief 新增一条IP过滤规则到内核。
 * @param after 指向现有规则名称的字符串，新规则将插入到此规则之后。如果为NULL或空字符串，可能表示添加到链表头部或尾部 (具体行为由内核实现决定)。
 * @param name 新规则的名称字符串。
 * @param sip 源IP地址字符串 (例如 "192.168.1.0/24" 或 "192.168.1.100")。
 * @param dip 目的IP地址字符串 (格式同sip)。
 * @param sport 源端口范围。高2字节为最小端口，低2字节为最大端口。0表示任意端口。
 *              例如，端口80: (80 << 16) | 80。范围80-90: (80 << 16) | 90。
 * @param dport 目的端口范围。编码方式同sport。
 * @param proto 协议类型 (例如 IPPROTO_TCP, IPPROTO_UDP)。
 * @param log 是否记录日志 (1表示记录，0表示不记录)。
 * @param action 对匹配数据包采取的动作 (NF_ACCEPT 或 NF_DROP)。
 * @return struct KernelResponse 内核的响应。
 * @功能描述: 构建一个添加IP规则的请求发送给内核。
 */
struct KernelResponse addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action);

/**
 * @brief 从内核删除指定名称的IP过滤规则。
 * @param name 要删除的规则的名称字符串。
 * @return struct KernelResponse 内核的响应。
 * @功能描述: 构建一个删除IP规则的请求发送给内核。
 */
struct KernelResponse delFilterRule(char *name);

/**
 * @brief 从内核获取所有已定义的IP过滤规则。
 * @return struct KernelResponse 内核的响应。响应的 `body` 部分将包含 `IPRule` 结构体数组。
 * @功能描述: 构建一个获取所有IP规则的请求发送给内核。
 */
struct KernelResponse getAllFilterRules(void);

/**
 * @brief 新增一条NAT规则到内核 (主要用于SNAT)。
 * @param sip 要进行NAT的原始源IP地址/子网字符串 (例如 "192.168.1.0/24")。
 * @param natIP SNAT转换后的目标源IP地址字符串 (例如 "202.100.10.1")。
 * @param minport SNAT可用的最小端口号。
 * @param maxport SNAT可用的最大端口号。
 * @return struct KernelResponse 内核的响应。
 * @功能描述: 构建一个添加NAT规则的请求发送给内核。
 */
struct KernelResponse addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport);

/**
 * @brief 从内核删除指定编号的NAT规则。
 * @param num 要删除的NAT规则的编号或索引 (具体含义由内核实现决定)。
 * @return struct KernelResponse 内核的响应。
 * @功能描述: 构建一个删除NAT规则的请求发送给内核。
 */
struct KernelResponse delNATRule(int num);

/**
 * @brief 从内核获取所有已定义的NAT规则。
 * @return struct KernelResponse 内核的响应。响应的 `body` 部分将包含 `NATRecord` 结构体数组。
 * @功能描述: 构建一个获取所有NAT规则的请求发送给内核。
 */
struct KernelResponse getAllNATRules(void);

/**
 * @brief 设置内核防火墙的默认动作。
 * @param action 默认动作 (NF_ACCEPT 或 NF_DROP)。
 * @return struct KernelResponse 内核的响应。
 * @功能描述: 构建一个设置默认防火墙策略的请求发送给内核。
 */
struct KernelResponse setDefaultAction(unsigned int action);

/**
 * @brief 从内核获取IP日志。
 * @param num 要获取的日志条目数量。如果 num=0，则表示获取所有可用的日志。
 * @return struct KernelResponse 内核的响应。响应的 `body` 部分将包含 `IPLog` 结构体数组。
 * @功能描述: 构建一个获取IP日志的请求发送给内核。
 */
struct KernelResponse getLogs(unsigned int num);

/**
 * @brief 从内核获取所有当前活动的连接信息。
 * @return struct KernelResponse 内核的响应。响应的 `body` 部分将包含 `ConnLog` 结构体数组。
 * @功能描述: 构建一个获取所有连接信息的请求发送给内核。
 */
struct KernelResponse getAllConns(void);

// ----- 一些工具函数 ------
// 以下函数为辅助函数，主要用于IP地址字符串和整数表示之间的转换。

/**
 * @brief 将IP地址字符串 (如 "192.168.1.1/24" 或 "192.168.1.1") 转换为整数形式的IP地址和子网掩码。
 * @param ipStr 指向输入的IP地址字符串的指针。
 * @param ip [输出参数] 指向用于存储转换后的IP地址 (网络字节序) 的 unsigned int 的指针。
 * @param mask [输出参数] 指向用于存储转换后的子网掩码 (网络字节序) 的 unsigned int 的指针。如果输入字符串中没有掩码，则可能设为0xFFFFFFFF或0。
 * @return int 成功返回0，失败返回错误码 (例如 ERROR_CODE_WRONG_IP)。
 * @功能描述: 解析IP地址字符串，提取IP地址和可选的子网掩码，并将其转换为整数形式。
 */
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask);

/**
 * @brief 将整数形式的IP地址和子网掩码转换为点分十进制的IP地址字符串 (例如 "192.168.1.1/24")。
 * @param ip 要转换的IP地址 (网络字节序)。
 * @param mask 要转换的子网掩码 (网络字节序)。如果mask为0或0xFFFFFFFF，可能只输出IP地址。
 * @param ipStr [输出参数] 指向用于存储转换后的IP地址字符串的字符数组的指针。调用者需保证足够空间。
 * @return int 成功返回0，失败返回错误码。
 * @功能描述: 将整数表示的IP和掩码格式化为标准的点分十进制字符串。
 */
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr);

/**
 * @brief 将整数形式的IP地址转换为点分十进制的IP地址字符串 (不带掩码)。
 * @param ip 要转换的IP地址 (网络字节序)。
 * @param ipStr [输出参数] 指向用于存储转换后的IP地址字符串的字符数组的指针。
 * @return int 成功返回0，失败返回错误码。
 * @功能描述: 将整数表示的IP格式化为点分十进制字符串。
 */
int IPint2IPstrNoMask(unsigned int ip, char *ipStr);

/**
 * @brief 将整数形式的IP地址和端口号转换为 "IP:Port" 格式的字符串。
 * @param ip 要转换的IP地址 (网络字节序)。
 * @param port 端口号 (主机字节序)。
 * @param ipStr [输出参数] 指向用于存储转换后的 "IP:Port" 字符串的字符数组的指针。
 * @return int 成功返回0，失败返回错误码。
 * @功能描述: 将整数IP和端口号格式化为 "A.B.C.D:PORT" 形式的字符串。
 */
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr);

#endif // _COMMON_APP_H 结束条件预处理指令