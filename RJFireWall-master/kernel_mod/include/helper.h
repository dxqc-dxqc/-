#ifndef _NETLINK_HELPER_H // 防止头文件被重复包含的预处理指令开始
#define _NETLINK_HELPER_H // 定义宏 _NETLINK_HELPER_H，表明该头文件已被包含

#include "dependency.h" // 包含另一个头文件 "dependency.h"，可能包含此文件所需的其他定义或库

// ---- APP 与 Kernel 通用协议 ------
// 定义了用户空间应用程序 (APP) 与内核模块之间通信时使用的协议常量和数据结构。

#define MAXRuleNameLen 11 // 定义IP规则名称的最大长度为11个字符。

// 定义请求类型常量，用于APP向内核发送请求时标识操作类型。
#define REQ_GETAllIPRules 1  // 请求：获取所有IP规则
#define REQ_ADDIPRule 2      // 请求：添加一条IP规则
#define REQ_DELIPRule 3      // 请求：删除一条IP规则
#define REQ_SETAction 4      // 请求：设置默认动作 (允许/拒绝)
#define REQ_GETAllIPLogs 5   // 请求：获取所有IP日志
#define REQ_GETAllConns 6    // 请求：获取所有连接信息
#define REQ_ADDNATRule 7     // 请求：添加一条NAT规则
#define REQ_DELNATRule 8     // 请求：删除一条NAT规则
#define REQ_GETNATRules 9    // 请求：获取所有NAT规则

// 定义响应类型常量，用于内核向APP发送响应时标识消息体内容类型。
#define RSP_Only_Head 10     // 响应：仅包含头部信息 (通常表示操作成功或失败，无额外数据)
#define RSP_MSG 11           // 响应：通用消息 (可能包含字符串等)
#define RSP_IPRules 12       // 响应：IP规则列表 (消息体是 IPRule 结构体数组)
#define RSP_IPLogs 13        // 响应：IP日志列表 (消息体是 IPLog 结构体数组)
#define RSP_NATRules 14      // 响应：NAT规则/记录列表 (消息体是 NATRecord 结构体数组)
#define RSP_ConnLogs 15      // 响应：连接日志/信息列表 (消息体是 ConnLog 结构体数组)

/**
 * @brief IP规则结构体 (IPRule)
 * @功能描述: 定义一条IP防火墙规则的各个属性。
 */
struct IPRule {
    char name[MAXRuleNameLen+1]; // 规则名称，长度为 MAXRuleNameLen + 1 (用于存放字符串结束符'\0')
    unsigned int saddr;          // 源IP地址 (网络字节序)
    unsigned int smask;          // 源IP地址子网掩码 (网络字节序)
    unsigned int daddr;          // 目的IP地址 (网络字节序)
    unsigned int dmask;          // 目的IP地址子网掩码 (网络字节序)
    unsigned int sport;          // 源端口号范围。高2字节表示最小端口，低2字节表示最大端口。0表示任意端口。
    unsigned int dport;          // 目的端口号范围。同上。0表示任意端口。
    u_int8_t protocol;           // 协议类型 (例如 TCP, UDP, ICMP)
    unsigned int action;         // 对匹配此规则的数据包采取的动作 (例如允许、拒绝)
    unsigned int log;            // 是否记录日志 (1表示记录，0表示不记录)
    struct IPRule* nx;           // 指向下一条IP规则的指针 (用于在内核中形成链表，在与用户空间交互时可能不直接使用)
};

/**
 * @brief IP日志结构体 (IPLog)
 * @功能描述: 定义一条IP包的日志记录信息。
 */
struct IPLog {
    long tm;                     // 时间戳 (记录日志的时间)
    unsigned int saddr;          // 源IP地址 (网络字节序)
    unsigned int daddr;          // 目的IP地址 (网络字节序)
    unsigned short sport;        // 源端口号 (网络字节序)
    unsigned short dport;        // 目的端口号 (网络字节序)
    u_int8_t protocol;           // 协议类型
    unsigned int len;            // 数据包长度
    unsigned int action;         // 对该数据包采取的动作
    struct IPLog* nx;            // 指向下一条IP日志的指针 (用于内核中可能的链式存储)
};

/**
 * @brief NAT记录或规则结构体 (NATRecord)
 * @功能描述: 用于定义网络地址转换 (NAT) 的规则或已建立的NAT转换记录。
 *           注释中区分了作为“记录”和作为“规则”时字段的不同含义。
 */
struct NATRecord {
    unsigned int saddr;         // 作为记录: 原始源IP地址 | 作为规则: 匹配的原始源IP地址
    unsigned int smask;         // 作为记录: 无实际作用   | 作为规则: 匹配的原始源IP的子网掩码
    unsigned int daddr;         // 作为记录: 转换后的源IP地址 | 作为规则: 用于NAT转换的目标源IP地址 (即转换后的IP)

    unsigned short sport;       // 作为记录: 原始源端口   | 作为规则: NAT端口范围的最小端口
    unsigned short dport;       // 作为记录: 转换后的源端口 | 作为规则: NAT端口范围的最大端口
    unsigned short nowPort;     // 作为记录: 当前实际使用的转换后端口 | 作为规则: 无实际作用
    struct NATRecord* nx;       // 指向下一条NAT记录/规则的指针 (用于内核中可能的链式存储)
};

/**
 * @brief 连接日志/信息结构体 (ConnLog)
 * @功能描述: 定义一条网络连接的详细信息，包括可能的NAT转换。
 */
struct ConnLog {
    unsigned int saddr;         // 连接的源IP地址
    unsigned int daddr;         // 连接的目的IP地址
    unsigned short sport;       // 连接的源端口号
    unsigned short dport;       // 连接的目的端口号
    u_int8_t protocol;          // 连接的协议类型
    int natType;                // NAT转换类型 (例如 NAT_TYPE_NO, NAT_TYPE_SRC)
    struct NATRecord nat;       // 该连接对应的NAT记录信息
};

/**
 * @brief 应用程序请求结构体 (APPRequest)
 * @功能描述: 用户空间应用程序向内核发送请求时使用的数据结构。
 */
struct APPRequest {
    unsigned int tp;                          // 请求类型 (使用上面定义的 REQ_* 常量)
    char ruleName[MAXRuleNameLen+1];          // 规则名称，用于删除或定位规则等操作
    union {                                   // 联合体，根据请求类型(tp)的不同，msg中存储不同的数据
        struct IPRule ipRule;                 // 当tp为 REQ_ADDIPRule 时，存储IP规则信息
        struct NATRecord natRule;             // 当tp为 REQ_ADDNATRule 时，存储NAT规则信息
        unsigned int defaultAction;           // 当tp为 REQ_SETAction 时，存储默认动作
        unsigned int num;                     // 通用数字参数，例如 REQ_GETAllIPLogs 时可能用于指定获取日志数量
    } msg;                                    // 请求的具体消息内容
};

/**
 * @brief 内核响应头部结构体 (KernelResponseHeader)
 * @功能描述: 内核向用户空间应用程序发送响应时，数据包中通用的头部信息。
 */
struct KernelResponseHeader {
    unsigned int bodyTp;     // 响应消息体的数据类型 (使用上面定义的 RSP_* 常量)
    unsigned int arrayLen;   // 如果消息体是数组 (如IPRule[]), 则表示数组的长度 (元素个数)
};

// 定义NAT转换类型的常量
#define NAT_TYPE_NO 0      // 没有进行NAT转换
#define NAT_TYPE_SRC 1     // 源NAT (SNAT)，修改源IP和/或源端口
#define NAT_TYPE_DEST 2    // 目的NAT (DNAT)，修改目的IP和/或目的端口 (此项目中可能未完全实现或使用)

// ----- netlink 相关 -----
// 这部分定义了与Netlink通信相关的常量和函数声明。

#include <linux/netlink.h> // 包含Linux Netlink库的头文件

// netlink 协议号
#define NETLINK_MYFW 17      // 自定义的Netlink协议类型编号，用于内核与用户空间特定应用通信。
                             // 这个值需要在系统中是唯一的，不能与已有的协议号冲突。

// 函数声明：
/**
 * @brief 初始化Netlink通信。
 * @return struct sock* Netlink套接字指针，失败则返回NULL。
 * @功能描述: 创建并配置内核端的Netlink套接字，用于接收和发送消息。
 */
struct sock *netlink_init(void);

/**
 * @brief 释放Netlink资源。
 * @return void
 * @功能描述: 关闭并释放在netlink_init中创建的Netlink套接字。
 */
void netlink_release(void);

/**
 * @brief 通过Netlink向用户空间进程发送数据。
 * @param pid 目标用户空间进程的ID。
 * @param data 指向要发送数据的指针。
 * @param len 要发送数据的长度。
 * @return int 发送成功则返回0或正数，失败则返回负数。
 * @功能描述: 内核模块使用此函数将数据通过Netlink发送给指定的用户空间应用程序。
 */
int nlSend(unsigned int pid, void *data, unsigned int len);


// ----- 应用交互相关 -------
// 这部分声明了处理从用户空间应用发来的消息以及准备数据返回给应用的核心逻辑函数。

/**
 * @brief 处理从用户空间应用通过Netlink接收到的消息。
 * @param pid 发送消息的用户空间进程ID。
 * @param msg 指向接收到的消息数据的指针 (通常是 struct APPRequest)。
 * @param len 消息数据的长度。
 * @return int 处理结果，通常0表示成功，负数表示错误。
 * @功能描述: 这是Netlink消息的主要处理入口，根据消息类型分发到不同的处理函数。
 */
int dealAppMessage(unsigned int pid, void *msg, unsigned int len);

/**
 * @brief 构建包含所有IP规则的数据包，用于发送给用户空间。
 * @param len [输出参数] 指向一个unsigned int的指针，函数会通过它返回构建的数据包的总长度。
 * @return void* 指向构建好的数据包的指针 (通常是 struct IPRule 数组，前面可能有一个 KernelResponseHeader)。如果无规则或失败，可能返回NULL。
 * @功能描述: 收集内核中当前所有的IP规则，并将其格式化为用户空间可解析的格式。
 */
void* formAllIPRules(unsigned int *len);

/**
 * @brief 将一条IP规则添加到防火墙规则链中。
 * @param after 一个字符串，指定新规则要插入到哪条现有规则之后。如果为空或特定值，可能表示添加到链表头部或尾部。
 * @param rule 要添加的IP规则 (struct IPRule)。
 * @return struct IPRule* 指向新添加的规则在链表中的节点，如果添加失败则返回NULL。
 * @功能描述: 在内核的IP规则链表中插入一条新的规则。
 */
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule);

/**
 * @brief 从防火墙规则链中删除指定名称的IP规则。
 * @param name 要删除的规则的名称。
 * @return int 成功删除返回0，未找到规则或删除失败返回负数。
 * @功能描述: 根据规则名称在内核的IP规则链表中查找并移除相应的规则。
 */
int delIPRuleFromChain(char name[]);

/**
 * @brief 构建包含指定数量IP日志的数据包，用于发送给用户空间。
 * @param num 要获取的日志条目数量。
 * @param len [输出参数] 指向一个unsigned int的指针，函数会通过它返回构建的数据包的总长度。
 * @return void* 指向构建好的数据包的指针 (通常是 struct IPLog 数组，前面可能有 KernelResponseHeader)。
 * @功能描述: 从内核日志缓存中获取最新的IP日志，并格式化。
 */
void* formAllIPLogs(unsigned int num, unsigned int *len);

/**
 * @brief 构建包含所有当前连接信息的数据包，用于发送给用户空间。
 * @param len [输出参数] 指向一个unsigned int的指针，函数会通过它返回构建的数据包的总长度。
 * @return void* 指向构建好的数据包的指针 (通常是 struct ConnLog 数组，前面可能有 KernelResponseHeader)。
 * @功能描述: 获取内核中当前跟踪的所有网络连接信息，并格式化。
 */
void* formAllConns(unsigned int *len);

/**
 * @brief 将一条NAT规则添加到NAT规则链中。
 * @param rule 要添加的NAT规则 (struct NATRecord)。
 * @return struct NATRecord* 指向新添加的NAT规则在链表中的节点，如果添加失败则返回NULL。
 * @功能描述: 在内核的NAT规则链表中插入一条新的规则。
 */
struct NATRecord * addNATRuleToChain(struct NATRecord rule);

/**
 * @brief 从NAT规则链中删除指定编号 (或特征) 的NAT规则。
 * @param num 用于标识要删除的NAT规则的编号或索引 (具体含义取决于实现)。
 * @return int 成功删除返回0，未找到或删除失败返回负数。
 * @功能描述: 从内核的NAT规则链表中移除指定的NAT规则。
 */
int delNATRuleFromChain(int num); // 参数num的具体含义需要看实现，可能是索引或唯一标识符

/**
 * @brief 构建包含所有NAT规则的数据包，用于发送给用户空间。
 * @param len [输出参数] 指向一个unsigned int的指针，函数会通过它返回构建的数据包的总长度。
 * @return void* 指向构建好的数据包的指针 (通常是 struct NATRecord 数组，前面可能有 KernelResponseHeader)。
 * @功能描述: 获取内核中当前配置的所有NAT规则，并格式化。
 */
void* formAllNATRules(unsigned int *len);


// ----- netfilter相关 -----
// 这部分声明了与Netfilter钩子函数交互、IP规则匹配和日志记录相关的函数。

// 最大缓存日志长度
#define MAX_LOG_LEN 1000 // 定义内核中IP日志缓存区的最大条目数量。

/**
 * @brief 在Netfilter钩子中匹配IP数据包与已定义的IP规则。
 * @param skb 指向当前正在被处理的网络数据包的套接字缓冲区 (struct sk_buff)。
 * @param isMatch [输出参数] 指向一个int的指针，函数通过它返回是否匹配到规则 (1表示匹配，0表示未匹配)。
 * @return struct IPRule 如果匹配到规则，则返回指向该匹配规则的指针；如果未匹配到任何规则，则返回NULL。
 * @功能描述: 遍历IP规则链表，检查传入的数据包是否符合某条规则的条件。
 */
struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch);

/**
 * @brief 添加一条IP日志到内核日志缓存中。
 * @param log 要添加的IP日志条目 (struct IPLog)。
 * @return int 成功添加返回0，缓存满或其他错误返回负数。
 * @功能描述: 将构造好的IPLog结构体存入内核的日志队列或数组中。
 */
int addLog(struct IPLog log);

/**
 * @brief 根据数据包信息和处理动作直接添加一条IP日志。
 * @param action 对该数据包采取的动作。
 * @param skb 指向当前网络数据包的套接字缓冲区。
 * @return int 成功添加返回0，失败返回负数。
 * @功能描述: 这是一个便捷函数，直接从sk_buff中提取信息并结合action来创建并添加IP日志。
 */
int addLogBySKB(unsigned int action, struct sk_buff *skb);


// ----- 连接池相关 --------
// 这部分定义了与网络连接跟踪 (connection tracking) 相关的常量、数据结构和函数声明。
// 连接跟踪用于记录和管理网络连接的状态，是实现有状态防火墙和NAT的基础。

#include <linux/rbtree.h> // 包含Linux内核红黑树库的头文件，连接池可能使用红黑树来高效存储和查找连接。

#define CONN_NEEDLOG 0x10      // 连接属性标志：表示此连接需要记录日志。
#define CONN_MAX_SYM_NUM 3     // 连接标识符 (conn_key_t) 的数组元素数量。通常用于存储源IP、目的IP、协议相关的组合键。
#define CONN_EXPIRES 7         // 新建连接或已有连接刷新时的默认存活时长（秒）。
#define CONN_NAT_TIMES 10      // NAT连接的超时时间相对于普通连接的倍率 (即NAT连接超时时间 = CONN_EXPIRES * CONN_NAT_TIMES)。
#define CONN_ROLL_INTERVAL 5   // 定期清理超时连接的定时器时间间隔（秒）。

// 定义连接的唯一标识符类型 conn_key_t。
// 它是一个包含 CONN_MAX_SYM_NUM 个 unsigned int 的数组。
// 通常这个key可能包含源IP、目的IP、源端口、目的端口、协议等组合信息，用于唯一识别一个连接。
// 这里的 CONN_MAX_SYM_NUM 为 3，具体存储内容需看实现。
typedef unsigned int conn_key_t[CONN_MAX_SYM_NUM];

/**
 * @brief 连接节点结构体 (connNode)
 * @功能描述: 代表连接池中的一个连接条目。通常存储在红黑树中以便快速查找。
 */
typedef struct connNode {
    struct rb_node node;    // 红黑树节点，用于将此结构嵌入到红黑树中。
    conn_key_t key;         // 连接的唯一标识符。
    unsigned long expires;  // 连接的绝对超时时间 (通常是jiffies值)。
    u_int8_t protocol;      // 连接的协议类型 (TCP, UDP等)，主要用于向用户空间展示。
    u_int8_t needLog;       // 标志位，指示此连接相关的包是否需要记录日志 (可能与CONN_NEEDLOG配合使用)。

    struct NATRecord nat;   // 如果此连接经过了NAT，这里存储相关的NAT转换记录。
    int natType;            // 此连接的NAT转换类型 (NAT_TYPE_SRC, NAT_TYPE_NO 等)。
} connNode;

// 宏：计算从现在开始 'plus' 秒之后的时间点 (以jiffies为单位)。
// jiffies 是内核中的一个全局变量，表示系统启动以来经过的时钟节拍数。
// HZ 是每秒的时钟节拍数。
#define timeFromNow(plus) (jiffies + ((plus) * HZ))

// 函数声明：

/**
 * @brief 初始化连接池。
 * @return void
 * @功能描述: 在模块加载时调用，用于创建和初始化连接池所需的数据结构 (如红黑树的根)。
 */
void conn_init(void);

/**
 * @brief 清理并退出连接池。
 * @return void
 * @功能描述: 在模块卸载时调用，用于释放连接池占用的所有资源，清除所有连接条目。
 */
void conn_exit(void);

/**
 * @brief 查找一个现有的连接。
 * @param sip 源IP地址。
 * @param dip 目的IP地址。
 * @param sport 源端口号。
 * @param dport 目的端口号。
 * @return struct connNode* 如果找到匹配的连接，则返回指向该连接节点的指针；否则返回NULL。
 * @功能描述: 根据连接的五元组 (或其派生key) 在连接池中查找是否存在活动连接。
 */
struct connNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
// 注意：hasConn 的参数列表可能不直接构成 conn_key_t，函数内部会转换。

/**
 * @brief 添加一个新的连接到连接池。
 * @param sip 源IP地址。
 * @param dip 目的IP地址。
 * @param sport 源端口号。
 * @param dport 目的端口号。
 * @param proto 协议类型。
 * @param log 是否需要记录日志的标志。
 * @return struct connNode* 成功添加则返回指向新创建的连接节点的指针；失败 (如内存不足) 则返回NULL。
 * @功能描述: 当一个新的、未被跟踪的连接首次出现时，调用此函数将其添加到连接池，并设置其初始超时时间。
 */
struct connNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);

/**
 * @brief 判断一个数据包是否匹配单条IP规则。
 * @param rule 指向要进行匹配的IP规则 (struct IPRule) 的指针。
 * @param sip 数据包的源IP地址。
 * @param dip 数据包的目的IP地址。
 * @param sport 数据包的源端口号。
 * @param dport 数据包的目的端口号。
 * @param proto 数据包的协议类型。
 * @return bool 如果数据包匹配该规则，返回true (或非0)；否则返回false (或0)。
 * @功能描述: 这是一个辅助函数，用于检查单个数据包的属性是否满足特定IP规则的条件。
 */
bool matchOneRule(struct IPRule *rule, unsigned int sip, unsigned int dip, unsigned short sport, unsigned int dport, u_int8_t proto);

/**
 * @brief 清除与指定IP规则相关的连接。
 * @param rule 一个IP规则 (struct IPRule)。
 * @return int 返回被清除的连接数量或操作状态码。
 * @功能描述: 当一条IP规则被删除或修改时，可能需要清除连接池中所有基于该旧规则建立的连接。
 *           此函数遍历连接池，移除那些如果按照新规则集本不应存在的连接。
 */
int eraseConnRelated(struct IPRule rule);

/**
 * @brief 延长一个连接的超时时间。
 * @param node 指向要刷新超时时间的连接节点 (struct connNode) 的指针。
 * @param plus 要额外增加的存活时长（秒）。
 * @return void
 * @功能描述: 当一个已存在的连接上有新的数据包活动时，调用此函数来更新其超时时间，防止其过早被清理。
 */
void addConnExpires(struct connNode *node, unsigned int plus);


// ---- NAT 初始操作相关 ----
// 这部分声明了与NAT操作（特别是源NAT的端口分配和规则匹配）相关的函数。

/**
 * @brief为一个连接设置NAT转换信息。
 * @param node 指向连接节点 (struct connNode) 的指针。
 * @param record NAT转换的具体记录 (struct NATRecord)，包含了转换前后的IP和端口。
 * @param natType NAT转换的类型 (NAT_TYPE_SRC 等)。
 * @return int 操作成功返回0，失败返回负数。
 * @功能描述: 当一个连接需要进行NAT时，此函数更新连接节点中的NAT相关信息。
 */
int setConnNAT(struct connNode *node, struct NATRecord record, int natType);

/**
 * @brief 匹配数据包与已定义的NAT规则。
 * @param sip 数据包的原始源IP地址。
 * @param dip 数据包的原始目的IP地址 (对于SNAT，目的IP通常不参与规则匹配，但可能用于更复杂的场景)。
 * @param isMatch [输出参数] 指向一个int的指针，函数通过它返回是否匹配到NAT规则 (1表示匹配，0表示未匹配)。
 * @return struct NATRecord* 如果匹配到NAT规则，则返回指向该NAT规则的指针；否则返回NULL。
 * @功能描述: 遍历NAT规则链表，检查出向数据包是否符合某条SNAT规则的条件。
 */
struct NATRecord *matchNATRule(unsigned int sip, unsigned int dip, int *isMatch);

/**
 * @brief 为NAT转换获取一个新的可用源端口。
 * @param rule 匹配到的NAT规则 (struct NATRecord)，其中定义了可用的端口范围。
 * @return unsigned short 返回一个可用的转换后源端口号。如果端口耗尽或出错，可能返回0或特定错误值。
 * @功能描述: 根据NAT规则中定义的端口范围，并考虑当前已使用的端口，分配一个新的、未被占用的端口用于SNAT。
 */
unsigned short getNewNATPort(struct NATRecord rule);

/**
 * @brief 生成一个NAT记录结构体。
 * @param preIP 原始IP地址。
 * @param afterIP 转换后的IP地址。
 * @param prePort 原始端口号。
 * @param afterPort 转换后的端口号。
 * @return struct NATRecord 返回填充好的NATRecord结构体。
 * @功能描述: 这是一个辅助函数，用于方便地创建一个NATRecord结构体实例。
 */
struct NATRecord genNATRecord(unsigned int preIP, unsigned int afterIP, unsigned short prePort, unsigned short afterPort);

#endif // _NETLINK_HELPER_H 结束条件预处理指令