#include "tools.h"  // 包含自定义的工具函数头文件 (可能包含 getPort 等函数的定义)
#include "helper.h" // 包含之前注释过的 netlink_helper.h 或类似文件，定义了 IPLog, KernelResponseHeader, RSP_IPLogs, MAX_LOG_LEN 等
#include <linux/timekeeping.h> // 包含内核时间相关的头文件，用于获取当前时间戳 (ktime_get_real_ts64)

// ---- 全局日志管理变量 ----
// logHead: 指向IP日志链表的头节点。
static struct IPLog *logHead = NULL;
// logTail: 指向IP日志链表的尾节点。
static struct IPLog *logTail = NULL;
// logNum: 当前日志链表中存储的日志条目数量。
static unsigned int logNum = 0;
// logLock: 定义一个读写锁，用于保护对日志链表 (logHead, logTail, logNum) 的并发访问，确保线程安全。
static DEFINE_RWLOCK(logLock); // DEFINE_RWLOCK 是内核提供的宏，用于静态初始化一个读写锁。

/**
 * @brief rollLog 函数用于整理日志链表，当日志数量超过最大限制 (MAX_LOG_LEN) 时，
 *        从链表头部移除多余的旧日志节点，以释放空间。
 *
 * @param void 无参数。
 * @return int 返回被移除的日志节点数量。
 *
 * @功能描述:
 *   1. 打印一条调试信息，表示正在整理日志链表。
 *   2. 获取写锁 (write_lock)，因为此操作会修改链表结构和数量。
 *   3. 循环检查当前日志数量 (logNum) 是否大于最大允许长度 (MAX_LOG_LEN)。
 *      - 如果链表头指针 (logHead) 为NULL (异常情况，可能意味着链表已损坏或逻辑错误)，
 *        尝试将 logHead 和 logTail 重置，并更新 logNum。然后释放锁并返回。
 *      - 正常情况下，保存当前头节点 (logHead) 到临时指针 (tmp)。
 *      - 将头指针 (logHead) 指向下一个节点 (logHead->nx)。
 *      - 日志数量 (logNum) 减1。
 *      - 移除的节点计数 (count) 加1。
 *      - 检查尾指针 (logTail) 是否指向了刚刚被移除的节点 (tmp)。
 *        如果是（意味着链表中只有一个节点或者尾指针也指向了头部），则需要更新尾指针，
 *        使其指向新的头节点 (logHead)，并相应更新 logNum。
 *      - 使用 kfree(tmp) 释放被移除的旧日志节点的内存。
 *   4. 循环结束后，释放写锁 (write_unlock)。
 *   5. 返回本次操作移除的日志节点总数 (count)。
 */
int rollLog(void) {
    struct IPLog *tmp;          // 临时指针，用于指向待删除的日志节点
    unsigned int count = 0;     // 记录本次操作删除的日志节点数量
    printk("[fw logs] roll log chain.\n"); // 内核打印调试信息

    write_lock(&logLock); // 获取写锁，防止并发修改日志链表
    while(logNum > MAX_LOG_LEN) { // 当日志数量超过最大限制时，循环删除
        if(logHead == NULL) { // 异常情况：链表头指针丢失 (不应发生)
            logHead = logTail; // 尝试用尾指针恢复头指针
            logNum = logTail==NULL ? 0 : 1; // 根据尾指针状态更新日志数量
            write_unlock(&logLock); // 释放写锁
            return count; // 返回已删除的数量
        }
        tmp = logHead;          // tmp 指向当前的头节点 (最旧的日志)
        logHead = logHead->nx;  // 头指针后移到下一个节点
        logNum--;               // 日志总数减一
        count++;                // 删除计数加一

        if(logTail == tmp) { // 如果尾指针也指向了刚被删除的节点 (说明原链表只有一个节点，或者删除的是最后一个节点)
            logTail = logHead; // 那么尾指针也应该更新为新的头指针 (如果新头指针为NULL，则链表为空)
            logNum = logTail==NULL ? 0 : 1; // 再次校准日志数量
        }
        kfree(tmp); // 释放旧头节点的内存
    }
    write_unlock(&logLock); // 释放写锁
    return count; // 返回总共删除的日志条数
}

/**
 * @brief addLog 函数用于向日志链表的尾部添加一条新的IP日志记录。
 *
 * @param log 要添加的 IPLog 结构体 (通过值传递，函数内部会为其分配内存并复制内容)。
 * @return int 成功添加返回1，内存分配失败返回0。
 *
 * @功能描述:
 *   1. 使用 kzalloc 为新的日志条目 (struct IPLog) 分配内核内存。GFP_KERNEL 表示常规内存分配，可能会睡眠。
 *   2. 如果内存分配失败，打印警告信息并返回0。
 *   3. 使用 memcpy 将传入的 log 结构体的内容复制到新分配的内存中。
 *   4. 将新日志节点的 nx (下一个节点) 指针设置为 NULL，因为它将成为新的尾节点。
 *   5. 获取写锁 (write_lock) 以保护对日志链表的修改。
 *   6. 检查日志链表是否为空 (logTail == NULL)。
 *      - 如果为空，则新节点既是头节点也是尾节点。更新 logHead, logTail 和 logNum。
 *      - 释放写锁并返回1。
 *   7. 如果链表不为空，则将当前尾节点 (logTail) 的 nx 指针指向新节点。
 *   8. 更新尾指针 (logTail) 为新节点。
 *   9. 日志数量 (logNum) 加1。
 *   10. 释放写锁 (write_unlock)。
 *   11. 检查添加新日志后，日志总数 (logNum) 是否超过了最大限制 (MAX_LOG_LEN)。
 *       - 如果超过，则调用 rollLog() 函数移除旧的日志。
 *   12. 返回1表示添加成功。
 */
int addLog(struct IPLog log) {
    struct IPLog *newLog; // 指向新分配的日志节点的指针

    // 为新的日志条目分配内存并清零
    // kzalloc = kmalloc + memset(0)
    // GFP_KERNEL 表示在内核上下文中分配，可能会睡眠
    newLog = (struct IPLog *) kzalloc(sizeof(struct IPLog), GFP_KERNEL);
    if(newLog == NULL) { // 检查内存分配是否成功
        printk(KERN_WARNING "[fw logs] kzalloc fail.\n"); // 分配失败，打印警告
        return 0; // 返回0表示失败
    }
    memcpy(newLog, &log, sizeof(struct IPLog)); // 将传入的log数据复制到新分配的内存中
    newLog->nx = NULL; // 新节点是尾节点，所以其next指针为NULL

    // 将新日志添加到日志链表的尾部
    write_lock(&logLock); // 获取写锁
    if(logTail == NULL) { // 如果日志链表当前为空
        logTail = newLog;   // 新节点既是头也是尾
        logHead = logTail;
        logNum = 1;         // 日志数量为1
        write_unlock(&logLock); // 释放写锁
        //printk("[fw logs] add a log at head.\n"); // 调试打印 (已注释)
        return 1; // 返回1表示成功
    }
    // 如果链表不为空，将新节点链接到当前尾节点的后面
    logTail->nx = newLog;
    logTail = newLog; // 更新尾指针为新节点
    logNum++;         // 日志数量加一
    write_unlock(&logLock); // 释放写锁
    //printk("[fw logs] add a log.\n"); // 调试打印 (已注释)

    if(logNum > MAX_LOG_LEN) { // 如果日志数量超过了最大限制
        rollLog(); // 调用rollLog来移除旧的日志
    }
    return 1; // 返回1表示成功
}

/**
 * @brief addLogBySKB 函数根据网络数据包 (sk_buff) 和指定的处理动作 (action) 创建一条IP日志，并将其添加到日志链表中。
 *
 * @param action 对该数据包采取的处理动作 (例如 NF_ACCEPT, NF_DROP)。
 * @param skb 指向网络数据包的套接字缓冲区 (struct sk_buff) 的指针。
 * @return int 调用 addLog 的返回值 (成功为1，失败为0)。
 *
 * @功能描述:
 *   1. 声明一个 IPLog 结构体变量 log。
 *   2. 获取当前时间戳 (秒级精度) 并存入 log.tm。
 *      - 使用 ktime_get_real_ts64(&now) 获取高精度时间。
 *   3. 从 skb 中获取IP头部指针。
 *   4. 调用 getPort (自定义函数) 从 skb 和IP头部中提取源端口和目的端口。
 *   5. 从IP头部中提取源IP地址、目的IP地址、数据包负载长度 (总长度 - IP头长度) 和协议类型，
 *      进行必要的字节序转换 (ntohl, ntohs) 后存入 log 结构体的相应字段。
 *   6. 将传入的 action 存入 log.action。
 *   7. 将 log.nx 设置为 NULL (因为 addLog 函数会处理链表链接)。
 *   8. 调用 addLog(log) 函数将这条新创建的日志添加到全局日志链表中。
 *   9. 返回 addLog 的结果。
 */
int addLogBySKB(unsigned int action, struct sk_buff *skb) {
    struct IPLog log;               // 临时日志结构体，用于填充信息
    unsigned short sport,dport;     // 用于存储源端口和目的端口
	struct iphdr *header;           // 指向IP头部的指针
    struct timespec64 now;          // 用于获取高精度时间戳

    ktime_get_real_ts64(&now);      // 获取当前的真实时间 (自Epoch以来的秒数和纳秒数)
    log.tm = now.tv_sec;            // 将秒数存入日志的时间戳字段

    header = ip_hdr(skb);           // 从skb获取IP头部
	getPort(skb, header, &sport, &dport); // 调用工具函数获取源、目的端口 (需要处理TCP/UDP等)

    log.saddr = ntohl(header->saddr); // 获取源IP地址并转换为主机字节序
    log.daddr = ntohl(header->daddr); // 获取目的IP地址并转换为主机字节序
    log.sport = sport;                // 存储源端口 (已是主机字节序，如果getPort返回的是网络字节序则需转换)
    log.dport = dport;                // 存储目的端口 (同上)
    // 计算IP数据包的负载长度：IP总长度 (header->tot_len) - IP头部长度 (header->ihl * 4)
    // header->tot_len 是网络字节序，需要用 ntohs 转换
    // header->ihl 是以4字节为单位的IP头部长度
    log.len = ntohs(header->tot_len) - (header->ihl * 4);
    log.protocol = header->protocol;  // 获取协议类型 (如 TCP, UDP, ICMP)
    log.action = action;              // 存储对该数据包采取的动作
    log.nx = NULL;                    // 下一个日志指针初始化为NULL (addLog会处理)

    return addLog(log); // 调用addLog将填充好的日志结构体添加到链表
}

/**
 * @brief formAllIPLogs 函数用于从全局日志链表中提取指定数量的最新日志，
 *        并将它们打包成一个包含 KernelResponseHeader 的内存块，通常用于通过Netlink发送给用户空间。
 *
 * @param num 用户空间请求获取的日志条目数量。如果为0或大于实际日志数，则获取所有日志。
 * @param len [输出参数] 指向一个unsigned int的指针，函数会通过它返回最终构建的数据包的总长度 (字节数)。
 * @return void* 指向构建好的数据包内存块的指针。如果内存分配失败或无日志，则返回NULL。
 *
 * @功能描述:
 *   1. 声明必要的指针和计数器。
 *   2. 获取读锁 (read_lock)，因为此操作仅读取日志链表。
 *   3. 遍历整个日志链表一次，计算当前日志的总数量 (count)。
 *   4. 打印调试信息，显示日志总数和请求数量。
 *   5. 根据请求数量 (num) 和实际日志数量 (count) 确定实际要发送的日志数量 (num)。
 *      - 如果 num 为0 (表示获取所有) 或 num 大于 count，则将 num 设置为 count。
 *   6. 计算所需内存的总大小：KernelResponseHeader 的大小 + (IPLog 结构体的大小 * 实际发送的日志数量 num)。
 *      将此大小存入输出参数 *len。
 *   7. 使用 kzalloc 分配计算得到的内存大小。GFP_ATOMIC 表示在原子上下文中分配，不能睡眠 (通常用于中断处理或持有锁时)。
 *      这里使用 GFP_ATOMIC 可能因为持有读锁，但如果日志量很大，kzalloc 可能会有性能影响。
 *      如果是在普通进程上下文且可以睡眠，GFP_KERNEL 更合适。
 *   8. 如果内存分配失败，打印警告，释放读锁，并返回NULL。
 *   9. 构建回包：
 *      - 将分配的内存块的起始地址转换为 KernelResponseHeader 指针 (head)。
 *      - 设置 head->bodyTp 为 RSP_IPLogs (表示消息体是IP日志数组)。
 *      - 设置 head->arrayLen 为实际发送的日志数量 (num)。
 *      - p 指针指向 KernelResponseHeader 之后的数据区域，即IPLog数组的起始位置。
 *   10. 再次遍历日志链表 (从 logHead 开始)。
 *       - 为了只获取最新的 num 条日志，使用一个技巧：先让 count 减去 num。
 *       - 在遍历时，如果 count 大于0，则跳过当前日志并递减 count (这会跳过 (总数-num) 条最旧的日志)。
 *       - 当 count 小于等于0时，开始将当前日志节点 (now) 的内容通过 memcpy 复制到 p 指向的内存位置。
 *       - p 指针向后移动一个 IPLog 结构体的大小，为下一个日志条目做准备。
 *   11. 复制完成后，释放读锁 (read_unlock)。
 *   12. 返回指向构建好的数据包内存块 (mem) 的指针。
 */
void* formAllIPLogs(unsigned int num, unsigned int *len) {
    struct KernelResponseHeader *head; // 指向响应头部的指针
    struct IPLog *now;                 // 用于遍历日志链表的指针
    void *mem,*p;                      // mem: 指向分配的总内存块, p: 用于在内存块中移动的指针
    unsigned int count;                // 记录日志链表中的实际日志总数

    read_lock(&logLock); // 获取读锁，因为我们只读取日志数据
    // 第一次遍历：计算日志链表中的日志总数
    for(now=logHead, count=0; now!=NULL; now=now->nx, count++);
    printk("[fw logs] form logs count=%d, need num=%d.\n", count, num); // 打印日志总数和请求数

    // 确定实际要发送的日志数量
    if(num == 0 || num > count) // 如果请求0条或请求数大于实际数，则发送所有日志
        num = count;

    // 计算需要分配的总内存大小 = 头部大小 + (单个日志大小 * 日志数量)
    *len = sizeof(struct KernelResponseHeader) + sizeof(struct IPLog) * num;
    // 分配内存，GFP_ATOMIC用于原子上下文，不能睡眠 (持有锁时常用)
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL) { // 检查内存分配是否成功
        printk(KERN_WARNING "[fw logs] formAllIPLogs kzalloc fail.\n");
        read_unlock(&logLock); // 释放锁
        return NULL; // 返回NULL表示失败
    }

    // 构建回包的头部
    head = (struct KernelResponseHeader *)mem; // mem转换为头部指针
    head->bodyTp = RSP_IPLogs;                 // 设置响应体类型为IP日志
    head->arrayLen = num;                      // 设置数组长度 (即日志条数)

    // p指向头部之后的数据区，即IPLog数组的开始位置
    p = (mem + sizeof(struct KernelResponseHeader));

    // 第二次遍历：复制日志数据到内存块
    // 为了获取最新的 num 条日志，我们从头开始遍历，但跳过前面的 (count - num) 条旧日志
    for(now=logHead; now!=NULL; now=now->nx) {
        if(count > num) { // 如果当前总日志数 (count) 大于要发送的日志数 (num)
            count--;      // 表示这条日志是旧的，跳过它
            continue;
        }
        // 当 count <= num 时，开始复制日志
        memcpy(p, now, sizeof(struct IPLog)); // 将当前日志节点数据复制到p指向的内存
        p = p + sizeof(struct IPLog);         // p后移，准备下一个日志的位置
    }
    read_unlock(&logLock); // 释放读锁
    return mem; // 返回构建好的内存块指针
}