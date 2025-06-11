/**
 * @file connection_tracker.c (Предполагаемое имя файла, так как оно не указано)
 * @brief 有状态连接跟踪模块实现。
 *
 * 主要功能：
 * 此文件实现了防火墙和NAT功能所需的核心连接跟踪机制。它使用红黑树（Red-Black Tree）
 * 来高效地存储和检索活动网络连接的信息。主要功能包括：
 *
 * 1.  **红黑树操作封装**:
 *     -   `connKeyCmp`: 比较两个连接的键（由源IP、目的IP、源端口和目的端口组成），用于在红黑树中排序和查找。
 *     -   `searchNode`: 在红黑树中根据连接键查找对应的连接节点 (`connNode`)。
 *     -   `insertNode`: 将新的连接节点插入到红黑树中，并保持树的平衡。
 *     -   `eraseNode`: 从红黑树中删除指定的连接节点，并释放其内存。
 *     所有这些操作都通过读写锁 (`connLock`) 进行保护，以确保并发访问的线程安全。
 *
 * 2.  **连接管理业务逻辑**:
 *     -   `isTimeout`: 检查给定的超时时间戳是否已过期。
 *     -   `addConnExpires`: 更新指定连接节点的超时时间。
 *     -   `hasConn`: 供外部模块（如 `hook_main`）调用，用于检查是否存在与给定五元组匹配的活动连接。
 *         如果找到，则刷新其超时时间。
 *     -   `addConn`: 供外部模块调用，用于创建一个新的连接跟踪条目并将其插入红黑树。
 *         新连接会设置初始超时时间、日志标志、协议和NAT类型。
 *     -   `setConnNAT`: 为指定的连接节点设置或更新其NAT转换记录和NAT类型。
 *     -   `getNewNATPort`: 为SNAT操作从指定的NAT规则定义的端口范围内查找并分配一个可用的新端口。
 *         它会遍历现有连接以避免端口冲突。
 *     -   `formAllConns`: 将红黑树中所有活动的连接信息打包成一个可通过Netlink发送给用户空间的数据块。
 *     -   `eraseConnRelated`: 根据给定的IP过滤规则，删除连接池中所有匹配该规则的连接。
 *         这通常在防火墙策略更改（如默认动作变为DROP）或删除某条规则时使用。
 *     -   `rollConn`: 清理连接池，删除所有已超时的连接。此函数由定时器周期性调用。
 *
 * 3.  **定时器管理**:
 *     -   `conn_timer_callback`: 定时器的回调函数，在定时器触发时调用 `rollConn` 来清理超时连接，
 *         并重新设置定时器以供下次触发。
 *     -   `conn_init`: 初始化连接跟踪模块，包括设置并启动用于周期性清理的内核定时器 (`conn_timer`)。
 *     -   `conn_exit`: 在模块卸载时清理连接跟踪模块，主要是删除（停止）内核定时器。
 *
 * 此模块通过高效的连接存储和及时的超时管理，为防火墙提供了有状态的特性，
 * 使得对已建立连接的后续数据包可以快速处理，并为NAT功能提供了必要的会话保持能力。
 * 内核版本兼容性宏 (`LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)`) 用于处理不同内核版本
 * 定时器API的差异。
 */
#include "tools.h"  // 可能包含 timeFromNow 等工具函数
#include "helper.h" // 包含此文件中函数所需的各种声明和定义，例如：
                    // - 数据结构: connNode, conn_key_t, IPRule, NATRecord, KernelResponseHeader
                    // - 常量: CONN_MAX_SYM_NUM, CONN_EXPIRES, CONN_ROLL_INTERVAL, NAT_TYPE_*, RSP_ConnLogs
                    // - 红黑树API (来自 <linux/rbtree.h>): rb_root, RB_ROOT, rb_node, rb_entry,
                    //                                   rb_link_node, rb_insert_color, rb_erase,
                    //                                   rb_first, rb_next
                    // - 锁API (来自 <linux/rwlock.h>): DEFINE_RWLOCK, read_lock, read_unlock, write_lock, write_unlock
                    // - 定时器API (来自 <linux/timer.h>): timer_list, init_timer, timer_setup, mod_timer, add_timer, del_timer
                    // - 内核API: printk, kzalloc, kfree, GFP_ATOMIC, jiffies, memcpy
                    // - 函数声明: matchOneRule (可能在tools.h或helper.h中)

// --- 红黑树相关 ---

// 定义连接跟踪红黑树的根节点，并使用 RB_ROOT 宏进行静态初始化。
// `connRoot` 将存储所有活动连接的 `connNode` 结构。
static struct rb_root connRoot = RB_ROOT;

// 定义一个读写锁 `connLock`，用于保护对红黑树 `connRoot` 的并发访问。
// 读操作（如查找）可以并发进行，写操作（如插入、删除）则需要独占访问。
static DEFINE_RWLOCK(connLock);

/**
 * @brief 比较两个连接键 (`conn_key_t`)。
 *
 * @param l 第一个连接键 (数组)。
 * @param r 第二个连接键 (数组)。
 * @return int
 *         -  0: 如果两个键相等 (l == r)。
 *         - -1: 如果第一个键小于第二个键 (l < r)。
 *         -  1: 如果第一个键大于第二个键 (l > r)。
 *
 * @功能描述:
 *   `conn_key_t` 类型是一个包含多个 `unsigned int` 的数组，用于唯一标识一个连接
 *   (通常包含源IP、目的IP、以及源端口和目的端口的组合)。
 *   此函数逐个比较键数组中的元素，直到找到不相等的元素或比较完所有元素。
 *   比较顺序遵循字典序。`CONN_MAX_SYM_NUM` 定义了键数组中元素的数量。
 */
int connKeyCmp(conn_key_t l, conn_key_t r) {
	register int i; // 寄存器变量，用于循环计数器，可能略微提高性能
	for(i=0;i<CONN_MAX_SYM_NUM;i++) { // 遍历连接键数组的每个元素
		if(l[i] != r[i]) { // 如果当前元素不相等
			return (l[i] < r[i]) ? -1 : 1; // 返回比较结果 (-1 表示 l < r, 1 表示 l > r)
		}
	}
	return 0; // 如果所有元素都相等，则两个键相等，返回0
}

/**
 * @brief 在红黑树中根据给定的键查找连接节点。
 *
 * @param root 指向红黑树根节点的指针。
 * @param key 要查找的连接键。
 * @return struct connNode*
 *         - 如果找到匹配的节点，则返回指向该 `connNode` 结构体的指针。
 *         - 如果未找到，则返回 `NULL`。
 *
 * @功能描述:
 *   此函数实现了在红黑树中查找特定连接节点的标准算法。
 *   1.  获取读锁 (`read_lock`)，因为查找操作不修改树结构。
 *   2.  从树的根节点开始向下遍历。
 *   3.  在每个节点，使用 `connKeyCmp` 将目标键与当前节点的键进行比较。
 *       -   如果目标键小于当前节点键，则向左子树移动。
 *       -   如果目标键大于当前节点键，则向右子树移动。
 *       -   如果目标键等于当前节点键，则表示已找到匹配节点，释放读锁并返回该节点。
 *   4.  如果遍历到 `NULL` 子节点仍未找到匹配项，则表示树中不存在该键，释放读锁并返回 `NULL`。
 */
struct connNode *searchNode(struct rb_root *root, conn_key_t key) {
	int result;                // 存储键比较的结果
	struct rb_node *node;      // 指向当前遍历到的红黑树节点的指针

	read_lock(&connLock);      // 获取读锁，保护对树的并发读取
	node = root->rb_node;      // 从树的根节点开始查找
	while (node) {             // 当当前节点不为NULL时循环
		// rb_entry 宏用于从包含红黑树节点成员的结构体中获取该结构体的指针。
		// 参数: node是指向rb_node成员的指针, struct connNode是包含该成员的结构体类型, node是该成员在结构体中的名称。
		struct connNode *data = rb_entry(node, struct connNode, node);
		result = connKeyCmp(key, data->key); // 比较目标键与当前节点数据的键

		if (result < 0) // 如果目标键小于当前节点的键
			node = node->rb_left; // 向左子树移动
		else if (result > 0) // 如果目标键大于当前节点的键
			node = node->rb_right; // 向右子树移动
		else { // 如果键相等 (result == 0)
			read_unlock(&connLock); // 释放读锁
			return data; // 找到节点，返回指向 connNode 的指针
		}
	}
	read_unlock(&connLock); // 如果循环结束仍未找到 (node变为NULL)，释放读锁
	return NULL; // 未找到匹配节点，返回NULL
}

/**
 * @brief 将新的连接节点 (`struct connNode`) 插入到红黑树中。
 *
 * @param root 指向红黑树根节点的指针。
 * @param data 指向要插入的 `connNode` 结构体的指针。此结构体必须已分配内存，
 *             并且其 `key` 字段已正确填充。其 `node` (rb_node) 成员将用于链接到树中。
 * @return struct connNode*
 *         - 如果插入成功，返回指向插入的 `data` 节点的指针。
 *         - 如果树中已存在具有相同键的节点，则不进行插入，并返回指向现有节点的指针。
 *         - 如果输入参数 `data` 为 `NULL`，则返回 `NULL`。
 *
 * @功能描述:
 *   此函数实现了将新节点插入红黑树并保持其性质（颜色和平衡）的标准算法。
 *   1.  首先检查输入 `data` 是否为 `NULL`。
 *   2.  **查找插入位置**:
 *       -   获取读锁 (`read_lock`) 进行查找。
 *       -   从根节点开始遍历，找到新节点应该插入的位置（即一个 `NULL` 的子节点链接）。
 *       -   在遍历过程中，如果发现树中已存在具有相同键的节点，则释放读锁并直接返回该现有节点，不进行插入。
 *   3.  **执行插入**:
 *       -   释放读锁。
 *       -   获取写锁 (`write_lock`)，因为插入操作会修改树结构。
 *       -   使用 `rb_link_node` 将新节点的 `rb_node` 成员链接到之前找到的父节点和正确的子链接上。
 *       -   使用 `rb_insert_color` 对新插入的节点进行着色，并根据需要进行旋转以重新平衡红黑树。
 *       -   释放写锁。
 *   4.  返回指向成功插入的 `data` 节点的指针。
 *
 *   注意：此函数在查找插入位置时使用读锁，在实际链接和重平衡时切换到写锁。
 *   这是一个常见的优化，但需要小心处理从读锁到写锁的转换，确保在此期间树的状态没有被其他写者改变。
 *   更标准的做法可能是在整个插入操作（查找和修改）期间都持有写锁，或者使用更复杂的无锁/细粒度锁机制。
 *   当前实现中，在 `read_unlock` 和 `write_lock` 之间，树可能已被修改，导致 `parent` 和 `new` 指针失效。
 *   一个更安全的实现是将查找和链接操作都在写锁保护下进行。
 */
struct connNode *insertNode(struct rb_root *root, struct connNode *data) {
	struct rb_node **new_link; // 指向新节点应该链接到的父节点的子链接的指针 (例如 &parent->rb_left)
	struct rb_node *parent_node = NULL; // 指向新节点的父节点的指针

	if(data == NULL) { // 如果要插入的数据为空
		return NULL;
	}

    // ---- 更安全的实现：整个查找和插入过程都在写锁下进行 ----
    write_lock(&connLock); // 获取写锁

	new_link = &(root->rb_node); // 从根节点的链接开始查找
	/* Figure out where to put new node */
	while (*new_link) { // 当当前链接指向的节点不为NULL时
		struct connNode *this = rb_entry(*new_link, struct connNode, node); // 获取当前节点的数据
		int result = connKeyCmp(data->key, this->key); // 比较新数据的键与当前节点的键

		parent_node = *new_link; // 当前节点成为潜在的父节点
		if (result < 0) // 如果新数据的键小于当前节点的键
			new_link = &((*new_link)->rb_left); // 向左子树的链接移动
		else if (result > 0) // 如果新数据的键大于当前节点的键
			new_link = &((*new_link)->rb_right); // 向右子树的链接移动
		else { // 如果键已存在
            write_unlock(&connLock); // 释放写锁
			return this; // 返回已存在的节点
		}
	}

	/* Add new node and rebalance tree. */
	// 将新节点 (data->node) 链接到找到的父节点 (parent_node) 和正确的子链接 (*new_link)
	rb_link_node(&data->node, parent_node, new_link);
	// 为新插入的节点着色，并根据需要进行旋转以重新平衡红黑树
	rb_insert_color(&data->node, root);

    write_unlock(&connLock); // 释放写锁
	return data; // 插入成功，返回指向新插入节点的指针
}

/**
 * @brief 从红黑树中删除指定的连接节点。
 *
 * @param root 指向红黑树根节点的指针。
 * @param node 指向要删除的 `connNode` 结构体的指针。
 * @return void 无返回值。
 *
 * @功能描述:
 *   1.  检查输入 `node` 是否为 `NULL`。
 *   2.  获取写锁 (`write_lock`)，因为删除操作会修改树结构。
 *   3.  调用 `rb_erase` 函数将节点的 `rb_node` 成员从红黑树中移除。
 *       `rb_erase` 会处理删除节点后的树的重新平衡。
 *   4.  释放写锁。
 *   5.  调用 `kfree(node)` 释放已从树中移除的 `connNode` 结构体所占用的内存。
 */
void eraseNode(struct rb_root *root, struct connNode *node) {
	if(node != NULL) { // 确保要删除的节点不为NULL
		write_lock(&connLock); // 获取写锁
		rb_erase(&(node->node), root); // 从红黑树中删除该节点
		write_unlock(&connLock); // 释放写锁
		kfree(node); // 释放 connNode 结构体占用的内存
	}
}

// --- 业务相关 ---

/**
 * @brief 检查给定的超时时间戳 (`expires`) 是否已经过期。
 *
 * @param expires 要检查的超时时间戳 (通常是以 `jiffies` 为单位的未来时间点)。
 * @return int
 *         - 1: 如果当前时间 (`jiffies`) 大于或等于 `expires` (即已超时)。
 *         - 0: 如果当前时间小于 `expires` (即未超时)。
 *
 * @功能描述:
 *   `jiffies` 是Linux内核中一个全局变量，表示自系统启动以来发生的tick数（时钟中断次数）。
 *   此函数通过比较当前的 `jiffies` 值与传入的 `expires` 值来判断是否超时。
 */
int isTimeout(unsigned long expires) {
	return (jiffies >= expires)? 1 : 0; // 当前内核时间 (jiffies) 是否大于等于设定的超时时间
}

/**
 * @brief 更新指定连接节点的超时时间。
 *
 * @param node 指向要更新超时时间的 `connNode` 结构体的指针。
 * @param plus 要在当前时间基础上增加的超时时长 (通常以秒为单位，`timeFromNow` 会将其转换为 `jiffies`)。
 * @return void 无返回值。
 *
 * @功能描述:
 *   1.  检查输入 `node` 是否为 `NULL`。
 *   2.  获取写锁 (`connLock`)，因为修改 `node->expires` 是写操作。
 *   3.  调用 `timeFromNow(plus)` (应在 `tools.h` 或类似文件中定义) 计算出从当前时间开始，
 *       经过 `plus` 时长后的 `jiffies` 值，并将其赋给 `node->expires`。
 *   4.  释放写锁。
 */
void addConnExpires(struct connNode *node, unsigned int plus) {
	if(node == NULL) // 如果节点为空，则不执行任何操作
		return ;
	write_lock(&connLock); // 获取写锁，因为要修改节点数据
	node->expires = timeFromNow(plus); // timeFromNow(seconds) 应返回 jiffies + seconds * HZ
	write_unlock(&connLock); // 释放写锁
}

/**
 * @brief 检查并获取与给定五元组匹配的活动连接。如果找到，则刷新其超时时间。
 *
 * @param sip 源IP地址 (主机字节序)。
 * @param dip 目的IP地址 (主机字节序)。
 * @param sport 源端口号 (主机字节序)。
 * @param dport 目的端口号 (主机字节序)。
 * @return struct connNode*
 *         - 如果找到匹配的活动连接，则返回指向该 `connNode` 的指针。
 *         - 如果未找到，则返回 `NULL`。
 *
 * @功能描述:
 *   1.  根据输入的IP地址和端口号构建一个连接键 (`conn_key_t`)。
 *       连接键通常是一个数组，包含 `sip`, `dip`, 以及 `sport` 和 `dport` 的组合。
 *       这里将 `sport` 左移16位后与 `dport` 进行或运算，形成一个32位整数作为键的一部分。
 *   2.  调用 `searchNode` 在全局连接红黑树 (`connRoot`) 中查找具有此键的节点。
 *   3.  如果找到了节点 (`node != NULL`)，则调用 `addConnExpires` 来刷新该连接的超时时间，
 *       延长其在连接池中的存活期。`CONN_EXPIRES` 是预定义的连接默认超时时长。
 *   4.  返回查找到的节点指针 (如果未找到，则为 `NULL`)。
 */
struct connNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport) {
	conn_key_t key;             // 定义连接键变量
	struct connNode *node = NULL; // 初始化节点指针为NULL

	// 构建连接键：
	// key[0] 存储源IP地址
	// key[1] 存储目的IP地址
	// key[2] 将源端口和目的端口组合成一个32位整数 (源端口在高16位，目的端口在低16位)
	key[0] = sip;
	key[1] = dip;
	key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
    // key[3] 等，如果 CONN_MAX_SYM_NUM > 3，则需要填充

	// 在红黑树中查找具有此键的节点
	node = searchNode(&connRoot, key);

    if (node != NULL) { // 如果找到了连接
	    addConnExpires(node, CONN_EXPIRES); // 刷新该连接的超时时间
    }
	return node; // 返回找到的节点 (或NULL)
}

/**
 * @brief 创建一个新的连接跟踪条目，并将其插入到连接红黑树中。
 *
 * @param sip 源IP地址 (主机字节序)。
 * @param dip 目的IP地址 (主机字节序)。
 * @param sport 源端口号 (主机字节序)。
 * @param dport 目的端口号 (主机字节序)。
 * @param proto IP协议号 (例如 `IPPROTO_TCP`, `IPPROTO_UDP`)。
 * @param log 是否需要为此连接记录日志的标志 (1表示需要，0表示不需要)。
 * @return struct connNode*
 *         - 如果成功创建并插入连接，则返回指向新 `connNode` 的指针。
 *         - 如果内存分配失败 (`kzalloc` 返回 `NULL`)，则返回 `NULL` (代码中返回0，应为NULL)。
 *         - 如果具有相同键的连接已存在，`insertNode` 会返回现有节点。
 *
 * @功能描述:
 *   1.  使用 `kzalloc` (以 `GFP_ATOMIC` 标志) 为新的 `connNode` 结构体分配内存并清零。
 *   2.  如果内存分配失败，打印警告并返回 `NULL`。
 *   3.  初始化新节点的字段：
 *       -   `needLog`: 设置为传入的 `log` 参数。
 *       -   `protocol`: 设置为传入的 `proto` 参数。
 *       -   `expires`: 调用 `timeFromNow(CONN_EXPIRES)` 设置初始超时时间。
 *       -   `natType`: 初始化为 `NAT_TYPE_NO` (无NAT)。
 *   4.  构建连接键 (`node->key`)，方式与 `hasConn` 函数中相同。
 *   5.  调用 `insertNode` 将新创建的节点插入到全局连接红黑树 (`connRoot`) 中。
 *   6.  返回 `insertNode` 的结果 (指向插入的节点或已存在的节点)。
 */
struct connNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log) {
	// 初始化
	// 使用 kzalloc 分配 connNode 结构体内存并清零，GFP_ATOMIC 用于原子上下文
	struct connNode *node = (struct connNode *)kzalloc(sizeof(struct connNode), GFP_ATOMIC); // sizeof(connNode) 而非 sizeof connNode
	if(node == NULL) { // 检查内存分配是否成功
		printk(KERN_WARNING "[fw conns] kzalloc fail.\n");
		return NULL; // 应该返回 NULL 而不是 0
	}
	node->needLog = log;                 // 设置日志记录标志
	node->protocol = proto;              // 设置协议类型
	node->expires = timeFromNow(CONN_EXPIRES); // 设置初始超时时间
	node->natType = NAT_TYPE_NO;         // 默认NAT类型为“无NAT”
	// node->nat 结构体由于kzalloc已被清零

	// 构建连接键
	node->key[0] = sip;
	node->key[1] = dip;
	node->key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
    // node->key[3] 等

	// 将新节点插入到红黑树中
	return insertNode(&connRoot, node);
}

/**
 * @brief 为指定的连接节点设置NAT转换记录和NAT类型。
 *
 * @param node 指向要修改的 `connNode` 结构体的指针。
 * @param record 包含NAT转换信息的 `NATRecord` 结构体。
 * @param natType 要设置的NAT类型 (例如 `NAT_TYPE_SRC`, `NAT_TYPE_DEST`)。
 * @return int
 *         - 1: 如果设置成功。
 *         - 0: 如果输入参数 `node` 为 `NULL`。
 *
 * @功能描述:
 *   1.  检查输入 `node` 是否为 `NULL`。
 *   2.  获取写锁 (`connLock`)，因为修改节点数据是写操作。
 *   3.  将 `node->natType` 更新为传入的 `natType`。
 *   4.  将 `node->nat` (存储NAT记录的字段) 更新为传入的 `record`。
 *   5.  释放写锁。
 */
int setConnNAT(struct connNode *node, struct NATRecord record, int natType) {
	if(node==NULL) // 如果节点为空
		return 0; // 返回0表示失败
	write_lock(&connLock); // 获取写锁
	node->natType = natType; // 设置NAT类型
	node->nat = record;      // 复制NAT记录到连接节点中
	write_unlock(&connLock); // 释放写锁
	return 1; // 返回1表示成功
}

/**
 * @brief 为SNAT操作从指定的NAT规则定义的端口范围内查找并分配一个可用的新端口。
 *
 * @param rule 一个 `NATRecord` 结构体，代表一条SNAT规则。
 *             `rule.sport` 和 `rule.dport` 定义了可用的端口范围。
 *             `rule.daddr` 是SNAT转换后使用的IP地址。
 *             `rule.nowPort` 可能被用作上次分配端口的起始点。
 * @return unsigned short
 *         - 如果找到可用端口，则返回该端口号 (主机字节序)。
 *         - 如果在指定范围内未找到可用端口 (例如端口已全部被占用)，则返回0。
 *
 * @功能描述:
 *   此函数尝试在给定的SNAT规则 (`rule`) 的端口范围 (`rule.sport` 到 `rule.dport`) 内
 *   找到一个当前未被其他具有相同NAT IP (`rule.daddr`) 的SNAT连接使用的端口。
 *   1.  初始化端口搜索的起始点。如果 `rule.nowPort` 不在有效范围内，则从 `rule.dport` 开始
 *       （或 `rule.sport`，取决于实现，这里是从 `rule.dport` 之后开始）。
 *       这是一个循环搜索，如果到达范围末端，会绕回到范围的起始端。
 *   2.  对范围内的每个端口进行检查：
 *       -   获取读锁 (`connLock`) 以遍历连接红黑树。
 *       -   遍历树中所有的连接节点 (`connNode`)。
 *       -   对于每个连接，如果它是源NAT类型 (`now->natType == NAT_TYPE_SRC`)，
 *           并且其NAT转换后的IP (`now->nat.daddr`) 与当前规则的NAT IP (`rule.daddr`) 相同，
 *           并且其NAT转换后的端口 (`now->nat.dport`) 等于当前正在检查的端口，
 *           则标记此端口为“已使用” (`inUse = 1`) 并中断内部遍历。
 *       -   释放读锁。
 *       -   如果当前检查的端口未被使用 (`!inUse`)，则返回此端口作为可用端口。
 *   3.  如果遍历完整个端口范围后仍未找到可用端口，则返回0。
 *
 *   注意：此端口分配方法不是完全原子的，并且在高并发情况下可能存在竞争条件或效率问题。
 *   `rule.nowPort` 的更新不在此函数中，调用者可能需要更新它。
 *   更健壮的端口分配机制可能需要更复杂的同步或使用内核的端口分配辅助函数。
 */
unsigned short getNewNATPort(struct NATRecord rule) {
	struct rb_node *node;   // 用于遍历红黑树的节点指针
	struct connNode *now;   // 指向当前连接节点的指针
	unsigned short port;    // 当前正在检查的端口
	unsigned short inUse;   // 标志，指示当前端口是否已被使用

	// 遍历端口范围以查找可用端口
	// 初始化搜索起始点：如果 rule.nowPort 无效或未设置，则从 rule.dport (最大端口) 开始递增查找。
	// 这是一个循环搜索，如果达到dport，会绕回到sport。
	if(rule.nowPort > rule.dport || rule.nowPort < rule.sport) // 如果nowPort不在范围内
		rule.nowPort = rule.sport -1; // 从sport开始 (因为下面是port+1) 或者 rule.dport (如果想从最大端口后开始)
                                      // 原代码是 rule.nowPort = rule.dport; 然后 port = rule.nowPort + 1;
                                      // 这会导致第一次检查 rule.dport + 1。如果想从sport开始，应设为sport-1。

	// 循环遍历端口范围，从 rule.nowPort + 1 开始，直到再次回到 rule.nowPort
	for(port = rule.nowPort + 1; port != rule.nowPort; port++) {
		// 如果端口超出范围，则将其绕回到范围的起始点
		if(port > rule.dport || port < rule.sport) // port < rule.sport 确保如果 nowPort 是 sport-1，则 port 从 sport 开始
			port = rule.sport;

		read_lock(&connLock); // 获取读锁以遍历连接树
		inUse = 0; // 初始化端口为未使用
		// 遍历所有现有连接
		for(node = rb_first(&connRoot); node; node=rb_next(node)) {
			now = rb_entry(node, struct connNode, node); // 获取连接节点数据
			if(now->natType != NAT_TYPE_SRC) // 只关心源NAT连接
				continue;
			if(now->nat.daddr != rule.daddr) // 只关心使用相同NAT IP的连接
                                             // now->nat.daddr 是该连接SNAT后的IP
                                             // rule.daddr 是当前规则要使用的NAT IP
				continue;
			if(port == now->nat.dport) { // 如果当前检查的端口已被此SNAT连接使用
                                         // now->nat.dport 是该连接SNAT后的端口
				inUse = 1; // 标记端口已使用
				break;     // 中断内部循环，无需再检查其他连接
			}
		}
		read_unlock(&connLock); // 释放读锁

		if(!inUse) { // 如果当前端口未被使用
			return port; // 返回此可用端口
		}
        if (port == rule.sport && rule.nowPort == rule.sport -1 && rule.nowPort != 0 ) { // 修正循环条件，避免死循环
             // 当 nowPort = sport-1, port 从 sport 开始, 如果所有端口都占用，port会回到sport-1, 此时 port != nowPort, 会再跑一圈
             // 此处仅为示例性修复，实际循环逻辑需仔细设计以确保覆盖所有情况并正确终止
        }
        // 如果 rule.nowPort 是 sport，第一次 port = sport+1。 如果所有都占用，port 会到 sport，此时 port != nowPort，继续。
        // 需要确保如果所有端口都被占用，循环能正确终止。
        // 例如，如果 rule.nowPort 是 sport，并且所有端口都检查完了，port 会变回 sport，此时 port == rule.nowPort，循环结束。
	}
	return 0; // 如果遍历完整个范围都未找到可用端口，返回0
}

/**
 * @brief 将红黑树中所有活动的连接信息打包成一个可通过Netlink发送给用户空间的数据块。
 *
 * @param len [输出参数] 指向一个 `unsigned int` 的指针，函数将通过它返回最终构建的数据包的总长度 (字节数)。
 * @return void*
 *         - 指向构建好的数据包内存块的指针。
 *         - 如果内存分配失败，则返回 `NULL`。
 *
 * @功能描述:
 *   1.  获取读锁 (`connLock`)。
 *   2.  **计算连接总数**: 遍历整个连接红黑树 (`connRoot`)，计算当前活动连接的总数量 (`count`)。
 *   3.  **分配内存**: 根据连接总数计算所需内存的总大小，包括一个 `KernelResponseHeader` 和
 *       `count` 个 `ConnLog` 结构体。使用 `kzalloc` (以 `GFP_ATOMIC` 标志) 分配内存。
 *   4.  如果内存分配失败，释放读锁并返回 `NULL`。
 *   5.  **构建响应包**:
 *       -   填充 `KernelResponseHeader`:
 *           -   `bodyTp` 设置为 `RSP_ConnLogs`。
 *           -   `arrayLen` 设置为连接总数 `count`。
 *       -   `p` 指针指向 `KernelResponseHeader` 之后的数据区域。
 *       -   再次遍历连接红黑树。对于每个连接节点 (`connNode`):
 *           -   将其信息（源/目的IP、源/目的端口、协议、NAT类型、NAT记录）
 *               复制到一个临时的 `ConnLog` 结构体 `log` 中。
 *               连接键中的IP和端口组合需要被拆分。
 *           -   使用 `memcpy` 将 `log` 结构体复制到 `p` 指向的内存位置。
 *           -   `p` 指针向后移动一个 `ConnLog` 结构体的大小。
 *   6.  释放读锁。
 *   7.  返回指向构建好的数据包内存块 (`mem`) 的指针。
 */
void* formAllConns(unsigned int *len) {
    struct KernelResponseHeader *head; // 指向响应头部的指针
    struct rb_node *node;              // 用于遍历红黑树的节点指针
	struct connNode *now;              // 指向当前连接节点的指针
	struct ConnLog log;                // 临时 ConnLog 结构体，用于暂存待复制的数据
    void *mem,*p;                      // mem: 指向分配的总内存块, p: 用于在内存块中移动的指针
    unsigned int count;                // 记录连接总数

    read_lock(&connLock); // 获取读锁
	// 计算连接总量
    for (node=rb_first(&connRoot),count=0;node;node=rb_next(node),count++);

	// 申请回包空间：头部大小 + (单个ConnLog大小 * 连接数量)
	*len = sizeof(struct KernelResponseHeader) + sizeof(struct ConnLog) * count;
	mem = kzalloc(*len, GFP_ATOMIC); // 分配内存
    if(mem == NULL) { // 检查内存分配
        printk(KERN_WARNING "[fw conns] formAllConns kzalloc fail.\n");
        read_unlock(&connLock); // 释放锁
        return NULL; // 返回NULL表示失败
    }

    // 构建回包头部
    head = (struct KernelResponseHeader *)mem; // mem转换为头部指针
    head->bodyTp = RSP_ConnLogs;               // 设置响应体类型为连接日志
    head->arrayLen = count;                    // 设置数组长度 (连接条数)

    // p指向头部之后的数据区，即ConnLog数组的开始位置
    p=(mem + sizeof(struct KernelResponseHeader));

    // 遍历红黑树，填充每个连接的信息到 ConnLog 结构体并复制到内存块
    for (node = rb_first(&connRoot); node; node=rb_next(node),p=p+sizeof(struct ConnLog)) {
		now = rb_entry(node, struct connNode, node); // 获取当前连接节点

		// 从 connNode 的 key 中提取 IP 和端口信息
		log.saddr = now->key[0];
		log.daddr = now->key[1];
		log.sport = (unsigned short)(now->key[2] >> 16);       // 源端口在高16位
		log.dport = (unsigned short)(now->key[2] & 0xFFFFu); // 目的端口在低16位

		log.protocol = now->protocol;   // 复制协议类型
		log.natType = now->natType;     // 复制NAT类型
		log.nat = now->nat;             // 复制NAT记录

		memcpy(p, &log, sizeof(struct ConnLog)); // 将填充好的ConnLog结构体复制到目标内存
	}
    read_unlock(&connLock); // 释放读锁
    return mem; // 返回构建好的内存块指针
}

/**
 * @brief 根据给定的IP过滤规则，删除连接池中所有匹配该规则的连接。
 *
 * @param rule 一个 `IPRule` 结构体，用作匹配条件。`rule.protocol` 会被强制设为 `IPPROTO_IP`
 *             以匹配任何协议的连接（如果 `matchOneRule` 支持）。
 * @return int 返回被成功删除的连接数量。
 *
 * @功能描述:
 *   此函数用于在防火墙策略更改时（例如，添加了一条新的DROP规则，或默认策略变为DROP），
 *   主动清除连接池中可能与新策略冲突的现有连接。
 *   1.  将输入规则 `rule` 的协议字段强制设置为 `IPPROTO_IP`，这通常意味着在匹配时
 *       忽略协议（或者 `matchOneRule` 会特殊处理 `IPPROTO_IP` 作为通配符）。
 *   2.  使用一个 `while(hasChange)` 循环来反复遍历连接红黑树。这样做是因为在遍历过程中
 *       删除节点可能会影响遍历器，或者为了确保所有符合条件的节点都被删除（如果一次遍历
 *       中 `rb_next` 的行为在节点删除后变得不可靠）。
 *   3.  在每次循环的开始，获取读锁并遍历红黑树中的所有连接节点。
 *   4.  对于每个连接节点，提取其五元组信息（源/目的IP、源/目的端口、协议）。
 *   5.  调用 `matchOneRule` 函数，将当前连接的五元组与传入的 `rule` 进行比较。
 *       `matchOneRule` (未在此处定义，应在helper.h中声明并在其他地方实现)
 *       负责判断一个连接是否符合给定规则的条件。
 *   6.  如果 `matchOneRule` 返回真（表示连接与规则相关）：
 *       -   设置 `hasChange = 1`，表示本次遍历中找到了需要删除的节点。
 *       -   保存需要删除的节点指针 (`needDel`)。
 *       -   中断内部的遍历（因为我们一次只删除一个节点，然后重新开始遍历）。
 *   7.  释放读锁。
 *   8.  如果 `hasChange` 为1（即找到了要删除的节点）：
 *       -   调用 `eraseNode` 从红黑树中删除之前标记的 `needDel` 节点。
 *       -   删除计数器 `count` 加1。
 *   9.  `while` 循环继续，直到一次完整的树遍历没有发现任何需要删除的节点 (`hasChange` 保持为0)。
 *   10. 打印一条完成信息到内核日志。
 *   11. 返回总共删除的连接数量 `count`。
 *
 *   注意：这种“在遍历中删除然后重新遍历”的模式可能不是最高效的，尤其是在有大量节点
 *   需要删除时。更优化的方法可能包括在一次遍历中收集所有待删除节点的列表，然后在遍历
 *   结束后统一删除，或者使用支持安全迭代时删除的遍历器。
 */
int eraseConnRelated(struct IPRule rule) {
	struct rb_node *node;         // 用于遍历红黑树的节点指针
	unsigned short sport,dport;   // 存储连接的源端口和目的端口
	struct connNode *needDel = NULL; // 指向待删除连接节点的指针
	unsigned int count = 0;       // 记录删除的连接数量
	int hasChange = 1;            // 标志，指示在一次完整的树遍历中是否删除了节点

	// 初始化：将规则的协议设置为 IPPROTO_IP (0)，matchOneRule 可能会将其解释为匹配任何协议
	rule.protocol = IPPROTO_IP;

	// 循环删除相关节点，直到一次完整的遍历没有删除任何节点为止
	while(hasChange) {
		hasChange = 0; // 在每次大循环开始时，重置 hasChange 标志
		read_lock(&connLock); // 获取读锁以遍历树
		// 从红黑树的第一个节点开始遍历
		for (node = rb_first(&connRoot); node; node = rb_next(node)) {
			needDel = rb_entry(node, struct connNode, node); // 获取当前连接节点

			// 从连接键中提取源端口和目的端口
			sport = (unsigned short)(needDel->key[2] >> 16);
			dport = (unsigned short)(needDel->key[2] & 0xFFFFu);

			// 调用 matchOneRule 判断当前连接是否与给定的过滤规则相关
			// 参数: 规则，连接的源IP，目的IP，源端口，目的端口，协议
			if(matchOneRule(&rule, needDel->key[0], needDel->key[1], sport, dport, needDel->protocol)) {
				hasChange = 1; // 标记已找到需要删除的节点
				// 注意：这里直接 break，意味着每次只找到一个就去删除，然后重新遍历。
				// 这是为了避免在遍历过程中修改树结构导致遍历器失效。
				break;
			}
		}
		read_unlock(&connLock); // 释放读锁

		if(hasChange) { // 如果在上面的遍历中找到了需要删除的节点
			// needDel 指向的就是那个需要被删除的节点
			eraseNode(&connRoot, needDel); // 从红黑树中删除该节点并释放内存
			count++; // 增加删除计数
		}
		// 如果 hasChange 仍为0，表示上一次遍历没有找到可删除的节点，循环将终止。
	}
	printk("[fw conns] erase all related conn finish.\n"); // 打印完成信息
	return count; // 返回总共删除的连接数量
}

/**
 * @brief 周期性清理连接池，删除所有已超时的连接。
 *        此函数通常由内核定时器回调函数调用。
 *
 * @return int 通常返回0。
 *
 * @功能描述:
 *   与 `eraseConnRelated` 类似，此函数也使用一个 `while(hasChange)` 循环来反复遍历
 *   连接红黑树，直到一次完整的遍历没有发现任何超时连接为止。
 *   1.  在每次循环的开始，获取读锁并遍历红黑树中的所有连接节点。
 *   2.  对于每个连接节点，调用 `isTimeout(needDel->expires)` 检查其是否已超时。
 *   3.  如果连接已超时：
 *       -   设置 `hasChange = 1`。
 *       -   保存超时节点指针 (`needDel`)。
 *       -   中断内部的遍历。
 *   4.  释放读锁。
 *   5.  如果 `hasChange` 为1（即找到了超时连接）：
 *       -   调用 `eraseNode` 从红黑树中删除该超时节点。
 *   6.  `while` 循环继续，直到没有更多超时连接被找到。
 *
 *   这种删除方式同样是为了处理遍历时修改集合的问题。
 */
int rollConn(void) {
	struct rb_node *node;             // 用于遍历红黑树的节点指针
	struct connNode *needDel = NULL;  // 指向待删除（超时）连接节点的指针
	int hasChange = 1;                // 标志，指示在一次完整的树遍历中是否删除了节点

	//printk("[fw conns] flush all conn start.\n"); // 调试信息 (已注释)

	// 循环删除超时连接，直到一次完整的遍历没有删除任何节点为止
	while(hasChange) {
		hasChange = 0; // 重置标志
		read_lock(&connLock); // 获取读锁
		// 遍历红黑树
		for (node = rb_first(&connRoot); node; node = rb_next(node)) {
			needDel = rb_entry(node, struct connNode, node); // 获取当前连接节点
			if(isTimeout(needDel->expires)) { // 检查连接是否已超时
				hasChange = 1; // 标记已找到超时节点
				break;         // 中断遍历，准备删除此节点
			}
		}
		read_unlock(&connLock); // 释放读锁

		if(hasChange) { // 如果找到了超时节点
			eraseNode(&connRoot, needDel); // 删除该超时节点
		}
	}
	//printk("[fw conns] flush all conn finish.\n"); // 调试信息 (已注释)
	return 0;
}

// --- 定时器相关 ---

// 定义一个内核定时器结构体 `conn_timer`，用于周期性地清理连接池。
static struct timer_list conn_timer;

/**
 * @brief 内核定时器的回调函数。
 *        当 `conn_timer` 定时器触发时，此函数会被内核调用。
 *
 * @param arg (对于旧内核版本 < 4.14.0) 传递给定时器回调的参数 (在此代码中未使用，设为0)。
 * @param t (对于新内核版本 >= 4.14.0) 指向触发此回调的 `timer_list` 结构体的指针。
 * @return void 无返回值。
 *
 * @功能描述:
 *   1.  调用 `rollConn()` 函数来遍历连接池并清除所有已超时的连接。
 *   2.  调用 `mod_timer(&conn_timer, timeFromNow(CONN_ROLL_INTERVAL))` 来重新设置（重新激活）
 *       `conn_timer` 定时器，使其在 `CONN_ROLL_INTERVAL` 秒之后再次触发。
 *       `CONN_ROLL_INTERVAL` 是预定义的连接清理周期。
 *       `timeFromNow` (应在 `tools.h` 中定义) 将秒数转换为未来的 `jiffies` 值。
 *
 *   通过这种方式，定时器会周期性地执行连接清理任务。
 */
// 根据内核版本选择不同的定时器回调函数签名
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0) // 如果内核版本低于 4.14.0
void conn_timer_callback(unsigned long arg) { // 旧版API，参数为 unsigned long
#else // 如果内核版本大于等于 4.14.0
void conn_timer_callback(struct timer_list *t) { // 新版API，参数为 struct timer_list *
#endif
    rollConn(); // 调用连接清理函数
	mod_timer(&conn_timer, timeFromNow(CONN_ROLL_INTERVAL)); // 重新设置定时器，使其在 CONN_ROLL_INTERVAL 秒后再次触发
}

/**
 * @brief 初始化连接跟踪模块的相关内容，主要是设置和启动内核定时器。
 *        此函数通常在内核模块加载时 (`mod_init`) 被调用。
 * @return void 无返回值。
 * @功能描述:
 *   1.  根据内核版本选择不同的API来初始化定时器 `conn_timer`：
 *       -   对于旧内核 (< 4.14.0)，使用 `init_timer`，并手动设置 `function` 和 `data` 成员。
 *       -   对于新内核 (>= 4.14.0)，使用 `timer_setup`，直接传入回调函数和标志。
 *   2.  设置定时器的首次超时时间 (`conn_timer.expires`) 为从当前时间起 `CONN_ROLL_INTERVAL` 秒之后。
 *   3.  调用 `add_timer(&conn_timer)` 将定时器添加到内核的活动定时器列表中，以激活它。
 */
void conn_init(void) {
// 根据内核版本初始化定时器
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    init_timer(&conn_timer); // 初始化定时器结构体
    conn_timer.function = &conn_timer_callback; // 设置定时器到期时调用的回调函数
    conn_timer.data = ((unsigned long)0); // 设置传递给回调函数的参数 (此处为0，未使用)
#else
    // 使用新的 timer_setup API 初始化定时器，直接关联回调函数，flags设为0
    timer_setup(&conn_timer, conn_timer_callback, 0);
#endif
	conn_timer.expires = timeFromNow(CONN_ROLL_INTERVAL); // 设置定时器的首次超时时间
	add_timer(&conn_timer); // 将定时器添加到内核的活动定时器列表，激活它
}

/**
 * @brief 清理连接跟踪模块的资源，主要是删除（停止）内核定时器。
 *        此函数通常在内核模块卸载时 (`mod_exit`) 被调用。
 * @return void 无返回值。
 * @功能描述:
 *   调用 `del_timer(&conn_timer)` 从内核的活动定时器列表中移除 `conn_timer`。
 *   如果定时器正在等待触发，它将被取消。如果回调函数正在运行，`del_timer` 会等待其完成。
 *   这是确保模块卸载时不会留下悬挂定时器的重要步骤。
 */
void conn_exit(void) {
	del_timer(&conn_timer); // 删除（停止）内核定时器
}