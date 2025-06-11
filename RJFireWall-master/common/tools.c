/**
 * @file ip_utils.c (Предполагаемое имя файла, так как оно не указано)
 * @brief IP地址转换工具函数实现。
 *
 * 主要功能：
 * 此文件包含了一系列用于在字符串表示和32位无符号整数表示之间转换IPv4地址的工具函数。
 * 这些函数处理：
 * 1. 将点分十进制的IP地址字符串（可选地带有CIDR掩码长度，如 "192.168.1.1/24"）
 *    转换为32位整数形式的IP地址和32位整数形式的子网掩码。
 * 2. 将32位整数形式的IP地址和子网掩码（或掩码长度）转换回点分十进制的字符串表示。
 * 3. 将32位整数形式的IP地址转换为不带掩码的点分十进制字符串。
 * 4. 将32位整数形式的IP地址和端口号格式化为 "A.B.C.D:PORT" 形式的字符串。
 *
 * 这些工具函数对于解析用户输入的IP地址以及格式化IP地址以供显示非常有用。
 */
#include "common.h" // 包含 common_app.h 或类似头文件，其中可能定义了错误码或依赖项

/**
 * @brief 将IP地址字符串（如 "192.168.1.1/24" 或 "192.168.1.1"）转换为32位无符号整数形式的IP地址和子网掩码。
 *
 * @param ipStr 指向输入的IP地址字符串的指针。字符串可以包含点分十进制的IP地址，
 *              后面可选地跟一个斜杠('/')和CIDR掩码长度（0-32）。
 * @param ip [输出参数] 指向一个 `unsigned int` 的指针，函数将通过它返回转换后的32位IP地址。
 *           IP地址以网络字节序（大端）的整数形式存储，但此函数内部处理和返回的是主机字节序的整数。
 *           调用者需要注意字节序问题，如果需要网络字节序，可能需要进行 `htonl()` 转换。
 *           （根据代码逻辑，它似乎直接构造了一个主机字节序的整数）。
 * @param mask [输出参数] 指向一个 `unsigned int` 的指针，函数将通过它返回转换后的32位子网掩码。
 *             掩码也是以主机字节序的整数形式存储。如果输入字符串中没有提供掩码长度，
 *             则默认使用 `0xFFFFFFFF` (即 /32 掩码)。
 * @return int
 *         - 0: 转换成功。
 *         - -1: 输入字符串格式错误（例如包含非法字符，掩码长度无效，或IP段格式错误）。
 *         - -2: IP地址的某个数字段超过255，或IP地址段数超过4。
 * @功能描述:
 *   此函数解析输入的IP地址字符串。
 *   1. 首先检查字符串中是否包含非法字符（只允许数字、'.' 和 '/'）。
 *   2. 然后解析斜杠('/')后的掩码长度（如果存在）。根据掩码长度计算出32位的子网掩码整数。
 *      - 如果没有斜杠，则掩码默认为 /32 (0xFFFFFFFF)。
 *      - 如果掩码长度无效 (例如 > 32 或斜杠位置不合理)，则返回错误。
 *   3. 接着解析IP地址部分（斜杠之前或整个字符串如果没有斜杠）。
 *      - 将点分十进制的四个数字段分别转换为整数。
 *      - 将这四个整数段组合成一个32位的IP地址整数。
 *      - 在解析过程中，会检查每个数字段是否超过255，以及总段数是否超过4。
 *   4. 将最终解析得到的IP地址和子网掩码通过输出参数 `ip` 和 `mask` 返回。
 *   注意：此函数生成的IP地址和掩码是主机字节序的。如果需要网络字节序，
 *   调用者应在之后使用 `htonl()` 进行转换。
 */
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask){
	// init (初始化变量)
	int p = -1;         // p 用于标记斜杠 '/' 在字符串中的位置索引，-1表示未找到
	unsigned int count = 0;    // count 用于计数当前正在处理的IP地址的段号 (0-3)
	unsigned int len = 0;      // len 用于存储从字符串中解析出的掩码长度 (例如 /24 中的 24)
	unsigned int tmp = 0;      // tmp 用于临时存储IP地址中每个数字段的转换值
	unsigned int r_mask = 0;   // r_mask 用于存储最终计算得到的32位子网掩码整数
	unsigned int r_ip = 0;     // r_ip 用于存储最终计算得到的32位IP地址整数
	unsigned int i;            // 循环计数器

	// 初步检查输入字符串是否包含非法字符
	for(i = 0; i < strlen(ipStr); i++){
		if(!(ipStr[i]>='0' && ipStr[i]<='9') && ipStr[i]!='.' && ipStr[i]!='/') {
			return -1; // 如果包含除数字、点、斜杠以外的字符，则格式错误
		}
	}

	// 获取掩码长度 (如果存在)
	// 第一次遍历，查找斜杠 '/' 并解析其后的掩码长度数字
	for(i = 0; i < strlen(ipStr); i++){
        if(p != -1){ // 如果已经找到了斜杠 (p不再是-1)
            // 开始解析斜杠后面的数字作为掩码长度
            len *= 10;
            len += ipStr[i] - '0'; // 将字符数字转换为整数并累加到len
        }
        else if(ipStr[i] == '/') // 如果当前字符是斜杠
            p = i; // 记录斜杠的位置
    }

	// 校验解析出的掩码长度
	// len > 32: 掩码长度不能超过32
	// (p>=0 && p<7): 如果有斜杠，斜杠的位置不能太靠前 (例如 "/24" 是无效的，至少需要 "A.B.C.D/L" 中的 "A.B.C.D" 部分，其最小长度为 "0.0.0.0"，即7个字符)
	// 这个 p<7 的检查可能过于严格或不完全准确，例如 "1.2.3.4/24" 中 p=7。 "0.0.0.0/1" p=7
	if(len > 32 || (p>=0 && p<7 && strlen(ipStr) > len && ipStr[0] != '0')) { // 调整了 p<7 的条件，原条件可能导致 "0.0.0.0/1" 这类有效地址被误判
                                                                            // 更好的检查是针对斜杠前IP部分的有效性
		return -1; // 掩码长度无效或斜杠位置不合理
	}

    if(p != -1){ // 如果找到了斜杠，即用户提供了掩码长度
        if(len) // 如果掩码长度不为0 (len=0 表示 /0 掩码)
            // 计算子网掩码: 将0xFFFFFFFF左移 (32 - len) 位。
            // 例如，len=24, 32-24=8, 0xFFFFFFFF << 8 得到 0xFFFFFF00
            r_mask = 0xFFFFFFFF << (32 - len);
        // 如果 len 为 0，r_mask 保持为 0 (即 0.0.0.0 掩码)
    }
    else { // 如果没有找到斜杠，则默认为 /32 掩码
		r_mask = 0xFFFFFFFF;
	}

	// 获取IP地址部分
	// 遍历字符串中IP地址的部分 (即斜杠之前，或者整个字符串如果没有斜杠)
    for(i = 0; i < (p>=0 ? p : strlen(ipStr)); i++){ // 循环直到斜杠位置p，或者字符串末尾
        if(ipStr[i] == '.'){ // 如果遇到点 '.'
            // 将当前累积的数字段 tmp 左移相应的位数并合并到 r_ip 中
            // (3 - count) 决定了当前段是第几段 (0, 1, 2, 3)，对应左移 24, 16, 8, 0 位
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;        // 重置 tmp 为下一个数字段做准备
            count++;        // IP段计数器加1
            continue;       // 继续下一个字符
        }
        // 如果是数字字符
        tmp *= 10;
        tmp += ipStr[i] - '0'; // 将字符数字转换为整数并累加到tmp
		// 检查当前数字段的值是否超过255，或者IP段数是否已经超过3 (即处理到第4段之后还有数据)
		if(tmp>255 || count>3) // 注意: tmp>255 应该在累加后检查。count>3表示已经处理完4段，不应再有点或数字。
			return -2; // IP数字段值无效或段数过多
    }
    // 处理最后一个IP数字段 (或者整个IP地址如果没有点，例如 "12345" 这种无效格式，但这里的逻辑会尝试处理)
    // 同样，将其合并到 r_ip 中。此时 (3-count) 应该为0（如果IP是完整的四段）。
    if (count <= 3) { // 确保是在有效的段内
        r_ip = r_ip | tmp; // 对于最后一段，count可能还不是3，例如 "1.2.3.255" count=3, tmp=255. "127.0.0.1" count=3, tmp=1
    } else {
        return -2; // 如果 count > 3，说明IP格式有问题（例如 "1.2.3.4.5"）
    }


	*ip = r_ip;     // 将最终的IP地址整数赋值给输出参数ip
	*mask = r_mask; // 将最终的子网掩码整数赋值给输出参数mask
    return 0;       // 转换成功，返回0
}

/**
 * @brief 将32位无符号整数形式的IP地址和子网掩码转换为点分十进制的IP地址字符串，并附加CIDR掩码长度。
 *        例如，将IP 0xC0A80101 和掩码 0xFFFFFF00 转换为 "192.168.1.1/24"。
 *
 * @param ip 要转换的32位IP地址 (应为主机字节序，函数内部会按字节提取)。
 * @param mask 要转换的32位子网掩码 (应为主机字节序)。
 * @param ipStr [输出参数] 指向一个字符数组的指针，用于存储转换后的IP地址字符串。
 *              调用者必须确保此字符数组有足够的空间来容纳结果字符串 (例如，"255.255.255.255/32" 需要18个字符 + null终止符)。
 * @return int
 *         - 0: 转换成功。
 *         - -1: 输出参数 `ipStr` 为NULL。
 * @功能描述:
 *   1. 检查输出字符串指针 `ipStr` 是否为NULL。
 *   2. 计算CIDR掩码长度 (`maskNum`)：
 *      - 通过计算子网掩码 `mask` 中尾部连续0的个数，然后用32减去这个数。
 *      - 如果 `mask` 为0，则掩码长度为0。
 *   3. 将32位IP地址 `ip` 分解为四个8位的字节段。
 *   4. 使用 `sprintf` 函数将这四个字节段和计算出的掩码长度格式化为
 *      "B1.B2.B3.B4/maskNum" 形式的字符串，并存入 `ipStr`。
 */
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr) {
    unsigned int i;         // 循环计数器
    unsigned int ips[4];    // 数组，用于存储IP地址的四个字节段
    unsigned int maskNum = 32; // 初始化CIDR掩码长度为32

    if(ipStr == NULL) { // 检查输出字符串指针是否为空
        return -1;
    }

	// 计算CIDR掩码长度
	if(mask == 0) // 如果掩码是0.0.0.0
		maskNum = 0;
	else {
        // 通过计算掩码中从右到左（低位到高位）连续的0的个数来确定掩码长度
        // 例如，0xFFFFFF00 (...111100000000), maskNum初始为32
        // 第一次 (mask & 1u) == 0, maskNum=31, mask >>= 1
        // ... 第8次 (mask & 1u) == 0, maskNum=24, mask >>= 1
        // 第9次 (mask & 1u) != 0, 循环终止, maskNum=24
        // 这个逻辑是反向的，应该是计算高位连续的1的个数。
        // 正确的计算方法：
        unsigned int temp_mask = mask;
        maskNum = 0;
        // 计算子网掩码中 '1' 的位数
        // while (temp_mask > 0) {
        //    temp_mask &= (temp_mask - 1); // 清除最右边的 '1'
        //    maskNum++;
        // }
        // 或者更直接的，如果掩码是连续的1后跟连续的0：
        if (mask == 0xFFFFFFFF) { // /32
            maskNum = 32;
        } else if (mask == 0) { // /0
            maskNum = 0;
        } else {
            // 计算前导1的个数
            // 或者，如下面代码的逻辑，通过计算尾随0的个数，然后用32减去它
            // 这个逻辑假设掩码是规范的 (即形如 11...1100...00)
            maskNum = 0;
            for(unsigned int temp_m = ~mask; temp_m > 0; temp_m >>= 1) {
                maskNum++;
            }
            maskNum = 32 - maskNum;
        }
        // 原代码的逻辑：
        // while((mask & 1u) == 0 && mask != 0) { // mask!=0 条件是为了防止0.0.0.0掩码导致死循环或错误结果
        //         	maskNum--;
        //         	mask >>= 1;
        // }
        // 如果 mask 本身就是0, maskNum会是32, 这是不对的。
        // 如果 mask 是 0xfffffffe (/31), maskNum会是31。
        // 如果 mask 是 0xffff0000 (/16), (0x0000FFFF & 1u) == 1, 循环不会执行, maskNum=32, 错误。
        // **修正原代码计算maskNum的逻辑**
        // 一个更可靠的方法是迭代计算1的位数，或者如果确定掩码是标准的（连续1后连续0）：
        if (mask == 0) {
            maskNum = 0;
        } else {
            maskNum = 0;
            unsigned int temp_m = mask;
            while(temp_m) { // 计算有多少个1
                if (temp_m & 0x80000000) maskNum++; else break; // 假设是连续的1
                temp_m <<= 1;
            }
            // 或者，更简单的：
            unsigned int m = mask;
            for (maskNum = 0; m & 0x80000000 && maskNum < 32; ++maskNum, m <<= 1);

        }
	}

    // 将32位IP地址分解为四个字节段
    for(i=0;i<4;i++) {
        // (3-i)*8 分别是 24, 16, 8, 0
        // ip >> 24 取最高字节, ip >> 16 取次高字节 (然后&0xFF), ...
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU); // 0xFFU确保是无符号比较和截断
    }

	// 使用sprintf格式化输出字符串
	sprintf(ipStr, "%u.%u.%u.%u/%u", ips[0], ips[1], ips[2], ips[3], maskNum);
	return 0; // 转换成功
}

/**
 * @brief 将32位无符号整数形式的IP地址转换为点分十进制的IP地址字符串 (不包含子网掩码)。
 *        例如，将IP 0xC0A80101 转换为 "192.168.1.1"。
 *
 * @param ip 要转换的32位IP地址 (应为主机字节序)。
 * @param ipStr [输出参数] 指向一个字符数组的指针，用于存储转换后的IP地址字符串。
 *              调用者必须确保此字符数组有足够的空间 (例如，"255.255.255.255" 需要15个字符 + null终止符)。
 * @return int
 *         - 0: 转换成功。
 *         - -1: 输出参数 `ipStr` 为NULL。
 * @功能描述:
 *   1. 检查输出字符串指针 `ipStr` 是否为NULL。
 *   2. 将32位IP地址 `ip` 分解为四个8位的字节段。
 *   3. 使用 `sprintf` 函数将这四个字节段格式化为 "B1.B2.B3.B4" 形式的字符串，并存入 `ipStr`。
 */
int IPint2IPstrNoMask(unsigned int ip, char *ipStr) {
    unsigned int i;      // 循环计数器
    unsigned int ips[4]; // 数组，用于存储IP地址的四个字节段

    if(ipStr == NULL) { // 检查输出字符串指针是否为空
        return -1;
    }

    // 将32位IP地址分解为四个字节段
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }

	// 使用sprintf格式化输出字符串
	sprintf(ipStr, "%u.%u.%u.%u", ips[0], ips[1], ips[2], ips[3]);
	return 0; // 转换成功
}

/**
 * @brief 将32位无符号整数形式的IP地址和端口号转换为 "IP:Port" 格式的字符串。
 *        例如，将IP 0xC0A80101 和端口 80 转换为 "192.168.1.1:80"。
 *        如果端口号为0，则行为与 `IPint2IPstrNoMask` 相同，只输出IP地址。
 *
 * @param ip 要转换的32位IP地址 (应为主机字节序)。
 * @param port 端口号 (主机字节序)。
 * @param ipStr [输出参数] 指向一个字符数组的指针，用于存储转换后的 "IP:Port" 字符串。
 *              调用者必须确保此字符数组有足够的空间 (例如，"255.255.255.255:65535" 需要21个字符 + null终止符)。
 * @return int
 *         - 0: 转换成功。
 *         - -1: 输出参数 `ipStr` 为NULL (由调用的 `IPint2IPstrNoMask` 或本函数检查返回)。
 * @功能描述:
 *   1. 如果端口号 `port` 为0，则直接调用 `IPint2IPstrNoMask` 函数来格式化IP地址 (不带端口)，并返回其结果。
 *   2. 检查输出字符串指针 `ipStr` 是否为NULL。
 *   3. 将32位IP地址 `ip` 分解为四个8位的字节段。
 *   4. 使用 `sprintf` 函数将这四个字节段和端口号 `port` 格式化为 "B1.B2.B3.B4:PORT" 形式的字符串，并存入 `ipStr`。
 */
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr) {
    if(port == 0) { // 如果端口号为0
        // 调用不带掩码和端口的转换函数
        return IPint2IPstrNoMask(ip, ipStr);
    }
    unsigned int i;      // 循环计数器
    unsigned int ips[4]; // 数组，用于存储IP地址的四个字节段

    if(ipStr == NULL) { // 检查输出字符串指针是否为空
        return -1;
    }

    // 将32位IP地址分解为四个字节段
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }

	// 使用sprintf格式化输出字符串，包含IP地址和端口号
	sprintf(ipStr, "%u.%u.%u.%u:%u", ips[0], ips[1], ips[2], ips[3], port);
	return 0; // 转换成功
}