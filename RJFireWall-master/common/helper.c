#include "common.h"

/**
 * @brief 添加IP过滤规则
 * @param after 新规则要插入的位置(规则名称)，空字符串表示插入到链表头部
 * @param name 新规则的名称(最大长度MAXRuleNameLen)
 * @param sip 源IP地址字符串(格式如"192.168.1.1/24")
 * @param dip 目的IP地址字符串
 * @param sport 源端口范围(高16位为最小端口，低16位为最大端口)
 * @param dport 目的端口范围(格式同sport)
 * @param proto 协议类型(IPPROTO_TCP/IPPROTO_UDP等)
 * @param log 是否记录日志(1=记录，0=不记录)
 * @param action 规则动作(NF_ACCEPT=允许，NF_DROP=拒绝)
 * @return struct KernelResponse 内核响应，包含错误码和响应数据
 *         - code: 错误码(>=0成功，<0失败)
 *         - data: 响应数据指针(需要调用者释放)
 */
struct KernelResponse addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
    struct KernelResponse rsp;
	// form rule
	struct IPRule rule;
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.saddr = rule.saddr;
	rule.daddr = rule.daddr;
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAXRuleNameLen);
	// form req
	req.tp = REQ_ADDIPRule;
	req.ruleName[0]=0;
	strncpy(req.ruleName, after, MAXRuleNameLen);
	req.msg.ipRule = rule;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 删除指定名称的过滤规则
 * @param name 要删除的规则名称
 * @return struct KernelResponse 内核响应
 *         - code: 错误码(ERROR_CODE_NO_SUCH_RULE=规则不存在)
 *         - data: 响应数据指针(需要调用者释放)
 */
struct KernelResponse delFilterRule(char *name) {
	struct APPRequest req;
	// form request
	req.tp = REQ_DELIPRule;
	strncpy(req.ruleName, name, MAXRuleNameLen);
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 获取所有过滤规则
 * @return struct KernelResponse 包含所有规则的响应
 *         - code: 错误码
 *         - data: 规则数据指针(需要调用者释放)
 *         - header->bodyTp: 响应体类型(RSP_IPRules)
 *         - header->arrayLen: 规则数量
 */
struct KernelResponse getAllFilterRules(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETAllIPRules;
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 添加NAT规则(仅支持源NAT)
 * @param sip 源IP地址字符串(格式如"192.168.1.1/24")
 * @param natIP NAT转换后的IP地址
 * @param minport 起始端口号
 * @param maxport 结束端口号
 * @return struct KernelResponse 内核响应
 *         - code: 错误码(ERROR_CODE_WRONG_IP=IP格式错误)
 */
struct KernelResponse addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport) {
	struct APPRequest req;
	struct KernelResponse rsp;
	// form rule
	struct NATRecord rule;
	if(IPstr2IPint(natIP,&rule.daddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;
		return rsp;
	}
	rule.sport = minport;
	rule.dport = maxport;
	// form req
	req.tp = REQ_ADDNATRule;
	req.msg.natRule = rule;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 删除指定序号的NAT规则
 * @param num 要删除的规则序号(从0开始)
 * @return struct KernelResponse 内核响应
 *         - code: 错误码(ERROR_CODE_NO_SUCH_RULE=规则不存在)
 */
struct KernelResponse delNATRule(int num) {
	struct APPRequest req;
	struct KernelResponse rsp;
	if(num < 0) {
		rsp.code = ERROR_CODE_NO_SUCH_RULE;
		return rsp;
	}
	req.tp = REQ_DELNATRule;
	req.msg.num = num;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 获取所有NAT规则
 * @return struct KernelResponse 包含所有NAT规则的响应
 *         - header->bodyTp: 响应体类型(RSP_NATRules)
 *         - header->arrayLen: 规则数量
 */
struct KernelResponse getAllNATRules(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETNATRules;
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 设置默认过滤动作
 * @param action 默认动作(NF_ACCEPT=允许，NF_DROP=拒绝)
 * @return struct KernelResponse 内核响应
 */
struct KernelResponse setDefaultAction(unsigned int action) {
	struct APPRequest req;
	// form request
	req.tp = REQ_SETAction;
	req.msg.defaultAction = action;
	// exchange
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 获取过滤日志
 * @param num 要获取的日志条数(0表示获取全部)
 * @return struct KernelResponse 包含日志的响应
 *         - header->bodyTp: 响应体类型(RSP_IPLogs)
 *         - header->arrayLen: 日志数量
 */
struct KernelResponse getLogs(unsigned int num) {
	struct APPRequest req;
	// exchange msg
	req.msg.num = num;
	req.tp = REQ_GETAllIPLogs;
	return exchangeMsgK(&req, sizeof(req));
}

/**
 * @brief 获取所有活动连接
 * @return struct KernelResponse 包含连接列表的响应
 *         - header->bodyTp: 响应体类型(RSP_ConnLogs)
 *         - header->arrayLen: 连接数量
 */
struct KernelResponse getAllConns(void) {
	struct APPRequest req;
	// exchange msg
	req.tp = REQ_GETAllConns;
	return exchangeMsgK(&req, sizeof(req));
}
