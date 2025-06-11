#include "contact.h"

/**
 * @brief 添加过滤规则的用户交互函数
 * @return struct KernelResponse 内核响应结果
 *         包含错误码和数据指针
 * @note 通过命令行交互获取规则参数，包括：
 *       - 规则位置(after)
 *       - 规则名称(name)
 *       - 源IP/掩码(saddr)
 *       - 目的IP/掩码(daddr) 
 *       - 源端口范围(sport)
 *       - 目的端口范围(dport)
 *       - 协议类型(proto)
 *       - 动作(action)
 *       - 日志标志(log)
 */
struct KernelResponse cmdAddRule() {
    struct KernelResponse empty;
    // 定义各种参数缓冲区
    char after[MAXRuleNameLen+1],name[MAXRuleNameLen+1],saddr[25],daddr[25],sport[15],dport[15],protoS[6];
    unsigned short sportMin,sportMax,dportMin,dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i;
    empty.code = ERROR_CODE_EXIT;
    
    // 获取前序规则名（在此规则后插入）
    printf("add rule after [enter for adding at head]: ");
    for(i=0;;i++) {
        if(i>MAXRuleNameLen) {
            printf("name too long.\n");
            return empty;
        }
        after[i] = getchar();
        if(after[i] == '\n' || after[i] == '\r') {
            after[i] = '\0';
            break;
        }
    }
    
    // 获取规则名称
    printf("rule name [max len=%d]: ", MAXRuleNameLen);
    scanf("%s",name);
    if(strlen(name)==0 || strlen(name)>MAXRuleNameLen) {
        printf("name too long or too short.\n");
        return empty;
    }
    
    // 获取源IP地址和掩码
    printf("source ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",saddr);
    
    // 获取源端口范围
    printf("source port range [like 8080-8031 or any]: ");
    scanf("%s",sport);
    if(strcmp(sport, "any") == 0) {
        sportMin = 0,sportMax = 0xFFFFu;  // 任意端口则设置为全范围
    } else {
        sscanf(sport,"%hu-%hu",&sportMin,&sportMax);  // 解析端口范围
    }
    if(sportMin > sportMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    
    // 获取目的IP地址和掩码
    printf("target ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",daddr);
    
    // 获取目的端口范围
    printf("target port range [like 8080-8031 or any]: ");
    scanf("%s",dport);
    if(strcmp(dport, "any") == 0) {
        dportMin = 0,dportMax = 0xFFFFu;  // 任意端口则设置为全范围
    } else {
        sscanf(dport,"%hu-%hu",&dportMin,&dportMax);  // 解析端口范围
    }
    if(dportMin > dportMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    
    // 获取协议类型
    printf("protocol [TCP/UDP/ICMP/any]: ");
    scanf("%s",protoS);
    if(strcmp(protoS,"TCP")==0)
        proto = IPPROTO_TCP;
    else if(strcmp(protoS,"UDP")==0)
        proto = IPPROTO_UDP;
    else if(strcmp(protoS,"ICMP")==0)
        proto = IPPROTO_ICMP;
    else if(strcmp(protoS,"any")==0)
        proto = IPPROTO_IP;
    else {
        printf("This protocol is not supported.\n");
        return empty;
    }
    
    // 获取动作类型（接受/丢弃）
    printf("action [1 for accept,0 for drop]: ");
    scanf("%d",&action);
    
    // 获取是否记录日志标志
    printf("is log [1 for yes,0 for no]: ");
    scanf("%u",&log);
    
    printf("result:\n");
    // 调用添加过滤规则的核心函数，将端口范围打包成32位整数
    return addFilterRule(after,name,saddr,daddr,
        (((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
        (((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

/**
 * @brief 添加NAT规则的用户交互函数
 * @return struct KernelResponse 内核响应结果
 * @note 仅支持源NAT转换，通过命令行交互获取：
 *       - 源IP/掩码(saddr)
 *       - NAT转换后的IP(daddr)
 *       - 端口范围(port)
 */
struct KernelResponse cmdAddNATRule() {
    struct KernelResponse empty;
    char saddr[25],daddr[25],port[15];
    unsigned short portMin,portMax;
    empty.code = ERROR_CODE_EXIT;
    
    printf("ONLY source NAT is supported\n");
    
    // 获取源IP地址和掩码
    printf("source ip and mask [like 127.0.0.1/16]: ");
    scanf("%s",saddr);
    
    // 获取NAT转换后的IP地址
    printf("NAT ip [like 192.168.80.139]: ");
    scanf("%s",daddr);
    
    // 获取端口范围
    printf("NAT port range [like 10000-30000 or any]: ");
    scanf("%s",port);
    if(strcmp(port, "any") == 0) {
        portMin = 0,portMax = 0xFFFFu;  // 任意端口则设置为全范围
    } else {
        sscanf(port,"%hu-%hu",&portMin,&portMax);  // 解析端口范围
    }
    if(portMin > portMax) {
        printf("the min port > max port.\n");
        return empty;
    }
    
    // 调用添加NAT规则的核心函数
    return addNATRule(saddr,daddr,portMin,portMax);
}

/**
 * @brief 显示错误命令提示信息
 * @note 当用户输入无效命令时显示帮助信息
 */
void wrongCommand() {
    printf("wrong command.\n");
    printf("uapp <command> <sub-command> [option]\n");
    printf("commands: rule <add | del | ls | default> [del rule's name]\n");
    printf("          nat  <add | del | ls> [del number]\n");
    printf("          ls   <rule | nat | log | connect>\n");
    exit(0);
}

/**
 * @brief 主函数，处理命令行参数并执行相应操作
 * @param argc 参数个数
 * @param argv 参数数组
 * @return int 程序退出状态码
 * @note 支持的命令包括：
 *       - 过滤规则管理(rule)
 *       - NAT规则管理(nat)
 *       - 查看各种信息(ls)
 */
int main(int argc, char *argv[]) {
    if(argc<3) {
        wrongCommand();
        return 0;
    }
    
    struct KernelResponse rsp;
    rsp.code = ERROR_CODE_EXIT;
    
    // 过滤规则相关命令处理
    if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
        if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
            // 列出所有过滤规则
            rsp = getAllFilterRules();
        } else if(strcmp(argv[2], "del")==0) {
            // 删除过滤规则
            if(argc < 4)
                printf("Please point rule name in option.\n");
            else if(strlen(argv[3])>MAXRuleNameLen)
                printf("rule name too long!");
            else
                rsp = delFilterRule(argv[3]);
        } else if(strcmp(argv[2], "add")==0) {
            // 添加过滤规则
            rsp = cmdAddRule();
        } else if(strcmp(argv[2], "default")==0) {
            // 设置默认规则
            if(argc < 4)
                printf("Please point default action in option.\n");
            else if(strcmp(argv[3], "accept")==0)
                rsp = setDefaultAction(NF_ACCEPT);
            else if(strcmp(argv[3], "drop")==0)
                rsp = setDefaultAction(NF_DROP);
            else
                printf("No such action. Only \"accept\" or \"drop\".\n");
        } else 
            wrongCommand();
    } 
    // NAT规则相关命令处理
    else if(strcmp(argv[1], "nat")==0 || argv[1][0] == 'n') {
        if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
            // 列出所有NAT规则
            rsp = getAllNATRules();
        } else if(strcmp(argv[2], "del")==0) {
            // 删除NAT规则
            if(argc < 4)
                printf("Please point rule number(seq) in option.\n");
            else {
                int num;
                sscanf(argv[3], "%d", &num);
                rsp = delNATRule(num);
            }
        } else if(strcmp(argv[2], "add")==0) {
            // 添加NAT规则
            rsp = cmdAddNATRule();
        } else {
            wrongCommand();
        }
    } 
    // 查看信息相关命令处理
    else if(strcmp(argv[1], "ls")==0 || argv[1][0] == 'l') {
        if(strcmp(argv[2],"log")==0 || argv[2][0] == 'l') {
            // 获取过滤日志
            unsigned int num = 0;
            if(argc > 3)
                sscanf(argv[3], "%u", &num);
            rsp = getLogs(num);
        } else if(strcmp(argv[2],"con")==0 || argv[2][0] == 'c') {
            // 获取连接状态
            rsp = getAllConns();
        } else if(strcmp(argv[2],"rule")==0 || argv[2][0] == 'r') {
            // 获取已有过滤规则
            rsp = getAllFilterRules();
        } else if(strcmp(argv[2],"nat")==0 || argv[2][0] == 'n') {
            // 获取已有NAT规则
            rsp = getAllNATRules();
        } else
            wrongCommand();
    } else 
        wrongCommand();
    
    // 处理内核响应并显示结果
    dealResponseAtCmd(rsp);
}