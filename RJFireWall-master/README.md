文项目援引自：https://github.com/RicheyJang/RJFireWall，一个基于Netfilter、Netlink的Linux传输层状态检测防火墙，支持NAT，仅用于学习与交流（华中科技大学2021学年网络安全课程设计项目）。本项目为2025年江苏大学信息安全入侵防御检测系统课程设计，如有侵权可告知删除，仅供交流学习

# RJ FireWall

一个基于Netfilter、Netlink的Linux传输层状态检测防火墙，核心代码不到2000行，使用红黑树实现状态检测，内核模块代码通过读写锁几乎全面实现并发安全。

仅用于学习与交流，**一定程度上**可以放心使用。

支持的功能：
- [x] 按源目的IP、端口、协议过滤报文
- [x] 掩码
- [x] 并发安全
- [x] 通过命令行应用新增、删除、查看过滤规则，更改默认动作
- [x] 记录报文过滤日志及通过命令行应用查看
- [x] 连接状态检测与记录
- [x] 通过命令行应用查看已建立的所有连接
- [x] NAT
- [x] 配置NAT规则
- [ ] ~~图形化界面 防火墙还写啥GUI~~

# 安装

### 环境

我所采用的环境为kali，Linux内核版本6.12.25-amd64，所有功能测试正常。

**一般而言**，所有Linux内核版本 > 4.9的系统皆可使用。

### 从源码安装/在安装这步可以问ai，我就是在安装编译的过程中发现很多问题，然后问ai成功安装的

安装时需要gcc以及make包，若未安装，请预先安装：
```bash
sudo apt install gcc make
```

首先，下载本项目源码至任意目录：
```bash
unzip RJFireWall.zip

cd RJFireWall
```

随后，**编译源码**：
```bash
sudo make
```

最后，**安装**：
```bash
sudo make install
```

# 使用/关于使用的具体情况，我写在了word文档里，并且有使用成功的相关截图

在安装时，内核模块已经加载至Linux内核中，此时，只需使用上层应用uapp来对防火墙进行控制即可。

新增一条过滤规则：
```bash
./uapp rule add
```
随后依据命令行提示设定规则即可。

删除一条过滤规则：
```bash
./uapp rule del 所需删除规则的名称
```

设置默认动作为Drop（防火墙初始时默认动作为Accept）：
```bash
./uapp rule default drop
```

展示已有规则：
```bash
./uapp ls rule
```

展示所有过滤日志：
```bash
./uapp ls log
```

展示最后100条过滤日志：
```bash
./uapp ls log 100
```

展示当前已有连接：
```bash
./uapp ls connect
```

新增一条NAT规则：
```bash
./uapp nat add
```
随后依据命令行提示设定规则即可。

删除一条NAT规则：
```bash
./uapp nat del 所需删除NAT规则的序号
```

展示已有NAT规则：
```bash
./uapp ls nat
```


先使用：
cd ~/Desktop/RJFireWall/kernel_mod
sudo insmod myfw.ko
加载内核
再用
lsmod | grep myfw
检查内核是否被加载
再进入cmd里，使用./uapp
如果在这一步骤中有问题，问ai即可


本文在源项目的基础上，删除了过旧版本内核的一些函数使用情况，在6.12.25内核版本中测试没有任何问题

除此之外，为了更好的方便阅读项目，本文从数据链的流转情况进行分析，且将项目中的所有代码都写上了详细注释(ai写的)，方便大家学习

除此之外，略微介绍以下各个文件夹的情况
首先，kernel_mod文件夹中的helpers文件夹，里面的conn_helper.c就是实现红黑树管理状态连接的完整实现，其中的红黑树是使用linux内核的红黑树api接口调用的，并且kernel_mod文件夹中的所有文件都使用了读写锁来确保安全访问控制，在代码中可以清晰的看到
