# 科研相关的通用模块

1. 数据结构与算法每天坚持学习1h
    - 代码随想录 https://programmercarl.com/
    - C++基础课 https://kamacoder.com/course.php?course_id=1
    - STL库 https://programmercarl.com/ke/stl.html
    - skipilst实现kv存储引擎 https://programmercarl.com/ke/kvcplus.html
    - 设计模式 https://programmercarl.com/ke/shejimoshi.html
    - 缓存系统 https://www.programmercarl.com/other/project_huancun.html#%E4%BB%80%E4%B9%88%E6%98%AF%E7%BC%93%E5%AD%98
    - 内存池 https://www.programmercarl.com/other/project_neicun.html
    - 协程库 https://www.programmercarl.com/other/project_coroutine.html
    - 网络库 https://www.programmercarl.com/other/project_muduo.html
    - 数据库 CMU 15445 https://www.programmercarl.com/other/project_15445.html
    - RPC框架 https://www.programmercarl.com/other/project_C++RPC.html
    - 高性能服务器 https://www.programmercarl.com/other/project_webserver.html
    - 基于异步日志系统的云存储服务 https://www.programmercarl.com/other/project_nibu.html
    - HTTP服务框架 https://www.programmercarl.com/other/project_http.html
    - 分布式存储 https://www.programmercarl.com/other/project_fenbushi.html
    - 操作系统 https://www.programmercarl.com/other/project_os.html
    - 分布式缓存 https://www.programmercarl.com/other/project_go.html
2. 通用模块
    - 写一个在kernel space或者user space使用eBPF或者perf采集应用程序运行时的函数或者硬件计数器的库，支持输出不同格式的文件，可以采集各个层次的info，用于在内核态或者用户态进行一些策略选择时使用（支持AMD, Intel以及ARM平台，支持eBPF，kernel module以及用户态，基本上满足所有在kernel中要profile的要求）。
    - 如何预处理获得的不同格式的数据？如果是用profile的数据去选择不同的应用，应该属于classification的问题，应该用什么AI模型？有没有具体的example可以参考
    - 采集真正应用运行的数据还是一些benchmark的数据？
    - 整理一套各种Figs，好看的Experiments可用的绘图脚本，python，把之前整理好的，包括配色，每次用到的新的绘图时添加到这个lib中
    - 在Linux kernel中能用的AI model的集合，在eBPF中能应用的AI model的集合，到时候可以根据需求和场景即插即用（soft actor-critic SAC method)
    - 主流的linux kernel适配，kernel更新的情况下，以上工具依旧可以使用
    - 适配裸机, Docker和kvm模式
    - Linux常用的备份系统和备份策略
    - 分不是的知识和理论的学习，包括system集群管理工具，了解集群管理工具和分布式技术的基本原理，以及总结出如何将单机应用部署到集群中的通用模版(slurm)
    - 积累通用方法的实现，比如滑动窗口,tree等，如何根据场景的不同设计成容易适配和修改的结构
    - 常见的作为benchmark,大数据应用，在experiment部分作为待测应用的框架的基本原理，以及最新的拥有优化特点的应用总结
    - MoE,LLM-training, LLM-inference相关的benchmark，常见的大模型框架作为benchmark使用的原理(LLM驱动的xxx设计)
    - 监控的数据接到用户态可以用Promethues和Grafana展示
3. 相关书籍
    - 深入理解软件性能
    - 大规模分布式系统
    - 深入理解进程与内存
    - 南大操作系统复习一遍查缺补漏
4. Rust操作系统内核项目
5. RISC-V项目内容
6. 分布式Go内容
7. Docker训练营的项目
8. 相关的八股文背到滚瓜烂熟
     