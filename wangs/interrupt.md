
##
```shell
延迟中断的方式: 
    软中断
    tasklets
    工作队列
工作队列运行于内核进程上下文，而 tasklets 运行于软中断上下文
这意味着工作队列函数不必像 tasklets 一样必须是原子性的。Tasklets 总是运行于它提交自的那个处理器，工作队列在默认情况下也是这样

tasklets:
    tasklets 构建于 softirq 中断之上，他是基于下面两个软中断实现的 TASKLET_SOFTIRQ HI_SOFTIRQ
    tasklets 是运行时分配和初始化的软中断。和软中断不同的是，同一类型的 tasklets 不能同时运行在多个处理器上
```