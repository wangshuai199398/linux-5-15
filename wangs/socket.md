
#### socket
```shell
socket 是用于负责对上给用户提供接口，并且和文件系统关联。而 sock, 负责向下对接内核网络协议栈
```

####
```shell
首先，Socket 系统调用会有三级参数 family、type、protocal，通过这三级参数，分别在 net_proto_family 表中找到 type 链表，在 type 链表中找到 protocal 对应的操作。这个操作分为两层，对于 TCP 协议来讲，第一层是 inet_stream_ops 层，第二层是 tcp_prot 层。

bind 第一层调用 inet_stream_ops 的 inet_bind 函数第二层调用 tcp_prot 的 inet_csk_get_port 函数；
listen 第一层调用 inet_stream_ops 的 inet_listen 函数，第二层调用 tcp_prot 的 inet_csk_get_port 函数；
accept 第一层调用 inet_stream_ops 的 inet_accept 函数，第二层调用 tcp_prot 的 inet_csk_accept 函数；
connect 第一层调用 inet_stream_ops 的 inet_stream_connect 函数，第二层调用 tcp_prot 的 tcp_v4_connect 函数。

TCP_NEW_SYN_RECV
```

#### 发送
```shell
这个过程分成几个层次:
VFS 层：write 系统调用找到 struct file，根据里面的 file_operations 的定义，调用 sock_write_iter 函数。sock_write_iter 函数调用 sock_sendmsg 函数。
Socket 层：从 struct file 里面的 private_data 得到 struct socket，根据里面 ops 的定义，调用 inet_sendmsg 函数。
Sock 层：从 struct socket 里面的 sk 得到 struct sock，根据里面 sk_prot 的定义，调用 tcp_sendmsg 函数。
TCP 层：tcp_sendmsg 函数会调用 tcp_write_xmit 函数，tcp_write_xmit 函数会调用 tcp_transmit_skb，在这里实现了 TCP 层面向连接的逻辑。
IP 层：扩展 struct sock，得到 struct inet_connection_sock，根据里面 icsk_af_ops 的定义，调用 ip_queue_xmit 函数。
IP 层：ip_route_output_ports 函数里面会调用 fib_lookup 查找路由表。FIB 全称是 Forwarding Information Base，转发信息表，也就是路由表。
  在 IP 层里面要做的另一个事情是填写 IP 层的头。
  在 IP 层还要做的一件事情就是通过 iptables 规则
MAC 层：IP 层调用 ip_finish_output 进行 MAC 层
MAC 层需要 ARP 获得 MAC 地址，因而要调用 ___neigh_lookup_noref 查找属于同一个网段的邻居，他会调用 neigh_probe 发送 ARP。
  有了 MAC 地址，就可以调用 dev_queue_xmit 发送二层网络包了，它会调用 __dev_xmit_skb 会将请求放入队列
设备层：网络包的发送会触发一个软中断 NET_TX_SOFTIRQ 来处理队列中的数据。这个软中断的处理函数是 net_tx_action。
  在软中断处理函数中，会将网络包从队列上拿下来，调用网络设备的传输函数 ixgb_xmit_frame，将网络包发到设备的队列上去。
```

#### 接收
```shell
- 硬件网卡接收到网络包之后，通过 DMA 技术，将网络包放入 Ring Buffer。
- 硬件网卡通过中断通知 CPU 新的网络包的到来。
- 网卡驱动程序会注册中断处理函数 ixgb_intr。
- 中断处理函数处理完需要暂时屏蔽中断的核心流程之后，通过软中断 NET_RX_SOFTIRQ 触发接下来的处理过程
- NET_RX_SOFTIRQ 软中断处理函数 net_rx_action，net_rx_action 会调用 napi_poll，进而调用 ixgb_clean_rx_irq，从 Ring Buffer 中读取数据到内核 struct sk_buff
- 调用 netif_receive_skb 进入内核网络协议栈，进行一些关于 VLAN 的二层逻辑处理后，调用 ip_rcv 进入三层 IP 层
- 在 IP 层，会处理 iptables 规则，然后调用 ip_local_deliver，交给更上层 TCP 层
- 在 TCP 层调用 tcp_v4_rcv，这里面有三个队列需要处理，如果当前的 Socket 不是正在被读；取，则放入 backlog 队列，如果正在被读取，不需要很实时的话，则放入 prequeue 队列，其他情况调用 tcp_v4_do_rcv
- 在 tcp_v4_do_rcv 中，如果是处于 TCP_ESTABLISHED 状态，调用 tcp_rcv_established，其他的状态，调用 tcp_rcv_state_process
- 在 tcp_rcv_established 中，调用 tcp_data_queue，如果序列号能够接的上，则放入 sk_receive_queue 队列；如果序列号接不上，则暂时放入 out_of_order_queue 队列，等序列号能够接上的时候，再放入 sk_receive_queue 队列

至此内核接收网络包的过程到此结束，接下来就是用户态读取网络包的过程，这个过程分成几个层次
- VFS 层：read 系统调用找到 struct file，根据里面的 file_operations 的定义，调用 sock_read_iter 函数。sock_read_iter 函数调用 sock_recvmsg 函数
- Socket 层：从 struct file 里面的 private_data 得到 struct socket，根据里面 ops 的定义，调用 inet_recvmsg 函数
- Sock 层：从 struct socket 里面的 sk 得到 struct sock，根据里面 sk_prot 的定义，调用 tcp_recvmsg 函数
- TCP 层：tcp_recvmsg 函数会依次读取 receive_queue 队列、prequeue 队列和 backlog 队列

```
