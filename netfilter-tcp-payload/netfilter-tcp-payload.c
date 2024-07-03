#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>  // 包含 init_net 的定义
#include <linux/skbuff.h>     // 包含 skb 的定义
#include <linux/printk.h>     // 包含 printk 的定义

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Simple Netfilter Module");

// 函数声明
static unsigned int main_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
//static int __init netfilter_init(void);
static void __exit netfilter_exit(void);

// 钩子操作结构
static struct nf_hook_ops netfilter_ops_in = {
    .hook = main_hook_func,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops netfilter_ops_out = {
    .hook = main_hook_func,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

// 处理函数
static unsigned int main_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *payload;
    int payload_len;

    // 获取 IP 头部
    iph = ip_hdr(skb);
    if (!iph) {
        return NF_ACCEPT;
    }

    // 检查协议是否为 TCP
    if (iph->protocol == IPPROTO_TCP) {
        // 获取 TCP 头部
        tcph = tcp_hdr(skb);
        if (!tcph) {
            return NF_ACCEPT;
        }

        // 检查端口
        if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80) {
            printk(KERN_INFO "Caught TCP packet from port 80\n");

            // 计算 TCP 有效负载的开始位置和长度
            payload = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4));
            payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);

            // 打印 TCP 有效负载
            if (payload_len > 0) {
                int i;
                printk(KERN_INFO "TCP Payload (%d bytes):\n", payload_len);
                for (i = 0; i < payload_len; i++) {
                    printk(KERN_CONT "%02x ", payload[i]);
                    if ((i + 1) % 16 == 0) {
                        printk(KERN_CONT "\n");
                    }
                }
                printk(KERN_CONT "\n");
            }
        }
    }

    return NF_ACCEPT;
}

// 初始化
int __init netfilter_init(void) {
    int ret;
    printk(KERN_INFO "Initializing Netfilter module\n");

    ret = nf_register_net_hook(&init_net, &netfilter_ops_in);
    if (ret) {
        printk(KERN_ERR "nf_register_net_hook (in) failed\n");
        return ret;
    }

    ret = nf_register_net_hook(&init_net, &netfilter_ops_out);
    if (ret) {
        printk(KERN_ERR "nf_register_net_hook (out) failed\n");
        nf_unregister_net_hook(&init_net, &netfilter_ops_in);
        return ret;
    }

    printk(KERN_INFO "Netfilter module loaded\n");
    return 0;
}

// 清理
static void __exit netfilter_exit(void) {
    printk(KERN_INFO "Exiting Netfilter module\n");
    nf_unregister_net_hook(&init_net, &netfilter_ops_in);
    nf_unregister_net_hook(&init_net, &netfilter_ops_out);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(netfilter_init);
module_exit(netfilter_exit);

