#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/inet.h> // 包含 in4_pton 函数

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter Module to Redirect Traffic");

#define PROCFS_NAME "netfilter_config"

// 配置参数
static char target_ip[16] = "192.168.1.100";
static int target_port = 8080;
static int listen_port = 12345;

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

// 将 IP 地址从字符串转换为数值
static __be32 str_to_ip(const char *str) {
    __be32 ip;
    in4_pton(str, -1, (u8 *)&ip, -1, NULL);
    return ip;
}

// 重新计算 IP 校验和
static void ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

// 重新计算 TCP 校验和
static void tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    tcph->check = 0;
    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    ntohs(iph->tot_len) - iph->ihl * 4,
                                    IPPROTO_TCP, csum_partial(tcph, ntohs(iph->tot_len) - iph->ihl * 4, 0));
}

// 重新计算 UDP 校验和
static void udp_checksum(struct iphdr *iph, struct udphdr *udph) {
    udph->check = 0;
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                    ntohs(udph->len), IPPROTO_UDP,
                                    csum_partial(udph, ntohs(udph->len), 0));
}

// 处理函数
static unsigned int main_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    iph = ip_hdr(skb);
    if (!iph) {
        return NF_ACCEPT;
    }

    // 检查协议是否为 TCP 或 UDP
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (!tcph) {
            return NF_ACCEPT;
        }

        // 检查源端口
        if (ntohs(tcph->source) == listen_port) {
            // 修改目的 IP 和端口
            iph->daddr = str_to_ip(target_ip);
            tcph->dest = htons(target_port);

            // 重新计算校验和
            ip_checksum(iph);
            tcp_checksum(iph, tcph);

            printk(KERN_INFO "Redirected TCP packet from port %d to %s:%d\n", listen_port, target_ip, target_port);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (!udph) {
            return NF_ACCEPT;
        }

        // 检查源端口
        if (ntohs(udph->source) == listen_port) {
            // 修改目的 IP 和端口
            iph->daddr = str_to_ip(target_ip);
            udph->dest = htons(target_port);

            // 重新计算校验和
            ip_checksum(iph);
            udp_checksum(iph, udph);

            printk(KERN_INFO "Redirected UDP packet from port %d to %s:%d\n", listen_port, target_ip, target_port);
        }
    }

    return NF_ACCEPT;
}

// 读取配置文件的函数
static ssize_t procfile_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char *proc_buffer;
    char ip[16];
    int lport, tport;
    
    proc_buffer = kmalloc(count + 1, GFP_KERNEL);
    if (!proc_buffer)
        return -ENOMEM;

    if (copy_from_user(proc_buffer, buffer, count)) {
        kfree(proc_buffer);
        return -EFAULT;
    }
    
    proc_buffer[count] = '\0';
    
    if (sscanf(proc_buffer, "%d %15s %d", &lport, ip, &tport) == 3) {
        listen_port = lport;
        strncpy(target_ip, ip, 16);
        target_port = tport;
        printk(KERN_INFO "Updated configuration: listen_port=%d, target_ip=%s, target_port=%d\n", listen_port, target_ip, target_port);
    } else {
        printk(KERN_ERR "Invalid configuration format\n");
    }

    kfree(proc_buffer);
    return count;
}

static const struct proc_ops proc_file_fops = {
    .proc_write = procfile_write,
};

// 初始化
int __init netfilter_init(void) {
    int ret;
    printk(KERN_INFO "Initializing Netfilter module\n");

    if (!proc_create(PROCFS_NAME, 0666, NULL, &proc_file_fops)) {
        printk(KERN_ERR "Error creating proc file\n");
        return -ENOMEM;
    }

    ret = nf_register_net_hook(&init_net, &netfilter_ops_in);
    if (ret) {
        remove_proc_entry(PROCFS_NAME, NULL);
        printk(KERN_ERR "nf_register_net_hook failed\n");
        return ret;
    }

    printk(KERN_INFO "Netfilter module loaded with target IP %s, target port %d, listen port %d\n", target_ip, target_port, listen_port);
    return 0;
}

// 清理
static void __exit netfilter_exit(void) {
    printk(KERN_INFO "Exiting Netfilter module\n");
    nf_unregister_net_hook(&init_net, &netfilter_ops_in);
    remove_proc_entry(PROCFS_NAME, NULL);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

module_init(netfilter_init);
module_exit(netfilter_exit);

