#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/inet.h>

static struct nf_hook_ops netfilter_ops_in;

static char target_ip[16] = "192.168.1.100";
static int target_port = 80;
static int src_port = 8080;
static char *config_file_path = "/etc/nf_config.conf";

module_param(config_file_path, charp, 0000);
MODULE_PARM_DESC(config_file_path, "Configuration file path");

struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;

static int load_config(void) {
    struct file *file;
    mm_segment_t oldfs;
    char buf[128];
    ssize_t len;
    char *pos, *line, *key, *value;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    file = filp_open(config_file_path, O_RDONLY, 0);
    set_fs(oldfs);

    if (IS_ERR(file)) {
        printk(KERN_ERR "Cannot open config file: %s\n", config_file_path);
        return PTR_ERR(file);
    }

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    len = kernel_read(file, 0, buf, sizeof(buf) - 1);
    set_fs(oldfs);

    if (len < 0) {
        printk(KERN_ERR "Cannot read config file: %s\n", config_file_path);
        filp_close(file, NULL);
        return len;
    }

    buf[len] = '\0';
    filp_close(file, NULL);

    pos = buf;
    while ((line = strsep(&pos, "\n")) != NULL) {
        key = strsep(&line, "=");
        value = line;
        if (strcmp(key, "target_ip") == 0) {
            strncpy(target_ip, value, sizeof(target_ip) - 1);
        } else if (strcmp(key, "target_port") == 0) {
            target_port = simple_strtol(value, NULL, 10);
        } else if (strcmp(key, "src_port") == 0) {
            src_port = simple_strtol(value, NULL, 10);
        }
    }

    return 0;
}

unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    sock_buff = skb;

    if (!sock_buff)
        return NF_ACCEPT;

    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
        if (tcp_header->dest == htons(src_port)) {
            // 修改目的 IP 和端口
            ip_header->daddr = in_aton(target_ip);
            tcp_header->dest = htons(target_port);
            // 重新计算校验和
            ip_header->check = 0;
            ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);
            tcp_header->check = 0;
            tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                                  ntohs(ip_header->tot_len) - ip_header->ihl * 4,
                                                  IPPROTO_TCP,
                                                  csum_partial((char *)tcp_header, ntohs(ip_header->tot_len) - ip_header->ihl * 4, 0));
        }
    } else if (ip_header->protocol == IPPROTO_UDP) {
        udp_header = (struct udphdr *)((__u32 *)ip_header + ip_header->ihl);
        if (udp_header->dest == htons(src_port)) {
            // 修改目的 IP 和端口
            ip_header->daddr = in_aton(target_ip);
            udp_header->dest = htons(target_port);
            // 重新计算校验和
            ip_header->check = 0;
            ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);
            udp_header->check = 0;
            udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                                  ntohs(ip_header->tot_len) - ip_header->ihl * 4,
                                                  IPPROTO_UDP,
                                                  csum_partial((char *)udp_header, ntohs(ip_header->tot_len) - ip_header->ihl * 4, 0));
        }
    }
    return NF_ACCEPT;
}

int init_module() {
    if (load_config() < 0) {
        return -1;
    }

    netfilter_ops_in.hook = main_hook;
    netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops_in.pf = PF_INET;
    netfilter_ops_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &netfilter_ops_in);
    printk(KERN_INFO "Netfilter module loaded: redirecting %d to %s:%d\n", src_port, target_ip, target_port);
    return 0;
}

void cleanup_module() {
    nf_unregister_net_hook(&init_net, &netfilter_ops_in);
    printk(KERN_INFO "Netfilter module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter module to redirect packets with configurable parameters");

