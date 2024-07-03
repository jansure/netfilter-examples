#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jansure");
MODULE_DESCRIPTION("A Simple Netfilter Module");


static struct nf_hook_ops netfilter_ops_in;
static struct nf_hook_ops netfilter_ops_out;


static unsigned int main_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct iphdr* iph;
  struct tcphdr* tcph;
  
  iph = ip_hdr(skb);
  if (!iph) 
    return NF_ACCEPT;
  if (iph->protocol == IPPROTO_TCP) {
    tcph = tcp_hdr(skb);
    if (!tcph) 
      return NF_ACCEPT;
    
    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80) {
      printk(KERN_INFO, "Caught TCP packet from port 80\n");
    }
  }
  return NF_ACCEPT;
}

int __init netfilter_init(void) {
  printk(KERN_INFO, "Netfilter Init\n");
  netfilter_ops_in.hook = main_hook_func;
  netfilter_ops_in.pf = PF_INET;
  netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
  netfilter_ops_in.priority = NF_IP_PRI_FIRST;

  netfilter_ops_out.hook = main_hook_func;
  netfilter_ops_out.pf = PF_INET;
  netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
  netfilter_ops_out.priority = NF_IP_PRI_FIRST;
  
  nf_register_net_hook(&init_net, &netfilter_ops_in);
  nf_register_net_hook(&init_net, &netfilter_ops_out);


  printk(KERN_INFO, "Netfilter module loaded\n");
  return 0;
}

static void __exit netfilter_exit(void) {
  nf_unregister_net_hook(&init_net, &netfilter_ops_out);
  nf_unregister_net_hook(&init_net, &netfilter_ops_in);
  printk(KERN_INFO, "Netfilter module unloaded\n");
}


module_init(netfilter_init);
module_exit(netfilter_exit);


