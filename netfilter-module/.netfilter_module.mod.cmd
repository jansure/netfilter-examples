savedcmd_/root/netfilter-module/netfilter_module.mod := printf '%s\n'   netfilter_module.o | awk '!x[$$0]++ { print("/root/netfilter-module/"$$0) }' > /root/netfilter-module/netfilter_module.mod
