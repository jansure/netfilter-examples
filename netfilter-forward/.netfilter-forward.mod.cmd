savedcmd_/root/netfilter-forward/netfilter-forward.mod := printf '%s\n'   netfilter-forward.o | awk '!x[$$0]++ { print("/root/netfilter-forward/"$$0) }' > /root/netfilter-forward/netfilter-forward.mod
