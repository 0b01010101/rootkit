# Om4-rootkit 
## FULL DISCLAIMER!
Created and intended for educational purposes!
May break the computer...(but it's unlikely;))
No one will run it on THEIR computer?!

#### Simple Kernel Rootkit. Essentially a keylogger and backdoor.
### Features
1) Hides itself (module) from the procfs/sysfs.
2) Registers a keyboard interrupt handler(keylogger) and netfilter(backdoor).
3) Creates a thread for the kelogger and hides it from the system. The stream writes the filtered characters of the key to the file("/tmp/om4.txt").
4) The keylogger catches "text" symbols (password, login, command filter) and there will be a kernel thread to dump key symbols into the file("/tmp/om4.txt").
5) The backdoor intercepts ICMP packets(IcmpShell) from the Internet(NF_INET_PRE_ROUTING) and from applications(Tunnel) to the Internet(NF_INET_LOCAL_OUT).
#### IcmpShell: (NF_INET_PRE_ROUTING)
- Checks the signature.
- Run a shellcode in userspace.
- Uses "call_usermodehelper()"functions.
#### Tunnel: (NF_INET_LOCAL_OUT)
- Intercepts TCP/UDP packets going to the IP(src/net.c-> const int lkm_lout_ipdst=NET_IP_TARGET).
- All TCP packets are dropped(NF_DROP).
- All UDP packets are dropped(NF_DROP) BUT send them using "netpool" interface.
