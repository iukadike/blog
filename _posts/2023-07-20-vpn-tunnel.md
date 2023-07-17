---
layout: post
title: VPN Tunnel
excerpt: A VPN, or Virtual Private Network, is a private network that is available over the internet. The internet as we all know is a public place, but a VPN makes it possible to have these private networks through a concept known as tunnelling. With VPN tunnelling, an organization can make internal networks available to remote offices or staff over the internet. VPN creates a secure connection as online activities are encrypted and internal IP addresses are masked. This makes it harder for hackers and bad actors to sniff private company data.
categories: [vpn, firewall]
---

![firewall-evasion]({{ site.baseurl }}/images/featured-images/vpn-tunnel.png)

A VPN, or Virtual Private Network, is a private network that is available over the internet. The internet as we all know is a public place, but a VPN makes it possible to have these private networks through a concept known as tunnelling. With VPN tunnelling, an organization can make internal networks available to remote offices or staff over the internet. VPN creates a secure connection as online activities are encrypted and internal IP addresses are masked. This makes it harder for hackers and bad actors to sniff private company data.

In this post, I aim to document my findings and observations while performing a SEED Lab.

### TUN vs TAP
TUN is also known as Network Tunnel while TAP is also known as Network Tap. Both are network device drivers used in virtual private network (VPN) implementations. However, TUN and TAP can't be used together because they transmit and receive packets at different layers of the network stack.

TUN devices operate at the network layer (Layer 3) of the OSI model, carrying IP packets. TUN devices route traffic between a client and a server (packets are routed through the device to their destination). TUN is typically used when you want to connect to a server so it processes requests on your behalf.

TAP devices operate at the data link layer (Layer 2) of the OSI model, carrying Ethernat packets. They are used to create a virtual Ethernet device (they emulate real Ethernet devices, allowing them to handle all types of network traffic not just IP). They are commonly used when creating virtual switches, bridges, or virtual LANs. TAP devices work in a bridging mode, where packets are forwarded between virtual and physical network interfaces or between virtual network interfaces. TAP is typically used when you want to mimick that all devices are connectd to the same ethernet cable.

### Create and Configure TUN Interface
This section involves creating and configuring a TUN interface using python and scapy. The program would do the following:
- Create the virtual interface
- Name the virtual interface
- Configure the virtual interface
  - Assign IP address to the interface
  - Bring up the interface
- Read from the tun interface
- Write to the tun interface
  - if this packet is an ICMP echo request packet, construct a corresponding echo reply packet and write it to the TUN interface.

```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ukadike%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f"Interface Name: {ifname}")

# Configure the tun interface
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# Send out a spoof packet using the tun interface
def icmp_spoof(c_pkt):
    # make a copy of the packet
    pkt = IP(bytes(c_pkt))
    
    # delete the checksum to force recalculation
    del(pkt.chksum)
    del(pkt[ICMP].chksum)
    
    # make corrections to the IP header
    pkt[IP].src = c_pkt[IP].dst
    pkt[IP].dst = c_pkt[IP].src
    
    # make corrections to the ICMP header
    pkt[ICMP].type = 0
    
    # send the packet
    os.write(tun, bytes(pkt))
    
    # print packet information to screen
    print(c_pkt.summary())
    print(pkt.summary())


while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
        c_pkt = IP(packet)
        if 'ICMP' in c_pkt and c_pkt[ICMP].type == 0x08:
            icmp_spoof(c_pkt)
        #print(c_pkt.summary())
```

On `Host U`, when I ping a host in the 192.168.53.0/24 network, as per the instructions in the code, a summary of the ICMP packet is displayed on screen. This is so because the host I am pinging is in the network associated with the tun interface. We can confirm this by running `ip r`.

***`Host U`s routing table***

***`Host U` pinging `192.168.53.200`***

***tcpdump on `Host U` when pinging `192.168.53.200`***

However when I ping a host in the internal network `192.168.60.0/24`, the program does not print anything out to the screen. This is so because since `Host U` is not aware of a route to reach the internal network as the internal network is not associated with any interface, it tries to use the default route which is associated with the eth interface, but the traffic will be dropped by the router.

***`Host U` pinging `192.168.60.5`***

***tcpdump on `Host U` when pinging `192.168.60.5`***

<br>

###  Send the IP Packet to VPN Server Through a Tunnel
This section involves puttng the IP packet received from the TUN interface into the UDP payload field of a new IP packet, and sending it to another computer (the VPN server). In other words, we place the original packet inside a new packet.

The VPN Server would do the following:
- listen to port 9090 on any address
- print out whatever is received.
  - print out the source and destination IP address of the enclosed IP packet.
 
```python
#!/usr/bin/env python3

from scapy.all import *

IP_A = "0.0.0.0"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
print("server running...")

while True:
    data, (ip, port) = sock.recvfrom(2048)
    print(f"{ip}:{port} --> {IP_A}:{PORT}")
    pkt = IP(data)
    print(f" Inside: {pkt.src} --> {pkt.dst}\n")
```

The VPN Client would do the following:
- Create the virtual interface
- Name the virtual interface
- Configure the virtual interface
  - Assign IP address to the interface
  - Bring up the interface
- Read from the tun interface
- Write to the sock interface
  - Send data to the VPN server using UDP

```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ukadike%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f"Interface Name: {ifname}")

# Configure the tun interface
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Configure the VPN server address and port
SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

while True:
    # Get a packet from the tun interface
    packet = os.read(tun, 2048)
    if packet:
    # Send the packet to the VPN server
        sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

When I run the respective program on the VPN server and the VPN client, and ping any IP address belonging to the 192.168.53.0/24 network, as per the instructions of the program, the VPN server prints out the packet it recieves and also the packet that was encapsulated in the packet it recieved.

The VPN server recievec this request because there is a route to the VPN server present on `Host U`.

***VPN server response***

Running a tcpdump on the eth interface of `Host U`, we can see that the packets sent are UDP packets.

***tcpdump on `Host U`***

However, the ultimate goal is to access the hosts inside the private network 192.168.60.0/24 using this tunnel we created. If ping Host V, the packets are not sent via the tun interface as seen in the previous section. To solve this problem, we have to tell `Host U` to send packets meant for 192.168.60.0/24 network via the tun interface. We do this by adding an entry to the routing table of `Host U`
- `ip route add 192.168.60.0/24 dev ukadike0 via 192.168.53.99`

Now, when I ping an IP address in the 192.168.60.0/24 network, the packets are received by VPN server through the tunnel.

***VPN server response***

<br>

###  Set Up the VPN Server
This section involves creating and configuring a TUN interface on the VPN server using python and scapy. The program would do the following:
- Create the virtual interface
- Name the virtual interface
- Configure the virtual interface
  - Assign IP address to the interface
  - Bring up the interface
- Read from the sock interface
- Write to the tun interface
- enable IP forwarding
  - `sysctl net.ipv4.ip_forward=1`

```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ukadike%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print(f"Interface Name: {ifname}")

# Configure the tun interface
os.system(f"ip addr add 192.168.53.1/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# Enable IP forwarding
os.system("sysctl net.ipv4.ip_forward=1")

IP_A = "0.0.0.0"
PORT = 9090

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
print("server running...")

while True:
    data, (ip, port) = sock.recvfrom(2048)
    if data:
        os.write(tun, data)
```

Now that everything is setup, the ICMP echo request from `Host U` arrive at `Host V` through the tunnel. As seen from the screenshot below, the icmp packet reaches `Host V` and `Host V` responds to the request.

***tcpdump on `Host V`***

<br>

### Handling Traffic in Both Directions















#### Extra
The tunnelling part had always got me confused. I guess the picture that always came to my mind about tunelling is this huge virtual pipe that connects the client to the server. However, getting more clarity, I have realised that tunelling is conceptual in the sense that the only traffic that can be observerd will always be the same but with varying payload.
The whole process involves:
- the vpn client getting packets from the tun interface
- the vpn client repackaging the packets
- the vpn client passes the repackaged packets to the OS to send over the internet
- when the package arives at the other end, the OS passes the package to the tun interface
- the vpn server gets the packets from the tun interface
- the vpn server unpacks the packets and passes them to the OS
- the OS then sends then to their intended destination
- sends it to the vpn server over the internet

