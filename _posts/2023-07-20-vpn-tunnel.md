---
layout: post
title: VPN Tunnel
excerpt: A VPN, or Virtual Private Network, is a private network that is available over the internet. The internet, as we all know, is a public place, but a VPN makes it possible to have these private networks through a concept known as tunneling. With VPN tunneling, an organization can make internal networks available to remote offices or staff over the internet. A VPN creates a secure connection as online activities are encrypted and internal IP addresses are masked. This makes it harder for hackers and bad actors to sniff private company data.
categories: [vpn, firewall]
---

![firewall-evasion]({{ site.baseurl }}/images/featured-images/vpn-tunnel.png)

A VPN, or Virtual Private Network, is a private network that is available over the internet. The internet, as we all know, is a public place, but a VPN makes it possible to have these private networks through a concept known as tunneling. With VPN tunneling, an organization can make internal networks available to remote offices or staff over the internet. A VPN creates a secure connection as online activities are encrypted and internal IP addresses are masked. This makes it harder for hackers and bad actors to sniff private company data.

<details>
<summary><b>SeedLabs: VPN Tunneling Lab</b></summary>
<div markdown="1">

- [VPN Tunneling Lab](https://seedsecuritylabs.org/Labs_20.04/Files/VPN_Tunnel/VPN_Tunnel.pdf)

___
</div></details>

<br>

### TUN vs TAP
TUN is also known as network tunnel, while TAP is also known as network Tap. Both are network device drivers used in virtual private network (VPN) implementations. However, TUN and TAP can't be used together because they transmit and receive packets at different layers of the network stack.

TUN devices operate at the network layer (Layer 3) of the OSI model, carrying IP packets. TUN devices route traffic between a client and a server (packets are routed through the device to their destination). TUN is typically used when you want to connect to a server, so it processes requests on your behalf.

TAP devices operate at the data link layer (Layer 2) of the OSI model, carrying Ethernat packets. They are used to create a virtual Ethernet device (they emulate real Ethernet devices, allowing them to handle all types of network traffic, not just IP). They are commonly used when creating virtual switches, bridges, or virtual LANs. TAP devices work in a bridging mode, where packets are forwarded between virtual and physical network interfaces or between virtual network interfaces. TAP is typically used when you want to mimic the fact that all devices are connected to the same Ethernet cable.

<br>

### Create and Configure TUN Interface
This section involves creating and configuring a TUN interface using Python and Scapy. The program would do the following:
- Create the virtual interface.
- Name the virtual interface.
- Configure the virtual interface.
  - Assign an IP address to the interface.
  - Bring up the interface.
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

***`Host U` routing table***
![1 1](https://github.com/iukadike/blog/assets/58455326/e65dcba2-585c-4d2b-b566-d31abb25870e)

***`Host U` pinging `192.168.53.200`***
![1 2 a](https://github.com/iukadike/blog/assets/58455326/58a4f651-85c2-4285-81fc-3e50f8adb4be)

![1 2 b](https://github.com/iukadike/blog/assets/58455326/8d06bf0e-1c5c-4f0c-9f2f-6e7baf5d47f3)

***tcpdump on `Host U` when pinging `192.168.53.200`***
![1 3](https://github.com/iukadike/blog/assets/58455326/5465453c-08ad-4bff-ad29-61de756b45d0)

However, when I ping a host in the internal network, `192.168.60.0/24`, the program does not print anything out to the screen. This is so because since `Host U` is not aware of a route to reach the internal network as the internal network is not associated with any interface, it tries to use the default route, which is associated with the `eth` interface, but the traffic will be dropped by the router.

***`Host U` pinging `192.168.60.5`***
![1 4 a](https://github.com/iukadike/blog/assets/58455326/b43d1013-b1bd-4610-9771-77e0fba6ce4f)

![1 4 b](https://github.com/iukadike/blog/assets/58455326/9476d021-c68d-4402-9b88-5641180e29cc)

***tcpdump on `Host U` when pinging `192.168.60.5`***
![1 5](https://github.com/iukadike/blog/assets/58455326/36e86916-e2ca-4216-b3ca-e762aaf98e55)

<br>

###  Send the IP Packet to VPN Server Through a Tunnel
This section involves putting the IP packet received from the TUN interface into the UDP payload field of a new IP packet, and sending it to another computer (the VPN server). In other words, we place the original packet inside a new packet.

The VPN Server would do the following:
- listen to port 9090 on any address.
- print out whatever is received.
  - print out the source and destination IP addresses of the enclosed IP packet.
 
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
- Create the virtual interface.
- Name the virtual interface.
- Configure the virtual interface.
  - Assign an IP address to the interface.
  - Bring up the interface.
- Read from the tun interface
- Write to the sock interface.
  - Send data to the VPN server using UDP.

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

When I run the respective programs on the VPN server and the VPN client, and ping any IP address belonging to the 192.168.53.0/24 network, as per the instructions of the program, the VPN server prints out the packet it receives and also the packet that was encapsulated in the packet it receives.

The VPN server received this request because there is a route to the VPN server present on `Host U`.

***VPN server response***
![2 1](https://github.com/iukadike/blog/assets/58455326/c27aa438-c30b-4788-ba9d-65c64a2d56de)

Running tcpdump on the eth interface of `Host U`, we can see that the packets sent are UDP packets.

***tcpdump on `Host U`***
![2 2](https://github.com/iukadike/blog/assets/58455326/215f8686-2919-4596-809f-83e7a4229f4f)

However, the ultimate goal is to access the hosts inside the private network 192.168.60.0/24 using this tunnel we created. If you ping Host V, the packets are not sent via the tun interface, as seen in the previous section. To solve this problem, we have to tell `Host U` to send packets meant for the 192.168.60.0/24 network via the tun interface. We do this by adding an entry to the routing table for `Host U`
- `ip route add 192.168.60.0/24 dev ukadike0 via 192.168.53.99`

Now, when I ping an IP address in the 192.168.60.0/24 network, the packets are received by the VPN server through the tunnel.

***VPN server response***
![2 3](https://github.com/iukadike/blog/assets/58455326/e11e0590-0628-432a-b708-445d32ecf5e3)

<br>

###  Set Up the VPN Server
This section involves creating and configuring a TUN interface on the VPN server using Python and Scapy. The program would do the following:
- Create the virtual interface.
- Name the virtual interface.
- Configure the virtual interface.
  - Assign IP address to the interface.
  - Bring up the interface.
- Read from the sock interface
- Write to the tun interface
- Enable IP forwarding
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

Now that everything is setup, the ICMP echo request from `Host U` arrives at `Host V` through the tunnel. As seen from the screenshot below, the ICMP packet reaches `Host V` and `Host V` responds to the request.

***tcpdump on `Host V`***
![3 1](https://github.com/iukadike/blog/assets/58455326/d0490526-a167-493c-adfb-56a827492389)

<br>

### Handling Traffic in Both Directions
This section involves solving a problem encountered in the previous section. When we send ping requests from `Host U` to `Host V` via the tunnel, it is observed that though `Host V` responds to the ping requests (as seen via tcpdump), `Host U` does not get the response.

The reason for this is that our tunnel only sends packets in one direction (from `Host U` to `Host V`). To receive a response to requests sent from `Host U`, we need to set up our tunnel so it also sends back packets in the reverse direction (from `Host V` to `Host U`).

Thus, our client and server programs should be modified to support this.

#### Client Program
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

# Configure routing information for internal network
os.system(f"ip route add 192.168.60.0/24 dev {ifname} via 192.168.53.99")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9090))
print("server running...")

# Configure the VPN server address and port
SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

while True: 
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        # if data is present on sock interface, send it to tun interface
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print(f"From socket ==>: {pkt.src} --> {pkt.dst}")
            os.write(tun, data)
        # if data is present on tun interface, send it to sock interface            
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun <==: {pkt.src} --> {pkt.dst}")
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

#### Server Program
```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import select
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

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9090))
print("server running...")

# Configure the VPN client address and port
SERVER_IP = "10.9.0.5"
SERVER_PORT = 9090

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        # if data is present on sock interface, send it to tun interface
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {pkt.src} --> {pkt.dst}")
            os.write(tun, data)
        # if data is present on tun interface, send it to sock interface            
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {pkt.src} --> {pkt.dst}")
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

After running the server program and the client program, we should be able to communicate with `Host V` from `Host U`. It is important to note, however, that though the VPN tunnel is complete, it is unencrypted.

#### Pinging `Host V` from `Host U`
When we ping `Host V` from `Host U`, we end up getting the reply.

***client software***
![4 1](https://github.com/iukadike/blog/assets/58455326/273d4bd6-c081-4aee-947b-93986c8e8931)

***server software***
![4 2](https://github.com/iukadike/blog/assets/58455326/3f4b58aa-9283-4fc6-bab5-5fe4286a1733)

***Host U pinging Host V***
![4 3](https://github.com/iukadike/blog/assets/58455326/7e5156ed-77fd-47b7-8c20-ab829262c666)

***ping from Host U to Host V - wireshark capture***
![4 4 a](https://github.com/iukadike/blog/assets/58455326/32d86378-8b25-4d59-adf8-8e81eed0684b)

![4 4 b](https://github.com/iukadike/blog/assets/58455326/3b8bd9b3-4d97-4f3f-86d9-fb522fbfd705)

Looking at the wireshark capture above, the following can be deduced:
- packets that flow across the internet from the client program to the server program are UDP packets.
- contained in these UDP packets are the actual packets meant for the internal host
- once packets reach the server program, they get forwarded to the internal host they are meant for.

#### Telnet into `Host V` from `Host U`
When we telnet into `Host V` from `Host U`, the connection is successful, and we can login.

***Host U telnets into Host V***
![4 5](https://github.com/iukadike/blog/assets/58455326/b5b70490-21c5-43a8-a91d-bba7457621bd)

***telnet from Host U into Host V - wireshark capture***
![4 6 a](https://github.com/iukadike/blog/assets/58455326/86b1fbb2-4c9c-47dc-b70c-7a2d3f44635e)

![4 6 b](https://github.com/iukadike/blog/assets/58455326/fe712331-3eb6-4def-8535-5f41bd160ba3)

Looking at the wireshark capture above, the following can be deduced:
- packets that flow across the internet from the client program to the server program are UDP packets.
- contained in these UDP packets are the actual packets meant for the internal host.
- once packets reach the server program, they get forwarded to the internal host they are meant for.
- encapsulated in the UDP packets are the following:
  - TCP 3-way handshake
  - once the TCP connection has been established, telnet data is exchanged over TCP.
 
<br>

### VPN Between Private Networks
This section involves a setup that simulates a situation where an organization has two sites, each with a private network. The only way machines on these separate private networks can communicate with each other is through the Internet. 

The program that would run on both servers and clients would do the following:
- Create the virtual interface.
- Name the virtual interface.
- Configure the virtual interface.
  - Assign IP address to the interface.
  - Bring up the interface.
- Read from the sock interface or tun interface.
- Write to the tun interface or sock interface.
- enable IP forwarding
  - `sysctl net.ipv4.ip_forward=1`
- Set a route for data going to the other private network.

#### VPN Client
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

# Configure routing information for other internal network
os.system(f"ip route add 192.168.60.0/24 dev {ifname} via 192.168.53.99")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9090))
print("server running...")

# Configure the VPN server address and port
SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

while True: 
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        # if data is present on sock interface, send it to tun interface
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket ==>: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)
        # if data is present on tun interface, send it to sock interface            
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun <==: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

#### VPN Server
```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import select
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

# Configure routing information for internal network
os.system(f"ip route add 192.168.50.0/24 dev {ifname} via 192.168.53.1")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9090))
print("server running...")

# Configure the VPN client address and port
SERVER_IP = "10.9.0.12"
SERVER_PORT = 9090

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        # if data is present on sock interface, send it to tun interface
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)
        # if data is present on tun interface, send it to sock interface            
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

As seen from the screenshots below, machines in intranet A can connect with machines in intranet B, and vice versa.

***`Host 192.168.50.5` successfully pings `Host 192.168.60.5`***
![5 1](https://github.com/iukadike/blog/assets/58455326/7fe3c58f-4eec-4f34-a5aa-dcd37da6431b)

***`Host 192.168.60.5` successfully pings `Host 192.168.50.5`***
![5 2](https://github.com/iukadike/blog/assets/58455326/79e280d2-7ab0-4f78-ad8d-da6b26f26159)

If we try to telnet from one intranet to another, this is also successful.

***`Host 192.168.50.5` successfully telnets into `Host 192.168.60.5`***
![5 3](https://github.com/iukadike/blog/assets/58455326/830da554-f7bf-46fb-8152-255a21e7de71)

***`Host 192.168.60.5` successfully telnets into `Host 192.168.50.5`***
![5 4](https://github.com/iukadike/blog/assets/58455326/b2887233-2d75-4efa-ade7-0b834c4c570a)

<br>

<details>
<summary>Extra</summary>
<br>
When picturing tunneling, I guess the picture that always comes to mind is this huge virtual pipe that connects the client to the server. However, as I have gained more clarity, I have realized that tunneling is conceptual in the sense that traffic still passes through the internet and can be sniffed.
<br>
I think of tunneling as a portal. One end of the portal is a tun/tap interface on a machine, and the other end of the portal is another tun/tap interface on another machine. Data that must flow through the tunnel must enter or leave through the tun/tap interface after arriving at the kernel.
<br>
The whole process usually involves:
<ul>
<li>the tun/tap program gets packets from the tun/tap interface</li>
<li>the tun/tap program encapsulates the packets</li>
<li>the tun/tap program passes the encapsulated packets to the kernel to send over the internet</li>
<li>when the package arrives at the other end, the kernel passes the package to the tun/tap interface</li>
<li>the tun/tap program gets the packets from the tun/tap interface</li>
<li>the tun/tap program deencapsulates the packets and passes them to the kernel for further processing</li>
</ul>
<br>
When creating Virtual Private Networks, a tunnel will have to be encrypted; otherwise,  it defeats the whole purpose of the Virtual Private Network.
</details>


<br>

Thanks for reading...
