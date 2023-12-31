---
layout: post
title: Firewall Evasion
excerpt: There are times when firewalls are implemented to the point that they cause inconvenience for users in a network. Sometimes firewalls can be incorporated to restrict free speech and censor information. Firewalls can be evaded in a couple of ways, but the typical way firewalls are evaded is by tunneling the traffic.
categories: [firewall, ssh]
---

![firewall-evasion]({{ site.baseurl }}/images/featured-images/firewall-evasion.webp)

There are times when firewalls are implemented to the point that they cause inconvenience for users in a network. Sometimes firewalls can be incorporated to restrict free speech and censor information. Firewalls can be evaded in a couple of ways, but the typical way firewalls are evaded is by tunneling the traffic.

<details>
<summary><b>SeedLabs: Firewall Evasion Lab</b></summary>
<div markdown="1">

- [Firewall Evasion Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Firewall_Evasion/Firewall_Evasion.pdf)

___
</div></details>

<br>

### Static Port Forwarding
Port forwarding is a technique used to redirect network traffic from one IP address and port number to another IP address and port number.

The firewall in the lab has been setup to prevent outside machines from connecting to any TCP server on the internal network other than the SSH server running on `192.168.60.99`. However, we would like to bypass this restriction. One way to do this would be to use static port forwarding.

Static port forwarding is when a specific port on one machine is forwarded to a particular port on another machine. It creates a fixed, permanent forwarding rule that does not change unless manually reconfigured.

SSH can be used to perform static port forwarding. The format typically follows:

```
$ ssh -4NT -L [A’s IP]:<A’s port X>:<T’s IP>:<T’s port Y> <user id>@<B’s IP>

// -4: use IPv4 only.
// -N: do not execute a remote command.
// -T: disable pseudo-terminal allocation (usesful when creating a tunnel).
// -L: forward connections made on the local socket to the remote socket
```

Our goal is to telnet into `192.168.20.5` from the external hosts. From the screenshot below, we can see that attempting to telnet from the external hosts to the internal hosts fails.

***failed telnet from 10.8.0.99 to 192.168.20.5***
![1-failed-telnet-1](https://github.com/iukadike/blog/assets/58455326/aadfcd6e-e32f-4780-b526-4aa57ad1ccff)

***failed telnet from 10.8.0.5 to 192.168.20.5***
![1-failed-telnet-2](https://github.com/iukadike/blog/assets/58455326/3492ac08-b505-47fa-a311-56464f6854e0)

***failed telnet from 10.8.0.6 to 192.168.20.5***
![1-failed-telnet-3](https://github.com/iukadike/blog/assets/58455326/342ee773-dc14-4530-be04-97b1faf37f7e)

In order to bypass this restriction, we can create static port forwarding via SSH.

We know that we can SSH into `192.168.20.99` but trying to SSH into `192.168.20.5` fails. If `192.168.20.99` is permitted to telnet into `192.168.20.5`, we can take advantage of this and telnet into `192.168.20.5` via `192.168.20.99`.

#### External Host 10.8.0.99
Armed with this knowledge, we can create a static port forward that will enable us to telnet into `192.168.20.5` from `192.168.20.99` after an SSH connection has been established.

The command to do this is:

`ssh -4NT -L 3333:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:3333`, we successfully telnet into `192.168.20.5`

***host 10.8.0.99 successfully telnets into 192.168.20.5***
![1-successful-telnet-1](https://github.com/iukadike/blog/assets/58455326/d8cfbaf9-07db-41ba-bda2-2da5c9a04a82)

#### External Host 10.8.0.5
We also create a static port forward that will also enable us to telnet into `192.168.20.5` from `10.8.0.6`.

The command to do this is:

`ssh -4NT -L 4444:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:4444`, we successfully telnet into `192.168.20.5`

***host 10.8.0.5 successfully telnets into 192.168.20.5***
![1-successful-telnet-2](https://github.com/iukadike/blog/assets/58455326/7ce72335-51e5-4275-b357-fa04019ca7a1)

#### External Host 10.8.0.6
We also create a static port forward that will also enable us to telnet into `192.168.20.5` from `10.8.0.6`

The command to do this is:

`ssh -4NT -L 5555:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:5555`, we successfully telnet into `192.168.20.5`

***host 10.8.0.6 successfully telnets into 192.168.20.5***
![1-successful-telnet-3](https://github.com/iukadike/blog/assets/58455326/1301d038-cd17-43aa-b19a-94053e0ac1ba)

When we look at the active connections on host `192.168.20.5`, we can see the telnet connections that emanate from `192.168.20.99`

***active sockets on 192.168.20.99***
![1-successful-telnet-4](https://github.com/iukadike/blog/assets/58455326/e06a2d00-2381-4d22-931a-3e1f14294d01)

***active sockets on 192.168.20.5***
![1-successful-telnet-5](https://github.com/iukadike/blog/assets/58455326/d5aadfe9-bbe5-411c-b674-1147861c9ac2)

Opening up Wireshark and observing the traffic flow during one of the sessions, the following is observed:
- the connection starts with the usual TCP 3-way handshake.
- `10.8.0.99` initiates the SSH connection to `192.168.20.99`
- there is a series of key exchanges between `10.8.0.99` and `192.168.20.99`
- once the key exchange is complete, every packet exchanged between `10.8.0.99` and `192.168.20.99` is encrypted.
- also every communication does so through the SSH connection.

***wireshark capture***
![1-wireshark-1](https://github.com/iukadike/blog/assets/58455326/65b61185-f169-4ca3-8282-8015880f8a11)

![1-wireshark-2](https://github.com/iukadike/blog/assets/58455326/3cb9140e-47d8-47d5-9ecd-350258f3b619)

As seen from the capture, there is little surprise why this works. All traffic that happens from the point of the network does so strictly between `10.8.0.99` and `192.168.20.99`. The traffic also appears to be legitimate SSH traffic between `10.8.0.99` and `192.168.20.99`. If the firewall cannot tell that it is not actually SSH traffic going through, how can it block it? Also, if the firewall cannot tell that the traffic is reaching a different host than that specified in the packet header, how can it block it?

<br>

### Dynamic Port Forwarding
In static port forwarding, if we want to forward data to multiple destinations, we need to set up multiple tunnels, which can be quite cumbersome and inconvenient. However, with dynamic port forwarding,
It does not require a predefined port, allowing the user to establish a connection to a remote network and forward requests for required ports as needed.

For this lab, three (3) websites have been blocked by adding a rule to the firewall that will drop packets to these websites. The websites are
- `www.example.com`
- `www.google.com`
- `www.facebook.com`

As seen from the screenshots below, when the internal host attempts to visit these websites, it doesn't work.

***Host 192.168.20.99 fails to connect to blocked websites***
![2-blocked-failed-1](https://github.com/iukadike/blog/assets/58455326/9150c01f-2b63-4e74-af35-11e9e7b03f87)

***Host 192.168.20.5 fails to connect to blocked websites***
![2-blocked-failed-2](https://github.com/iukadike/blog/assets/58455326/491f56dd-e40a-4679-8b46-deaf0eab33dd)

***Host 192.168.20.6 fails to connect to blocked websites***
![2-blocked-failed-3](https://github.com/iukadike/blog/assets/58455326/4e6d47e1-b040-47f6-b401-7420422aa027)

However, We can use ssh to create a dynamic port-forwarding tunnel between the internal host and a machine that can reach the blocked websites. The machine that can reach blocked websites is often called a proxy. The format typically follows:

```
$ ssh -4NT -D [A’s IP]:<A’s port X> <user id>@<B’s IP>

// -4: use IPv4 only.
// -N: do not execute a remote command.
// -T: disable pseudo-terminal allocation (usesful when creating a tunnel).
// -D: forward connections made on the local socket to the remote socket based on the application protocol
```

We know that we can SSH into `10.168.20.99` as the firewall doesn't block this connection. Once we successfully set up the tunnel, we can take advantage of it and visit the blocked websites.

#### Internal Host 192.168.20.99
Equiped with this knowledge, we can create a dynamic port forward that will enable us to visit the blocked websites via `192.168.20.99` after an SSH connection has been established.

The command to do this is:

`ssh -4NT -D 8888 seed@192.168.20.99`

When we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.example.com`, the connection is successful. So also, when we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.google.com` and `curl --proxy socks5h://127.0.0.1:8888 -I http://www.facebook.com`, the connections are successful.

***host 192.168.20.99 successfully visits blocked websites***
![2-blocked-bypass-1](https://github.com/iukadike/blog/assets/58455326/0e3c7185-1006-45d9-bb46-ecc9993a8af5)

#### Internal Host 192.168.20.5
We also create a dynamic port forward that will also enable us to access the blocked websites from `192.168.20.5`.

The command to do this is:

`ssh -4NT -D 8888 seed@192.168.20.5`

When we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.example.com`, the connection is successful. So also, when we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.google.com` and `curl --proxy socks5h://127.0.0.1:8888 -I http://www.facebook.com`, the connections are successful.

***host 192.168.20.5 successfully visits blocked websites***
![2-blocked-bypass-2](https://github.com/iukadike/blog/assets/58455326/ad5fc902-b1d6-4556-9313-a4b1f6d63c14)

#### Internal Host 192.168.20.6
We also create a dynamic port forward that will also enable us to access the blocked websites from `192.168.20.5`.

The command to do this is:

`ssh -4NT -D 8888 seed@192.168.20.6`

When we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.example.com`, the connection is successful. So also, when we run `curl --proxy socks5h://127.0.0.1:8888 -I http://www.google.com` and `curl --proxy socks5h://127.0.0.1:8888 -I http://www.facebook.com`, the connections are successful.

***host 192.168.20.6 successfully visits blocked websites***
![2-blocked-bypass-3](https://github.com/iukadike/blog/assets/58455326/edd780c7-ffb2-474c-a74d-acbe511b2fed)

When we look at the active connections on host `10.8.0.99`, we can see the ssh tunnels from the internal hosts`

***active sockets on 10.8.0.99***
![2-blocked-bypass-4](https://github.com/iukadike/blog/assets/58455326/1b8a38f6-5d17-4f23-b429-7f6274453ca5)

The following can be drawn from the connection:
- It is external host `10.8.0.99` that establishes the actual connection with the intended web servers.
- Since no server and port were provided as targets, one might wonder how `10.8.0.99` knows which server it should connect to. As with a web request that was generated locally, `10.8.0.99` performs DNS resolution and thus obtains the target server. To get the port, `10.8.0.99` looks at the application protocol, and since it is HTTP, it uses the default port 80 as the port.

<details>
<summary>Additional Notes</summary>
<br>
When using dynamic port forwarding, you have to tell the application to use the proxy, and the application must support socks in order for you to use dynamic port forwarding.
</details>

<br>

### Writing a SOCKS Client Using Python
Using the socks module in Python, we can write a proxy that supports SOCKS.

```python
#!/bin/env python3
import socks
import sys


def main():
  if len(sys.argv) != 4:
    print("./proxy.py proxy-server proxy-port website")
    sys.exit(1)

  proxy = sys.argv[1]
  proxy_port = sys.argv[2]
  hostname = sys.argv[3]

  s = socks.socksocket()
  s.set_proxy(socks.SOCKS5, "127.0.0.1", 8888)
  s.connect((hostname, 80))
  
  req = b"GET / HTTP/1.0\r\nHost: " + hostname.encode('utf-8') + b"\r\n\r\n"
  s.sendall(req)
  response = s.recv(512).split(b"\r\n")

  for x in range(5):
    print(response[x].decode())


if __name__ == '__main__':
  main()
```

#### Internal Host 192.168.20.99
With the dynamic port forwarding setup, we run the Python program on `192.168.20.99` to test our program.

***python program successfully accesses blocked websites***
![3-python-1](https://github.com/iukadike/blog/assets/58455326/ba2541f0-4b90-458c-82f2-fe47bd92fd2e)

#### Internal Host 192.168.20.5
With the dynamic port forwarding setup, we run the Python program on `192.168.20.99` to test our program.

***python program successfully accesses blocked websites***
![3-python-2](https://github.com/iukadike/blog/assets/58455326/be760d04-c676-4069-86c3-bf0da8608da1)

#### Internal Host 192.168.20.6
With the dynamic port forwarding setup, we run the Python program on `192.168.20.99` to test our program.

***python program successfully accesses blocked websites***
![3-python-3](https://github.com/iukadike/blog/assets/58455326/8f521d51-52de-49cf-8056-c8de129120ac)

<br>

### Virtual Private Network (VPN)

A VPN is often used to bypass firewalls. SSH can be used to create a VPN; however, we need to change some default SSH settings on the server to allow VPN creation.
The changes made in the configuration file found at `/etc/ssh/sshd_config`:

```
PermitRootLogin yes
PermitTunnel yes
```

The process of creating a VPN using SSH involves the following:

- run the SSH command as root, instructing both machines to create a tun device
  - `ssh -w any:any root@<VPN Server’s IP>`

- configure the tun interface on the client
  - assign an IP address to the tun interface
  - bring the tun interface up

- configure the tun interface on the server
  - assign an IP address to the tun interface
  - bring the tun interface up

- set up routes on the client
  - configure the blocked network address to pass through the tun interface
  - configure the server address to pass through the eth interface (or any interface publicly facing the internet)

- set up ip forwarding and NAT on the server
  - configure the server to forward packets to other machines
  - `sysctl net.ipv4.ip_forward=1`
  - configure the server to perform NAT so it gets back the response to the forwarded packets
  - `iptables -t nat -A POSTROUTING -j MASQUERADE -o eth0`

#### Bypassing Ingress Firewall

##### On the client side

- Run the ssh command to create a tunnel
  - `ssh -4 -w any:any root@192.168.20.99`

- Check for the newly created tun device. It will be the tun interface without an IP address (this will enable you to obtain the right tun device to configure if there are multiple tun devices present on the device).
  - `ip -br addr`

    ***interface device on client***
    ![1 1-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/31e1d0b3-cefe-4231-b938-5bc17f022404)

- Configure the tun device
  - `ip addr add 192.168.53.88/24 dev tun0`

- Enable the tun interface by bringing it up
 -  `ip link set tun0 up`

- Set up routes
  - `ip route add 192.168.20.0/24 via 192.168.53.88 dev tun0`
  - `ip route add 192.168.20.99 via 10.8.0.11 dev eth0`

    ***routes on client***
    ![1 2-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/4a07df96-1895-4a7e-8257-3dd20b46b84b)

##### On the server side

Using the SSH session obtained,

- Check for the newly created tun device. It will be the tun interface without an IP address (this will enable you to obtain the right tun device to configure if there are multiple tun devices present on the device).
  - `ip -br addr`

    ***interface device on server***
    ![1 3-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/a61b399a-c7ea-4f5c-9f8c-fe6cc963f5c5)

- Configure the tun device
  - `ip addr add 192.168.53.99/24 dev tun0`

- Enable the tun interface by bringing it up
 -  `ip link set tun0 up`

- Enable ip forwarding and NAT
  - `sysctl net.ipv4.ip_forward=1`
  - `iptables -t nat -A POSTROUTING -j MASQUERADE -o eth0`

##### Testing the tunnel

Pinging `192.168.20.99`, `192.168.20.5`, and `192.168.20.6` works.

***pinging 192.168.20.99***
![1 4-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/a5da3591-f43e-4ddb-8357-aae7ac23efe0)

***pinging 192.168.20.5***
![1 5-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/782542f9-2d7e-48d7-89de-77d8afcf2027)

***pinging 192.168.20.6***
![1 6-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/3a057255-02bc-48fb-bd31-bb9ac6313b64)

Also, the telnet connection to `192.168.20.5`, and `192.168.20.6` is successful, while the telnet connection to `192.168.20.99` fails. This happens because our connections to `192.168.20.99` don't go through the tunnel. The other end of our tunnel needs to be reachable over the internet, meaning the router can see and block the traffic.

***telnet into 192.168.20.99***
![1 7-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/20ca7946-323e-4fb0-9d78-18bd4b87577a)

***telnet into 192.168.20.5***
![1 8-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/ceea2f8f-9adc-4e42-9f2d-5a01de12c41c)

***telnet into 192.168.20.6***
![1 9-vpn-ingress](https://github.com/iukadike/blog/assets/58455326/1a127f53-b567-4356-ad48-dc6e8dd6e383)

<br>

#### Bypassing Egress Firewall

The following websites are blocked by the firewall
- `www.example.com`

  ![2 1-vpn-egress](https://github.com/iukadike/blog/assets/58455326/4b773dd5-d512-4e7a-aa32-ad650b7dc983)

- `www.google.com`

  ![2 2-vpn-egress](https://github.com/iukadike/blog/assets/58455326/fce34ccb-c559-44e8-a045-fc76883eff12)

- `www.facebook.com`

  ![2 3-vpn-egress](https://github.com/iukadike/blog/assets/58455326/2a935a91-34c1-4fb0-bfbd-eb6d150fbf2b)

Our goal is to use a VPN to bypass this restriction and access the blocked websites.

##### On the client side

- Run the ssh command to create a tunnel
  - `ssh -4 -w any:any root@10.8.0.99`

- Check for the newly created tun device. It will be the tun interface without an IP address (this will enable you to obtain the right tun device to configure if there are multiple tun devices present on the device).
  - `ip -br addr`

    ***interface device on client***
    ![2 4-vpn-egress](https://github.com/iukadike/blog/assets/58455326/46b7956a-d027-4a15-8f7d-c33500443ad6)

- Configure the tun device
  - `ip addr add 192.168.53.88/24 dev tun0`

- Enable the tun interface by bringing it up
 -  `ip link set tun0 up`

- Set up routes
  - `ip route replace default via 192.168.53.88 dev tun0` ("default" ensures that any address without and explicit route follows the default route)
  - `ip route add 10.8.0.99 via 192.168.20.11 dev eth0`

    ***routes on client***
    ![2 5-vpn-egress](https://github.com/iukadike/blog/assets/58455326/572e2a16-67bb-4157-ab01-cb242f3a125c)

##### On the server side

Using the SSH session obtained,

- Check for the newly created tun device. It will be the tun interface without an IP address (this will enable you to obtain the right tun device to configure if there are multiple tun devices present on the device).
  - `ip -br addr`

    ***interface device on server***
    ![2 6-vpn-egress](https://github.com/iukadike/blog/assets/58455326/b864694a-7b65-4c78-a6ae-b6447f781e0a)

- Configure the tun device
  - `ip addr add 192.168.53.99/24 dev tun0`

- Enable the tun interface by bringing it up
 -  `ip link set tun0 up`

- Enable ip forwarding and NAT
  - `sysctl net.ipv4.ip_forward=1`
  - `iptables -t nat -A POSTROUTING -j MASQUERADE -o eth0`

##### Testing the tunnel

I attempted to access the blocked websites, and they are accessible, meaning the firewall has been successfully bypassed.

***`www.example.com`***
![2 7-vpn-egress](https://github.com/iukadike/blog/assets/58455326/77a18058-57c8-4e54-ad58-30f6930b1377)

***`www.google.com`***
![2 8-vpn-egress](https://github.com/iukadike/blog/assets/58455326/c8148cf0-fa36-4686-88f8-763c65deea0c)

***`www.facebook.com`***
![2 9-vpn-egress](https://github.com/iukadike/blog/assets/58455326/fc5baa9d-ff57-4b28-a06f-bec743710532)

<details>
  <summary>Additional notes</summary>
  <br>
  When working with the routing table, you have to take precaution because if you mess up the routing table, network connectivity will suffer.
  <br>
  Best practice is to backup the routing table before making any modification
  <ul>
    <li>ip route show > route_backup.txt</li>
  </ul>
  You can easily restore the routing table
  <ul>
    <li>ip route flush all</li>
    <li>ip route < route_backup.txt</li>
  </ul>
</details>


<br>

Thanks for reading...
