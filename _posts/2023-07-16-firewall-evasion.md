---
layout: post
title: Firewall Evasion
excerpt: 
categories: [firewall, wireshark]
---

![firewall-evasion]({{ site.baseurl }}/images/firewall-evasion.webp)

There are times when firewalls are implemented to the extreme that they cause inconvininence for users in a network. Some times firewalls can be incorporated to restrict free speech and censor information. Firewalls can be evaded in a couple of ways, but the typical way firewalls are evaded is by tunnelling the traffic.

In this post, I aim to document my findings and observations while performing a SEED Lab.

<br>

### Static Port Forwarding
Port forwarding is a technique used to redirect network traffic from one IP address and port number to another IP address and port number.

The firewall in the lab has been setup to prevent outside machines from connecting to any TCP server on the internal network, other than the SSH server running on `192.168.60.99`. However, we would like to bypass this restriction. One way to do this would be to use static port forwarding.

Static port forwarding is a when a specific port on one machine is forwarded to a particular port on a another machine. It creates a fixed, permanent forwarding rule that does not change unless manually reconfigured.

SSH can be used to perform static port forwarding. The format typically follows:

```
$ ssh -4NT -L <A’s IP>:<A’s port X>:<T’s IP>:<T’s port Y> <user id>@<B’s IP>

// -4: use IPv4 only.
// -N: do not execute a remote command.
// -T: disable pseudo-terminal allocation (usesful when creating a tunnel).
// -L: forward connections made on the local socket to the remote socket
```

Our goal is to telnet into `192.168.20.5` from the external hosts. From the screenshot below, we can see that attempting to telnet from the external hosts to the internal hosts fail.

***failed telnet from 10.8.0.99 to 192.168.20.5***

***failed telnet from 10.8.0.5 to 192.168.20.5***

***failed telnet from 10.8.0.6 to 192.168.20.5***

In order to bypass this restriction, we can create a static port forwarding via SSH.

We know that we can SSH into `192.1168.20.99` but trying to ssh into `192.1168.20.5` fails. If `192.1168.20.99` is permitted to telnet into `192.1168.20.5`, we can take advantage of this an telnet into `192.1168.20.5` via `192.1168.20.99`.

#### External Host 10.8.0.99
Equiped with this knowledge, we can create a static port forward that will enable us telnet into `192.1168.20.5` from `192.1168.20.99` after SSH connection has been established.

The command to do this is:

`ssh -4NT -L 3333:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:3333`, we successfully telnet into `192.1168.20.5`

***host 10.8.0.99 successfully telnets into 192.168.20.5***

#### External Host 10.8.0.5
We also create a static port forward that will also enable us telnet into `192.1168.20.5` from `10.8.0.6`.

The command to do this is:

`ssh -4NT -L 4444:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:4444`, we successfully telnet into `192.1168.20.5`

***host 10.8.0.5 successfully telnets into 192.168.20.5***

#### External Host 10.8.0.6
We also create a static port forward that will also enable us telnet into `192.1168.20.5` from `10.8.0.6`

The command to do this is:

`ssh -4NT -L 5555:192.168.20.5:23 seed@192.168.20.99`

When we run `telnet 127.0.0.1:5555`, we successfully telnet into `192.1168.20.5`

***host 10.8.0.6 successfully telnets into 192.168.20.5***

When we look at the active connections on host `192.1168.20.5`, we can see the telnet connections that emanate from `192.1168.20.99`

***active sockets on 192.168.20.99***

***active sockets on 192.168.20.5***

Opening up wireshark and observing the traffic flow during one of the sessions, the following is observed:
- the connection starts with the usually tcp 3-way hansdshake
- `10.8.0.99` initiates the SSH connection to `192.168.20.99`
- there is a series of key exchanges between `10.8.0.99` and `192.168.20.99`
- once the key exhange is complete, every packet exchanged between `10.8.0.99` and `192.168.20.99` is encrypted
- also every communication does so through the SSH connection


As seen from the capture, there is little surprise why this works. All traffic that happens from the point of the network does so strictly between `10.8.0.99` and `192.168.20.99`. The traffic also appears to be legitimate SSH traffic between `10.8.0.99` and `192.168.20.99`. If the firewall cannot tell that it is not actually SSH traffic going through, how can it block it? Also, if the firewall cannot tell that the traffic is reaching a diiferent host than that specified in the packet header, how can it block it?

<br>

### Dynamic Port Forwarding
In the static port forwarding, if we want to forward data to multiple destinations, we need to set up multiple tunnels which can be quite cumbersome and inconvininent. However, with dynamic port forwarding,
It does not require a predefined port 


