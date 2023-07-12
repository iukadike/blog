---
layout: post
title: Firewall
excerpt: Firewall are set of rules that decide what kind of internet traffic is allowed or not allowed through a network. A firewall checks every called packet that tries to go through the network. It looks at the packets and decides if they are safe or not. If they are safe as defined by the firewall rules, they can pass through the networkelse if they fail the test, the firewall stops them from going through.
categories: [netfilter, iptables]
---

![Firewalls](/images/featured-images/firewalls.jpg)

<br>

Firewall are set of rules that decide what kind of internet traffic is allowed or not allowed through a network. A firewall checks every called packet that tries to go through the network. It looks at the packets and decides if they are safe or not. If they are safe as defined by the firewall rules, they can pass through the networkelse if they fail the test, the firewall stops them from going through. This basically how a firewall operates.

A firewall is usually placed between an internal network and an external network to protect devices on the internal network. A firewall can also be placed between two internal networks. A firewall can be implemented as a hardware device or as a software device.

In this post, I aim to document my findings and observations while performing a SEED Lab.

<br>

### NetFilter
Netfilter examines each packet that goes through the network and decides based on predefined rules whether to accept, drop, or modify the packets. These rules are defined in tables within the Netfilter framework, such as the "filter" table for packet filtering, "nat" table for address translation, and "mangle" table for packet modification. 

Netfilter's filtering is usually defined in terms of:
- Hooks: These are predefined points in the network stack where Netfilter can intercept packets.
  - PREROUTING hook: is responsible for intercepting incoming packets before the Linux kernel makes any routing decisions. This hook is triggered as soon as a packet arrives at the network interface.
  - INPUT hook: is responsible for processing incoming packets that are destined for the local machine.
  - FORWARD hook: is responsible for forwarding packets between NICs
  - OUTPUT hook: is responsible for processing outgoing packets that are leaving the local machine.
  - POSTROUTING hook: is responsible for processing outgoing packets that have been routed to the appropriate destination IP address or are leaving the local machine.

- Tables: Tables are used to organize and categorize the various types of network traffic. Each table contains chains, which are collections of rules. The rules are evaluated in order. The most commonly used tables are:
  - Filter table: is used for filtering packets.
  - NAT table: is used for modifying source or destination IP addresses.
  - Mangle table: is used for modifying packet header fields.

- Chains: A chain is a list of rules. Chains define the actions to take for packets that pass through that chain. When a packet matches a rule, an action is taken, such as accepting or dropping the packet, or passing it on to the next chain for further processing. Netfilter chains correspond to the hooks and indicates where its rules are enforced. The chains include:
  - PREROUTING chain
  - INPUT chain
  - FORWARD chain
  - OUTPUT chain
  - POSTROUTING chain

- Modules: Netfilter uses modular architecture which allows adding various kernel modules as needed to extend its functionality. Modules provide additional features to the netfilter framework.

<br>

### IPtables
Linux has a built-in firewall that is based on netfilter called iptables. To help manage these firewall rules for different purposes, iptables organizes all rules using a hierarchical structure: table-->chain-->rules. IPtables is made up of a number of tables; A table is made up of a number of chains; A chain is made up of a number of rules.

`iptables` command is used to add rules to the chains in each table. `man iptables` provides a manual page for iptables. Understanding how to structure `iptables` command-line arguments is essential in knowing how to use `iptables`.

When using `iptables`, you must:
- specify table name, chain name, and an action to take
- specify the rule, rule number, or both where required
- specify the action to take when a packet maches the rule where required

To view the configured rules:
- `iptables -t <table> -L [chain] -n --line-number`

To delete rules in a table:
- `iptables -t <table> -D <chain> {rulenum | rule-specs}`

To add rules in a table:
- `iptables -t <table> -A <chain> <rule-specs>`
- `iptables -t <table> -I <chain> [rulenum] <rule-specs>`

To modify rules in a table:
- `iptables -t <table> -R <chain> <rulenum> <rule-specs>`

By default, all chains in a table have a policy set. The default policy is `ACCEPT`. To change the default policy of a chain in a table:
- `iptables -t <table> -P <chain> {ACCEPT | DROP}`

<br>

### Protecting the Router
A common configuration is to prevent machines from responding to ping requests. This is done for a number of reasons:
- Ping requests can be used by attackers to determine if a system is online.
- Ping flood attacks can be used to cause DoS attacks.
- Ping requests can adversely affect the overall network performance.
- Some machines are by design intended to be hidden and non-discoverable

The proper way to block traffic to or from a machine is to set the policy of the chain to DROP. This means in order to block ping requests to the router, it is sufficient to set the `INPUT` chain of the `filter` table to `DROP`
- `iptables -t filter -P INPUT DROP`

##### image
As seen from the screenshot below, the ping request from the host to the router fails to go through.
##### image

However, while blocking ping requests can improve security and network performance, it can also make troubleshooting and network debugging more difficult. In such a case that it would be logical to allow ping requests reach the router, a rule can be created in the chain to allow ping requests to the machine.
- `iptables -t filter -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`

##### image
As seen from the screenshot below, the ping request from the host to the router now goes through.
##### image


But blocking traffic to the machine will usually not be enough, we also need to block outgoing traffic from the machine so that rouge requests will not go out of the machine. Just like the policy of `INPUT` chain was set to `DROP`, we will also set the policy of `OUTPUT` chain to `DROP`
- `iptables -t filter -P OUTPUT DROP`

##### image

Now we have a problem, the ping request from the host doesn't get to the router because the router drops echo replies going out of the router

##### image

We need to set a rule that will allow echo replies to leave the router
- `iptables -t filter -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT`

##### image
As seen from the screenshot below, the ping request from the host to the router now goes through.
##### image

We can test to see if we can ping out of the router. This should fail because we did not add a rule that will allow ping requests (we only added that for ping replies).

As seen from the screenshot below, the ping request from the router to the host fails.
##### image

Similarly, we can test to see if we can telnet into the router from the host.

As seen from the screenshot below, this also fails.
##### image



##### Additional notes
If for any reason you want to reset the rules or start all over again,
- `iptables -t filter -P INPUT ACCEPT`
- `iptables -t filter -P OUTPUT ACCEPT`
- `iptables -t filter -F`

<br>

### Protecting the Internal Network
In the previous task, we added rules to protect the router itself. In this task, we would be adding rules that will protect the internal network. Packets that go from the internal network to the external nework or from the external network to the internal network all go through the `FORWARD` chain.

At the end of this exercise, the following is expected:
1. Outside hosts cannot ping internal hosts.
2. Outside hosts can ping the router.
3. Internal hosts can ping outside hosts.
4. All other packets between the internal and external networks should be blocked.

The first step is to set the policy on `INPUT`, `OUTPUT`, and `FORWARD` chain to `DROP`
- `iptables -t filter -P INPUT DROP`
- `iptables -t filter -P OUTPUT DROP`
- `iptables -t filter -P FORWARD DROP`

As it is right now, every traffic to and from the router is blocked. So also is every traffic to and from the internal network. Thus, we have achieved the first objective.

Since we want outside hosts to be able to ping the router, we would add a rule that will enable ping requests to the router
- `iptables -t filter -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`
- `iptables -t filter -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT`

from the screenshot below, we can see that the external machine can ping the router but cannot ping internal hosts
##### image



However, there is an issue. I do not want an outside machine to be able to ping the internal network interface of the router. This means I have to modify the rules as the one I have in place seem ineffective.
- `iptables -t filter -R INPUT 1 -d 10.9.0.11 -p icmp --icmp-type echo-request -j ACCEPT`

from the screenshot below, we can see that the external machine can ping the router's external interface but cannot ping the router's internal interface.
##### image


what I did is effectively allowing ping requests only to the router's external interface. This poses another problem, internal hosts cannot ping the router.

##### image

To correct this, we can add another rule that will allow icmp echo requests from the internal hosts reach the router. To do this, I identified the internal facing interface and added a rule that permits the icmp traffice.
- `iptables -t filter -A INPUT -i eth1 -p icmp --icmp-type echo-request -j ACCEPT`

from the screenshot below, we can see that the internal machine can now ping the router successfully.
##### image


##### Additional notes
You might wonder why I used `-d 10.9.0.11` instead of `-i eth0`. The reason is that it doesn't block traffice to `eth1`. Both interfaces are on the same machine thus there is no forwarding done. When `eth0` gets the traffic, it just passes it on to `eth1`.


So far so good, everything is looking good. We also want all internal hosts to be able to ping outside hosts. As it stands now, they cannot

##### image

What we want to do is to allow inside hosts ping outside hosts while still preventing outside hosts from pinging inside hosts. Here, we will specify the interface we want to permit the traffic on. we will choose the internal facing network interface.
- `iptables -t filter -A FORWARD -i eth1 -p icmp --icmp-type echo-request -j ACCEPT`
- `iptables -t filter -A FORWARD -o eth1 -p icmp --icmp-type echo-reply -j ACCEPT`

from the screenshot below, we can see that the internal host can now ping the external host successfully, while the external host still cannot ping the internal host.
##### image



Finally, we want all other packets between the internal and external networks should be blocked. This should be the case by default because we have set the default policy to `DROP` and added rules for the connections we want accepted. To verify, we will try to telnet from the external host to the internal host.

We can verify by viewing the iptables verbosely
- `iptables -t filter -L -n -v

we can see the packet drop count for the `FORWARD` chain

##### image

after running the telnet command from the external host to connect to the internal host and check the router's iptables, we can see that thye packets drop count has increased.

##### image

<br>

### Protecting Internal Servers
Usually in a corporate setup, organizations have more than one servers running on the internal network. Of these servers, one or more may be serving resources to the public. The ideal configuration would be to protect the servers and ensure that only the intented server is accessible to external hosts.

For this configuration, all the internal hosts run a telnet server (listening to port 23) and we want outside hosts to only access the telnet server on 192.168.60.5, not the other internal hosts.

The first step is to set the policy on `INPUT`, `OUTPUT`, and `FORWARD` chain to `DROP`
- `iptables -t filter -P INPUT DROP`
- `iptables -t filter -P OUTPUT DROP`
- `iptables -t filter -P FORWARD DROP`

Next we add rules to the FORWARD chain that would allow the external host to telnet into the specific internal host while not able to telnet into otherr internal hosts
- `iptables -t filter -A FORWARD -d 192.168.60.5 -p tcp --dport 23 -j ACCEPT`
- `iptables -t filter -A FORWARD -s 192.168.60.5 -p tcp --sport 23 -j ACCEPT`

from the screenshot below, we can see that the external host can telnet to `192.168.60.5` successfully, but fails to telnet into `192.168.60.6`
##### image

We also want to ensure that outside hosts cannot access other internal servers. This should already be the case as the default policy set is `DROP`. However to test it out, we fireup a python webserver on a host inside the network and see if we can connect from the external host

##### image

from the screenshot below, we can see that the external host cannot connect to the webserver on `192.168.60.6`.
##### image

However, we want internal hosts to be able to access all the internal servers. This should already be the case as any traffic between the internal servers does not need to go through the router. This means that the rules we defined on the router should not affect internal machines communicating amongst one another. To test this out, we can try telneting from `192.168.60.5` to `192.168.60.6`. We can also try connecting to the webserver running on `192.168.60.6` from other hosts.

from the screenshot below, we can see that `192.168.60.5` can telnet into `192.168.60.6.
##### image


from the screenshot below, we can see that `192.168.60.5` and `192.168.60.7` can reach the webserver on `192.168.60.6.
##### image


Finally, we do not want internal hosts to be able to access external servers. This should already be the case as the default policy is set to `DROP` and no rule that will allow traffic from the internal host to external servsers has been created. To test this out, we can try create a webserver on `10.9.0.5` and try connecting to the webserver from the internal hosts.

##### image


<br>

### Connection Tracking and Stateful Firewall
A stateful firewall takes into consideration the state of a connection when determining whether to allow or block network traffic. To do this, it needs to be able to somehow track connections. When it receives a packet, it compares the packet against any entries in its state table to determine whether it belongs to an existing, legitimate connection or if it is part of a new, potentially malicious connection.

On a linux machine, conntrack, a kernel feature, keeps track of the state of network connections passing through the system. It allows the Linux kernel to maintain records of all connections, including information such as source and destination IP addresses, ports, protocols, and connection states.

The connection trackiing information can be displayed via `conntrack -L`

#### ICMP
When an echo request is sent from `host 10.9.0.5` to `host 192.168.60.5` and we view the connection tracking information, we can observer the following:
- conntrack records the protocol (ICMP)
- conntrack records the source and destination address of the echo request
- conntrack records the source and destination address of the echo reply
- conntrack gives the entry a TTL of 30 seconds

  ##### image

#### UDP
When we setup a udp server on `host 192.168.60.5`, initiate a connection from `host 10.9.0.6` and view the connection tracking information, we can observe the following:
- conntrack records the protocol (UDP)
- conntrack records the source address, destination address, source port, and destination port of the udp request (it also signifies that the connection does not have a reply)
- conntrack records the source address, destination address, source port, and destination port of the udp reply
- conntrack gives the entry a TTL of 30 seconds

  ##### image

However, when there is a reply and constant exchange of data between `host 10.9.0.5` and `host 192.168.60.6`, we observer the following:
- conntrack signifies that the connection is assured
- conntrack updates the entry to a TTL of 120 seconds

  ##### image

#### TCP
When we setup a tcp server on `host 192.168.60.5`, initiate a connection from `host 10.9.0.6` and view the connection tracking information, we can observe the following:
- conntrack records the protocol (TCP)
- conntrack records that a connection is ESTABLISHED
- conntrack records the source address, destination address, source port, and destination port of the tcp request
- conntrack records the source address, destination address, source port, and destination port of the tcp reply (it also signifies that the connection is assured)
- conntrack gives the entry a TTL of 432000 seconds

  ##### image

<br>

### Protecting Internal Servers using stateful firewall
For this configuration, we want to make use of a stateful firewall to protect internal servers. As with the previous configuration, all the internal hosts run a telnet server (listening to port 23) and we want outside hosts to only access the telnet server on 192.168.60.5, not the other internal hosts.

The first step is to set the policy on `FORWARD` chain to `DROP`
- `iptables -t filter -P FORWARD DROP`

Next we add rules to the FORWARD chain that would allow the external host to telnet into the specific internal host while not able to telnet into otherr internal hosts. However, these rules use connection tracking
- `iptables -t filter -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
- `iptables -t filter -A FORWARD -i eth0 -d 192.168.60.5 -p tcp --dport 23 --syn -m conntrack --ctstate NEW -j ACCEPT`

from the screenshot below, we can see that the external host can telnet to `192.168.60.5` successfully, but fails to telnet into `192.168.60.6`
##### image

Niether can the external host access other internal servers.
##### image

However, internal hosts can access one another
##### image

Unlike the previous configraution where the internal hosts could not access external servers, we would like them to do so, thus we add the rule to enable them do so.
- `iptables -t filter -A FORWARD -i eth1 -p tcp --syn -m conntrack --ctstate NEW -j ACCEPT`

from the screenshot below, we can see that the internal hosts can connect successfully to external servers
##### image

the final ip table is shown below
##### image

<br>

### Limiting Network Traffic
The number of packets allowed into or from a host can also be limited via iptables by using the limit module of iptables.

Say for instance, we want to limit the number of packets that come from `10.9.0.5` to `192.168.60.5`, we can add the following rule to iptables FORWARD chain:
- `iptables -A FORWARD -s 10.9.0.5 -m limit --limit 10/minute --limit-burst 5 -j ACCEPT`

What this does is that it limits the connection it will accept from `10.9.0.5` to `192.168.60.5` to 10 packets per minute. However, before it limits the connection to 10 packets per minute, it will accept up to a maximum of 5 packets. Only then would it start limiting the connection.

However, it seems like the rule is not working. The firewall doesn't limit the connection to 10 packets per minute. The ping request goes on unrestricted. This is because after it processes the nth packet, the others are processed by the next rule (which in this case is the default FORWARD chain policy - ACCEPT).

To ensure that the rule works as expected, we have to add a new rule that would drop the packets not processed by our initial rule:
- `iptables -A FORWARD -s 10.9.0.5 -j DROP`

This works as expected

##### images

<br>

### Load Balancing





<br>

#### Additional Notes
When doing configurations remotely, it is important to set the CHAIN policy last because if you set it to DENY without actually setting a rule that permits your remote connection,, you will effectively lock yourself out.
