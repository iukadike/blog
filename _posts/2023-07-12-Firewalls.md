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






1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can only access the telnet
server on 192.168.60.5, not the other internal hosts.
2. Outside hosts cannot access other internal servers.
3. Internal hosts can access all the internal servers.
4. Internal hosts cannot access external servers.
5. In this task, the connection tracking mechanism is not allowed. It will be used in a later task.




<br>

#### Additional Notes
When doing configurations remotely, it is important to set the CHAIN policy last because if you set it to DENY without actually setting a rule that permits your remote connection,, you will effectively lock yourself out.
