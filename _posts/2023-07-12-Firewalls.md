---
layout: post
title: Firewall
excerpt: Firewall are set of rules that decide what kind of internet traffic is allowed or not allowed through a network. A firewall checks every called packet that tries to go through the network. It looks at the packets and decides if they are safe or not. If they are safe as defined by the firewall rules, they can pass through the networkelse if they fail the test, the firewall stops them from going through.
categories: [netfilter, iptables]
---

![Firewalls]({{ site.baseurl }}/images/featured-images/firewalls.jpg)

A firewall is a set of rules that decide what kind of internet traffic is allowed or not allowed through a network. A firewall checks every packet that tries to go through the network. It looks at the packets and decides if they are safe or not. If they are safe as defined by the firewall rules, they can pass through the network; if they fail the test, the firewall stops them from going through. This is basically how a firewall operates.

A firewall is usually placed between an internal network and an external network to protect devices on the internal network. A firewall can also be placed between two internal networks. A firewall can be implemented as a hardware device or as a software device.

<details>
<summary><b>SeedLabs: Firewall Exploration Lab</b></summary>
<div markdown="1">

- [Firewall Exploration Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Firewall/Firewall.pdf)

___
</div></details>

<br>

### Netfilter
Netfilter examines each packet that goes through the network and decides based on predefined rules whether to accept, drop, or modify the packets. These rules are defined in tables within the Netfilter framework, such as the "filter" table for packet filtering, the "nat" table for address translation, and the "mangle" table for packet modification.

Netfilter's filtering is usually defined in terms of:
- **Hooks**: These are predefined points in the network stack where Netfilter can intercept packets.
  - PREROUTING hook: is responsible for intercepting incoming packets before the Linux kernel makes any routing decisions. This hook is triggered as soon as a packet arrives at the network interface.
  - INPUT hook: is responsible for processing incoming packets that are destined for the local machine.
  - FORWARD hook: is responsible for forwarding packets between NICs.
  - OUTPUT hook: is responsible for processing outgoing packets that are leaving the local machine.
  - POSTROUTING hook: is responsible for processing outgoing packets that have been routed to the appropriate destination IP address or are leaving the local machine.

- **Tables**: Tables are used to organize and categorize the various types of network traffic. Each table contains chains, which are collections of rules. The rules are evaluated in order. The most commonly used tables are:
  - Filter table: is used for filtering packets.
  - NAT table: is used for modifying source or destination IP addresses.
  - Mangle table: is used for modifying packet header fields.

- **Chains**: A chain is a list of rules. Chains define the actions to take for packets that pass through that chain. When a packet matches a rule, an action is taken, such as accepting or dropping the packet or passing it on to the next chain for further processing. Netfilter chains correspond to the hooks and indicate where their rules are enforced. The chains include:
  - PREROUTING chain
  - INPUT chain
  - FORWARD chain
  - OUTPUT chain
  - POSTROUTING chain

- **Modules**: Netfilter uses a modular architecture that allows adding various kernel modules as needed to extend its functionality. Modules provide additional features to the netfilter framework.

<br>

### IPtables
Linux has a built-in firewall that is based on Netfilter called iptables. To help manage these firewall rules for different purposes, iptables organizes all rules using a hierarchical structure: table-->chain-->rules. IPtables is made up of a number of tables; A table is made up of a number of chains; A chain is made up of a number of rules.

`iptables` command is used to add rules to the chains in each table. `man iptables` provides a manual page for iptables. Understanding how to structure `iptables` command-line arguments is essential to knowing how to use `iptables`.

When using `iptables`, you must:
- specify table name, chain name, and action to take.
- specify the rule, rule number, or both where required.
- specify the action to take when a packet matches the rule where required.

To view the configured rules:
- `iptables -t <table> -L [chain] -n --line-number`

To delete rules in a table:
- `iptables -t <table> -D <chain> {rulenum | rule-specs}`

To add rules to a table:
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
- Ping requests can adversely affect the overall network's performance.
- Some machines are, by design, intended to be hidden and non-discoverable.

The proper way to block traffic to or from a machine is to set the policy of the chain to DROP. This means that in order to block ping requests to the router, it is sufficient to set the `INPUT` chain of the `filter` table to `DROP`
- `iptables -t filter -P INPUT DROP`

As seen in the screenshot below, the ping request from the host to the router fails to go through.

***failed ping request***
![2 a failed-ping-1](https://github.com/iukadike/blog/assets/58455326/49fbab7a-ac8f-4108-911c-8419375a6784)

However, while blocking ping requests can improve security and network performance, it can also make troubleshooting and network debugging more difficult. In such a case that it would be logical to allow ping requests to reach the router, a rule can be created in the chain to allow ping requests to the machine.
- `iptables -t filter -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`

As seen in the screenshot below, the ping request from the host to the router now goes through.

***successful ping request***
![2 a success-ping-1](https://github.com/iukadike/blog/assets/58455326/e1aed2db-32f0-4b18-8ebe-4d9be0b86ae5)

But blocking traffic to the machine will usually not be enough, we also need to block outgoing traffic from the machine so that rouge requests will not go out of the machine. Just like the policy of `INPUT` chain was set to `DROP`, we will also set the policy of `OUTPUT` chain to `DROP`
- `iptables -t filter -P OUTPUT DROP`

Now we have a problem, the ping request from the host doesn't get to the router because the router drops echo replies going out of the router.

***failed ping request***
![2 a failed-ping-2](https://github.com/iukadike/blog/assets/58455326/775292a1-e2e2-4591-bfbe-541c8a98c798)

We need to set a rule that will allow echo replies to leave the router.
- `iptables -t filter -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT`

As seen in the screenshot below, the ping request from the host to the router now goes through.

***successful ping request***
![2 a success-ping-2](https://github.com/iukadike/blog/assets/58455326/20421b92-c60d-4fd5-ac9a-6db5adb5e396)

We can test to see if we can ping from the router. This should fail because we did not add a rule that will allow ping requests that are generated from the router (we only added that for ping replies).

As seen in the screenshot below, the ping request from the router to the host fails.

***failed ping request***
![2 a failed-ping-3](https://github.com/iukadike/blog/assets/58455326/d5b69cd3-f3eb-45bb-847b-037e228c8746)

Similarly, we can test to see if we can telnet into the router from the host.

As seen from the screenshot below, this also fails.

***failed telnet***
![2 a failed-telnet](https://github.com/iukadike/blog/assets/58455326/5f94068e-4097-4f64-a7c0-e949cade602a)


<details>
<summary>Additional notes</summary>
<br>
If, for any reason, you want to reset the rules or start all over again:
<ul>
<li>iptables -t filter -P INPUT ACCEPT</li>
<li>iptables -t filter -P OUTPUT ACCEPT</li>
<li>iptables -t filter -F</li>
</ul>
</details>

<br>

### Protecting the Internal Network
In the previous task, we added rules to protect the router itself. In this task, we will be adding rules that will protect the internal network. Packets that go from the internal network to the external network or from the external network to the internal network all go through the `FORWARD` chain.

At the end of this exercise, the following is expected:
1. Outside hosts cannot ping internal hosts.
2. Outside hosts can ping the router.
3. Internal hosts can ping outside hosts.
4. All other packets between the internal and external networks should be blocked.

The first step is to set the policy on `INPUT`, `OUTPUT`, and `FORWARD` chains to `DROP`
- `iptables -t filter -P INPUT DROP`
- `iptables -t filter -P OUTPUT DROP`
- `iptables -t filter -P FORWARD DROP`

As it is right now, all traffic to and from the router is blocked. So is every traffic to and from the internal network. Thus, we have achieved the first objective.

Since we want outside hosts to be able to ping the router, we would add a rule that will enable ping requests to the router.
- `iptables -t filter -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`
- `iptables -t filter -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT`

From the screenshot below, we can see that the external machine can ping the router but cannot ping internal hosts.

***external host successfully pinging the router***
![2 b out-ping-router-1](https://github.com/iukadike/blog/assets/58455326/2396e595-3219-4d27-b1b8-1ba1473c327b)

***external host fails to ping internal hosts***
![2 b out-not-ping-in-1](https://github.com/iukadike/blog/assets/58455326/01721e2d-818f-4a10-bad3-66bd18067652)

However, there is an issue. I do not want an outside machine to be able to ping the internal network interface of the router. This means I have to modify the rules, as the ones I have in place seem ineffective.
- `iptables -t filter -R INPUT 1 -d 10.9.0.11 -p icmp --icmp-type echo-request -j ACCEPT`

From the screenshot below, we can see that the external machine can ping the router's external interface but cannot ping the router's internal interface.

***external host pinging the router***
![2 b out-ping-router-2](https://github.com/iukadike/blog/assets/58455326/135b8ea6-92a2-46fc-b719-f26ae67683da)

What I did was effectively allow ping requests only to the router's external interface. This poses another problem: internal hosts cannot ping the router.

***internal host fails to ping the router***
![2 b in-ping-router-1](https://github.com/iukadike/blog/assets/58455326/b91824c9-45fb-48d5-b71f-c01811f63383)

To correct this, we can add another rule that will allow ICMP echo requests from the internal hosts to reach the router. To do this, I identified the internal-facing interface and added a rule that permits the ICMP traffic.
- `iptables -t filter -A INPUT -i eth1 -p icmp --icmp-type echo-request -j ACCEPT`

From the screenshot below, we can see that the internal machine can now ping the router successfully.

***internal host successfully pings the router***
![2 b in-ping-router-2](https://github.com/iukadike/blog/assets/58455326/90fbdd85-97c1-4199-82ed-48f55b933a30)


<details>
<summary>Additional notes</summary>
<br>
You might wonder why I used "-d 10.9.0.11" instead of "-i eth0". The reason is that it doesn't block traffic to "eth1". Both interfaces are on the same machine, so there is no forwarding. When "eth0" gets the traffic, it just passes it on to "eth1".
</details>

<br>

So far, so good; everything is looking good. We also want all internal hosts to be able to ping outside hosts. As it stands now, they cannot.

***internal host fails to ping external host***
![2 b in-ping-out-1](https://github.com/iukadike/blog/assets/58455326/635dfcc0-8aff-4470-be48-5ce0e513ae89)

What we want to do is allow inside hosts to ping outside hosts while still preventing outside hosts from pinging inside hosts. Here, we will specify the interface we want to permit traffic on. We will choose the internal-facing network interface.
- `iptables -t filter -A FORWARD -i eth1 -p icmp --icmp-type echo-request -j ACCEPT`
- `iptables -t filter -A FORWARD -o eth1 -p icmp --icmp-type echo-reply -j ACCEPT`

From the screenshot below, we can see that the internal host can now ping the external host successfully, while the external host still cannot ping the internal host.

***internal host successfully pings external host***
![2 b in-ping-out-2](https://github.com/iukadike/blog/assets/58455326/49022c9f-5a2d-4ee0-998d-1bcfd117ec8f)

Finally, we want all other packets between the internal and external networks to be blocked. This should be the case by default because we have set the default policy to `DROP` and added rules for the connections we want accepted. To verify, we will try to telnet from the external host to the internal host.

We can verify this by viewing the iptables verbosely.
- `iptables -t filter -L -n -v

We can see the packet drop count for the `FORWARD` chain.

***iptables***
![2 b block-other-traffic-1](https://github.com/iukadike/blog/assets/58455326/be1b6864-00d5-4ab9-ac05-30bb43e3cafc)

After running the telnet command from the external host to connect to the internal host and check the router's iptables, we can see that the packet drop count has increased.

***external host fails to telnet to internal host***
![2 b block-other-traffic-2](https://github.com/iukadike/blog/assets/58455326/92b8c929-0565-4079-a67a-6c62502e66e0)

***iptables***
![2 b block-other-traffic-3](https://github.com/iukadike/blog/assets/58455326/8c95d40a-493d-4399-acc1-1d6327e6fc57)

<br>

### Protecting Internal Servers
Usually, in a corporate setup, organizations have more than one server running on the internal network. Of these servers, one or more may be serving resources to the public. The ideal configuration would be to protect the servers and ensure that only the intended server is accessible to external hosts.

For this configuration, all the internal hosts run a telnet server (listening to port 23), and we want outside hosts to only access the telnet server on 192.168.60.5 and not the other internal hosts.

The first step is to set the policy on `INPUT`, `OUTPUT`, and `FORWARD` chains to `DROP`
- `iptables -t filter -P INPUT DROP`
- `iptables -t filter -P OUTPUT DROP`
- `iptables -t filter -P FORWARD DROP`

Next, we add rules to the FORWARD chain that would allow the external host to telnet into the specific internal host while not being able to telnet into other internal hosts.
- `iptables -t filter -A FORWARD -d 192.168.60.5 -p tcp --dport 23 -j ACCEPT`
- `iptables -t filter -A FORWARD -s 192.168.60.5 -p tcp --sport 23 -j ACCEPT`

From the screenshot below, we can see that the external host can telnet to `192.168.60.5` successfully, but fails to telnet into `192.168.60.6`

***external host successfully telnet into internal host 1***
![2 c external-telnet-internal-1](https://github.com/iukadike/blog/assets/58455326/2cd3f6d3-4e62-4e17-9b49-f49460b75c6d)

***external host fails to telnet into internal host 2***
![2 c external-telnet-internal-2](https://github.com/iukadike/blog/assets/58455326/03060442-4507-4dba-a707-33c8c5dd2953)


We also want to ensure that outside hosts cannot access other internal servers. This should already be the case, as the default policy set is `DROP`. However, to test it out, we fire up a Python webserver on a host inside the network and see if we can connect from the external host.

From the screenshot below, we can see that the external host cannot connect to the webserver on `192.168.60.6`.

***webserver on 192.168.60.6***
![2 c python-webserver-1](https://github.com/iukadike/blog/assets/58455326/cdaff1e6-5d9c-42db-9f64-0a74fb464bb7)

***external host fails to connect to webserver***
![2 c python-webserver-2](https://github.com/iukadike/blog/assets/58455326/eac08528-16c8-4a48-ba2b-1d65e0d8d495)


However, we want internal hosts to be able to access all the internal servers. This should already be the case, as any traffic between the internal servers does not need to go through the router. This means that the rules we defined on the router should not affect internal machines communicating with one another. To test this out, we can try telneting from `192.168.60.5` to `192.168.60.6`. We can also try connecting to the webserver running on `192.168.60.6` from other hosts.

From the screenshot below, we can see that `192.168.60.5` can telnet into `192.168.60.6.

![2 c in-to-in-1](https://github.com/iukadike/blog/assets/58455326/80ebb593-ba1c-44ac-929d-0a513b7983b6)

From the screenshot below, we can see that `192.168.60.5` and `192.168.60.7` can reach the webserver on `192.168.60.6.

***curl on host 192.168.60.5***
![2 c in-to-in-2](https://github.com/iukadike/blog/assets/58455326/56d7c4f6-e3fa-486c-aa9c-737f25fdad34)

***curl on host 192.168.60.7***
![2 c in-to-in-3](https://github.com/iukadike/blog/assets/58455326/3c49e7b2-4fc6-4884-9615-cdf699cb80cf)

***webserver on host 192.168.60.6***
![2 c in-to-in-4](https://github.com/iukadike/blog/assets/58455326/30941844-c392-47a3-96f7-5b4e468ea7c1)

Finally, we do not want internal hosts to be able to access external servers. This should already be the case as the default policy is set to `DROP` and no rule that will allow traffic from the internal host to external servers has been created. To test this out, we can try creating a webserver on `10.9.0.5` and connecting to the webserver from the internal hosts.

***webserver on external host***
![2 c out-webserver](https://github.com/iukadike/blog/assets/58455326/e5533435-c582-463b-8f6e-744ab23e202f)


<br>

### Connection Tracking and Stateful Firewall
A stateful firewall takes into consideration the state of a connection when determining whether to allow or block network traffic. To do this, it needs to be able to somehow track connections. When it receives a packet, it compares the packet against any entries in its state table to determine whether it belongs to an existing, legitimate connection or if it is part of a new, potentially malicious connection.

On a Linux machine, conntrack, a kernel feature, keeps track of the state of network connections passing through the system. It allows the Linux kernel to maintain records of all connections, including information such as source and destination IP addresses, ports, protocols, and connection states.

The connection tracking information can be displayed via `conntrack -L`

#### ICMP
When an echo request is sent from `host 10.9.0.5` to `host 192.168.60.5` and we view the connection tracking information, we can observe the following:
- conntrack records the protocol (ICMP) and the protocol number.
- conntrack records the source and destination addresses of the echo request.
- conntrack records the source and destination addresses of the echo reply.
- conntrack gives the entry a TTL of 30 seconds.

  ***conntrack record for an ICMP traffic***
  ![3 a icmp](https://github.com/iukadike/blog/assets/58455326/5e07373c-1125-4e12-8914-1a047fcbcc56)

#### UDP
When we setup a udp server on `host 192.168.60.5`, initiate a connection from `host 10.9.0.6` and view the connection tracking information, we can observe the following:
- conntrack records the protocol (UDP) and the protocol number.
- conntrack records the source address, destination address, source port, and destination port of the UDP request (it also signifies that the connection does not have a reply).
- conntrack records the source address, destination address, source port, and destination port of the UDP reply.
- conntrack gives the entry a TTL of 30 seconds.

  ***conntrack record for a UDP traffic***
  ![3 a udp-1](https://github.com/iukadike/blog/assets/58455326/747458b5-83ef-453f-a0df-582773c9cfb3)

However, when there is a reply and constant exchange of data between `host 10.9.0.5` and `host 192.168.60.6`, we observe the following:
- conntrack signifies that the connection is assured.
- conntrack updates the entry to a TTL of 120 seconds.

  ***conntrack record for a UDP traffic***
  ![3 a udp-2](https://github.com/iukadike/blog/assets/58455326/ed35881a-91f8-44b2-850c-e77bc4af3fba)

#### TCP
When we setup a tcp server on `host 192.168.60.5`, initiate a connection from `host 10.9.0.6` and view the connection tracking information, we can observe the following:
- conntrack records the protocol (TCP) and the protocol number.
- conntrack records that a connection is ESTABLISHED
- conntrack records the source address, destination address, source port, and destination port of the TCP request.
- conntrack records the source address, destination address, source port, and destination port of the TCP reply (it also signifies that the connection is assured).
- conntrack gives the entry a TTL of 432000 seconds.

  ***conntrack record for a TCP traffic***
  ![3 a tcp](https://github.com/iukadike/blog/assets/58455326/37142f70-1e10-420b-a620-93ff4ec3b50c)

<br>

### Protecting Internal Servers using stateful firewall
For this configuration, we want to make use of a stateful firewall to protect internal servers. As with the previous configuration, all the internal hosts run a telnet server (listening to port 23), and we want outside hosts to only access the telnet server on 192.168.60.5 and not the other internal hosts.

The first step is to set the policy on `FORWARD` chain to `DROP`
- `iptables -t filter -P FORWARD DROP`

Next, we add rules to the FORWARD chain that would allow the external host to telnet into the specific internal host while not being able to telnet into other internal hosts. However, these rules use connection tracking.
- `iptables -t filter -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
- `iptables -t filter -A FORWARD -i eth0 -d 192.168.60.5 -p tcp --dport 23 --syn -m conntrack --ctstate NEW -j ACCEPT`

From the screenshot below, we can see that the external host can telnet to `192.168.60.5` successfully but fails to telnet into `192.168.60.6`

***external host successfully telnet into 192.168.60.5***
![3 b-1](https://github.com/iukadike/blog/assets/58455326/56f9fd8b-2e23-4561-b7e9-5375574b0211)

***external host fails to telnet into 192.168.60.6***
![3 b-2](https://github.com/iukadike/blog/assets/58455326/8ca5f437-c32b-4b03-877d-bbcc5276df64)

Neither can the external host access other internal servers.

***external host fails to connect to the internal webserver***
![3 b-3](https://github.com/iukadike/blog/assets/58455326/adf06a78-b833-4348-b3c2-957d7dfcb32f)

However, internal hosts can access one another.

***internal hosts successfully connect to the internal webserver***
![3 b-4](https://github.com/iukadike/blog/assets/58455326/b20d7667-eee1-4c65-a189-732b6d855245)

Unlike the previous restriction where the internal hosts could not access external servers, we would like them to do so, so we added the rule to enable them to do so.
- `iptables -t filter -A FORWARD -i eth1 -p tcp --syn -m conntrack --ctstate NEW -j ACCEPT`

from the screenshot below, we can see that the internal hosts can connect successfully to external servers.

***internal hosts successfully connect to the external webserver***
![3 b-5](https://github.com/iukadike/blog/assets/58455326/25f7fd1a-094c-4e77-b944-9531ee25227c)

The final iptables is shown below

***iptables***
![3 b-6-iptables](https://github.com/iukadike/blog/assets/58455326/8a033315-d33b-4cd4-b2b3-eb90ca51dd18)

<br>

### Limiting Network Traffic
The number of packets allowed into or from a host can also be limited via iptables by using the limit module of iptables.

For instance, if we want to limit the number of packets that come from `10.9.0.5` to `192.168.60.5`, we can add the following rule to the iptables FORWARD chain:
- `iptables -A FORWARD -s 10.9.0.5 -m limit --limit 10/minute --limit-burst 5 -j ACCEPT`

What this does is limit the connection it will accept from `10.9.0.5` to `192.168.60.5` to 10 packets per minute. However, before it limits the connection to 10 packets per minute, it will accept up to a maximum of 5 packets. Only then would it start limiting the connection.

***external host pinging 10.9.0.5***
![4a](https://github.com/iukadike/blog/assets/58455326/b01441d7-b154-4e46-a28d-aa6eba7c95ae)

However, it seems like the rule is not working. The firewall doesn't limit the connection to 10 packets per minute. The ping request goes on unrestricted. This is because after it processes the nth packet, the others are processed by the next rule (which in this case is the default FORWARD chain policy, ACCEPT).

To ensure that the rule works as expected, we have to add a new rule that would drop the packets not processed by our initial rule:
- `iptables -A FORWARD -s 10.9.0.5 -j DROP`

This works as expected.

***external host pinging 10.9.0.5***
![4b](https://github.com/iukadike/blog/assets/58455326/1b21d6d0-e120-43d0-80c1-823d89e03563)

<br>

### Load Balancing
It's very common practice to incorporate load balancing when serving resources that require high availability over a network. This is usually done for a number of reasons:
- to equally distribute incoming network traffic across multiple servers
- to maximize throughput
- to improve response time.
- to avoid overload.

Requests are usually made to the load balancer, which decides which of the servers in the cluster will handle the request. Using the statistics module of iptables, we can make our router a load balancer.

To demonstrate this, we will fire up a UDP server on all three internal hosts, configure the router to distribute traffic amongst them, and connect to the load balancer (router) from an external host.

The statistics module can make a decision based on either the nth number of packets or a probability distribution. We will explore both.

#### Load balancing using statistics nth module
- first we fire up a UDP server on all three internal hosts:
  - `netcat -nlukvp 8080
    n: means do not perform name resolution.
    l: means to listen for connections on the specified port.
    p: specifies the port to listen on.
    u: means listen for udp.
    v: means display extra information, i.e., diagnostic messages.
    k: means keep listening for a connection even after a client disconnects (the default action of netcat is to disconnect once a client disconnects).

- second we need to set up rules on the `PREROUTING` chain of the `nat` table:
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination 192.168.60.5:8080`
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 192.168.60.6:8080`
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 1 --packet 0 -j DNAT --to-destination 192.168.60.7:8080`
  
  Since we have three servers we want to distribute our load over, we will need to add three rules. We start with the `nth` from the total number of servers, decreasing the number by one for every new rule we add. The rules are evaluated from top to bottom.

  The statistics mode tracks the connection, as we saw from running `conntrack -L`. Thus, based on the flow, it decides which server gets the traffic. This means that if there is an active flow, all packets sent go to the same server. Traffic only gets sent to another server when another flow is seen in Conntrack.

- third, we initiate a connection with the external host and test our connection.

  ***external host***
  ![5-nth-ext-host](https://github.com/iukadike/blog/assets/58455326/fd9bdd19-c6ab-406d-ba5e-68b737f24c38)

  ***internal server 1***
  ![5-nth-host-1](https://github.com/iukadike/blog/assets/58455326/8638819f-db0e-48b8-8905-2b03ec24632a)

  ***internal server 2***
  ![5-nth-host-2](https://github.com/iukadike/blog/assets/58455326/38a21308-4cce-44d9-bdc2-fba0859f2fa1)

  ***internal server 3***
  ![5-nth-host-3](https://github.com/iukadike/blog/assets/58455326/cb7b9ef5-6aa6-4af5-a8ee-1f8e79e8a30c)

  from the above screenshots, we can see that the load is distributed amongst the three servers.

#### Load balancing using statistics and random modules
- first we fire up a UDP server on all three internal hosts:
  - `netcat -nlukvp 8080`

- second we need to set up rules on the `PREROUTING` chain of the `nat` table:
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode random --probability 0.33 -j DNAT --to-destination 192.168.60.5:8080`
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode random --probability 0.492537313 -j DNAT --to-destination 192.168.60.6:8080`
  - `iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode random --probability 1.0 -j DNAT --to-destination 192.168.60.7:8080`
 
    we know that the rules are evaluated from top to bottom. We have three servers we want to distribute the load to. To get the average percentage, we perform ${100 \over 3} = 33.33333$. This means we want an approximate load of $33$% to go to each server. To determine the numbers that we will put for each probability, we go about it the following way:
 
    - at the beginning, we have a $100$% load. If we send $33$% to server one,

      ${33 \over 100} = 0.33$
 
    - after deducting $33$% load, we now have $100% - 33% = 67$% load. if we send another $33$% to server two,

      ${33 \over 67} = 0.492537313$
 
    - after deducting $33$% load, we now have $67% - 33% = 34$% load. Here, we decide to send the reminder of the load to server three.

      ${34 \over 34} = 1.0$
 

- third, we initiate a connection with the external host and test our connection.

  ***external host***
  ![5-rnd-ext-host](https://github.com/iukadike/blog/assets/58455326/78cbef5c-f5fc-42ee-9925-0a408f71adea)

  ***internal server 1***
  ![5-rnd-host-1](https://github.com/iukadike/blog/assets/58455326/d7bc4508-95f6-4ecf-ac5e-f8c5fcaca824)

  ***internal server 2***
  ![5-rnd-host-2](https://github.com/iukadike/blog/assets/58455326/b4da63fc-8456-4880-a2fd-d40a69e29537)

  ***internal server 3***
  ![5-rnd-host-3](https://github.com/iukadike/blog/assets/58455326/0f25773f-933b-4dbe-acff-2108c96f0099)

  From the above screenshots, we can see that the load is distributed amongst the three servers, and it is done randomly because there is no defined sequence.

<br>

<details>
<summary>Additional Notes</summary>
<br>
When doing configurations remotely, it is important to set the CHAIN policy last because if you set it to DENY without actually setting a rule that permits your remote connection, you will effectively lock yourself out.
</details>


<br>

Thanks for reading...
