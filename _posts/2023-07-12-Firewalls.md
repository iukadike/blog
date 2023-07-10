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



<br>
#### Additional Notes
