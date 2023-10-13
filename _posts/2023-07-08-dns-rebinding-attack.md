---
layout: post
title: DNS Rebinding Attack
categories: dns
excerpt: In the world of the web, web browsers define web resources in the form of an origin. An origin refers to the protocol scheme, the domain name, and the port number of a web resource. The idea of defining web resources in terms of an origin is to be able to create a rule called the "same-origin" policy.
---

### Origin
In the world of the web, web browsers define web resources in the form of an origin. An origin refers to the protocol scheme, the domain name, and the port number of a web resource.

For example, below are different origins:
- `http://example.com:80`
- `https://example.com:80`
- `http://www.example.com:80`

The idea of defining web resources in terms of an origin is to be able to create a rule called the "same-origin" policy.

### Same-origin Policy
Origins define the boundaries for the rule that governs web resource sharing, the same-origin policy. This policy ensures that resources from one origin cannot access resources from another origin unless explicitly allowed.

This policy is important for web security as it helps protect users from malicious actions.

When web browsers load a web page, they also load accompanying resources like CSS, JavaScript, XML, etc. Many of these resources are designed to improve the user's experience. A resource like Javascript can execute arbitrary code within the browser to access a resource from another origin. It is important that the javascript code is not able to access such a resource, because if the javascript code can access a resource from another origin, attackers can leverage that to do malicious things.

Take, for example, an attacker who gets a victim to visit `fakewebsite.com`. While on `fakewebsite.com`, the web browser loads a malicious javascript that makes a request to the victim's logged-in Facebook session to steal personal information. However, because `fakewebsite.com` is of a different origin than Facebook, the web browser blocks the request thanks to the same-origin policy.

### DNS Rebinding
When a browser wants to access resources from an origin, it needs to know the IP address because IP addresses are how computers communicate. Thus, a DNS resolution is performed.

By default, web browsers enforce the same-origin policy. However, as we have seen, an origin is "protocol scheme + domain name + port number". It does not take into consideration the IP address binding for the "protocol scheme + domain name + port number". This means that if the IP address mapping for an origin changes, the browser cares less.

This is where DNS rebinding comes in. DNS rebinding is the act of changing the IP address binding for a particular host name.

For example:
- web browser: I want to access `fakewebsite.com`. Give me the IP address.
- dns resolver: OK, web browser, the IP address for `fakewebsite.com` is `1.2.3.4`
- web browser: Thanks.
- web browser: I want to make another request to `fakewebsite.com`. Give me the IP address.
- dns resolver: OK, web browser, the IP address for `fakewebsite.com` is `5.6.7.8`
- web browser: Thanks.

DNS rebinding attacks typically involve the following:
- an attacker sets up a website that contains malicious Javascript.
- the victim visits the website, and the web browser runs the code (the code is usually in a loop).
- the victim's computer performs DNS resolution, and the attacker's name server responds with the IP address of the website but with a relatively short TTL.
- the attacker's server waits until the TTL value of the DNS response expires and then changes the response to an IP address within the victim's local network.
- another request is sent by the victim's browser, and this time, the attacker's server responds with the IP address within the victim's local network.
- the victim's browser assumes that the website visited is trustworthy, processes the request, and establishes a connection to the IP address within the local network.

A [practical example of DNS rebinding technique](https://seedsecuritylabs.org/Labs_20.04/Networking/DNS/DNS_Rebinding/) is shown below.

**malicious website before DNS rebinding**

![rebind-1](https://github.com/iukadike/blog/assets/58455326/1787deb5-8443-457e-bea2-969f7d46c00f)

**malicious website after DNS rebinding**

![rebind-2](https://github.com/iukadike/blog/assets/58455326/16f6e7a5-aa84-405e-83cd-df9e3a8707a9)


<br>

Thanks for reading...
