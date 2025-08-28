---
layout: post
title: Hybrid Connectivity between Azure VNet and a simulated on-prem network
categories: [azure, cloud, vpn gateway, hybrid connectivity]
---

As I continue to build out more realistic cloud architectures, I wanted to explore the secure connection between an on-premises environment and a cloud environment. To achieve this, I explored Azure VPN Gateway. This service enables secure hybrid connectivity by establishing encrypted tunnels over the public internet between an Azure Virtual Network and an on-premises network (or even another cloud provider).

In a typical enterprise setup, VPN Gateway acts as the bridge between on-premises infrastructure and the cloud. In my case, I simulated the on-premises environment by using another virtual network in Azure to represent it. Then, I configured a site-to-site VPN connection between this "on-prem" VNet and my hub VNet in the cloud.

In this post, I'll walk through the steps I took to create the VPN gateway and establish the tunnel. This helped me gain a better understanding of how organizations extend their on-prem infrastructure into Azure in a secure and scalable way. At the end of the post, I'll highlight a few key takeaways and share some lessons learned along the way.

My objective for undergoing this mini-project was to:
- Simulate an on-prem VPN device
- Create a VPN Gateway 
- Configure VPN connection with shared key 
- Test connectivity with VMs on both networks 
- Monitor VPN tunnel health

To accomplish the objective, I broke it down to the following actionable steps:
- Create a vnet simulating the cloud environment (HubVnet)
- Create a vnet simulating the on-premise environment (OnPrem)
- add others...


### Modular Design

```bash
.
├── main.tf
├── modules
│   ├── compute
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── network
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── peering
│   │   ├── main.tf
│   │   └── variables.tf
│   ├── route
│   │   ├── main.tf
│   │   └── variables.tf
│   └── security
│       ├── main.tf
│       ├── outputs.tf
│       └── variables.tf
├── outputs.tf
├── providers.tf
└── variables.tf

7 directories, 17 files
```
