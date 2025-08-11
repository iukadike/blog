---
layout: post
title: Creating a Hub Network and Two Spoke VMs
categories: [azure, cloud, hub, spoke]
---

As I continue learning cloud architecture and security, I’ve been exploring common design patterns in Azure, one of which is the hub-and-spoke network topology. A hub-and-spoke topology in Azure connects multiple VNets (spokes) to a central VNet (hub). The hub often hosts shared services, and spokes can communicate with each other through the hub, making it easier to manage security and connectivity. 

This model is widely used in enterprise environments to centralize services (like firewalls or DNS) in a hub network, while keeping workloads isolated in separate spoke networks.

While working on my most recent cloud lab, I made use of Infrastructure as Code (IaC) practice using Terraform. To take it a notch higher, I decided to practice modularization while working on this lab.

In this post, I’ll walk through the steps I took to create a hub network and connect two spoke VNets, each with its virtual machine.

The project helped me understand how Azure VNet peering works, how to control traffic between VNets, and how to structure networks for scalability and security. At the end of the post, I highlight a few key takeaways and share some lessons learned along the way.

My objective for undergoing this mini-project was to:
- Create a hub network
- Create two spoke networks
- Pair the spoke networks to the hub network
- Deploy a VM in each spoke network
- Verify that the deployed VMs can only communicate via the hub network

To accomplish the objective, I broke it down to the following actionable steps:
- Create Resource Group rg-hubspoke
- Hub VNet vnet-hub with subnet for Firewall and VPN Gateway
- Spoke VNets: vnet-spoke-app and vnet-spoke-db with separate subnets
- Deploy Azure Firewall in hub subnet
- Peer spoke VNets with hub VNet (VNet peering)
- Create routing tables to route spoke traffic through the Firewall
- Configure NSGs on spoke subnets
- Deploy VMs in spoke VNets to simulate app & DB tiers


This lab project would have a centralized service like a firewall to enforce a uniform security policy and reduce duplication of effort. All traffic from either spoke network would be routed through the firewall (hub network). To achieve this, I made use of custom route tables to force all egress through the Azure Firewall. This helps organizations implement inspection, logging, and access control at a single point.


### Modular Design

```bash
.
├── main.tf
├── modules
│   ├── compute
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── network
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── peering
│   │   ├── main.tf
│   │   └── variables.tf
│   ├── route
│   │   ├── main.tf
│   │   └── variables.tf
│   └── security
│       ├── main.tf
│       ├── outputs.tf
│       └── variables.tf
├── outputs.tf
├── providers.tf
└── variables.tf

7 directories, 17 files
```

Below, I attempt to explain the modular design I opted for, which is a best practice for managing large or reusable infrastructure code.

#### Root Directory Files (Top-Level)
```bash
.
├── main.tf
├── providers.tf
├── variables.tf
├── outputs.tf
```

The files at the root level form the root module and call the individual modules under the `modules/` directory. Whereas the `modules/` directory is where the modularization happens. Each subfolder under `modules/` represents a self-contained unit of functionality, which can be reused in other environments or projects.

- __main.tf__: This is where I reference my modules and pass in input variables.

```hcl
# Resource Group
resource "azurerm_resource_group" "lab2_rg" {
  name     = "rg-lab2-hub-spoke"
  location = var.location
}

# Network Setup
module "network" {
  source              = "./modules/network"
  resource_group_name = azurerm_resource_group.lab2_rg.name
  location            = var.location
}

# Compute Setup (VMs)
module "compute" {
  source              = "./modules/compute"
  resource_group_name = azurerm_resource_group.lab2_rg.name
  location            = var.location
  app_nic_id          = module.network.app_nic_id
  db_nic_id           = module.network.db_nic_id
}

# Security (Firewall and NSG)
module "security" {
  source                = "./modules/security"
  location              = var.location
  resource_group_name   = azurerm_resource_group.lab2_rg.name
  hub_firewal_subnet_id = module.network.hub_firewal_subnet_id
  spoke_app_subnet_id   = module.network.spoke_app_subnet_id
  spoke_db_subnet_id    = module.network.spoke_db_subnet_id
  hub_firewal_pip_id    = module.network.hub_firewal_pip_id
}

# Routing
module "route" {
  source              = "./modules/route"
  resource_group_name = azurerm_resource_group.lab2_rg.name
  location            = var.location
  spoke_app_subnet_id = module.network.spoke_app_subnet_id
  spoke_db_subnet_id  = module.network.spoke_db_subnet_id
  firewall_private_ip = module.security.firewall_private_ip
}

# VNET Peering
module "peering" {
  source              = "./modules/peering"
  resource_group_name = azurerm_resource_group.lab2_rg.name
  location            = var.location
  hub_vnet_name       = module.network.hub_vnet_name
  spoke_app_vnet_name = module.network.spoke_app_vnet_name
  spoke_db_vnet_name  = module.network.spoke_db_vnet_name
  hub_vnet_id         = module.network.hub_vnet_id
  spoke_app_vnet_id   = module.network.spoke_app_vnet_id
  spoke_db_vnet_id    = module.network.spoke_db_vnet_id
}
```

- __providers.tf__: This is where I define the required provider.

```hcl
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>4.0"
    }
  }
}

# Get subscription_id using `az account list`
provider "azurerm" {
  subscription_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  features {}
}
```

- __variables.tf__: This is where I declare input variables required by the root module.

```hcl
variable "location" {
  type        = string
  default     = "eastus"
  description = "Location of the resource group."
}
```

- __outputs.tf__: This file is used to expose outputs from the root module by pulling outputs from submodules.

```hcl
output "hub_firewal_pip_addr" {
  value = module.network.hub_firewal_pip_addr
}

output "ssh_private_key" {
  value     = module.compute.ssh_private_key
  sensitive = true
}
```


### modules/network/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

I aimed to put the infrastructure for virtual networks and subnets in this module

- __main.tf__: This contained the VNet and subnet definitions.

```hcl
# HUB Vnet
resource "azurerm_virtual_network" "hub" {
  name                = "vnet-hub"
  address_space       = ["10.0.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "hub_firewall" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "hub_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.2.0/24"]
}

# SPOKE VNets
resource "azurerm_virtual_network" "spoke_app" {
  name                = "vnet-spoke-app"
  address_space       = ["10.1.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.spoke_app.name
  address_prefixes     = ["10.1.1.0/24"]
}

resource "azurerm_virtual_network" "spoke_db" {
  name                = "vnet-spoke-db"
  address_space       = ["10.2.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.spoke_db.name
  address_prefixes     = ["10.2.1.0/24"]
}

# Public IP for firewall
resource "azurerm_public_ip" "hub_fw_pip" {
  name                = "fw-hub-pip"
  resource_group_name = var.resource_group_name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Spoke app nic
resource "azurerm_network_interface" "nic_app" {
  name                = "nic-app"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "ipconfig_app"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Spoke db nic
resource "azurerm_network_interface" "nic_db" {
  name                = "nic-db"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "ipconfig_db"
    subnet_id                     = azurerm_subnet.db.id
    private_ip_address_allocation = "Dynamic"
  }
}
```

- __variables.tf__: This contained inputs that the configurations in main.tf would reference.

```hcl
variable "resource_group_name" {}
variable "location" {}
```

- __outputs.tf__: This contained outputs which other modules can consume or use in their configuration.

```hcl
output "hub_vnet_id" {
  value = azurerm_virtual_network.hub.id
}

output "spoke_app_vnet_id" {
  value = azurerm_virtual_network.spoke_app.id
}

output "spoke_db_vnet_id" {
  value = azurerm_virtual_network.spoke_db.id
}

output "hub_vnet_name" {
  value = azurerm_virtual_network.hub.name
}

output "spoke_app_vnet_name" {
  value = azurerm_virtual_network.spoke_app.name
}

output "spoke_db_vnet_name" {
  value = azurerm_virtual_network.spoke_db.name
}

output "app_nic_id" {
  value = azurerm_network_interface.nic_app.id
}

output "db_nic_id" {
  value = azurerm_network_interface.nic_db.id
}

output "spoke_app_subnet_id" {
  value = azurerm_subnet.app.id
}

output "spoke_db_subnet_id" {
  value = azurerm_subnet.db.id
}

output "hub_firewal_subnet_id" {
  value = azurerm_subnet.hub_firewall.id
}

output "hub_firewal_pip_id" {
  value = azurerm_public_ip.hub_fw_pip.id
}

output "hub_firewal_pip_addr" {
  value = azurerm_public_ip.hub_fw_pip.ip_address
}
```


### modules/compute/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

I aimed to put the infrastructure for compute, such as VMs, scale sets, or app service deployments, in this module

- __main.tf__: This contained the resource definitions for compute resources.

```hcl
# SSH Key (auto-generated)
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_linux_virtual_machine" "vm_app" {
  name                = "vm-app"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B1s"
  network_interface_ids = [
    var.app_nic_id
  ]
  admin_username      = "azureuser"
  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.ssh.public_key_openssh
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts"
    version   = "latest"
  }
}

resource "azurerm_linux_virtual_machine" "vm_db" {
  name                = "vm-db"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B1s"
  network_interface_ids = [
    var.db_nic_id
  ]
  admin_username      = "azureuser"
  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.ssh.public_key_openssh
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts"
    version   = "latest"
  }
}
```

- __variables.tf__: This contained inputs that the configurations in main.tf would reference.Inputs like VM size, image, and SSH keys.

```hcl
variable "resource_group_name" {}
variable "location" {}
variable "db_nic_id" {}
variable "app_nic_id" {}
```

- __outputs.tf__: This contained outputs that other modules can consume or use in their configuration.

```hcl
output "ssh_private_key" {
  value     = tls_private_key.ssh.private_key_pem
  sensitive = true
}
```


### modules/security/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

I aimed to put the infrastructure that deals with Network Security Groups (NSGs) and firewall rules in this module.

- __main.tf__: This contained NSG definitions and rules.

```hcl
# Firewall for the hub
resource "azurerm_firewall" "hub_firewall" {
  name                = "fw-hub"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"

  ip_configuration {
    name                 = "fw-config"
    subnet_id            = var.hub_firewal_subnet_id
    public_ip_address_id = var.hub_firewal_pip_id
  }
}

# NSGs
resource "azurerm_network_security_group" "nsg_app" {
  name                = "nsg-app"
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_network_security_group" "nsg_db" {
  name                = "nsg-db"
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = var.spoke_app_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_app.id
}

resource "azurerm_subnet_network_security_group_association" "db" {
  subnet_id                 = var.spoke_db_subnet_id
  network_security_group_id = azurerm_network_security_group.nsg_db.id
}
```

- __variables.tf__: This contained inputs that the configurations in main.tf would reference.

```hcl
variable "resource_group_name" {}
variable "location" {}
variable "hub_firewal_subnet_id" {}
variable "spoke_app_subnet_id" {}
variable "spoke_db_subnet_id" {}
variable "hub_firewal_pip_id" {}
```

- __outputs.tf__: This contained outputs that other modules can consume or use in their configuration.

```hcl
# Output the Private IP of the Firewall
output "firewall_private_ip" {
  value = azurerm_firewall.hub_firewall.ip_configuration[0].private_ip_address
}
```


### modules/peering/

```bash
.
├── main.tf
└── variables.tf

1 directory, 2 files
```

I aimed to put the infrastructure that deals with setting up VNet peering between the hub network and spoke networks in this module.

- __main.tf__: This contained the resource definitions for peering the NVets.

```hcl
# VNET Peering
resource "azurerm_virtual_network_peering" "spoke_app_to_hub" {
  name                      = "spoke-app-to-hub"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.spoke_app_vnet_name  #azurerm_virtual_network.spoke_app.name
  remote_virtual_network_id = var.hub_vnet_id  #azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
}

resource "azurerm_virtual_network_peering" "hub_to_spoke_app" {
  name                      = "hub-to-spoke-app"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.hub_vnet_name  #azurerm_virtual_network.hub.name
  remote_virtual_network_id = var.spoke_app_vnet_id  #azurerm_virtual_network.spoke_app.id
  allow_virtual_network_access = true
}

resource "azurerm_virtual_network_peering" "spoke_db_to_hub" {
  name                      = "spoke-db-to-hub"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.spoke_db_vnet_name  #azurerm_virtual_network.spoke_db.name
  remote_virtual_network_id = var.hub_vnet_id  #azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
}

resource "azurerm_virtual_network_peering" "hub_to_spoke_db" {
  name                      = "hub-to-spoke-db"
  resource_group_name       = var.resource_group_name
  virtual_network_name      = var.hub_vnet_name  #azurerm_virtual_network.hub.name
  remote_virtual_network_id = var.spoke_db_vnet_id  #azurerm_virtual_network.spoke_db.id
  allow_virtual_network_access = true
}
```

- __variables.tf__: This contained inputs that the configurations in main.tf would reference.

```hcl
variable "resource_group_name" {}
variable "location" {}
variable "hub_vnet_name" {}
variable "spoke_app_vnet_name" {}
variable "spoke_db_vnet_name" {}
variable "hub_vnet_id" {}
variable "spoke_app_vnet_id" {}
variable "spoke_db_vnet_id" {}
```


### modules/route/

```bash
.
├── main.tf
└── variables.tf

1 directory, 2 files
```

I aimed to put the infrastructure that deals with defining custom route tables and route associations in this module.

- __main.tf__: This contained the resource definitions for creating route tables and defining routes.

```hcl
# ROUTE TABLE FOR APP
resource "azurerm_route_table" "rt_app" {
  name                = "rt-spoke-app"
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_route" "route_app" {
  name                    = "route-to-internet-app"
  resource_group_name     = var.resource_group_name
  route_table_name        = azurerm_route_table.rt_app.name
  address_prefix          = "0.0.0.0/0"
  next_hop_type           = "VirtualAppliance"
  next_hop_in_ip_address  = var.firewall_private_ip
}

resource "azurerm_subnet_route_table_association" "app" {
  subnet_id      = var.spoke_app_subnet_id
  route_table_id = azurerm_route_table.rt_app.id
}

# ROUTE TABLE FOR DB
resource "azurerm_route_table" "rt_db" {
  name                = "rt-spoke-db"
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_route" "route_db" {
  name                    = "route-to-internet-db"
  resource_group_name     = var.resource_group_name
  route_table_name        = azurerm_route_table.rt_db.name
  address_prefix          = "0.0.0.0/0"
  next_hop_type           = "VirtualAppliance"
  next_hop_in_ip_address  = var.firewall_private_ip
}

resource "azurerm_subnet_route_table_association" "db" {
  subnet_id      = var.spoke_db_subnet_id
  route_table_id = azurerm_route_table.rt_db.id
}
```

- __variables.tf__: This contained inputs that the configurations in main.tf would reference.

```hcl
variable "resource_group_name" {}
variable "location" {}
variable "spoke_app_subnet_id" {}
variable "spoke_db_subnet_id" {}
variable "firewall_private_ip" {}
```


### Deploying the Resources
After the terraform commands completed successfully, I verified that the expected resources were created in the cloud console.

<img width="1013" height="578" alt="hub-spoke-console" src="https://github.com/user-attachments/assets/c0d58051-5fcd-49a2-8c12-0a59e4cc5880" /><br>







