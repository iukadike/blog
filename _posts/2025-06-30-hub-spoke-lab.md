---
layout: post
title: Creating a Hub Network and Two Spoke VMs
categories: [azure, cloud, hub, spoke]
---

As I continue learning about cloud architecture and security, I’ve been exploring common design patterns in Azure, one of which is the hub-and-spoke network topology. This topology connects multiple VNets (spokes) to a central VNet (hub). The hub often hosts shared services, and spokes can communicate with each other through the hub, making it easier to manage security and connectivity. This model is widely used in enterprise environments to centralize services, like firewalls or DNS, in a hub network while keeping workloads isolated in separate spoke networks.

While working on my most recent cloud lab, I practiced Infrastructure as Code (IaC) using Terraform. To take it a step further, I decided to practice modularization while building this lab.

In this post, I'll walk through the steps I took to create a hub network and connect two spoke VNets, each with its virtual machine. This project helped me understand how Azure VNet peering works, how to control traffic between VNets, and how to structure networks for scalability and security. At the end of the post, I'll highlight a few key takeaways and share some lessons learned along the way.

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
- Deploy Azure Firewall in the hub subnet
- Peer spoke with VNets with hub VNet (VNet peering)
- Create routing tables to route spoke traffic through the Firewall
- Configure NSGs on spoke subnets
- Deploy VMs in spoke VNets to simulate app & DB tiers


This lab project uses a centralized service, the Azure Firewall, to enforce a uniform security policy and reduce duplicated effort. All traffic from either spoke network is routed through the firewall in the hub network. To achieve this, I used custom route tables to force all egress traffic through the Azure Firewall. This design helps organizations implement inspection, logging, and access control at a single point.


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

Below, I will explain the modular design I opted for, which is a best practice for managing large or reusable infrastructure code.

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


#### modules/network/

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


#### modules/compute/

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


#### modules/security/

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


#### modules/peering/

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


#### modules/route/

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


### Deploying and Verifying the Deployed Resources
After the terraform commands completed successfully, I verified that the expected resources were created in the cloud console.

- Cloud console
<img width="1013" height="578" alt="hub-spoke-console" src="https://github.com/user-attachments/assets/c0d58051-5fcd-49a2-8c12-0a59e4cc5880" /><br>

- Hub Vnet (Firewall)
<img width="1254" height="491" alt="vnet-hub-1" src="https://github.com/user-attachments/assets/fa49ac5c-9732-461c-b19b-6137657593f8" /><br>
<img width="1280" height="304" alt="vnet-hub-2" src="https://github.com/user-attachments/assets/1381a992-9fd1-48c9-b673-61c35ea4d44f" /><br>

- Spoke Vnet (App)
<img width="1280" height="280" alt="vnet-spoke-app" src="https://github.com/user-attachments/assets/52cc9a53-9494-4c92-a607-a090f1df5fc8" /><br>

- Spoke Vnet (Database)
<img width="1264" height="306" alt="vnet-spoke-db" src="https://github.com/user-attachments/assets/86f52532-099c-4023-92e5-3e3db53402b5" /><br>

- Route table for Vnet App (spoke 1)
<img width="1201" height="503" alt="route-table-app" src="https://github.com/user-attachments/assets/cc44e32f-918c-4059-a3d1-60385de97b44" /><br>

- Route table for Vnet Db (spoke 2)
<img width="1141" height="473" alt="route-table-db" src="https://github.com/user-attachments/assets/59d6c102-bb26-4492-b689-c003d9f50bd6" /><br>

- Azure Firewall (Hub)
<img width="1280" height="434" alt="AzureFirewall" src="https://github.com/user-attachments/assets/883158ce-b94e-4208-8a6c-61413e51573d" /><br>


### Testing the Network Connections

With the resources successfully created, it was time to test the connection. That's when I realized I hadn't planned ahead for the remaining exercises. I would need to connect to the VMs, but at the moment, I had no way of doing so. I could have edited the Terraform configuration to incorporate a connection method and rerun it to modify the resources. However, I chose to proceed with the cloud console since it was a test lab that would be destroyed relatively soon after creation. In a professional setting, the best practice is always to edit the Terraform code and rerun it to modify or update resources, rather than making manual changes. Therefore, from this point, the remaining changes to my lab project were made via the cloud console.

#### Accessing the VMs

To connect to the VMs, I initially explored using an Azure Bastion host. However, I ultimately chose not to use it and instead configured the firewall to act as a jump host. I did this by using the DNAT functionality of the firewall, configuring it to forward traffic from port 2222 and port 2223, respectively, on the firewall to port 22 on the VMs. It's important to note that using a jump host is generally not the recommended best practice for secure VM access, especially in a production environment, when dedicated services like Azure Bastion are available.

<img width="1249" height="284" alt="firewall-rule-1" src="https://github.com/user-attachments/assets/62f8f9c1-d9b6-4ab3-a9e9-9cd2f950156a" /><br>
<img width="1259" height="227" alt="firewall-rule-2" src="https://github.com/user-attachments/assets/7e2a17bd-b340-4d4f-9bd8-9a25c71b640c" /><br>

#### Pinging Either Spoke VM from the other

After gaining access to the VMs, I sent a ping to one of the spoke VMs from the other, but the attempt failed. I then realized that I also needed to create a rule on the firewall to allow traffic to flow from one spoke network to the other.

<img width="1280" height="291" alt="firewall-rule-4" src="https://github.com/user-attachments/assets/c327e97c-4b4a-44b9-9f2f-23e7b4922ba2" /><br>
<img width="1250" height="259" alt="firewall-rule-3" src="https://github.com/user-attachments/assets/e8d26c2e-d95c-4ae4-8d96-e7c4795eb475" /><br>

However, even with the firewall rule created, I still couldn't ping one of the spoke VMs from the other. After some investigation, I discovered I needed to enable `allow_forwarded_traffic` on the virtual network peering. This setting essentially allows traffic from a peered network to be routed to a gateway or network virtual appliance (NVA), like the firewall, in the local virtual network.

This issue can be fixed by including the following line in the Terraform code for peering:
```hcl
allow_forwarded_traffic   = true
```

The allow_forwarded_traffic setting allows the spoke networks to forward traffic destined for other spoke networks to the hub's firewall. Without this setting, the traffic would be dropped at the peering connection because it would be seen as an attempt to access a non-local resource. Furthermore, even if the traffic successfully reaches the firewall, it will be blocked by default unless you explicitly create a network rule within the firewall policy to permit the specific source, destination, and ports required for spoke-to-spoke communication.

<img width="406" height="399" alt="pairing-configuration" src="https://github.com/user-attachments/assets/1c52e10a-a6f2-4619-b324-162dc85c096a" /><br>

After enabling forwarded traffic and with the firewall rule in place, the Spoke-Spoke ping works as expected.

<img width="679" height="244" alt="connection-status-1" src="https://github.com/user-attachments/assets/ca90d8fe-0c24-4bfe-a411-43841791ca34" /><br>

#### Testing Access to the Public Internet

With the spoke-to-spoke connection working, the next step was to test if the VMs could reach the public internet. While they didn't require internet access for this lab, I wanted to understand how to enable it for a potential future use case.

As expected, the connection to the public internet failed with error code 470, indicating that the Azure Firewall was blocking the traffic.

<img width="384" height="139" alt="connection-status-2" src="https://github.com/user-attachments/assets/c324db78-f464-4872-91cc-bfb51b7ab82b" /><br>

To enable internet access from the `vm-app`, I needed to create a new rule on the firewall to allow traffic from the `vm-app` to specified destinations. While I could have modified the initial rule for spoke-to-spoke communication, creating a separate rule offers better manageability and visibility. For example, if I wanted to revoke internet access for the spoke networks later, I could simply delete that specific rule while retaining the spoke-to-spoke connectivity.

<img width="1280" height="268" alt="firewall-rule-5" src="https://github.com/user-attachments/assets/334ab16c-db62-4469-a83a-528c40af857a" /><br>
<img width="1280" height="268" alt="firewall-rule-6" src="https://github.com/user-attachments/assets/d4270203-144b-482d-8119-bf3a81aa3a4c" /><br>

After creating this new firewall rule, the spoke-to-internet connection worked as expected.

<img width="957" height="229" alt="connection-status-3" src="https://github.com/user-attachments/assets/0da22e18-94bc-4e48-a1bd-b936dcc49f13" /><br>


### Takeaways and Lessons Learned

- Instead of generating the SSH key pair on my local machine, I used Terraform to generate it using the tls_private_key data resource. This approach helped me understand how Terraform outputs work. The key pair is generated at runtime, and you can retrieve both the public and private keys using `terraform output <output_name>`. For example, I used `terraform output ssh_private_key` to get the private key.
  - To prevent accidental exposure, make sure `sensitive = true` is set in your outputs.tf configuration.
  - Never expose private keys in plaintext in shared environments or CI/CD pipelines

- I learned that Azure VNet peering is not implicitly bidirectional. To allow traffic to flow both ways, you must configure the peering from both VNets.

- I created a Network Security Group (NSG) and attached it to the spoke subnets, but I didn’t define any rules. As a result, all traffic was blocked, leading me to discover that an NSG attached to a subnet will block all traffic by default if no rules are defined. This is because NSGs operate on an "implicit deny" principle. If you don't explicitly create rules to allow inbound or outbound traffic, everything is blocked.

- To ensure all traffic from my VMs was inspected, I specified the Azure Firewall as the next hop in the custom route tables (UDRs). This forces all egress traffic to pass through the firewall, enabling centralized inspection and logging. It's important to remember that these route tables are attached to the subnet, not the individual VMs.

- I initially forgot to enable forwarded traffic on the VNet peering connections, which caused communication between spokes via the hub to fail, even though I had configured firewall rules to allow it, leading to another key discovery - the need to enable "allow forwarded traffic" on the peered connection to allow spokes to communicate with each other via the hub. Without this setting, the connection fails, even with a firewall rule in place.

- I initially thought I had to run `terraform init` every time I made a code change, but this is a common beginner misconception. For most changes to variables or resource properties, `terraform plan` and `terraform apply` are sufficient. I only needed to run terraform init when:
  - Setting up a working directory for the first time
  - Adding or changing providers or modules
  - After deleting the `.terraform/` directory

- Modularizing the Terraform code made maintenance easier, even though it was a bit complex at first. Once I exposed the necessary variables in one module, I could reuse them in another. Some of the payoffs include:
  - Cleaner, reusable code
  - Better separation of concerns
  - Easier updates through exposed variables or outputs

- Perhaps the most surprising lesson was the cost of running an Azure Firewall. It accounted for over 96% of the total cost of my lab, even with no active traffic. Azure Firewall is a PaaS (Platform as a Service), with a significant base hourly cost that is charged regardless of usage. Unlike a VM, you can't just "stop" it; you have to delete it to stop incurring costs. For learning and testing environments, a cheaper alternative like a Linux VM with IP forwarding enabled would be more cost-effective. If you do use the Azure Firewall for a lab, it is best to destroy it immediately after use, or automate its teardown with `terraform destroy`.

<img width="1180" height="561" alt="cost-analysis-1" src="https://github.com/user-attachments/assets/927460f2-d582-4442-a3ad-ff59066a0e27" /><br>


<br>

Thanks for reading...
