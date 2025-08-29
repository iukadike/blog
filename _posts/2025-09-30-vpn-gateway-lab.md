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
├── main.tf
├── modules
│   ├── compute
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── gateways
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── hub
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── monitoring
│   │   ├── main.tf
│   │   └── variables.tf
│   ├── onprem
│   │   ├── main.tf
│   │   ├── outputs.tf
│   │   └── variables.tf
│   ├── security
│   │   ├── main.tf
│   │   └── variables.tf
│   └── vpn
│       ├── main.tf
│       └── variables.tf
├── outputs.tf
├── providers.tf
└── variables.tf

9 directories, 22 files
```

Below, I will explain the modular design I opted for, which is a best practice for managing large or reusable infrastructure code.

#### Top-Level Directory (Root Module)
```bash
.
├── main.tf
├── outputs.tf
├── providers.tf
└── variables.tf
```

The files at the root level form the root module and call the individual modules under the `modules/` directory. Whereas the `modules/` directory is where the modularization happens. Each subfolder under `modules/` represents a self-contained unit of functionality, which can be reused in other environments or projects.

- __main.tf__: This is where I instantiate my modules and pass in input variables.

```hcl
# Resource Group
resource "azurerm_resource_group" "site_site_vpn_lab" {
  name     = var.rg_name
  location = var.location
}

# Hub Network
module "hub" {
  source                    = "./modules/hub"
  rg_name                   = var.rg_name
  location                  = var.location
  hub_vnet_address          = var.hub_vnet_address
  hub_gateway_subnet_prefix = var.hub_gateway_subnet_prefix

  depends_on = [azurerm_resource_group.site_site_vpn_lab]
}

# Onprem Network
module "onprem" {
  source                       = "./modules/onprem"
  rg_name                      = var.rg_name
  location                     = var.location
  onprem_vnet_address          = var.onprem_vnet_address
  onprem_gateway_subnet_prefix = var.onprem_gateway_subnet_prefix

  depends_on = [azurerm_resource_group.site_site_vpn_lab]
}

# Gateways
module "gateways" {
  source              = "./modules/gateways"
  rg_name             = var.rg_name
  location            = var.location
  hub_vnet_address    = var.hub_vnet_address
  onprem_vnet_address = var.onprem_vnet_address
  hub_pip             = module.hub.hub_pip
  hubgw_subnet_id     = module.hub.hubgw_subnet_id
  onprem_pip          = module.onprem.onprem_pip
  onpremgw_subnet_id  = module.onprem.onpremgw_subnet_id

  depends_on = [azurerm_resource_group.site_site_vpn_lab, module.hub, module.onprem]
}

# VPN Connection
module "vpn" {
  source            = "./modules/vpn"
  rg_name           = var.rg_name
  location          = var.location
  hub_vnet_gw_id    = module.gateways.hub_vnet_gw_id
  hub_lnet_gw_id    = module.gateways.hub_lnet_gw_id
  onprem_vnet_gw_id = module.gateways.onprem_vnet_gw_id
  onprem_lnet_gw_id = module.gateways.onprem_lnet_gw_id
  shared_key        = var.shared_key

  depends_on = [azurerm_resource_group.site_site_vpn_lab, module.gateways]
}

# Compute
module "compute" {
  source           = "./modules/compute"
  rg_name          = var.rg_name
  location         = var.location
  hub_subnet_id    = module.hub.hub_subnet_id
  onprem_subnet_id = module.onprem.onprem_subnet_id

  depends_on = [azurerm_resource_group.site_site_vpn_lab, module.onprem, module.hub]
}

# Security
module "security" {
  source           = "./modules/security"
  rg_name          = var.rg_name
  location         = var.location
  hub_subnet_id    = module.hub.hub_subnet_id
  onprem_subnet_id = module.onprem.onprem_subnet_id

  depends_on = [azurerm_resource_group.site_site_vpn_lab, module.onprem, module.hub]
}

# Monitoring
module "monitoring" {
  source         = "./modules/monitoring"
  rg_name        = var.rg_name
  location       = var.location
  hub_vnet_gw_id = module.gateways.hub_vnet_gw_id

  depends_on = [azurerm_resource_group.site_site_vpn_lab, module.gateways]
}
```

- __outputs.tf__: This file is used to expose outputs from the root module by pulling outputs from submodules.

```hcl
output "hub_pip" {
  value = module.hub.hub_pip.ip_address
}

output "onprem_pip" {
  value = module.onprem.onprem_pip.ip_address
}

output "hub_vm_private_ip" {
  value = module.compute.hub_vm_private_ip
}

output "onprem_vm_private_ip" {
  value = module.compute.onprem_vm_private_ip
}
```

- __providers.tf__: This is where I define the required provider.

```hcl
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=4.0"
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
variable "rg_name" {
  default     = "rg-lab-site-site-vpn"
  description = "Name of the resource group"
}

variable "location" {
  type        = string
  default     = "eastus"
  description = "Location of the resources"
}

variable "shared_key" {
  default     = "X0XX9XX868xxxxx2xxXxxxxXxXXx2x0XXxXxxXxXXXx="
  description = "Shared key used for the site-stie vpn connection"
}

variable "hub_vnet_address" {
  default     = "10.0.0.0/16"
  description = "Vnet for the azure side"
}

variable "onprem_vnet_address" {
  default     = "10.1.0.0/16"
  description = "Vnet for the simulated on-prem side"
}

variable "hub_gateway_subnet_prefix" {
  default = "10.0.255.0/27"
}

variable "onprem_gateway_subnet_prefix" {
  default = "10.1.255.0/27"
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

This module was used to manage the infrastructure for compute resources, such as Virtual Machines (VMs), VM Scale Sets, or App Services

- __main.tf__:

```hcl
# Hub VM
resource "azurerm_network_interface" "hub_vm_nic" {
  name                = "hubVmNic"
  location            = var.location
  resource_group_name = var.rg_name
  ip_configuration {
    name                          = "hubVmIpConfig"
    subnet_id                     = var.hub_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "hub_vm" {
  name                = "hubVm"
  location            = var.location
  resource_group_name = var.rg_name
  network_interface_ids = [azurerm_network_interface.hub_vm_nic.id]
  size               = var.vm_size
  disable_password_authentication = false
  admin_username     = var.admin_username
  admin_password     = var.admin_password
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

resource "azurerm_network_interface" "onprem_vm_nic" {
  name                = "onpremVmNic"
  location            = var.location
  resource_group_name = var.rg_name
  ip_configuration {
    name                          = "onpremVmIpConfig"
    subnet_id                     = var.onprem_subnet_id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "onprem_vm" {
  name                = "onpremVm"
  location            = var.location
  resource_group_name = var.rg_name
  network_interface_ids = [azurerm_network_interface.onprem_vm_nic.id]
  size               = var.vm_size
  disable_password_authentication = false
  admin_username     = var.admin_username
  admin_password     = var.admin_password
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

- __outputs.tf__:

```hcl
output "hub_vm_private_ip" {
  value = azurerm_network_interface.hub_vm_nic.private_ip_address
}

output "onprem_vm_private_ip" {
  value = azurerm_network_interface.onprem_vm_nic.private_ip_address
}
```

- __variables.tf__:

```hcl
variable "vm_size" {
  default = "Standard_B1s"
}

variable "admin_username" {
  default = "azureuser"
}

variable "admin_password" {
  default = "Abc1234!"
  sensitive = true
}

variable "location" {}

variable "rg_name" {}

variable "hub_subnet_id" {}

variable "onprem_subnet_id" {}
```


~~dsdsdsds~~
#### modules/gateways/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

This module was used to manage the infrastructure for the network gateway resources, such as Application Gateways, NAT Gateways, ExpressRoute Gateways, or in this scenario, VPN Gateways

- __main.tf__:

```hcl
# VPN Gateways
resource "azurerm_virtual_network_gateway" "hub" {
  name                = "HubVpnGateway"
  location            = var.location
  resource_group_name = var.rg_name 
  type                = "Vpn"
  vpn_type            = "RouteBased"
  active_active       = false
  enable_bgp          = false
  sku                 = "VpnGw1"
  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id         = var.hub_pip.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                    = var.hubgw_subnet_id
  }
}

resource "azurerm_virtual_network_gateway" "onprem" {
  name                = "OnPremVpnGateway"
  location            = var.location
  resource_group_name = var.rg_name
  type                = "Vpn"
  vpn_type            = "RouteBased"
  active_active       = false
  enable_bgp          = false
  sku                 = "VpnGw1"
  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id         = var.onprem_pip.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                    = var.onpremgw_subnet_id
  }
}

# Local Network Gateways
resource "azurerm_local_network_gateway" "hub_to_onprem" {
  name                = "OnPremLocalGW"
  resource_group_name = var.rg_name
  location            = var.location
  gateway_address     = var.onprem_pip.ip_address
  address_space       = [var.onprem_vnet_address]
}

resource "azurerm_local_network_gateway" "onprem_to_hub" {
  name                = "HubLocalGW"
  resource_group_name = var.rg_name
  location            = var.location
  gateway_address     = var.hub_pip.ip_address
  address_space       = [var.hub_vnet_address]
}
```

- __outputs.tf__:

```hcl
output "hub_vm_private_ip" {
output "hub_vnet_gw_id" {
  value = azurerm_virtual_network_gateway.hub.id
}

output "hub_lnet_gw_id" {
  value = azurerm_local_network_gateway.hub_to_onprem.id
}

output "onprem_vnet_gw_id" {
  value = azurerm_virtual_network_gateway.onprem.id
}

output "onprem_lnet_gw_id" {
  value = azurerm_local_network_gateway.onprem_to_hub.id
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "hub_vnet_address" {}

variable "onprem_vnet_address" {}

variable "rg_name" {}

variable "hub_pip" {}

variable "hubgw_subnet_id" {}

variable "onprem_pip" {}

variable "onpremgw_subnet_id" {}
```

~~de~~
#### modules/hub/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

This module was used to manage the simulated cloud network infrastructure.

- __main.tf__:

```hcl
# Hub VNet
resource "azurerm_virtual_network" "hub" {
  name                = "HubVNet"
  address_space       = [var.hub_vnet_address]
  location            = var.location
  resource_group_name = var.rg_name
}

# Hub Gateway Subnet
resource "azurerm_subnet" "hub_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = var.rg_name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [var.hub_gateway_subnet_prefix]
}

# Hub VM Subnet
resource "azurerm_subnet" "hub_vm" {
  name                 = "vm-hub"
  resource_group_name  = var.rg_name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Public IP
resource "azurerm_public_ip" "hub" {
  name                = "HubVpnGwIP"
  location            = var.location
  resource_group_name = var.rg_name
  allocation_method   = "Static"
  sku                 = "Standard"
}
```

- __outputs.tf__:

```hcl
output "hub_pip" {
  value     = azurerm_public_ip.hub
}

output "hubgw_subnet_id" {
  value = azurerm_subnet.hub_gateway.id
}

output "hub_subnet_id" {
  value = azurerm_subnet.hub_vm.id
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "hub_vnet_address" {}

variable "hub_gateway_subnet_prefix" {}

variable "rg_name" {}
```


~~del~~

#### modules/onprem/

```bash
.
├── main.tf
├── outputs.tf
└── variables.tf

1 directory, 3 files
```

This module was used to manage the simulated on-premise network infrastructure.

- __main.tf__:

```hcl
# On-Prem VNet
resource "azurerm_virtual_network" "onprem" {
  name                = "OnPremVNet"
  address_space       = [var.onprem_vnet_address]
  location            = var.location
  resource_group_name = var.rg_name
}

# Onprem Gateway Subnet
resource "azurerm_subnet" "onprem_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = var.rg_name
  virtual_network_name = azurerm_virtual_network.onprem.name
  address_prefixes     = [var.onprem_gateway_subnet_prefix]
}

# Onprem VM Subnet
resource "azurerm_subnet" "onprem_vm" {
  name                 = "vm-onprem"
  resource_group_name  = var.rg_name
  virtual_network_name = azurerm_virtual_network.onprem.name
  address_prefixes     = ["10.1.1.0/24"]
}

# Public IP
resource "azurerm_public_ip" "onprem" {
  name                = "OnPremVpnGwIP"
  location            = var.location
  resource_group_name = var.rg_name
  allocation_method   = "Static"
  sku                 = "Standard"
}
```

- __outputs.tf__:

```hcl
output "onprem_pip" {
  value     = azurerm_public_ip.onprem
}

output "onpremgw_subnet_id" {
  value = azurerm_subnet.onprem_gateway.id
}

# vm subnet
output "onprem_subnet_id" {
  value = azurerm_subnet.onprem_vm.id
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "onprem_vnet_address" {}

variable "onprem_gateway_subnet_prefix" {}

variable "rg_name" {}
```


~~de~~

#### modules/monitoring/

```bash
.
├── main.tf
└── variables.tf

1 directory, 2 files
```

This module was used to manage the infrastructure used for monitoring, such as log analytics, metrics, alerts, and dashboard resources.

- __main.tf__:

```hcl
# Storage account for diagnostics
resource "azurerm_storage_account" "diag" {
  name                     = "diagstore${random_id.suffix.hex}"
  resource_group_name      = var.rg_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# Enable diagnostics for Hub VPN Gateway
resource "azurerm_monitor_diagnostic_setting" "vpn_gateway_diag" {
  name               = "hubVpnGatewayDiag"
  target_resource_id = var.hub_vnet_gw_id
  storage_account_id = azurerm_storage_account.diag.id

  enabled_log {
    category = "GatewayDiagnosticLog"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "rg_name" {}

variable "hub_vnet_gw_id" {}
```


~~dele~~

#### modules/security/

```bash
.
├── main.tf
└── variables.tf

1 directory, 2 files
```

This module was used to manage the infrastructure for implementing security controls such as NSGs, firewall rules, policies, or IAM roles.

- __main.tf__:

```hcl
resource "azurerm_network_security_group" "hub_nsg" {
  name                = "hub-nsg"
  location            = var.location
  resource_group_name = var.rg_name

  security_rule {
    name                       = "Allow-SSH-ICMP-Inbound"
    description                = "Allow SSH and ICMP inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = ["22"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "onprem_nsg" {
  name                = "onprem-nsg"
  location            = var.location
  resource_group_name = var.rg_name

  security_rule {
    name                       = "Allow-SSH-ICMP-Inbound"
    description                = "Allow SSH and ICMP inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_ranges    = ["22"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Associate NSG with subnet
resource "azurerm_subnet_network_security_group_association" "hub_assoc" {
  subnet_id                 = var.hub_subnet_id
  network_security_group_id = azurerm_network_security_group.hub_nsg.id
}

resource "azurerm_subnet_network_security_group_association" "onprem_assoc" {
  subnet_id                 = var.onprem_subnet_id
  network_security_group_id = azurerm_network_security_group.onprem_nsg.id
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "rg_name" {}

variable "hub_subnet_id" {}

variable "onprem_subnet_id" {}
```


~~dele~~

#### modules/vpn/

```bash
.
├── main.tf
└── variables.tf

1 directory, 2 files
```

This module was used to manage the infrastructure for VPN tunnelling, both site-to-site and point-to-site.

- __main.tf__:

```hcl
# VPN Connections
resource "azurerm_virtual_network_gateway_connection" "hub_to_onprem" {
  name                = "HubToOnPremConnection"
  location            = var.location
  resource_group_name = var.rg_name
  type                = "IPsec"
  virtual_network_gateway_id = var.hub_vnet_gw_id
  local_network_gateway_id   = var.hub_lnet_gw_id
  shared_key                 = var.shared_key
}

resource "azurerm_virtual_network_gateway_connection" "onprem_to_hub" {
  name                = "OnPremToHubConnection"
  location            = var.location
  resource_group_name = var.rg_name
  type                = "IPsec"
  virtual_network_gateway_id = var.onprem_vnet_gw_id
  local_network_gateway_id   = var.onprem_lnet_gw_id
  shared_key                 = var.shared_key
}
```

- __variables.tf__:

```hcl
variable "location" {}

variable "rg_name" {}

variable "shared_key" {}

variable "hub_vnet_gw_id" {}

variable "hub_lnet_gw_id" {}

variable "onprem_vnet_gw_id" {}

variable "onprem_lnet_gw_id" {}
```


### Deploying and Verifying the Deployed Resources
After the Terraform commands completed successfully, I verified that the expected resources were created in the cloud console.
