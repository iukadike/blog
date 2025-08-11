---
layout: post
title: Setting Up a Basic Azure Virtual Network
categories: [azure, cloud]
---


Cloud computing is at the core of modern IT, and understanding how cloud networks are built and secured is essential for anyone working in this space. As part of my ongoing learning in cloud security, I recently set up a basic Azure Virtual Network (VNet) to get a hands-on feel for core cloud networking components and how they function in a secure environment.

While I could have used the Azure portal to set everything up, I decided to take it a step further and get some Infrastructure as Code (IaC) practice using Terraform. In this post, I’ll walk through the steps I took, highlight a few key takeaways, and share some lessons learned along the way.


My objective for undergoing this mini-project was to:

- Create a virtual network
- Create a subnet
- Create an NSG (Network Security Group)
- Create a Linux VM (Virtual Machine) with secure SSH access. 


To accomplish the objective, I broke it down to the following actionable steps:

- Creating the resource group `rg-lab1` 
- Creating the VNet `vnet-lab1` with address space `10.0.0.0/16` 
- Creating the subnet `subnet-lab1` with `10.0.1.0/24` 
- Creating the NSG `nsg-lab1` allowing SSH (port 22) only from my IP address 
- Associating the NSG with the NIC
- Create a Linux VM `vm-lab1` in the `subnet-lab1` with public IP disabled 
- Creating an Azure Bastion host for secure VM access
- Connecting to the VM via Bastion using the Azure Portal


### Setting up Terraform
Terraform is an open-source Infrastructure as Code (IaC) tool developed by HashiCorp that allows users to define, provision, and manage infrastructure resources using a declarative configuration language. This means that instead of manually configuring servers, networks, and other infrastructure components, users can describe the desired state of their infrastructure in human-readable configuration files and let Terraform automatically provision and manage the resources.

As terraform is a major component of the tasks I would work on, I needed to set up a terraform environment. Below are the steps I took.
- Open Cloud Shell.
- Select the command-line environment.
- Determine the version of Terraform being used in Cloud Shell.

```bash
terraform version
```

If the Terraform version installed in Cloud Shell isn't the latest, you will see a message indicating that the version of Terraform is out of date.

From the screenshot below, the Terraform version that was running in my Cloud Shell was not the latest.

<img width="635" height="105" alt="terraform-version" src="https://github.com/user-attachments/assets/61872ef5-7177-4107-adc3-8429c5bb40d0" /></br>

I decided to update Terraform to the latest version before proceeding with the tasks ahead.

```bash
curl -O <terraform_download_url>
```

<img width="738" height="170" alt="terraform-download" src="https://github.com/user-attachments/assets/2cc85bc8-affd-4957-9749-94dacca9e57a" /></br>

```bash
unzip <zip_file_downloaded_in_previous_step>
```

<img width="495" height="248" alt="unzip-downloaded-terraform" src="https://github.com/user-attachments/assets/85408b75-ba96-4474-a2a3-fb589688f1ee" /></br>

```bash
# Create the '~/.local/bin' folder if it does not exist
mkdir -p ~/.local/bin

# Move the terraform file into the bin directory.
mv terraform ~/.local/bin    

# Close and restart Cloud Shell.
```

<img width="349" height="211" alt="finalize-terraform-upgrade" src="https://github.com/user-attachments/assets/7549e81e-fc7e-4392-8c57-0af0c8c2ef02" /></br>

Finally, I verified that the upgrade was successful, and I was now using the latest version of Terraform

```bash
# Verify that the downloaded version of Terraform is first in the path.
terraform version
```

<img width="312" height="97" alt="verify-terraform-upgrade" src="https://github.com/user-attachments/assets/dd3bf461-a89b-42a1-b3ae-da4745ba3300" /></br>


### Using up Terraform
With the Terraform set up complete, the next steps were to write the code that Terraform would use to create and manage the assets. To accomplish the task, I made use of the following Terraform files:

- __providers.tf__: This file is used to define the providers the Terraform configuration will use (like AWS, Azure, Google Cloud, etc.).
- __main.tf__: This is the main configuration file that defines the actual infrastructure resources to create (like EC2 instances, S3 buckets, VPCs, etc.).
- __variables.tf__: This file is used to define input variables that the configuration needs,  making the configuration reusable and modular.
- __dev.tfvars__: This file is used to define values for variables. It can be named anything, but the extension must be .tfvars.

<img width="360" height="76" alt="basic-azure-vnet-tree" src="https://github.com/user-attachments/assets/56364fd3-e5f0-4f6a-838f-1decd3321c87" /></br>

#### providers.tf

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

#### variables.tf

```hcl
variable "location" {
  type        = string
  default     = "eastus"
  description = "Location of the resource group."
}

variable "ssh_key" {
  type        = string
  description = "public key for ssh access"
}

variable "my_ip" {
  type        = string
  description = "my public IP for whitelisting"
}
```

#### dev.tfvars

```hcl
ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUKMnIFgaYWm/yiN/gQCwLm5yqp8UBvlpeox0n/tkaT"
my_ip   = "xxx.xx.xx.xx/32"
```

#### main.tf

```hcl
# Create a new resource group
resource "azurerm_resource_group" "lab1_rg" {
  name     = "rg-lab1"
  location = var.location
}

# Create a new virtual network
resource "azurerm_virtual_network" "lab1_vnet" {
  name                = "vnet-lab1"
  address_space       = ["10.0.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name
}

# Create a new subnet within lab1_vnet
resource "azurerm_subnet" "lab1_subnet" {
  name                 = "subnet-lab1"
  resource_group_name  = azurerm_resource_group.lab1_rg.name
  virtual_network_name = azurerm_virtual_network.lab1_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Create a network resource group
resource "azurerm_network_security_group" "lab1_nsg" {
  name                = "nsg-lab1"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.my_ip
    destination_address_prefix = "*"
  }
}

# Create a subnet for the Azure Bastion host
resource "azurerm_subnet" "bastion_subnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.lab1_rg.name
  virtual_network_name = azurerm_virtual_network.lab1_vnet.name
  address_prefixes     = ["10.0.2.0/27"]
}

# Create a public IP used to connect to the Azure Bastion host
resource "azurerm_public_ip" "bastion_ip" {
  name                = "bastion-ip"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Create the Azure Bastion host
resource "azurerm_bastion_host" "bastion" {
  name                = "bastion-host"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name

  ip_configuration {
    name                 = "bastion-config"
    subnet_id            = azurerm_subnet.bastion_subnet.id
    public_ip_address_id = azurerm_public_ip.bastion_ip.id
  }

  sku = "Basic"
}

# Create a Network Interface Card to attach to the VM
resource "azurerm_network_interface" "nic" {
  name                = "vm-lab1-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab1_subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# Connect the security group to the network interface
resource "azurerm_network_interface_security_group_association" "lab1" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.lab1_nsg.id
}

# Create a Linux VM
resource "azurerm_linux_virtual_machine" "lab1_vm" {
  name                = "vm-lab1"
  location            = var.location
  resource_group_name = azurerm_resource_group.lab1_rg.name
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  network_interface_ids = [
    azurerm_network_interface.nic.id
  ]

  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}
```

Once the file structure was created, the next step was to run a series of Terraform commands to deploy the architecture.

- Initialize the Terraform project: this downloads required providers, sets up the .terraform directory, and prepares the project to run other Terraform commands.
```bash
terraform init
```

<img width="609" height="375" alt="terraform-init" src="https://github.com/user-attachments/assets/83bae2f9-37c0-460c-8210-a2b6f787f6a4" /></br>

- Format the Terraform code for readability and consistency by automatically aligning and indenting the .tf files and applying standard Terraform style.
```bash
terraform fmt
```

- Validate the Terraform configuration files by checking for syntax errors or misconfigured blocks, and ensuring that the .tf files are valid Terraform code.
```bash
terraform validate
```

<img width="316" height="82" alt="terraform-validate" src="https://github.com/user-attachments/assets/25e1cc0c-a3e4-43ac-a7e3-7604abc4fcf6" /></br>

- Generate an execution plan to show what Terraform will do when I apply the configuration: this reads variable values from .tfvars, calculates what changes need to be made to reach the desired state, and saves that plan to a file called main.tfplan.
```bash
terraform plan -var-file="dev.tfvars" -out main.tfplan
```

<img width="574" height="422" alt="terraform-plan" src="https://github.com/user-attachments/assets/9ae1aeed-ee39-4f68-9e66-bce96f35b9fa" /></br>


- Apply the changes defined in a saved plan file (in this case, main.tfplan): this reads the execution plan from the file and makes the actual infrastructure changes (create, update, delete resources), ensuring no drift.
```bash
terraform apply main.tfplan
```

Once the terraform configuration applies successfully, you will be able to see the created resources in the cloud console.

<img width="1120" height="388" alt="basic-azure-vnet-resources" src="https://github.com/user-attachments/assets/701c3835-714e-4efc-9f0d-13c9c5edbafd" /></br>


### Validating Created Resources
To verify that the resources I created using Terraform functioned as expected, I tried connecting via the Bastion host to the Linux VM I created.

<img width="928" height="423" alt="bastion-host" src="https://github.com/user-attachments/assets/3231328b-17c6-47fa-b00f-5c563d0c3479" /></br>

<img width="781" height="563" alt="bastion-connection" src="https://github.com/user-attachments/assets/bdf2c199-3521-4fd2-a5fc-c6e584391923" /></br>


### Takeaways and Lessons Learned

- An Azure Bastion host always needs its dedicated subnet, named specifically: AzureBastionSubnet, and a public IP address (Standard SKU) connected to it. The Bastion host is deployed into a specific subnet so that it can manage access to other VMs without exposing them directly to the internet. 

- When creating an NSG, you have to attach it to a resource. Failure to do so would mean updating the Terraform code and running it again, as I discovered that if I make the association via the cloud console, it introduces a change that Terraform is not aware of, and the next time I try to use Terraform, it would complain. This is because Terraform maintains a "desired state" of the infrastructure, and manual changes that are not reflected in the Terraform codebase will cause a drift (Terraform's state and the actual resource differ).

- Bation hosts are expensive to run, as when I ran the infrastructure for 7days (no ingress or egress), the bastion service made up for over 95% of the usage cost. This is because Azure Bastion is priced based on:
  - Hourly usage (even if idle)
  - Data transfer (egress)

<img width="1258" height="736" alt="basic-azure-vnet-cost" src="https://github.com/user-attachments/assets/3c082026-3e9d-47df-8721-a19ea437e343" /></br>

This means that for testing or short-lived projects, Azure Bastion might not be cost-effective unless you're actively using it. To minimize cost, turn off or destroy Bastion resources when not in use, especially in development or test environments.

- When done with a test resource, the best option is to destroy everything created so as not to incur additional cost. In cloud environments, unused resources such as public IPs, Bastion hosts, premium disks, load balancers, VMs, app services, etc., continue to rack up costs even if idle. If provisioned using IaaC like Terraform, destroying all tracked resources becomes very easy.

- Unlike the cloud shell, where I was presented a list of VMs to choose from, when using Terraform, knowing the right parameters to choose was not straightforward. However, I discovered I could get the information I needed either through the Azure marketplace or the Cloud Shell.
  - `az vm image list --all`
  - Go to the Azure marketplace and select the image to get information.


<br>

Thanks for reading...
