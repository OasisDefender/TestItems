import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network.models import (
    NatGateway,
    PublicIPAddress,
    PublicIPAddressSkuName,
    PublicIPPrefix,
    PublicIPPrefixSkuName,
    LoadBalancer,
    BackendAddressPool,
    NetworkInterface,
    NetworkInterfaceIPConfiguration,
    Subnet,
)
from azure.mgmt.network.models import (
    VirtualNetwork,
    NetworkSecurityGroup,
    SecurityRule,
    AddressSpace,
    IPAllocationMethod,
)
from azure.mgmt.compute.models import (
    VirtualMachine,
    DiskCreateOption,
    HardwareProfile,
    NetworkProfile,
    OSProfile,
    LinuxConfiguration,
)

from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, BlobLeaseClient

# , SSHConfiguration, SSH, OSVirtualHardDisk)
from azure.core.exceptions import ResourceExistsError
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import RecordSet, ARecord
from dotenv import load_dotenv

load_dotenv("azure.env")

location = "UAE North"  # XXX
# Azure Setup
credential = DefaultAzureCredential()
subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
network_client = NetworkManagementClient(credential, subscription_id)
resource_client = ResourceManagementClient(credential, subscription_id)
compute_client = ComputeManagementClient(credential, subscription_id)
sql_client = SqlManagementClient(credential, subscription_id)
dns_client = DnsManagementClient(credential, subscription_id)
# blob_service_client = BlobServiceClient(credential, subscription_id)

'''
# create container
container_client = blob_service_client.get_container_client(container="$root")
# Create the root container if it doesn't already exist
if not container_client.exists():
    container_client.create_container()

container_name = "oazContainer"
oaz_container = blob_service_client.create_container(name=container_name)
'''

# Define the VM parameters


def vm_parameters(vm_name, nic, avset_id):
    return {
        "location": location,
        "hardware_profile": {"vm_size": "Standard_DS1_v2"},
        "storage_profile": {
            "image_reference": {
                "publisher": "Canonical",
                "offer": "UbuntuServer",
                "sku": "16.04-LTS",
                "version": "latest",
            }
            # 'osDisk': {
            #    'caching': 'ReadWrite',
            #    'createOption': 'FromImage',
            #    'name': 'myVMosdisk'
            #    ,
            #    'vhd': {"uri": "http://{existing-storage-account-name}.blob.core.windows.net/{existing-container-name}/myDisk.vhd"
            #            },
            #
            # }
        },
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": "toor",
            "admin_password": "ROOTtoor1",
        },
        "network_profile": {
            "network_interfaces": [{"id": nic.id, "properties": {"primary": True}}]
        },
        "availability_set": {"id": avset_id},
    }


def vm_parameters1(vm_name, nic):
    return {
        "location": location,
        "hardware_profile": {"vm_size": "Standard_DS1_v2"},
        "storage_profile": {
            "image_reference": {
                "publisher": "Canonical",
                "offer": "UbuntuServer",
                "sku": "16.04-LTS",
                "version": "latest",
            }
        },
        "os_profile": {
            "computer_name": vm_name,
            "admin_username": "toor",
            "admin_password": "ROOTtoor1",
        },
        "network_profile": {
            "network_interfaces": [{"id": nic.id, "properties": {"primary": True}}]
        },
    }


# Create Resource Group
res_group_name = "oazResourceGroup"
resource_group = resource_client.resource_groups.create_or_update(
    res_group_name, {"location": location}
)

# Next, create a public IPs for your VM
std_public_ip_params = {
    "location": location,
    "public_ip_allocation_method": "Static",
    "sku": {"name": "Standard"},
    "public_ip_address_version": "IPV4",
}
basic_public_ip_params = {
    "location": location,
    "public_ip_allocation_method": "Static",
    "sku": {"name": "Basic"},
    "public_ip_address_version": "IPV4",
}
std_public_ip_address_name = "oazPublicIPstd"
gw_public_ip_address_name = "oazPublicIPGW"
lb_public_ip_address_name = "oazPublicIPLB"
gw_public_ip = network_client.public_ip_addresses.begin_create_or_update(
    res_group_name, gw_public_ip_address_name, std_public_ip_params
).result()

nat_public_ip = network_client.public_ip_addresses.begin_create_or_update(
    res_group_name, std_public_ip_address_name, std_public_ip_params
).result()
lb_public_ip = network_client.public_ip_addresses.begin_create_or_update(
    res_group_name, lb_public_ip_address_name, std_public_ip_params
).result()

# Create a NAT Gateway
nat_gateway_name = "oazNATGateway"
nat_gateway_params = {
    "location": location,
    "sku": {"name": "Standard"},
    "public_ip_addresses": [{"id": nat_public_ip.id}],
}
nat_gateway = network_client.nat_gateways.begin_create_or_update(
    res_group_name, nat_gateway_name, nat_gateway_params
).result()

'''
nat_gateway = NatGateway(location=location, sku={"name": "Standard"}, public_ip_addresses=[{"id": nat_public_ip.id}], {"subnets": [{"id": pub_subnet.id"}]})
'''

# Create VNet
vnet_name = "oazVNet"
subnet_srv_pub_name = "SrvPubNet"
subnet_srv_priv_name = "SrvPrivNet"
subnet_cln_priv_name = "CliPrivNet"
subnet_gw_name = "GatewaySubnet"
vnet = network_client.virtual_networks.begin_create_or_update(
    res_group_name,
    vnet_name,
    {
        "location": location,
        "address_space": {"address_prefixes": ["10.1.0.0/16"]},
        "subnets": [
            {"name": subnet_srv_pub_name, "address_prefix": "10.1.1.0/24", "nat_gateway": {"id": nat_gateway.id}},
            {"name": subnet_srv_priv_name, "address_prefix": "10.1.2.0/24"},
            {"name": subnet_cln_priv_name, "address_prefix": "10.1.3.0/24"},
            {"name": subnet_gw_name, "address_prefix": "10.1.4.0/24"},
        ],
    },
).result()

# Create Application Security Groups
asg_www = network_client.application_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    application_security_group_name="asg_www",
    parameters={"location": location, "properties": {}},
).result()
asg_db = network_client.application_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    application_security_group_name="asg_db",
    parameters={"location": location, "properties": {}},
).result()
asg_app = network_client.application_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    application_security_group_name="asg_app",
    parameters={"location": location, "properties": {}},
).result()
asg_cln = network_client.application_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    application_security_group_name="asg_cln",
    parameters={"location": location, "properties": {}},
).result()

# Create Network Security Groups
nsg_creation = network_client.network_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    network_security_group_name="sg_www",
    parameters={
        "location": location,
        "properties": {
            "securityRules": [
                {
                    "name": "in443",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "443",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Inbound",
                    },
                },
                {
                    "name": "in80",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "80",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                        "access": "Allow",
                        "priority": 101,
                        "direction": "Inbound",
                    },
                },
                {
                    "name": "out_app",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "2222",
                        "sourceAddressPrefix": "*",
                        "destinationApplicationSecurityGroups": [asg_app],
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Outbound",
                    },
                },
            ]
        },
    },
)
nsg_www = nsg_creation.result()

nsg_creation = network_client.network_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    network_security_group_name="sg_app",
    parameters={
        "location": location,
        "properties": {
            "securityRules": [
                {
                    "name": "in2222",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "2222",
                        "sourceApplicationSecurityGroups": [asg_www],
                        "destinationApplicationSecurityGroups": [asg_app],
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Inbound",
                    },
                },
                {
                    "name": "out_db",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "3306",
                        "sourceAddressPrefix": "*",
                        "destinationApplicationSecurityGroups": [asg_db],
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Outbound",
                    },
                },
            ]
        },
    },
)
nsg_app = nsg_creation.result()

nsg_creation = network_client.network_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    network_security_group_name="sg_db",
    parameters={
        "location": location,
        "properties": {
            "securityRules": [
                {
                    "name": "in3306",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "3306",
                        "sourceApplicationSecurityGroups": [asg_app],
                        "destinationApplicationSecurityGroups": [asg_db],
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Inbound",
                    },
                },
                {
                    "name": "deny_out",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "*",
                        "sourceAddressPrefix": "*",
                        "destinationAddressPrefix": "*",
                        "access": "Deny",
                        "priority": 100,
                        "direction": "Outbound",
                    },
                },
            ]
        },
    },
)
nsg_db = nsg_creation.result()

nsg_creation = network_client.network_security_groups.begin_create_or_update(
    resource_group_name=res_group_name,
    network_security_group_name="sg_cln",
    parameters={
        "location": location,
        "properties": {
            "securityRules": [
                {
                    "name": "out80",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "80",
                        "sourceApplicationSecurityGroups": [asg_cln],
                        "destinationApplicationSecurityGroups": [asg_www],
                        "access": "Allow",
                        "priority": 100,
                        "direction": "Inbound",
                    },
                },
                {
                    "name": "out443",
                    "properties": {
                        "protocol": "tcp",
                        "sourcePortRange": "*",
                        "destinationPortRange": "443",
                        "sourceApplicationSecurityGroups": [asg_cln],
                        "destinationApplicationSecurityGroups": [asg_www],
                        "access": "Allow",
                        "priority": 101,
                        "direction": "Inbound",
                    },
                },
            ]
        },
    },
)
nsg_cln = nsg_creation.result()
'''
"""
async_subnet_creation = network_client.subnets.create_or_update(res_group_name, vnet_name, subnet_srv_pub_name,
    SUBNET_NAME,
    {'address_prefix': '10.0.0.0/24'}
)
subnet_info = async_subnet_creation.result()
"""

#create virtualNetworkGateway

           'gateway_type': 'VPN',
            'vpn_type': 'RouteBased',
            'enable_bgp': False,
            'sku': {
                'tier': 'Standard',
                'capacity': 2,
                'name': 'Standard'},
            'ip_configurations':[{
                'name': 'default',
                'private_ip_allocation_method': 'Dynamic',
                'subnet': {
                    'id': gateway_subnet_info.id
                },
                'public_ip_address': {
                    'id': public_ip_address.id
                }
            }],
        }
'''

'''
gw_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_gw_name)
rvn_gw = network_client.virtual_network_gateways.begin_create_or_update(
        resource_group_name=res_group_name,
        virtual_network_gateway_name="oaz_VN_GW",
        parameters={
            "location": location,           
            "properties": {
                "activeActive": False,
                "allowRemoteVnetTraffic": False,
                "allowVirtualWanTraffic": False,
                # "customRoutes": {"addressPrefixes": ["101.168.0.6/32"]},
                # "disableIPSecReplayProtection": False,
                "enableBgp": False,
                "enableBgpRouteTranslationForNat": False,
                "enableDnsForwarding": False,
                "gatewayType": "ExpressRoute",
                "ipConfigurations": [
                    {
                        "name": "gwipconfig",
                        "properties": {
                            "privateIPAllocationMethod": "Dynamic",
                            "subnet": {"id": gw_subnet.id},
                            "publicIPAddress": {
                                "id": gw_public_ip.id
                            },
                        },
                    }
                ],
                "sku": {"name": "Basic", "tier": "Basic"},
                # "vpnType": "RouteBased",
            },
        },
).result()
'''

# Create DBs
# Create private SQL server
server_params = {
    "location": location,
    "administrator_login": "oazAdminLogin",
    "administrator_login_password": "oazAdminPassword1",
}
priv_server = sql_client.servers.begin_create_or_update(
    res_group_name, "oazPrivSqlServer", server_params
).result()

# Create SQL database
# db_params = {'location': location}
# db = sql_client.databases.begin_create_or_update(res_group_name, 'oazPrivSqlServer', 'oazSqlDb', db_params).result()

# Create private endpoint
priv_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_srv_priv_name
)
private_endpoint_params = {
    "location": location,
    "subnet": {"id": priv_subnet.id},
    "private_link_service_connections": [
        {
            "name": "oazDBPrivConnection",
            "private_link_service_id": priv_server.id,
            "group_ids": ["sqlServer"],
            "application_security_groups": [asg_db],
            "network_interfaces":[
                { 
                    "parameters" : 
                    { 
                        "location": location,
                        "properties": {"networkSecurityGroup": nsg_db}
                    }
                }
            ],
        },
    ],
}
private_endpoint = network_client.private_endpoints.begin_create_or_update(
    res_group_name, "oazDBPrivateEndpoint", private_endpoint_params
).result()
"""
# Create private DNS zone
dns_zone = dns_client.private_zones.create_or_update(res_group_name, 'privatelink.database.windows.net', {}).result()

# Link private DNS zone to virtual network
vnet_link_params = {
    'registration_enabled': False,
    'virtual_network': {'id': vnet.id}
}
dns_client.virtual_network_links.create_or_update(
    res_group_name, 'privatelink.database.windows.net', 'myVNetLink', vnet_link_params
)

# Create DNS record set
record_set_params = {
    'ttl': 3600,
    'a_records': [{'ipv4_address': private_endpoint.ip_addresses[0]}]
}
dns_client.record_sets.create_or_update(
    res_group_name, 'privatelink.database.windows.net', '/', 'A', 'mySqlServer', record_set_params
)
 
"""
# Create public SQL server
server_params = {
    "location": location,
    "administrator_login": "oazAdminLogin",
    "administrator_login_password": "oazAdminPassword2",
}
pub_server = sql_client.servers.begin_create_or_update(
    res_group_name, "oazPubSqlServer", server_params
).result()

# Create SQL database
# db_params = {'location': location}
# db = sql_client.databases.begin_create_or_update(res_group_name, 'oazPubSqlServer', 'oazSqlDb', db_params).result()
"""
# Set up public endpoint for SQL server
# In this case, the server is already publicly accessible via the fully qualified domain name (FQDN), which is formed as follows:
public_endpoint = f"{pub_server.name}.database.windows.net"

# Create DNS zone
dns_zone = dns_client.zones.begin_create_or_update(res_group_name, 'myDnsZone', location=location).result()

# Create a DNS record set
record_set_params = RecordSet(ttl=300, a_records=[ARecord(ipv4_address='1.2.3.4')])  # Replace '1.2.3.4' with the public IP address of your SQL Server
record_set = dns_client.record_sets.begin_create_or_update(res_group_name, 'myDnsZone', 'www', 'A', record_set_params).result()
"""
pub_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_srv_pub_name)
public_endpoint_params = {
    "location": location,
    "subnet": {"id": pub_subnet.id},
    "private_link_service_connections": [
        {
            "name": "oazDBPubConnection",
            "private_link_service_id": pub_server.id,
            "group_ids": ["sqlServer"],
            "application_security_groups": [asg_db],
            "network_interfaces":[
                { 
                    "parameters" : 
                    { 
                        "location": location,
                        "properties": {"networkSecurityGroup": nsg_db}
                    }
                }
            ],
 
        }
    ],
}
private_endpoint = network_client.private_endpoints.begin_create_or_update(
    res_group_name, "oazDBPubEndpoint", private_endpoint_params
).result()

# Create a Load Balancer
load_balancer_name = "oazLoadBalancer"
frontend_ip_configuration_name = "LBFrontEndIpConfig"
backend_address_pool_name = "LBBackEndAddressPool"
load_balancer_params = {
    "location": location,
    "sku": {"name": "Standard", "tier": "Regional"},
    "frontend_ip_configurations": [
        {
            "name": frontend_ip_configuration_name,
            "public_ip_address": {"id": lb_public_ip.id},
        }
    ],
    "backend_address_pools": [{"name": backend_address_pool_name}],
}
poller = network_client.load_balancers.begin_create_or_update(
    res_group_name, load_balancer_name, load_balancer_params
)
load_balancer = poller.result()

# create availability set for load balancer
avset_name = "oazPubAvailSet"
pub_avset = compute_client.availability_sets.create_or_update(
    resource_group_name=res_group_name,
    availability_set_name=avset_name,
    parameters={
        "location": location,
        "properties": {"platformFaultDomainCount": 2, "platformUpdateDomainCount": 2},
        "sku": {"name": "Aligned"},
    },
)

# Create 3 servers in public network and connect it to load balancer
if_base_name = "oazPubNetworkInterface"
srv_base_name = "oazPubWebSrv"
pub_srvs = []
pub_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_srv_pub_name)
backend_address_pool_id = load_balancer.backend_address_pools[0].id
for i in range(1, 4):
    if_name = if_base_name + str(i)
    vm_name = srv_base_name + str(i)

    # ip_config = NetworkInterfaceIPConfiguration(name=if_name, subnet=pub_subnet, load_balancer_backend_address_pools=[BackendAddressPool(id=backend_address_pool_id)])
    ip_config = NetworkInterfaceIPConfiguration(
        name=if_name,
        subnet=pub_subnet,
        application_security_groups=[asg_www],
        load_balancer_backend_address_pools=[
            BackendAddressPool(id=backend_address_pool_id)]
    )
    iface = network_client.network_interfaces.begin_create_or_update(
        resource_group_name=res_group_name,
        network_interface_name=if_name,
        parameters={
            "location": location,
            "properties": {"networkSecurityGroup": nsg_www, "ipConfigurations": [ip_config]},
        },
    ).result()

    vm_params = vm_parameters(vm_name, iface, pub_avset.id)
    vm = compute_client.virtual_machines.begin_create_or_update(
        res_group_name, vm_name, vm_params
    ).result()
    pub_srvs.append(vm)

# Create App server in public network
if_name = if_base_name + str(5)
vm_name = "oazPubAppSrv"
ip_config = NetworkInterfaceIPConfiguration(
    name=if_name,
    subnet=pub_subnet,
    application_security_groups=[asg_app],
    public_ip_allocation_method=IPAllocationMethod.dynamic,
)
iface = network_client.network_interfaces.begin_create_or_update(
    resource_group_name=res_group_name,
    network_interface_name=if_name,
    parameters={
        "location": location,
        "properties": {"networkSecurityGroup": nsg_app, "ipConfigurations": [ip_config]},
    },
).result()

vm_params = vm_parameters1(vm_name, iface)
poller = compute_client.virtual_machines.begin_create_or_update(
    res_group_name, vm_name, vm_params
)

# Create 4 Servers in Private Subnet
if_base_name = "oazPrivNetworkInterface"
srv_base_name = "oazPrivWebSrv"
priv_srvs = []
priv_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_srv_priv_name
)
for i in range(1, 3):
    if_name = if_base_name + str(i)
    vm_name = srv_base_name + str(i)
    ip_config = NetworkInterfaceIPConfiguration(
        name=if_name,
        subnet=priv_subnet,
        application_security_groups=[asg_www],
        private_ip_allocation_method=IPAllocationMethod.dynamic,
    )
    nic_params = NetworkInterface(
        location=location, ip_configurations=[ip_config])
    iface = network_client.network_interfaces.begin_create_or_update(
        resource_group_name=res_group_name,
        network_interface_name=if_name,
        parameters={
            "location": location,
            "properties": {"networkSecurityGroup": nsg_www, "ipConfigurations": [ip_config]},
        }
    ).result()
    vm_params = vm_parameters1(vm_name, iface)
    # try:
    poller = compute_client.virtual_machines.begin_create_or_update(
        res_group_name, vm_name, vm_params
    )
    priv_srvs.append(poller.result())

# Create App server in private network
if_name = if_base_name + str(5)
vm_name = "oazPrivAppSrv"
ip_config = NetworkInterfaceIPConfiguration(
    name=if_name,
    subnet=priv_subnet,
    application_security_groups=[asg_www],
    private_ip_allocation_method=IPAllocationMethod.dynamic,
)
nic_params = NetworkInterface(location=location, ip_configurations=[ip_config])
iface = network_client.network_interfaces.begin_create_or_update(
    resource_group_name=res_group_name,
    network_interface_name=if_name,
    parameters={
        "location": location,
        "properties": {"networkSecurityGroup": nsg_app, "ipConfigurations": [ip_config]},
    }
).result()
vm_params = vm_parameters1(vm_name, iface)
poller = compute_client.virtual_machines.begin_create_or_update(
    res_group_name, vm_name, vm_params
)

# Create 3 Private Clients
if_base_name = "oazClnNetworkInterface"
srv_base_name = "oazPrivCln"
priv_clns = []
priv_subnet = network_client.subnets.get(
    res_group_name, vnet_name, subnet_cln_priv_name
)
for i in range(1, 3):
    if_name = if_base_name + str(i)
    vm_name = srv_base_name + str(i)
    ip_config = NetworkInterfaceIPConfiguration(
        name=if_name,
        subnet=priv_subnet,
        application_security_groups=[asg_cln],
        private_ip_allocation_method=IPAllocationMethod.dynamic,
    )
    nic_params = NetworkInterface(
        location=location, ip_configurations=[ip_config])
    iface = network_client.network_interfaces.begin_create_or_update(
        resource_group_name=res_group_name,
        network_interface_name=if_name,
        parameters={
            "location": location,
            "properties": {"networkSecurityGroup": nsg_cln, "ipConfigurations": [ip_config]},
        }
    ).result()
    vm_params = vm_parameters1(vm_name, iface)
    # try:
    poller = compute_client.virtual_machines.begin_create_or_update(
        res_group_name, vm_name, vm_params
    )
    priv_clns.append(poller.result())
