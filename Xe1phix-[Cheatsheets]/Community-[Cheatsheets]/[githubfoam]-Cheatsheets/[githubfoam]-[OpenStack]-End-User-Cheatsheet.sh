---------------------------------------------------------------------------------------------------
Openstack Panel - Dashboard Horizon

Network-Networks-Create Network
Network-Network Name-testnetwork
Subnet-Subnet Name-testnetwork_subnet
Subnet-Network Address-10.66.35.0/24
Subnet-Gateway IP-10.66.35.1
Create

Network-Routers-Create Router
Router Name-testrouter
External Network-ext_net2
Create Router

testrouter-Interfaces-Add Interface
Subnet-testnetwork
Submit
---------------------------------------------------------------------------------------------------
Openstack Panel - Dashboard Horizon

#increase memory,cpu
Compute-Instances-shut off instance
Compute-Instances-resize instance
---------------------------------------------------------------------------------------------------
# access an instance through a remote console, returns a URL from which you can access instance
$ nova get-vnc-console INSTANCE_NAME VNC_TYPE
---------------------------------------------------------------------------------------------------
# two official Heat clients; a stand-alone command line client and a web-based client included with Horizon, the OpenStack dashboard projec

#linux
$ virtualenv venv
$ source venv/bin/activate
(venv) $ pip install python-heatclient

#windows
$ virtualenv venv
$ venv\Scripts\activate
(venv) $ pip install python-heatclient
---------------------------------------------------------------------------------------------------
parameters:
  dns_servers:
    type: comma_delimited_list
    default: 192.168.1.254,8.8.8.8
    description: Comma separated list of DNS nameservers for the private network.
---------------------------------------------------------------------------------------------------
#The HOT template is  defined  in YAML format.

heat_template_version: 2013-05-23 
description: <description> 
parameters: 
  <parameters>
resources: 
  <resources>
outputs: 
  <outputs
---------------------------------------------------------------------------------------------------
heat_template_version: 2013-05-23 
...
resources: 
  ...
  the_resource:
    type: FCX::AutoScaling::LaunchConfiguration 
    properties:
      BlockDeviceMappingsV2: [{"source_type": String, "destination_type": String, "boot_index": String, 
"device_name": String, "volume_size": String, "uuid": String, "delete_on_termination": Boolean}, ...] 
      ImageId: String
      InstanceType: String 
      KeyName: String
      NovaSchedulerHints: [{"Value": String, "Key": String}, {"Value": String, "Key": String}, ...] 
      SecurityGroups: [
Value, Value, ...] 
      UserData: String
---------------------------------------------------------------------------------------------------
# Intrinsic functions The embedded functions described below can be used in the HOT template

resources: 
  my_instance:
    type: OS::Nova::Server 
    properties:
      # general properties ... 
      user_data:
        get_file: my_instance_user_data.sh 
  my_other_instance:
    type: OS::Nova::Server 
    properties:
      # general properties ... 
      user_data:
        get_file: http://example.com/my_other_instance_user_data.sh   
---------------------------------------------------------------------------------------------------
Linux:   - Shell script (begins with #!)
Windows: - PowerShell (begins with #ps1_sysnative or #ps1_x86)
         - Windows batch (begins with rem cmd

# the c:temp directory is created using PowerShell
user_data: | 
  #!ps1_sysnative
  New-Item "c:\\temp" -Type Directory 



---------------------------------------------------------------------------------------------------
# The resource name must exist in the resources section of the template.
# https://docs.openstack.org/heat/latest/template_guide/hot_spec.html#hot-spec-intrinsic-functions
outputs:
  private_key:
    description: private key of created key pair
    value: { get_attr: [key, private_key] }
   server_networks:
    description: The networks of the deployed server 
    value: { get_attr: [heat_server, networks] }
  instance_name:
    description: Name of the instance
    value: { get_attr: [heat_server, name] }
  instance_details:
    description: Shows details of  virtual servers.
    value: { get_attr: [ heat_server, show ] }
  instance_ip:
    description: IP address of the instance
    value: { get_attr: [heat_server, first_address] }
  instance_private_ip:
    description: Private IP address of the deployed compute instance
    value: { get_attr: [heat_server, networks, private, 0] }
---------------------------------------------------------------------------------------------------
outputs:
   data_security_group_id:
     description: Get resource id of this security group
     value: { get_resource: bigip_data_security_group     
---------------------------------------------------------------------------------------------------
# https://docs.openstack.org/heat/pike/template_guide/openstack.html#OS::Heat::ResourceGroup
outputs:
  private_ips:
      description: "Private IP addresses in resource group"
      value: { get_attr: [heat_rg, "attributes", first_address] }
  refs:
      description: "Resource ID"
      value: { get_attr: [heat_rg, refs] }
  refs_map:
      description: "A list of resource IDs for the resources in the group"
      value: { get_attr: [heat_rg, refs_map] }
  resource_group_show:
      description: "A list of resource IDs for the resources in the group"
      value: { get_attr: [heat_rg, show] }  
---------------------------------------------------------------------------------------------------
parameters:
  DBRootPassword:
    type: string
    label: Database Password
    description: Root password for MySQL
    hidden: true

resources:
  my_instance:
    type: OS::Nova::Server
    properties:
      # general properties ...
      user_data:
        str_replace:
          template: |
            #!/bin/bash
            echo "Hello world"
            echo "Setting MySQL root password"
            mysqladmin -u root password $db_rootpassword
            # do more things ...
          params:
            $db_rootpassword: { get_param: DBRootPassword }
---------------------------------------------------------------------------------------------------
#create resource with the name based on the client and project
heat_template_version: 2013-05-23

description: Create network with

parameters:
  client_code:
    type: string
    description: 4 character customer code. Will be used for instance naming
  project_code:
    type: string
    description: 3 character project code
resources:
  test:
    type: OS::Neutron::Net
    properties:
      name:
       list_join: ['-', [ {get_param: tenant}, 'net']]   
---------------------------------------------------------------------------------------------------
#create resource with the name based on the client and project
heat_template_version: 2013-05-23

description: Create network with

parameters:
  client_code:
    type: string
    description: 4 character customer code. Will be used for instance naming
  project_code:
    type: string
    description: 3 character project code
resources:
  test:
    type: OS::Neutron::Net
    properties:
      name:
        str_replace:
        template: cust%-proj%
        params:
          "cust%": { get_param: client_code } 
          "proj%": { get_param: project_code }       
---------------------------------------------------------------------------------------------------
PROBLEM:
Cannot define the following properties at the same time: security_groups, networks/port.

  #server
  heat_server:
    type: OS::Nova::Server
    properties:
      name: heat_server
      image: { get_param: image }
      flavor: { get_param: flavor }
      # availability_zone: { get_param: AZ }
      # block_device_mapping: [{"volume_size": { get_param: VOLUME_SIZE }, "volume_id": { get_resource: SYS-VOL }, "delete_on_termination": True, "device_name": "/dev/vda" }]
      key_name: { get_param: heat_key }
      security_groups:
        - { get_resource: heat_security_group }
      networks:
        - port: { get_resource: heat_server_port}
      user_data: |
        #!/bin/sh
        sudo apt-get update
        HOST_IP_ADDR=$(hostname -I | awk '{print $1}')
        echo $HOST_IP_ADDR
        cat /etc/hosts
        echo "nameserver $HOST_IP_ADDR" |sudo tee -a /etc/hosts
        cat /etc/hosts #verify
      user_data_format: RAW  
      
FIX:

  #server
  heat_server:
    type: OS::Nova::Server
    properties:
      # name: heat_server
      name: { get_param: vm_name } 
      image: { get_param: image }
      flavor: { get_param: flavor }
      availability_zone: { get_param: az }
      # block_device_mapping: [{"volume_size": { get_param: VOLUME_SIZE }, "volume_id": { get_resource: SYS-VOL }, "delete_on_termination": True, "device_name": "/dev/vda" }]
      key_name: { get_param: key }
      networks:
        - port: { get_resource: heat_server_port}
      # change default user and password for any image.
      user_data: |
        #cloud-config
        user: bubuntu
        password: bubuntu
        chpasswd: {expire: False}
      user_data_format: RAW

  heat_server_port:
    type: OS::Neutron::Port
    properties:
      network: { get_resource: heat_network }
      security_groups:
        - { get_resource: heat_security_group }
      fixed_ips:
        - subnet_id: { get_resource: heat_network_subnet }

---------------------------------------------------------------------------------------------------
  s-security-group:
    type: OS::Neutron::SecurityGroup
    properties:
      description: "in:ssh,http,https - out:http,https,ping,dns"
      rules:
        - { direction: ingress, ethertype: IPv4, remote_mode: remote_group_id }
        - { direction: ingress, ethertype: IPv6, remote_mode: remote_group_id }
        - { direction: ingress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 22, port_range_max: 22, protocol: tcp }
        - { direction: ingress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 80, port_range_max: 80, protocol: tcp }
        - { direction: ingress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 443, port_range_max: 443, protocol: tcp }
#        - { direction: ingress, remote_ip_prefix: 10.0.0.0/8, port_range_min: 1, port_range_max: 65535, protocol: tcp }
#        - { direction: ingress, remote_ip_prefix: 10.0.0.0/8, port_range_min: 1, port_range_max: 65535, protocol: udp }
        - { direction: egress, ethertype: IPv4, remote_mode: remote_group_id }
        - { direction: egress, ethertype: IPv6, remote_mode: remote_group_id }
        - { direction: egress, remote_ip_prefix: 0.0.0.0/0, protocol: icmp }
        - { direction: egress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 80, port_range_max: 80, protocol: tcp }
        - { direction: egress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 443, port_range_max: 443, protocol: tcp }
        - { direction: egress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 53, port_range_max: 53, protocol: tcp }
        - { direction: egress, remote_ip_prefix: 0.0.0.0/0, port_range_min: 53, port_range_max: 53, protocol: udp }
#        - { direction: egress, remote_ip_prefix: 10.200.0.0/16, port_range_min: 53, port_range_max: 53, protocol: tcp }
#        - { direction: egress, remote_ip_prefix: 10.200.0.0/16, port_range_min: 53, port_range_max: 53, protocol: udp }
#        - { direction: egress, remote_ip_prefix: 10.100.0.0/16, port_range_min: 53, port_range_max: 53, protocol: tcp }
#        - { direction: egress, remote_ip_prefix: 10.100.0.0/16, port_range_min: 53, port_range_max: 53, protocol: udp }
---------------------------------------------------------------------------------------------------
#assing static IP to an instance

resources:
  myVM_port1:
    type: OS::Neutron::Port
    properties:
      name: "myVM_port1"
      network_id: { get_param: network_id } 
      fixed_ips: [{"subnet": { get_param: network-subnet }, "ip_address": { get_param: fixed-ip } }]

  myVM_1:
    type: OS::Nova::Server
    properties:
      name: "myVM"
      image: { get_param: cirros_Image }
      flavor: "m1.tiny"
      availability_zone: "compute1"
      networks:
      - port: { get_resource: myVM_port1 }
---------------------------------------------------------------------------------------------------
resources:

   security_group:
    type: OS::Neutron::SecurityGroup
    properties:
      description: security group rules
      name: security_group
      rules: 
        - protocol: icmp
          direction: ingress
        - protocol: icmp
          direction: egress
        - protocol: tcp
          direction: ingress
        - protocol: tcp
          direction: egress
        - protocol: udp
          direction: ingress
        - protocol: udp
          direction: egress
---------------------------------------------------------------------------------------------------
resources:

   security_group:
    type: OS::Neutron::SecurityGroup
    properties:
      description: security group rules 
      name: security_group
      rules:
        - remote_ip_prefix: 0.0.0.0/0
          protocol: icmp
        - remote_ip_prefix: 0.0.0.0/0
          protocol: udp
          port_range_min: 1026
          port_range_max: 1043
        - remote_ip_prefix: 0.0.0.0/0
          protocol: tcp
          port_range_min: 4353
          port_range_max: 4353

---------------------------------------------------------------------------------------------------
