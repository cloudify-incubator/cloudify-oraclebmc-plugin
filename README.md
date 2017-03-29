## cloudify-oraclebmc-plugin
A plugin for the Oracle Bare Metal Cloud

- Tested with the Python oraclebmc package version 1.1.2

### Limitations (as of 3/28/2017)
* Plugin must be installed via wagon package
* Only supports compute and networking.
* Tested with 3.4.x CLI and 3.4.x BMC Manager

### Plugin Components

#### cloudify.oraclebmc.nodes.Instance

Represents a compute instance.  Instance can be bare metal or a virtual machine, based on
configured shape.

##### Required properties

* `bmc_config` A dict containing API access credentials including
 * `user` The API user
 * `fingerprint` The key fingerprint
 * `key_file` The private key file
 * `tenancy` The tenant id (OCID)
 * `region` The region
* `public_key_file` The public key that will be used for ssh communication to the instance.
* `image_id` An Oracle OCID indicating the OS image to use
* `instance_shape` An Oracle OCID indicating the platform attributes
* `compartment_id` The compartment of the instance
* `availability_domain` The availability domain of the instance

##### Attributes

* `ip` The standard Cloudify runtime attribute representing the IP that the manager will use.
* `private_ip` The private IP address
* `public_ip` The public IP address

##### Relationships

* `cloudify.oraclebmc.relationships.instance_connected_to_subnet`

The subnet instance (see below) to attach the instance to.

#### cloudify.oraclebmc.nodes.VCN

Represents a network (VCN)

##### Required properties (if not referring to an existing network)

* `bmc_config` See cloudify.oraclebmc.nodes.Instance description above
* `cidr_block` The CIDR block of the network (e.g. 10.10.0.0/16)
* `compartment_id`  The compartment of the network

##### Attributes

* `id` The OCID of the network


#### cloudify.oraclebmc.nodes.Subnet

##### Required properties (if not referring to an existing subnet)

* `bmc_config` See cloudify.oraclebmc.nodes.Instance description above
* `cidr_block` The CIDR block of the subnet (e.g. 10.10.10.0/24)
* `security_rules` A list of ingress rules of the form `<cidr>,<port>[,<tcp|udp>]`. Defaults to TCP.
* `compartment_id` The compartment of the instance
* `availability_domain` The availability domain of the instance

##### Attributes

* `id` The OCID of the subnet 

##### Relationships

* `cloudify.oraclebmc.relationships.subnet_in_network` 

Used to attach the subnet to a network

#### cloudify.oraclebmc.nodes.Gateway

##### Required properties (if not referring to an existing subnet)

* `bmc_config` See cloudify.oraclebmc.nodes.Instance description above
* `compartment_id` The compartment of the instance
* `route_cidrs` A list of CIDRs that have access from the internet

##### Attributes

* `id` The OCID of the gateway
* `route_table_id` The OCID of the associated route table

##### Relationships

* `cloudify.oraclebmc.relationships.gateway_connected_to_network`

Used to attach the gateway to a network

