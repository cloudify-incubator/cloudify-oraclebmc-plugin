########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

import sys

# Third-party Imports
import oraclebmc

# Cloudify imports
from cloudify import ctx
from cloudify.exceptions import NonRecoverableError
from cloudify.decorators import operation


TCP_PROTOCOL_TYPE = "6"
UDP_PROTOCOL_TYPE = "17"


def _set_security_rules(ctx,vcn_client,vcn):

    rules=[]
    for sr in ctx.node.properties['security_rules']:
        cidr = sr.split(',')[0]
        port = sr.split(',')[1]
        prot = TCP_PROTOCOL_TYPE
        if len(sr.split(',')) > 2:
               prot = UDP_PROTOCOL_TYPE if sr.split(',')[2] == 'udp' else TCP_PROTOCOL_TYPE
        rule = oraclebmc.core.models.IngressSecurityRule()
        rule.protocol = prot
        rule.source = cidr
        portrange = oraclebmc.core.models.PortRange()
        portrange.min = port
        portrange.max = port
        if prot == TCP_PROTOCOL_TYPE:
            topts = oraclebmc.core.models.TcpOptions()
            topts.destination_port_range = portrange
            rule.tcp_options = topts
        else:
            uopts = oraclebmc.core.models.UdpOptions()
            uopts.destination_port_range = portrange
            rule.udp_options = uopts
        rules.append(rule)

    details = oraclebmc.core.models.CreateSecurityListDetails()
    details.compartment_id = vcn.compartment_id
    details.display_name = "{}_seclist".format(ctx.instance.id)
    details.vcn_id = vcn.id
    details.ingress_security_rules = rules

    # For now, egress wide open
    egress_rules = []
    rule = oraclebmc.core.models.EgressSecurityRule()
    rule.destination = '0.0.0.0/0'
    rule.protocol = TCP_PROTOCOL_TYPE
    egress_rules.append(rule)
    rule = oraclebmc.core.models.EgressSecurityRule()
    rule.destination = '0.0.0.0/0'
    rule.protocol = UDP_PROTOCOL_TYPE
    egress_rules.append(rule)
    details.egress_security_rules = egress_rules

    resp = None
    try:
        resp = vcn_client.create_security_list(details)
    except oraclebmc.exceptions.ServiceError as e:
        raise NonRecoverableError("unable to create seclist. err= {}".format(
                                  e.message))
    ctx.instance.runtime_properties['seclist_id'] = resp.data.id
    return resp.data.id


@operation
def create_vcn(**kwargs):
    ctx.logger.info("Creating VCN")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                  ctx.node.properties['bmc_config']))

    vcn = None

    if ctx.node.properties['use_external_resource']:
        resource_id = ctx.node.properties['resource_id']
        vcn = vcn_client.get_vcn(resource_id).data
        if not vcn:
            raise NonRecoverableError("resource id {} not found".
                                      format(resource_id))
        ctx.logger.info("Using existing resource")

    else:

        vcn_details = oraclebmc.core.models.CreateVcnDetails()
        vcn_details.cidr_block = ctx.node.properties['cidr_block']
        vcn_details.compartment_id = ctx.node.properties['compartment_id']
        vcn_details.display_name = ctx.node.properties['name']
        response = None

    	try:
            response = vcn_client.create_vcn(vcn_details)
        except:
            ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
            raise NonRecoverableError("VCN create failed: {}".
                                  format(sys.exc_info()[0]))
        vcn = response.data

    ctx.logger.info("Created VCN {} {}".format(ctx.node.properties['name'],
                                               vcn.id))
    ctx.instance.runtime_properties['id'] = vcn.id


@operation
def delete_vcn(**kwargs):
    ctx.logger.info("Deleting VCN")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                  ctx.node.properties['bmc_config']))

    if ctx.node.properties['use_external_resource']:
        return

    try:
        vcn_client.delete_vcn(
            ctx.instance.runtime_properties['id'])
    except:
        ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
        raise NonRecoverableError("VCN create failed: {}".
                                  format(sys.exc_info()[0]))


@operation
def wait_for_vcn_terminated(**kwargs):

    if ctx.node.properties['use_external_resource']:
        return

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
               ctx.node.properties['bmc_config']))

    # instance doesn't have a terminated state.  just vanishes
    # and api throws exception
    try:
        instance = vcn_client.get_vcn(ctx.instance.runtime_properties['id'])
        return ctx.operation.retry(
            message="Waiting for instance to terminate ({}). \
            Retrying...".format(instance.data.lifecycle_state),
            retry_after=kwargs['terminate_retry_interval'])

    except:
        pass


@operation
def create_subnet(**kwargs):
    ctx.logger.info("Creating subnet")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))

    if ctx.node.properties['use_external_resource']:
        resource_id = ctx.node.properties['resource_id']
        subnet = vcn_client.get_subnet(resource_id).data
        if not subnet:
            raise NonRecoverableError("resource id {} not found".
                                      format(resource_id))
        ctx.logger.info("Using existing resource")
        ctx.instance.runtime_properties["id"] = subnet.id
        return

    details = oraclebmc.core.models.CreateSubnetDetails()
    details.cidr_block = ctx.node.properties['cidr_block']
    details.availability_domain = ctx.node.properties['availability_domain']
    details.compartment_id = ctx.node.properties['compartment_id']
    details.display_name = ctx.node.properties['name']
    vcn = vcn_client.get_vcn(
        ctx.instance.runtime_properties['vcn_id']).data
    details.route_table_id = vcn.default_route_table_id
    details.vcn_id = ctx.instance.runtime_properties['vcn_id']
    list_id = _set_security_rules(ctx, vcn_client, vcn)
    ctx.instance.runtime_properties['seclist_id'] = list_id
    details.security_list_ids = [vcn.default_security_list_id, list_id]
    response = vcn_client.create_subnet(details)

    ctx.instance.runtime_properties["id"] = response.data.id
    ctx.logger.info("Created subnet {}".format(details.display_name))


@operation
def delete_subnet(**kwargs):
    ctx.logger.info("Deleting subnet")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))

    if ctx.node.properties['use_external_resource']:
        return

    vcn_client.delete_subnet(ctx.instance.runtime_properties['id'])


@operation
def wait_for_subnet_terminated(**kwargs):

    if ctx.node.properties['use_external_resource']:
        return

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
               ctx.node.properties['bmc_config']))

    # instance doesn't have a terminated state.  just vanishes
    # and api throws exception
    try:
        instance = vcn_client.get_subnet(ctx.instance.runtime_properties['id'])
        return ctx.operation.retry(
            message="Waiting for instance to terminate ({}). \
            Retrying...".format(instance.data.lifecycle_state),
            retry_after=kwargs['terminate_retry_interval'])
    except:
        pass


def _addto_route_table(vcn_client, vcn_id, cidrs, gateway_id):
    rules = []
    for cidr in cidrs:
        route_rule = oraclebmc.core.models.RouteRule()
        route_rule.network_entity_id = gateway_id
        route_rule.cidr_block = cidr
        rules.append(route_rule)
    details = oraclebmc.core.models.UpdateRouteTableDetails()
    details.route_rules = rules
    vcn = vcn_client.get_vcn(vcn_id)
    resp = vcn_client.update_route_table(
        vcn.data.default_route_table_id, details)
    ctx.instance.runtime_properties['route_table_id'] = resp.data.id


def _delfrom_route_table(vcn_client, vcn_id, cidrs, gateway_id):

    vcn = vcn_client.get_vcn(vcn_id)
    resp = vcn_client.get_route_table(vcn.data.default_route_table_id)
    new_rules = []
    rules = resp.data.route_rules
    for rule in rules:
        if rule.cidr_block not in cidrs:
            new_rules.append(rule)
        else:
            ctx.logger.debug("removing route rule: {}".
                             format(rule.cidr_block))
    details = oraclebmc.core.models.UpdateRouteTableDetails()
    details.route_rules = new_rules
    vcn_client.update_route_table(
        vcn.data.default_route_table_id, details)


@operation
def create_gateway(**kwargs):
    ctx.logger.info("Creating internet gateway")

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))

    if ctx.node.properties['use_external_resource']:
        resource_id = ctx.node.properties['resource_id']
        gateway = vcn_client.get_internet_gateway(resource_id).data
        if not gateway:
            raise NonRecoverableError("resource id {} not found".
                                      format(resource_id))
        ctx.instance.runtime_properties["id"] = gateway.id
        ctx.logger.info("Using existing resource")
        return

    details = oraclebmc.core.models.CreateInternetGatewayDetails()
    details.compartment_id = ctx.node.properties['compartment_id']
    details.display_name = ctx.node.properties['name']
    details.is_enabled = ctx.node.properties['enabled']
    details.vcn_id = ctx.instance.runtime_properties['vcn_id']
    response = vcn_client.create_internet_gateway(details)

    ctx.instance.runtime_properties["id"] = response.data.id
    ctx.logger.info("Created internet gateway {}".format(details.display_name))

    ctx.logger.info("Updating route table")
    if len(ctx.node.properties['route_cidrs']) > 0:
        _addto_route_table(vcn_client, details.vcn_id,
                          ctx.node.properties['route_cidrs'],
                          response.data.id)


@operation
def delete_gateway(**kwargs):
    ctx.logger.info("Deleting gateway")

    if ctx.node.properties['use_external_resource']:
        return

    vcn_client = (oraclebmc.core.VirtualNetworkClient(
                      ctx.node.properties['bmc_config']))
    if len(ctx.node.properties['route_cidrs']) > 0:
        _delfrom_route_table(vcn_client,
                            ctx.instance.runtime_properties['vcn_id'],
                            ctx.node.properties['route_cidrs'],
                            ctx.instance.runtime_properties['id'])
    vcn_client.delete_internet_gateway(ctx.instance.runtime_properties['id'])


@operation
def connect_subnet_to_network(**kwargs):
    ctx.source.instance.runtime_properties['vcn_id'] = \
        ctx.target.instance.runtime_properties['id']


@operation
def connect_gateway_to_network(**kwargs):
    ctx.source.instance.runtime_properties['vcn_id'] = \
        ctx.target.instance.runtime_properties['id']


@operation
def connect_instance_to_subnet(**kwargs):
    ctx.logger.debug("HERE")
    ctx.logger.debug('setting subnet_{} to {}'.
                     format(ctx.target.instance.id,
                            ctx.target.instance.runtime_properties['id']))

    ctx.source.instance.runtime_properties[(
        'subnet_'+ctx.target.instance.id)] = \
        ctx.target.instance.runtime_properties['id']
