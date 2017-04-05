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
import collections

# Third-party Imports
import oraclebmc

# Cloudify imports
from cloudify import ctx
from cloudify.exceptions import NonRecoverableError
from cloudify.decorators import operation

RUNNING_STATE = 'RUNNING'
TERMINATED_STATE = "TERMINATED"


# TODO: This may also be a util.
def merge_config_node_props_kwargs(config_name, from_ctx, from_kw):
    props_config = from_ctx.get(config_name)
    kwarg_config = from_kw.get(config_name)
    return dict_update(kwarg_config, props_config)


# TODO: This should be put in utils.
def dict_update(orig, updates):
    '''Recursively merges two objects
       Copied from cloudify-azure-plugin.
    '''
    for key, val in updates.iteritems():
        if isinstance(val, collections.Mapping):
            orig[key] = dict_update(orig.get(key, {}), val)
        else:
            orig[key] = updates[key]
    return orig


def update_config(payload, data):
    for key, value in data:
        setattr(payload, key, value)
    return payload


@operation
def validate_node(**_):
    # Deprecated from Cloudify 4.0.
    return True


def _get_subnets(ctx):
    ids = []
    ctx.logger.debug("RTPROPS={}".format(ctx.instance.runtime_properties))
    for prop in ctx.instance.runtime_properties:
        if prop.startswith("subnet_"):
            ids.append(ctx.instance.runtime_properties[prop])
    return ids


@operation
def launch_instance(**kwargs):
    """
    Launch an instance.
    Create the LaunchInstanceDetails object, which is primarily
    populated by the launch_instance_details node property,
    but may be overridden if provided in kwargs.

    :param kwargs:
    :return:
    """

    ctx.logger.info("Launching instance")

    # Get launch_instance_details
    # from node properties and kwargs then recursively merge
    launch_instance_details = \
        merge_config_node_props_kwargs('launch_instance_details',
                                       ctx.node.properties,
                                       kwargs)

    # instantiate LaunchInstanceDetails object
    launch_config = oraclebmc.core.models.LaunchInstanceDetails()
    launch_config = update_config(launch_config,
                                  launch_instance_details)

    # Attempt to ensure that there is a connected subnet.
    # TODO: decide if we care if a user provides multiple subnet relationships.
    subnet_ids = _get_subnets(ctx)
    if not getattr(launch_config, 'subnet_id') and subnet_ids:
        launch_config.subnet_id = subnet_ids[0]

    # Get client_config
    # from node properties and kwargs then recursively merge
    client_config = \
        merge_config_node_props_kwargs('bmc_config',
                                       ctx.node.properties,
                                       kwargs)

    try:
        compute_client = \
            oraclebmc.core.ComputeClient(client_config)
        response = compute_client.launch_instance(launch_config)
    except:
        ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
        raise NonRecoverableError("Instance create failed: {}".
                                  format(sys.exc_info()[0]))

    ctx.instance.runtime_properties['instance_id'] = response.data.id


@operation
def wait_for_running(**kwargs):

    compute_client = oraclebmc.core.ComputeClient(
        ctx.node.properties['bmc_config'])

    instance = compute_client.get_instance(
         ctx.instance.runtime_properties['instance_id'])

    if RUNNING_STATE != instance.data.lifecycle_state:
        return ctx.operation.retry(
            message="Waiting for instance to start ({}). Retrying...".format(
                instance.data.lifecycle_state),
            retry_after=kwargs['start_retry_interval'])

    try:
        vnc_client = oraclebmc.core.VirtualNetworkClient(
           ctx.node.properties['bmc_config'])

        vnas = compute_client.list_vnic_attachments(
            ctx.node.properties['compartment_id'],
            instance_id=ctx.instance.runtime_properties['instance_id'])

        vnic = vnc_client.get_vnic(vnas.data[0].vnic_id)
        ctx.instance.runtime_properties['public_ip'] = vnic.data.public_ip
        ctx.instance.runtime_properties['private_ip'] = vnic.data.private_ip
        ctx.instance.runtime_properties['ip'] = vnic.data.private_ip

    except:
        raise NonRecoverableError("Instance create failed: {}".format(
            sys.exc_info()[0]))


@operation
def terminate_instance(**kwargs):
    ctx.logger.info("Terminating instance")

    compute_client = None

    try:
        compute_client = oraclebmc.core.ComputeClient(
            ctx.node.properties['bmc_config'])
        compute_client.terminate_instance(
            ctx.instance.runtime_properties['instance_id'])
    except:
        ctx.logger.error("Exception:{}".format(sys.exc_info()[0]))
        raise NonRecoverableError("Instance delete failed: {}".
                                  format(sys.exc_info()[0]))


@operation
def wait_for_terminated(**kwargs):

    compute_client = oraclebmc.core.ComputeClient(
        ctx.node.properties['bmc_config'])

    instance = compute_client.get_instance(
         ctx.instance.runtime_properties['instance_id'])

    if TERMINATED_STATE != instance.data.lifecycle_state:
        return ctx.operation.retry(
            message="Waiting for instance to terminate ({}). Retrying...".format(
                instance.data.lifecycle_state),
            retry_after=kwargs['terminate_retry_interval'])
