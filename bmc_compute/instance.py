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

RUNNING_STATE = 'RUNNING'
TERMINATED_STATE = "TERMINATED"


@operation
def validate_node(**_):
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

    ctx.logger.info("Launching instance")
    subnet_ids = _get_subnets(ctx)
    launch_config = oraclebmc.core.models.LaunchInstanceDetails()
    launch_config.availability_domain = \
        ctx.node.properties['availability_domain']
    launch_config.compartment_id = \
        ctx.node.properties['compartment_id']
    launch_config.display_name = \
        ctx.node.properties['name']
    launch_config.image_id = \
        ctx.node.properties['image_id']
    launch_config.shape = \
        ctx.node.properties['instance_shape']
    launch_config.subnet_id = subnet_ids[0]
    launch_config.metadata = ({'ssh_authorization_keys':
                               ctx.node.properties['public_key_file']})

    compute_client = None

    try:
        compute_client = oraclebmc.core.ComputeClient(
            ctx.node.properties['bmc_config'])
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
