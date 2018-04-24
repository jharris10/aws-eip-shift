from __future__ import print_function

import json
import boto3

import logging
from botocore.exceptions import ClientError
import argparse
import re
import os

# Read Environment Variables for Tags
# All TAGS should have a tag-name of 'tag_key_name'
# The primary firewall should have a tag-value of 'pri_fw_tag_key_value'
# The primary firewall should have a tag-value of 'sec_fw_tag_key_value'

tag_key_name = os.environ['tag_key_name']
prifw_tag_key_value = os.environ['prifw_tag_key_value']
secfw_tag_key_value = os.environ['secfw_tag_key_value']
int_index_number = os.environ['int_index_number']

ec2 = boto3.resource('ec2')
client = boto3.client('ec2')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading function')


# get_vpn_priv
# ec2.describe_interfaces does not always return the address in the order expected
# We have to move through the array looking for the index number of the interface
# DeviceIndex 0 == eth0, DeviceIndex 1 == eth1 ......

def get_vpn_priv_int(instance):
    interface = instance.network_interfaces
    for int in (instance.network_interfaces):
        if ((int.attachment["DeviceIndex"]) == int_index_number):
            return int


def lambda_handler(event, context):
    global gcontext

    logger.info('[INFO] Got event{}'.format(event))
    logger.info("tag_key_name: {}".format(tag_key_name))
    logger.info("prifw_tag_key_value: {}".format(prifw_tag_key_value))
    logger.info("secfw_tag_key_value: {}".format(secfw_tag_key_value))
    logger.info("Interface that pubip will be associated with is eth{}".format(int_index_number))

    # create filter for instances in running state
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]

    eiptagged = [
        {
            'Name': 'tag-key',
            'Values': [tag_key_name]

        }
    ]

    # filter the instances based on filters() above
    instances = ec2.instances.filter(Filters=eiptagged)

    VPNInstances = []
    secfw = {}
    prifw = {}
    for instance in instances:
        # for each instance, append to array
        VPNInstances.append(instance.id)
        for tag in instance.tags:
            if tag["Value"] == secfw_tag_key_value:
                secfw["instance"] = instance
                secfw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
                logger.info("Found VPN secondaryfw instance.id via TAG value secondaryfw: {}".format(instance.id))
            elif tag["Value"] == prifw_tag_key_value:
                prifw["instance"] = instance
                prifw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
                logger.info("Found VPN primaryfw instance.id via TAG value primaryfw: {}".format(instance.id))
        association = ec2.NetworkInterfaceAssociation('instance.id')

    client = boto3.client('ec2')
    addresses_dict = client.describe_addresses(Filters=eiptagged)
    pubip = addresses_dict["Addresses"][0]
    prifwstatus = prifw["instance"].state['Name']
    logger.info("Primary firewall running status: {}".format(prifwstatus))
    secfwstatus = secfw["instance"].state['Name']
    logger.info("Secondart firewall running status: {}".format(secfwstatus))
    secfwintid = get_vpn_priv_int(secfw["instance"])
    prifwintid = get_vpn_priv_int(prifw["instance"])

    if ((prifwstatus == 'running') and (secfwstatus == 'running')):
        logger.info("Both firewalls running - exiting")
        exit()

    elif ((prifwstatus != 'running') and (secfwstatus == 'running')):
        if 'NetworkInterfaceId' in pubip:
            if ((pubip["NetworkInterfaceId"] == secfwintid.id)):
                logger.info("Interface Already associated with firewall")
                exit()

            elif (pubip["NetworkInterfaceId"] != secfwintid.id):
                #       if "AssociationId" in pubip:
                logger.info("Moving public IP with Association-ID: {}".format(pubip["AssociationId"]))
                try:
                    release_result = client.disassociate_address(AssociationId=pubip["AssociationId"], DryRun=False)
                except Exception as e:
                    logger.info("Disassociation Fail [RESPONSE]: {}".format(e))
        # EIP not associated with this firewall so go ahead and associate it.
        try:
            association_result = client.associate_address(
                NetworkInterfaceId=secfwintid.id,
                AllocationId=pubip["AllocationId"],
                AllowReassociation=False)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))

    elif ((prifwstatus == 'running') and (secfwstatus != 'running')):

        # Check that the EIP is currently associated with an interface
        # If it is then go ahead and perform the normal checks
        if 'NetworkInterfaceId' in pubip:
            if ((pubip["NetworkInterfaceId"] == prifwintid.id)):
                logger.info("Interface Already associated with firewall")
                exit()

            elif (pubip["NetworkInterfaceId"] != prifwintid.id):
                #       if "AssociationId" in pubip:
                logger.info("Moving public IP with Association-ID: {}".format(pubip["AssociationId"]))
                try:
                    release_result = client.disassociate_address(AssociationId=pubip["AssociationId"], DryRun=False)
                except Exception as e:
                    logger.info("Disassociation Fail [RESPONSE]: {}".format(e))
        # EIP not associated with this firewall so go ahead and associate it.
        try:
            association_result = client.associate_address(
                NetworkInterfaceId=prifwintid.id,
                AllocationId=pubip["AllocationId"],
                AllowReassociation=False)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))
