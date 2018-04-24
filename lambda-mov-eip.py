

import boto3
from collections import defaultdict
import logging
from botocore.exceptions import ClientError
import argparse
import re
import sys

session =''
secfwintid = ''
prifwintid = ''

ec2 = boto3.resource('ec2')


ec2 = boto3.resource('ec2')
ec2_client = boto3.client('ec2')
lambda_client = boto3.client('lambda')
iam_client = boto3.client('iam')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_vpn_priv_int(instance):
    interface = instance.network_interfaces
    for int in (instance.network_interfaces):
        print (int);
        if ((int.attachment["DeviceIndex"])==1):
            return int

def get_secret():
    secret_name = "transit-vpc-key"
    endpoint_url = "https://secretsmanager.eu-west-1.amazonaws.com"
    region_name = "eu-west-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=endpoint_url
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
    else:
        # Decrypted secret using the associated KMS CMK
        # Depending on whether the secret was a string or binary, one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
        return secret

def config_gw_lambda_handler(event, context):
    global gcontext

    logger.info('[INFO] Got event{}'.format(event))

    # create filter for instances in running state
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]

    eiptagged = [{'Name':'tag-key', 'Values':['vpn']}]

    # filter the instances based on filters() above
    instances = ec2.instances.filter(Filters=eiptagged)

    VPNInstances = []
    secfw = {}
    prifw ={}
    for instance in instances:
        # for each instance, append to array and print instance id
        VPNInstances.append(instance.id)
        for tag in instance.tags:
            if tag["Value"] == 'secondaryfw':
                secfw["instance"] = instance
                secfw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
            elif tag["Value"] == 'primaryfw':
                prifw["instance"] = instance
                prifw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
        logger.info("instance.id".format(instance.id))


        association = ec2.NetworkInterfaceAssociation('instance.id')

    client = boto3.client('ec2')
    addresses_dict = client.describe_addresses(Filters=eiptagged)
    pubip = addresses_dict["Addresses"][0]
    prifwstatus = prifw["instance"].state['Name']
    secfwstatus = secfw["instance"].state['Name']
    secfwintid = get_vpn_priv_int(secfw["instance"])
    prifwintid = get_vpn_priv_int(prifw["instance"])

    if  ((prifwstatus == 'running') and (secfwstatus == 'running')):
        logger.info("Both firewalls running - exiting")
        exit()

    elif ((prifwstatus != 'running') and (secfwstatus == 'running')):
        logger.info ("Moving public IP with Association-ID: {}".format(pubip["AssociationId"]))

        if "AssociationId" in pubip:
            try:
                release_result = client.disassociate_address(AssociationId = pubip["AssociationId"], DryRun=False)

            except Exception as e:
                logger.info("Release [RESPONSE]: {}".format(e))

        try:
            association_result = client.associate_address(
                NetworkInterfaceId=secfwintid.id,
                AllocationId=pubip["AllocationId"],
                AllowReassociation=False)
        except Exception as e:
            logger.info("Association Fail [RESPONSE]: {}".format(e))


    elif ((prifwstatus == 'running') and (secfwstatus != 'running')):
        logger.info ("Moving public IP with Association-ID: {}".format(pubip["AssociationId"]))

        if "AssociationId" in pubip:
            try:
                release_result = client.disassociate_address(AssociationId=pubip["AssociationId"], DryRun=False)

            except Exception as e:
                logger.info("Disassociation Fail [RESPONSE]: {}".format(e))

        try:
            association_result = client.associate_address(
                NetworkInterfaceId=prifwintid.id,
                AllocationId=pubip["AllocationId"],
                AllowReassociation=False)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))


