"""Contains helper utility functions. 
"""
import os
import sys

import boto3

STACK = "BedrockGuardrails-AgentcoreGateway-Demo"
AWS_REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"

# Retrieve CloudFormation stack resources and values
def outputs():
    """The stack's outputs, keyed by output name."""
    client = boto3.client("cloudformation", region_name=AWS_REGION)
    try:
        stacks = client.describe_stacks(StackName=STACK)["Stacks"]
    except client.exceptions.ClientError as err:
        sys.exit(
            f"error: could not read stack {STACK} in {AWS_REGION}.\n"
            f"       {err.response['Error']['Message']}\n"
            f"       Deploy first:  cd infra && npx cdk deploy"
        )
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
