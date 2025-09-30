#!/usr/bin/env python3
import aws_cdk as cdk
import yaml
from vpc.vpc_stack import VpcStack

# Load the config
with open("config/config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)["env"]["dev"]

account_id = config["accounts"]["account1"]
region = config["region"]

app = cdk.App()

VpcStack(
    app,
    "VpcStack",
    config=config,
    env=cdk.Environment(
        account=account_id,
        region=region
    )
)

app.synth()
